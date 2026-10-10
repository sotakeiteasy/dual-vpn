"""Пробер состояния: что сейчас поднято и работает ли оно на самом деле.

Живёт в службе и пишет результат в state\\status.json. Трей и окно только
читают этот файл — так они остаются обычным пользовательским процессом и не
лезут в сеть сами.

Проверки разделены на две скорости. Локальные (интерфейсы, маршруты, процесс)
дёшевы и идут раз в две секунды. Сетевые (внешний адрес, корп-DNS, корп-HTTPS)
ходят наружу, поэтому идут не по расписанию, а по событию: один раз, когда
туннель поднялся, и дальше только по запросу (check_now) — трей зовёт её при
открытии меню, окно при открытии и по кнопке. Раньше они шли раз в двадцать
секунд: каждая неудачная попытка перекрашивала корп в «молчит», хотя сайт
открывался, а сервисы адреса выхода с общего адреса VPN отвечали 429.
"""

import base64
import functools
import json
import os
import re
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.request

from . import buildconfig, paths, tunnels, winnet

# Быстрый опрос — несколько WMI-запросов по 10–20 мс (см. winnet). Пока они
# шли через запуск PowerShell, цикл стоил секунды и приходилось реже.
FAST_EVERY = 2.0
# Сколько check_now ждёт уже идущую проверку: при плохой сети она до ~12 с —
# столько стоит корп-HTTPS с повтором; запас — на медленный резолв имён.
CHECK_WAIT = 40.0
# Корп-проверка: пакет через WireGuard теряется и при живом туннеле, поэтому
# одна неудача ещё не «молчит» — повторяем. Попытки короче прежних 12 с, и
# худший случай не дольше прежнего.
CORP_TRIES = 2
CORP_DNS_TIMEOUT = 2.5
CORP_HTTP_TIMEOUT = 6.0
# Старые стороны окна: corp — первый туннель «по списку», personal — основной.
# Их <сторона>_seq пробер ведёт до шага окна, рядом с итогами по туннелям.
LEGACY_SIDES = ("corp", "personal")
# Что спрашивать у DNS туннеля «по списку» без домена в «пускать»: важен любой
# ответ, даже NXDOMAIN от сервера без выхода наружу — сервер жив.
DNS_ASK_NAME = "dns.msftncsi.com"
# Ответ DNS без A-записи: сервер ответил, но имени не знает.
DNS_NO_ADDR = "без адреса"
# Чем проверять полный конфиг вне VPN, как delay у clash_api (tunnel.DELAY_URL).
TRIAL_URL = "http://cp.cloudflare.com/generate_204"
# Ответ проверки конфига, когда ответил его DNS: адрес домена — из рабочей
# сети, а итог читает любой (test-config — без прав).
BY_DNS = "по DNS"


def _probe_host(tunnel):
    """Чем проверять туннель «по списку»: первый домен из «пускать» — не
    подсеть и не *.домен. '' — проверить нечем."""
    return next((e for e in (tunnel or {}).get("include") or []
                 if "/" not in e and not e.startswith("*.")), "")


def _list_part(p):
    """Чем проверять туннель «по списку» p: 'dns' — его DNS (домен проверки
    или, без него, DNS_ASK_NAME), 'http' — HTTPS к домену, когда DNS у туннеля
    нет. При DNS HTTPS не нужен: адрес домена бывает в «не пускать», и запрос
    мерил бы соседа."""
    return "dns" if p["dns"] else "http"


def _check_result(p, got, st):
    """(итог, ответ) проверки туннеля p по ответам его частей got и снимку st.

    Итог: up — ответил, error — молчит, rules — DNS туннеля отвечает, но
    домена из «пускать» не знает (ответ — этот домен): сервер жив, не
    подходят правила; none — «по списку» без DNS и без домена в
    «пускать», проверять нечем; '' — туннель не поднят. Основной работает,
    если выход виден и он не мимо туннеля и не запасной напрямую.
    """
    if not p["running"]:
        return "", ""
    if p["mode"] == "all":
        ip = st.get("exit_ip") or ""
        ok = (ip and st.get("out") != buildconfig.DIRECT_TAG
              and st.get("exit_state") not in ("leak", "direct"))
        return ("up" if ok else "error"), ip
    mine = got.get(p["id"]) or {}
    if p["dns"]:
        said = mine.get("dns")
        if not said:
            return "error", ""
        if not p["host"]:
            return "up", "по DNS"
        if said == DNS_NO_ADDR:
            return "rules", p["host"]
        return "up", said
    if not p["host"]:
        return "none", ""
    if mine.get("http"):
        return "up", f"HTTP {mine['http']}"
    return "error", ""


def _test_result(p, got):
    """(итог, ответ) проверки конфига «по списку» p по ответам его части got:
    как _check_result, но без адреса в ответе и с причиной молчания."""
    result, answer = _check_result({**p, "running": True}, {p["id"]: got}, {})
    if result == "up" and p["dns"]:
        answer = BY_DNS
    elif result == "error":
        answer = "сервер не отвечает"
    return result, answer


def _proxy_url(link):
    """http-вход временного процесса с логином — адресом прокси для urllib.
    Логин — hex, пароль — urlsafe (buildconfig.new_link): экранировать нечего."""
    return f"http://{link['username']}:{link['password']}@127.0.0.1:{link['port']}"


def _recv_exact(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("соединение закрыто")
        buf += chunk
    return buf


def _dns_query(name, qid):
    """Запрос A-записи name. Домен из «пускать» бывает кириллическим —
    в idna; неверное имя — UnicodeError (ValueError)."""
    labels = name.rstrip(".").encode("idna").split(b".")
    qname = b"".join(bytes([len(x)]) + x for x in labels) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def _skip_name(msg, at):
    """Позиция за именем в сообщении DNS (метки или указатель сжатия)."""
    while True:
        size = msg[at]
        if size >= 0xC0:
            return at + 2
        if size == 0:
            return at + 1
        at += size + 1


def _dns_addr(reply, qid):
    """IPv4 из ответа DNS; '' — ответ без A-записи (и NXDOMAIN); None — это
    не ответ на наш запрос."""
    if len(reply) < 12:
        return None
    rid, flags, qd, an = struct.unpack("!HHHH", reply[:8])
    if rid != qid or not flags & 0x8000:
        return None
    try:
        at = 12
        for _ in range(qd):
            at = _skip_name(reply, at) + 4
        for _ in range(an):
            at = _skip_name(reply, at)
            rtype, _, _, size = struct.unpack("!HHIH", reply[at:at + 10])
            at += 10
            if rtype == 1 and size == 4:
                return socket.inet_ntoa(reply[at:at + 4])
            at += size
    except (IndexError, struct.error):
        pass                  # обрезанный хвост: сервер всё равно ответил
    return ""


def _dns_via_proxy(link, server, name):
    """Адрес name от DNS server через http-вход link: CONNECT на server:53
    и запрос по TCP. DNS_NO_ADDR — ответил без адреса; '' — молчит. sing-box
    отвечает на CONNECT до рукопожатия, поэтому мёртвый сервер — это
    таймаут чтения ответа."""
    auth = base64.b64encode(f"{link['username']}:{link['password']}".encode()).decode()
    for _ in range(CORP_TRIES):
        qid = int.from_bytes(os.urandom(2), "big")
        try:
            query = _dns_query(name, qid)
            with socket.create_connection(("127.0.0.1", link["port"]),
                                          CORP_HTTP_TIMEOUT) as sock:
                sock.settimeout(CORP_HTTP_TIMEOUT)
                sock.sendall(f"CONNECT {server}:53 HTTP/1.1\r\nHost: {server}:53\r\n"
                             f"Proxy-Authorization: Basic {auth}\r\n\r\n".encode())
                head = b""
                while not head.endswith(b"\r\n\r\n") and len(head) < 4096:
                    head += _recv_exact(sock, 1)
                if head.split(b" ", 2)[1:2] != [b"200"]:
                    continue
                sock.sendall(struct.pack("!H", len(query)) + query)
                size = struct.unpack("!H", _recv_exact(sock, 2))[0]
                ip = _dns_addr(_recv_exact(sock, size), qid)
        except (OSError, ValueError):
            continue
        if ip is not None:
            return ip or DNS_NO_ADDR
    return ""


def trial_check(link, full, host, dns):
    """(итог, ответ) конфига через http-вход link временного sing-box
    (Tunnel.trial). Полный — HTTP 204 через него; «по списку» — как живой
    туннель (_list_part): его DNS домен проверки host или DNS_ASK_NAME, без DNS —
    HTTPS к host. Ни того, ни другого служба не запускает (none)."""
    proxy = _proxy_url(link)
    if full:
        code = Prober._http_code(TRIAL_URL, proxy)
        if code == "204":
            return "up", "HTTP 204"
        return "error", f"HTTP {code}" if code else "сервер не отвечает"
    p = {"id": "", "mode": "list", "host": host, "dns": dns}
    if dns:
        got = {"dns": _dns_via_proxy(link, dns, host or DNS_ASK_NAME)}
    else:
        got = {"http": Prober._http_code(f"https://{host}", proxy) if host else ""}
    return _test_result(p, got)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Редирект — тоже ответ корп-сайта: 302 на страницу входа уже значит,
    что сервер достижим. Идти по нему — значит мерить чужой хост."""

    def redirect_request(self, *args, **kwargs):
        return None


def _from_ipinfo(text):
    """JSON-объект или {}: при 429 сервисы отвечают и текстом, и числом."""
    try:
        data = json.loads(text or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _from_ipwho(text):
    """Ответ ipwho.is — в поля ipinfo."""
    raw = _from_ipinfo(text)
    if not raw.get("ip"):
        return {}
    return {"ip": raw["ip"], "country": raw.get("country_code", ""),
            "city": raw.get("city", ""),
            "org": (raw.get("connection") or {}).get("org", "")}


def _from_plain(text):
    """Голый адрес без страны."""
    return {"ip": text} if re.match(r"^[\d.]+$", text or "") else {}


class Prober:
    def __init__(self, log=None):
        # Журнал службы: итог сетевой проверки нужен рядом со строками сторожа,
        # а не только в status.json, который перезаписывается.
        self.log = log
        self.st = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        # При плохой сети probe_slow идёт до ~12 с (самая долгая часть). Без
        # флага проверка по запросу и проверка на подъёме туннеля шли бы
        # разом и наперегонки писали exit_ip — следующая ждёт, пока
        # закончится эта.
        self.slow_busy = threading.Event()
        # Проверку по запросу (check_now) и плановую запускают разные потоки:
        # «свободен ли» и «занял» должны быть одним шагом.
        self._slow_gate = threading.Lock()
        # Служба переподключила туннель: цикл мог не застать его упавшим между
        # двумя кругами, и тогда остались бы ответы прошлой сети.
        self._remeasure = threading.Event()
        # Номер сетевой проверки. check_seq — последней начатой, seq в
        # checks[id] — последней, в которой этот туннель уже проверен: по ним
        # трей и окно красят кружок каждого туннеля, не дожидаясь остальных.
        self._seq = 0

    def remeasure(self):
        """Сетевая проверка, как на подъёме туннеля, даже если цикл не
        видел его падения. Увидел — проверка всё равно одна."""
        self._remeasure.set()

    def set(self, **kw):
        with self.lock:
            self.st.update(kw)

    def snapshot(self):
        with self.lock:
            return dict(self.st)

    # ------------------------------------------------------------ быстрые

    def probe_fast(self):
        up_idx, gw = winnet.default_route()
        tun = winnet.tun_index(paths.TUN_IP)

        halves = {}
        for half in ("0.0.0.0/1", "128.0.0.0/1"):
            halves[half] = any(r.get("InterfaceIndex") == tun
                               for r in winnet.routes_for(half)) if tun else False

        self.set(
            iface=up_idx, gw=gw, tun=tun,
            r_low=halves["0.0.0.0/1"], r_high=halves["128.0.0.0/1"],
            pid=",".join(str(p) for p in winnet.pids_of(paths.SINGBOX)),
            v6_off=winnet.v6_blocked(),
            profile=self.current_profile(),
        )

    @staticmethod
    def current_profile():
        """Активный конфиг основного туннеля из tunnels.json; '' — не выбран."""
        try:
            main = tunnels.main_tunnel(tunnels.load())
        except ValueError:
            return ""
        return main["active"] if main else ""

    @staticmethod
    def corp_probe():
        """Чем проверять рабочую сеть — домен проверки первого туннеля «по
        списку» (_probe_host). '' — проверить нечем."""
        try:
            data = tunnels.load()
        except ValueError:
            return ""
        return _probe_host(tunnels.by_kind(data["tunnels"], "corp"))

    @staticmethod
    def check_plan():
        """Что проверять у каждого туннеля, по порядку tunnels.json:
        [{id, name, mode, host, dns, running}]. host — домен проверки «по
        списку», dns — DNS туннеля из собранного конфига, running — туннель
        включён и есть в собранном конфиге (без конфига сборка его пропускает,
        выключенный собирается без процесса). dns — только «по списку»: у
        основного DNS в собранном конфиге есть ради смены на лету, но
        проверяется он выходом, а не DNS."""
        try:
            items = tunnels.load()["tunnels"]
        except ValueError:
            return []
        cfg = buildconfig.read_json(paths.CONFIG_JSON)
        running = set(buildconfig.side_ids(cfg))
        dns = buildconfig.tunnel_dns(cfg)
        return [{"id": t["id"], "name": t["name"], "mode": t["mode"],
                 "host": _probe_host(t) if t["mode"] == "list" else "",
                 "dns": dns.get(t["id"], "") if t["mode"] == "list" else "",
                 "running": t["enabled"] and t["id"] in running}
                for t in items]

    @staticmethod
    def main_tag():
        """Тег endpoint основного туннеля из собранного конфига, иначе ''."""
        try:
            with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
                tid = buildconfig.main_id(json.load(fh))
        except Exception:
            return ""
        return buildconfig.ep_tag(tid) if tid else ""

    # ------------------------------------------------------------ сетевые

    @staticmethod
    def _get(url, timeout):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace").strip()
        except Exception:
            return ""

    def peer_addrs(self):
        """Адреса пиров из собранных конфигов туннелей: {tag: address}."""
        out = {}
        try:
            with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
                ids = buildconfig.side_ids(json.load(fh))
        except Exception:
            ids = []
        for cfg_path in map(buildconfig.side_json, ids):
            try:
                with open(cfg_path, encoding="utf-8") as fh:
                    cfg = json.load(fh)
                for e in cfg.get("endpoints", []):
                    peers = e.get("peers") or []
                    if peers:
                        out[e.get("tag", "")] = peers[0].get("address", "")
            except Exception:
                pass
        return out

    def _exit_info(self):
        """Внешний адрес и страна. Несколько сервисов по очереди.

        Выход VPN — общий адрес на многих клиентов, и ipinfo.io с него быстро
        начинает отвечать 429 Too Many Requests. С одним сервисом адрес выхода
        тогда не определялся никогда, и окно вечно показывало «проверяю».

        Спрашиваем все разом, берём первый годный по порядку: со страной
        лучше голого адреса. По очереди таймауты складывались до 28 с.
        """
        asks = (("https://ipinfo.io/json", 8, _from_ipinfo),
                ("https://ipwho.is/", 8, _from_ipwho),
                ("https://api.ipify.org", 6, _from_plain),
                ("https://ifconfig.me/ip", 6, _from_plain))
        got = [{} for _ in asks]

        def ask(i, url, timeout, parse):
            got[i] = parse(self._get(url, timeout))

        threads = [threading.Thread(target=ask, args=(i, *item), daemon=True)
                   for i, item in enumerate(asks)]
        for t in threads:
            t.start()
        for i, t in enumerate(threads):
            t.join()
            if got[i].get("ip"):
                return got[i]
        return {}

    def probe_slow(self):
        """Сетевая проверка. Части независимы и идут параллельно: по очереди
        их таймауты складывались, и проверка «висела» до минуты, хотя каждая
        часть по отдельности укладывается в секунды.

        Основной туннель проверяет выход, туннель «по списку» — домен
        проверки через свой DNS, а без DNS — по HTTPS (_list_part). Итог
        туннеля — в checks, как только кончились его части: молчащий сосед
        его не держит.
        """
        took = {}
        seq = self.snapshot().get("check_seq", 0)
        plan = self.check_plan()
        by_id = {p["id"]: p for p in plan}
        work = next((p for p in plan if p["mode"] == "list"), None)
        got = {p["id"]: {} for p in plan}      # id → {"dns": адрес, "http": код}
        legacy = {"dns": "corp_ip", "http": "corp_http"}

        def ask(how, fn, p):
            answer = fn(p)
            got[p["id"]][how] = answer
            if p is work:
                self.set(**{legacy[how]: "" if answer == DNS_NO_ADDR else answer})

        jobs = {"exit": self._slow_exit, "v6": self._slow_v6}
        # (вид, имя) → части, после которых известен итог туннеля или старой стороны.
        waits = {}
        for p in plan:
            mine = set()
            if p["running"] and p["mode"] == "all":
                mine.add("exit")
            elif p["running"] and (p["dns"] or p["host"]):
                how = _list_part(p)
                fn = self._slow_dns if how == "dns" else self._slow_http
                name = f"{how} {p['id']}"
                jobs[name] = functools.partial(ask, how, fn, p)
                mine.add(name)
            waits[("tunnel", p["id"])] = mine
        waits[("side", "personal")] = {"exit"}
        waits[("side", "corp")] = set(waits[("tunnel", work["id"])]) if work else set()
        wid = work["id"] if work else ""
        self.set(corp_dns=work["dns"] if work else "",
                 **{field: "" for how, field in legacy.items()
                    if f"{how} {wid}" not in jobs})

        def finish(key):
            """Итог туннеля или стороны известен. Под self.lock; номер — вместе
            с итогом: кто увидел свежий seq, видит и свежий итог."""
            kind, name = key
            if kind == "side":
                self.st[f"{name}_seq"] = seq
                return
            result, answer = _check_result(by_id[name], got, self.st)
            # Новый словарь, а не правка прежнего: snapshot отдаёт его без замка.
            self.st["checks"] = {**(self.st.get("checks") or {}), name: {
                "result": result, "answer": answer, "seq": seq}}

        with self.lock:
            # Итоги удалённых туннелей не таскаем; прежний итог остаётся до свежего.
            kept = self.st.get("checks") or {}
            self.st["checks"] = {tid: kept[tid] for tid in by_id if tid in kept}
            for key, names in waits.items():
                if not names:
                    finish(key)

        def timed(name, fn):
            began = time.monotonic()
            try:
                fn()
            finally:
                took[name] = time.monotonic() - began
                with self.lock:
                    for key, names in waits.items():
                        if name in names:
                            names.discard(name)
                            if not names:
                                finish(key)

        began = time.monotonic()
        parts = [threading.Thread(target=timed, args=item, daemon=True)
                 for item in jobs.items()]
        for t in parts:
            t.start()
        for t in parts:
            t.join()
        # Туннель опустили, пока шла проверка: адрес выхода мерил уже прямую
        # сеть, и метка по нему врала бы — адрес провайдера звался «tunnel».
        try:
            self.probe_fast()
        except Exception:
            pass                  # WMI не ответил — судим по прошлому кругу
        s = self.snapshot()
        if not (s.get("tun") and s.get("r_low")):
            self.set(exit_state="unknown", exit_is_peer=False)
        if self.log:
            self.log(self._slow_summary(time.monotonic() - began, took, plan, got))

    def _slow_summary(self, total, took, plan, got):
        """Строка для журнала: что намерила проверка и сколько шла каждая часть."""
        s = self.snapshot()

        def sec(name):
            return f"{took[name]:.1f} с" if name in took else "не дошла"

        where = " ".join(filter(None, (s.get("exit_country"), s.get("exit_org"))))
        out = (f"выход {s.get('exit_ip') or 'не узнал'}"
               f"{f' ({where})' if where else ''}, {s.get('exit_state') or 'unknown'}, "
               f"{sec('exit')}")
        lines = [out]
        for p in plan:
            if p["mode"] != "list" or not p["running"]:
                continue
            if not p["dns"] and not p["host"]:
                lines.append(f"«{p['name']}» не проверял (ни DNS в конфиге, "
                             f"ни домена в «пускать»)")
                continue
            mine, how = got.get(p["id"]) or {}, _list_part(p)
            label = "DNS" if how == "dns" else "HTTPS"
            said = mine.get(how) or "молчит"
            if how == "dns" and mine.get(how) and not p["host"]:
                said = "отвечает"
            elif said == DNS_NO_ADDR:
                said = f"отвечает, но «{p['host']}» не знает"
            lines.append(f"«{p['name']}» {label} {said} ({sec(how + ' ' + p['id'])})")
        v6 = (f"утечка IPv6 {s['v6_leak']}" if s.get("v6_leak")
              else "IPv6 без утечки")
        return (f"→ проверка сети за {total:.1f} с: {'; '.join(lines)}; "
                f"{v6}, {sec('v6')}")

    def _slow_exit(self):
        peers = self.peer_addrs()
        main_tag = self.main_tag()
        try:
            info = self._exit_info()
            ip = info.get("ip", "")
            real = ""
            try:
                with open(paths.REAL_IP_FILE, encoding="utf-8") as fh:
                    real = fh.read().strip()
            except OSError:
                pass
            # Три исхода, а не два: «подтверждено», «утечка» и «не могу
            # сказать». Молча считать неизвестность утечкой — значит пугать зря.
            if not ip:
                state = "unknown"
            elif self.snapshot().get("out") == buildconfig.DIRECT_TAG:
                # Личный не работает, служба сама увела выход напрямую: адрес
                # провайдера тут ожидаем, это не утечка.
                state = "direct"
            elif not main_tag:
                # Основного нет: всё, что не забрал туннель «по списку», идёт
                # напрямую — так задумано, адрес провайдера тут не утечка.
                state = "direct"
            elif ip == peers.get(main_tag):
                state = "tunnel"          # одноногий сервер, адреса совпали
            elif real and ip == real:
                state = "leak"            # нас видно тем же адресом, что и без VPN
            elif real:
                state = "tunnel"          # адрес другой — значит не наш провайдер
            else:
                state = "unknown"         # реальный адрес неизвестен, сравнить не с чем
            self.set(exit_ip=ip, exit_country=info.get("country", ""),
                     exit_city=info.get("city", ""), exit_org=info.get("org", "")[:26],
                     exit_real=real, exit_state=state,
                     exit_is_peer=(state == "tunnel"))
        except Exception:
            self.set(exit_ip="", exit_country="", exit_city="", exit_org="",
                     exit_is_peer=False, exit_state="unknown")

    def _slow_v6(self):
        # IPv6: любой ответ здесь означает, что трафик идёт мимо туннеля.
        v6 = self._get("https://api6.ipify.org", 6)
        self.set(v6_leak=v6 if re.match(r"^[0-9a-fA-F:]+$", v6 or "") else "")

    def check_one(self, tid, delay):
        """(итог, ответ) одного живого туннеля — проверка конфига, с которым
        он работает. Основной — delay(tag) через его socks (мс или None): выход
        проверяет общая проверка, а здесь важен сервер; «по списку» —
        тем же, чем probe_slow. Нет в собранном конфиге — ('', '')."""
        p = next((p for p in self.check_plan() if p["id"] == tid), None)
        if not p or not p["running"]:
            return "", ""
        if p["mode"] == "all":
            ms = delay(buildconfig.socks_tag(tid))
            return ("up", f"{ms} мс") if ms else ("error", "сервер не отвечает")
        got = {}
        if p["dns"] or p["host"]:
            how = _list_part(p)
            got[how] = (self._slow_dns if how == "dns" else self._slow_http)(p)
        return _test_result(p, got)

    def tunnel_answer(self, tid):
        """Ответ DNS туннеля tid через туннель (_slow_dns): адрес или DNS_NO_ADDR —
        сервер жив; '' — молчит или DNS у туннеля нет."""
        p = next((p for p in self.check_plan() if p["id"] == tid), None)
        return self._slow_dns(p) if p and p["dns"] else ""

    def _slow_dns(self, p):
        return self._dns_ask(p["dns"], p["host"] or DNS_ASK_NAME)

    def _slow_http(self, p):
        return self._http_code(f"https://{p['host']}")

    @staticmethod
    def _dns_ask(server, name):
        """Адрес name от server; DNS_NO_ADDR — ответил без адреса (NXDOMAIN окончателен,
        повтор не нужен); '' — молчит после всех попыток."""
        for _ in range(CORP_TRIES):
            said, ip = winnet.dns_ask_via(name, server, timeout=CORP_DNS_TIMEOUT)
            if re.match(r"^[\d.]+$", ip or ""):
                return ip
            if said:
                return DNS_NO_ADDR
        return ""

    @staticmethod
    def _http_code(url, proxy=""):
        """Код ответа корп-сайта. Нас устраивает любой — важно, что он есть.
        proxy — http-вход временного sing-box (trial_check).

        Даже 403 значит, что до сервера дошли: без туннеля не было бы и его.

        Сертификат не проверяем: служба под LocalSystem не видит корп-CA из
        хранилища пользователя, и проверка падала на TLS при открытом в
        браузере сайте. Мерим только достижимость: HEAD без данных и без
        учётных записей. Прокси не берём — сайт ходит через туннель напрямую.
        """
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
            _NoRedirect())
        for _ in range(CORP_TRIES):
            try:
                req = urllib.request.Request(url, method="HEAD")
                with opener.open(req, timeout=CORP_HTTP_TIMEOUT) as r:
                    return str(r.status)
            except urllib.error.HTTPError as exc:
                return str(exc.code)
            except Exception:
                continue
        return ""

    # -------------------------------------------------------------- запись

    def write_status(self):
        """Кладёт состояние в state\\status.json — его читают трей и окно.

        Пишем через временный файл и os.replace: читатель либо видит прошлую
        версию целиком, либо новую, но никогда не половину.
        """
        data = self.snapshot()
        data["updated"] = time.time()
        data["up"] = bool(data.get("tun")) and bool(data.get("r_low"))
        data["version"] = paths.version()
        tmp = paths.STATUS_JSON + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1, default=str)
            os.replace(tmp, paths.STATUS_JSON)
        except OSError:
            pass

    def run(self):
        was_up = False
        want_slow = False
        while not self.stop_event.is_set():
            try:
                self.probe_fast()
            except Exception:
                pass
            s = self.snapshot()
            up = bool(s.get("tun")) and bool(s.get("r_low"))

            # Сетевая проверка — один раз на подъём туннеля, дальше только
            # check_now. До подъёма мерить выход наружу бессмысленно: получим
            # свой реальный адрес, как будто туннель не работает.
            if up and (not was_up or self._remeasure.is_set()):
                self._remeasure.clear()
                want_slow = True
            was_up = up

            if not up:
                want_slow = False
                self.set(exit_ip="", corp_ip="", corp_http="", v6_leak="",
                         exit_is_peer=False, exit_state="unknown")
                self._forget_checks()
            elif want_slow and self._take_slow():
                # Занято — ответ той проверки мерил прошлый туннель (она шла
                # во время переподключения): ждём её конца и меряем заново.
                want_slow = False
                threading.Thread(target=self._slow_guarded,
                                 daemon=True).start()
            self.write_status()
            self.stop_event.wait(FAST_EVERY)

    def _forget_checks(self):
        """Туннель опущен: итоги прошлой сети не в счёт, номера проверок остаются."""
        with self.lock:
            self.st["checks"] = {tid: {**c, "result": "", "answer": ""}
                                 for tid, c in (self.st.get("checks") or {}).items()}

    def _take_slow(self):
        """Занимает сетевую проверку. False — она уже идёт."""
        with self._slow_gate:
            if self.slow_busy.is_set():
                return False
            # Номер — раньше флага: кто увидел флаг, видит и номер этой проверки.
            self._seq += 1
            self.set(check_seq=self._seq)
            self.slow_busy.set()
            return True

    def check_now(self, wait=CHECK_WAIT):
        """Сетевая проверка сейчас — трей зовёт её при открытии меню, окно
        при открытии и по кнопке.

        Если проверка уже идёт, вторую не запускаем, а ждём её конца: ответ
        будет таким же свежим, а сервисы адреса выхода реже отвечают 429.
        """
        if self._take_slow():
            self._slow_guarded()
            return
        deadline = time.monotonic() + wait
        while self.slow_busy.is_set() and time.monotonic() < deadline:
            time.sleep(0.1)

    def _slow_guarded(self):
        try:
            self.probe_slow()
        except Exception:
            pass
        finally:
            self.slow_busy.clear()
