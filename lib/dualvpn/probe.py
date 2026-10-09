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

import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request

from . import buildconfig, paths, winnet

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
# Части проверки, после которых известен итог конфига. Сторона готова, как
# только кончились её части: личный не ждёт долгого корп-HTTPS.
SIDE_PARTS = {"personal": ("exit",), "corp": ("dns", "http")}


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
        # Номер сетевой проверки. check_seq — последней начатой, <сторона>_seq —
        # последней, в которой эта сторона уже проверена: по ним трей и окно
        # красят кружок каждого конфига, не дожидаясь второго.
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
        try:
            with open(paths.PROFILE_FILE, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""

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

    def corp_dns(self):
        """Корп-DNS — DNS первого туннеля «по списку» из собранного конфига."""
        try:
            with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
                cfg = json.load(fh)
            return next(iter(buildconfig.tunnel_dns(cfg).values()), "")
        except Exception:
            return ""

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
        часть по отдельности укладывается в секунды."""
        took = {}
        seq = self.snapshot().get("check_seq", 0)
        left = {side: set(names) for side, names in SIDE_PARTS.items()}

        def timed(name, fn):
            began = time.monotonic()
            try:
                fn()
            finally:
                took[name] = time.monotonic() - began
                with self.lock:
                    for side, names in left.items():
                        if name in names:
                            names.discard(name)
                            if not names:
                                self.st[f"{side}_seq"] = seq

        began = time.monotonic()
        parts = [threading.Thread(target=timed, args=item, daemon=True)
                 for item in (("exit", self._slow_exit), ("v6", self._slow_v6),
                              ("dns", self._slow_corp_dns),
                              ("http", self._slow_corp_http))]
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
            self.log(self._slow_summary(time.monotonic() - began, took))

    def _slow_summary(self, total, took):
        """Строка для журнала: что намерила проверка и сколько шла каждая часть."""
        s = self.snapshot()

        def sec(name):
            return f"{took[name]:.1f} с" if name in took else "не дошла"

        where = " ".join(filter(None, (s.get("exit_country"), s.get("exit_org"))))
        out = (f"выход {s.get('exit_ip') or 'не узнал'}"
               f"{f' ({where})' if where else ''}, {s.get('exit_state') or 'unknown'}, "
               f"{sec('exit')}")
        if paths.site_env().get("CORP_PROBE"):
            corp = (f"корп DNS {s.get('corp_ip') or 'молчит'}, {sec('dns')}; "
                    f"корп HTTPS {s.get('corp_http') or 'молчит'}, {sec('http')}")
        else:
            corp = "корп не проверял (CORP_PROBE не задан)"
        v6 = (f"утечка IPv6 {s['v6_leak']}" if s.get("v6_leak")
              else "IPv6 без утечки")
        return (f"→ проверка сети за {total:.1f} с: {out}; {corp}; "
                f"{v6}, {sec('v6')}")

    def _slow_exit(self):
        peers = self.peer_addrs()
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
            elif ip == peers.get(buildconfig.PERSONAL_TAG):
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

    def corp_answer(self):
        """Адрес CORP_PROBE от корп-DNS через туннель; "" — молчит или
        спрашивать нечего (нет CORP_PROBE или корп-DNS в конфиге)."""
        probe_host = paths.site_env().get("CORP_PROBE", "")
        dns = self.corp_dns()
        return self._dns_ask(dns, probe_host) if dns and probe_host else ""

    def _slow_corp_dns(self):
        self.set(corp_dns=self.corp_dns(), corp_ip=self.corp_answer())

    def _slow_corp_http(self):
        probe_host = paths.site_env().get("CORP_PROBE", "")
        if probe_host:
            self.set(corp_http=self._http_code(f"https://{probe_host}"))
        else:
            self.set(corp_http="")

    @staticmethod
    def _dns_ask(server, name):
        for _ in range(CORP_TRIES):
            ip = winnet.resolve4_via(name, server, timeout=CORP_DNS_TIMEOUT)
            if re.match(r"^[\d.]+$", ip or ""):
                return ip
        return ""

    @staticmethod
    def _http_code(url):
        """Код ответа корп-сайта. Нас устраивает любой — важно, что он есть.

        Даже 403 значит, что до сервера дошли: без туннеля не было бы и его.

        Сертификат не проверяем: служба под LocalSystem не видит корп-CA из
        хранилища пользователя, и проверка падала на TLS при открытом в
        браузере сайте. Мерим только достижимость: HEAD без данных и без
        учётных записей. Прокси не берём — сайт ходит через туннель напрямую.
        """
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
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
            elif want_slow and self._take_slow():
                # Занято — ответ той проверки мерил прошлый туннель (она шла
                # во время переподключения): ждём её конца и меряем заново.
                want_slow = False
                threading.Thread(target=self._slow_guarded,
                                 daemon=True).start()
            self.write_status()
            self.stop_event.wait(FAST_EVERY)

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
