"""Служба Windows: владеет туннелем, отвечает трею, пишет состояние.

Работает под LocalSystem, потому что правка таблицы маршрутов и создание
сетевого адаптера требуют прав, которых у обычного пользователя нет. Всё
остальное приложение — трей и окно — обычные пользовательские процессы,
и общаются они со службой через именованный канал (см. ipc.py).

Служба ставится один раз установщиком и запускается вручную или при входе в
систему; сама она туннель не поднимает, пока не попросят. Автоподключение —
это отдельный флажок в state\\autostart, который читается при старте службы.
"""

import collections
import datetime
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

from . import buildconfig, ipc, paths, probe, routelist, tunnel, tunnels, winnet

AUTOSTART_FILE = os.path.join(paths.STATE, "autostart")
SERVICE_LOG = os.path.join(paths.LOGS, "service.log")
# Сколько читать с конца журнала sing-box: окно просит 400 строк, это
# десятки КБ. Запас — на длинные строки с адресами и ошибками TLS.
LOG_TAIL_BYTES = 256 * 1024
# Итог последней проверки по каждому конфигу: без туннеля мерить нечем, но
# «как он отработал в прошлый раз» видно и при выключенном VPN.
LAST_CHECK_FILE = os.path.join(paths.STATE, "last-check.json")
# Записей в одном списке правил через канал. Запрос канала — одно чтение
# ipc._BUF (64 КБ), а каждая запись — правило в конфиге sing-box: тысячи —
# скорее вставленный по ошибке файл, чем замысел. Руками в tunnels.json — сколько угодно.
MAX_RULES = 500
# Сколько кругов пробера (по FAST_EVERY) новая сеть должна продержаться,
# прежде чем переподключаться: Wi-Fi при смене точки и пробуждении моргает,
# и на каждый пропавший на секунду маршрут перезапуск только мешал бы.
UPLINK_SETTLE = 3
# Новая сеть бывает не готова сразу (в 14:51 DNS ещё не резолвил корп-сервер):
# не подняли — пробуем ещё столько раз с таким шагом, а не бросаем VPN выключенным.
# Больше двух не нужно: если сеть не поднялась за полминуты, повторы только
# дёргают маршруты, а человек всё равно увидит ошибку и включит сам.
RECONNECT_TRIES = 2
RECONNECT_GAP = 10.0
# Мёртвый туннель: keepalive идёт, а TCP через него не открывается (5 октября личный
# молчал две минуты, корп — до замены конфига). Сетевой пинг давал бы постоянный
# трафик и ложное «молчит», поэтому смотрим на живые соединения в журнале
# процесса туннеля. Один адрес может лежать сам — нужны разные. Перезапускается
# только процесс этого туннеля, tun и второй туннель не трогаем (полный
# перезапуск по таймерам человек запретил 6 октября: «я руками сам перезапущу»);
# один и тот же — не чаще DEAD_GAP, чтобы лежащий сервер не дёргал его по кругу.
DEAD_RE = re.compile(
    r"ERROR .*open connection to (\S+) "
    r"using (?:outbound|endpoint)/wireguard\[([^\]]+)\]: context deadline exceeded")
# Таймауты в журнале бывают и при живом туннеле (6 октября в 12:03 перезапуск
# порвал оба туннеля, а человек видел, что всё работает): прежде чем
# перезапускать, сторож сам спрашивает корп-DNS или задержку через socks личного.
# Адреса не считаем: 6 октября в 13:25 оба туннеля молчали три минуты, а таймауты
# шли к одному адресу (проверка сети Windows, корп-DNS) — порог «два разных»
# сторожа не будил, и интернет стоял.
DEAD_HITS = 3
DEAD_WINDOW = 60.0
DEAD_GAP = 60.0
# Пока выход идёт напрямую, личный проверяем задержкой через его socks не чаще
# этого: проверка ждёт до 5 с, а круг сторожа — раз в FAST_EVERY.
BACK_EVERY = 15.0
# Пауза между кругами сторожа длиннее этого (при шаге FAST_EVERY) — компьютер спал:
# после пробуждения сеть и туннель чаще всего и ломаются, и без отметки
# о сне дыра в штампах журнала читается как зависшая служба.
SLEEP_GAP = 60.0
# Куда что ходит: число соединений по тегу туннеля и адресу — по нему решать, что
# из site.env действительно нужно, а что лишнее. Строки info-уровня sing-box:
# соединение несёт только IP, домен берём из DNS-ответа с тем же номером запроса
# (первое имя — то, что спрашивали, дальше цепочка CNAME). DNS-серверы (:53) не
# считаем: это настройка, а не трафик. SB_LOG_LEVEL выше info глушит эти строки.
PATHS_FILE = os.path.join(paths.STATE, "paths.json")
PATHS_EVERY = 600.0
PATHS_KEEP = 1000      # адресов на тег в файле: хвост из единичных не копим
PATHS_NAMES = 20000    # сколько IP → имя помнить, потом память сбрасываем
CONN_RE = re.compile(
    r"\] (?:endpoint|outbound)/\w+\[([^\]]+)\]: outbound (?:packet )?connection to (\S+)")
PREMATCH_RE = re.compile(
    r"pre-match: .* connection from \S+ to (\S+) via (?:endpoint|outbound)/\w+\[([^\]]+)\]")
DNS_RE = re.compile(r"\[(\d+) [^\]]*\] dns: \w+ \w+ (\S+?)\.? \d+ IN (\w+) (\S+?)\.?$")
# Штамп строки sing-box и заголовка запуска из open_log: по нему команда log сводит
# журналы трёх процессов в один.
STAMP_RE = re.compile(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")


def _read_conf(tid, name):
    """Разобранный конфиг туннеля; нет файла или это не конфиг — None."""
    try:
        with open(tunnels.conf_path(tid, name), encoding="utf-8", errors="replace") as fh:
            return buildconfig.parse_text(fh.read())
    except (OSError, ValueError):
        return None


# Полный ли конфиг, {путь: (mtime, итог)}: статус окно спрашивает каждые
# пару секунд, а файл меняется редко.
_full_cache = {}


def _conf_full(tid, name):
    """Есть ли у конфига туннеля 0.0.0.0/0; нет или не читается — False."""
    if not name:
        return False
    try:
        path = tunnels.conf_path(tid, name)
        stamp = os.stat(path).st_mtime_ns
    except (OSError, ValueError):
        return False
    hit = _full_cache.get(path)
    if hit and hit[0] == stamp:
        return hit[1]
    conf = _read_conf(tid, name)
    full = bool(conf) and buildconfig.is_full(conf)
    _full_cache[path] = (stamp, full)
    return full


def _private_dns(conf):
    """Частные адреса из [Interface] DNS. Публичный (1.1.1.1) общий у разных
    провайдеров — о том, куда ведёт конфиг, он ничего не говорит."""
    out = set()
    for d in buildconfig.conf_dns(conf):
        try:
            if not ipaddress.ip_address(d).is_global:
                out.add(d)
        except ValueError:
            pass
    return out


def _same_dns(conf, other):
    """Общий частный DNS — новый доступ в ту же сеть (решение #13)."""
    return bool(_private_dns(conf) & _private_dns(other))


def _nets(entries):
    """Подсети из записей списка или AllowedIPs; домены пропускаются."""
    out = []
    for entry in entries:
        try:
            out.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass
    return out


def _taken(a, b, out):
    """Забирает ли подсеть b часть подсети a, не вынесенную в «не пускать» out."""
    if a.version != b.version or not a.overlaps(b):
        return False
    # Подсети либо вложены, либо не пересекаются: общая часть — меньшая.
    inner = a if a.prefixlen >= b.prefixlen else b
    return not any(x.version == inner.version and inner.subnet_of(x) for x in out)


def _domains(entries):
    """[(домен, только поддомены)] из записей списка; подсети пропускаются.

    Как split_entries для sing-box: «x.su» — сам домен и поддомены, «*.x.su» —
    только поддомены.
    """
    return [(e[2:], True) if e.startswith("*.") else (e, False)
            for e in entries if not _nets([e])]


def _covers(x, y):
    """Все ли имена доменной записи y попадают под запись x."""
    (xd, x_sub), (yd, y_sub) = x, y
    return (xd == yd and (y_sub or not x_sub)) or yd.endswith("." + xd)


def _domain_taken(a, b, out):
    """Забирает ли доменная запись b имена записи a, не вынесенные в «не
    пускать» out."""
    # Имена либо вложены, либо не пересекаются: общая часть — меньшая запись.
    if _covers(b, a):
        inner = a
    elif _covers(a, b):
        inner = b
    else:
        return False
    return not any(_covers(x, inner) for x in out)


def _clash(t, other, conf, conf_name=""):
    """[(запись, причина)] записей «пускать» туннеля t, которые уже
    забирает other; [] — не забирает.

    Порядок туннелей на маршрут не влияет (решение #16), а sing-box берёт
    первое совпавшее правило: запись, которую забирают два туннеля «по
    списку», ушла бы в тот, что выше в файле. Забирает — та же запись в его
    «пускать», пересечение с его подсетями (AllowedIPs конфига conf и
    «пускать») или доменами по суффиксу (a.ru забирает x.a.ru), не вынесенное
    в «не пускать» ни там, ни в t: исключённое одним идёт дальше и достаётся
    другому. Все записи, а не первая: окно показывает их под полем
    разом, а не по одной на каждое «Сохранить». conf_name — имя активного
    конфига other: в тексте видно, какой из его конфигов забирает запись.
    """
    nets = _nets(other["include"])
    if conf:
        nets += _nets(buildconfig.allowed_nets(conf, v6=True))
    out = _nets(other["exclude"] + t["exclude"])
    domains = _domains(other["include"])
    out_domains = _domains(other["exclude"] + t["exclude"])
    where = f"«{other['name']}»" + (f" (конфиг {conf_name})" if conf_name else "")
    found = []
    for entry in t["include"]:
        if entry in other["include"]:
            found.append((entry, f"«{entry}» уже в {where}"))
        elif (any(_taken(a, b, out) for a in _nets([entry]) for b in nets)
              or any(_domain_taken(a, b, out_domains)
                     for a in _domains([entry]) for b in domains)):
            found.append((entry, f"«{entry}» из «{t['name']}» уже идёт через "
                                 f"{where} — убери его здесь или впиши "
                                 f"туда в «не пускать»"))
    return found


class Core:
    """Логика службы, отделённая от обвязки Windows.

    Отдельным классом — чтобы её можно было запустить и в консоли
    (`tunnelvpn.exe run-service`) при отладке, не устанавливая службу.
    """

    def __init__(self):
        self.lock = threading.Lock()      # один start/stop одновременно
        self.tunnel = tunnel.Tunnel(self.log)
        self.prober = probe.Prober(self.log)
        self.server = ipc.Server(self.handle, self.log)
        self.last_error = ""
        self.busy = ""
        # Журнал sing-box читают сторож и остановка туннеля — из разных потоков.
        self.log_lock = threading.Lock()
        self._paths = {}         # тег → Counter адресов с прошлой записи в файл
        self._ip_names = {}      # IP → имя из DNS-ответа
        # Начало запуска в журнале (log_start основного процесса или туннеля) →
        # до какого байта сторож дочитал.
        self._log_at = {}
        # kind туннеля → раньше чего его процесс снова не перезапускаем, и для
        # какой паузы уже записали «жду»: раз за паузу, не каждый круг.
        self._side_after = {}
        self._side_noted = {}
        # Туннели, чей DNS отвечает при таймаутах: «не перезапускаю» — раз на смену
        # состояния, а не на каждую пачку таймаутов к адресу чужой сети.
        self._side_said = set()
        # Проверки конфигов (_test_conf): запись итога и временные процессы —
        # по одному: у каждого свой host-маршрут и json в run\.
        self._tests_lock = threading.Lock()
        self._trial_lock = threading.Lock()

    # Сколько ещё попыток поднять туннель после неудачного переподключения.
    # Команда человека (start/stop) их отменяет: он уже решил сам.
    _retry_left = 0
    # Номер последней команды человека и тот, что сторож видел в начале круга:
    # круг ждёт проверок по нескольку секунд, и решение, принятое до «Выключить»,
    # после него уже не в силе.
    _human = 0
    _round_human = 0

    # Таймауты (время, тег, адрес) за DEAD_WINDOW.
    _dead_hits = ()
    # Когда в следующий раз проверять, везёт ли личный, пока выход напрямую.
    _back_at = 0.0
    # Когда статистику адресов снова писать в PATHS_FILE.
    _paths_at = 0.0
    # (id туннеля, имя конфига) → {result, answer, at, stamp, checking}: итоги
    # _test_conf. Пишется новым словарём под _tests_lock: статус читает без замка.
    _conf_checks = {}

    # ---------------------------------------------------------------- лог

    def log(self, line):
        paths.ensure_dirs()
        # С миллисекундами: по разнице штампов соседних строк видно, какой
        # шаг включения ест время, — секунд для этого мало.
        stamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        try:
            with open(SERVICE_LOG, "a", encoding="utf-8") as fh:
                fh.write(f"{stamp} {line}\n")
        except OSError:
            pass

    # -------------------------------------------------------------- жизнь

    def start(self):
        paths.ensure_dirs()
        self.log(f"=== служба запущена, версия {paths.version()} ===")
        # Запасного пути через PowerShell нет: каждый отказ WMI и COM — в журнал.
        winnet.on_error = lambda msg: self.log(f"!! {msg}")
        self._migrate()
        threading.Thread(target=self.prober.run, daemon=True).start()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()
        if self.autostart_enabled():
            self.log("→ автоподключение включено")
            # Служба стартует при загрузке раньше сети: 9 октября в 08:19 первая
            # попытка упала на «нет маршрута по умолчанию», и VPN так и стоял
            # красным, пока его не включили руками. Повторы сторож тратит, только
            # когда шлюз появился, — то есть ждёт сеть.
            threading.Thread(target=self._do_start,
                             kwargs={"retries": RECONNECT_TRIES, "wake": True},
                             daemon=True).start()

    def shutdown(self):
        """Остановка службы. Туннель снимаем обязательно.

        Оставить его поднятым нельзя: без службы никто не уберёт маршруты, и
        после перезагрузки половина интернета смотрела бы в мёртвый адаптер.
        """
        self.log("=== служба останавливается ===")
        self.prober.stop_event.set()
        self.server.stop_event.set()
        with self.lock:
            self._flush_paths()
            self.tunnel.stop()

    # ----------------------------------------------------------- автозапуск

    @staticmethod
    def autostart_enabled():
        return os.path.exists(AUTOSTART_FILE)

    @staticmethod
    def set_autostart(on):
        paths.ensure_dirs()
        if on:
            with open(AUTOSTART_FILE, "w", encoding="utf-8") as fh:
                fh.write("1\n")
        else:
            try:
                os.remove(AUTOSTART_FILE)
            except OSError:
                pass

    # -------------------------------------------------------------- команды

    def handle(self, op, payload, is_admin):
        """Обработчик команд из канала. Права уже проверены в ipc.Server.

        Туннель команды — по id или имени (tunnel), а без него — по старому
        типу (kind: corp|personal): так зовут окно и трей до шага окна.
        """
        tid = payload.get("tunnel", "")
        if op == "status":
            return {"ok": True, "status": self._status()}
        if op == "howto":
            return {"ok": True, "howto": self._howto(is_admin)}
        if op == "start":
            return self._do_start(payload.get("profile", ""), wake=True)
        if op == "stop":
            return self._do_stop()
        if op == "apply":
            return self._apply(bool(payload.get("ask")))
        if op == "set-profile":
            return self._set_profile(payload.get("profile", ""))
        if op == "set-active":
            return self._set_active(payload.get("name", ""), tunnel=tid)
        if op == "set-enabled":
            # Строго True, как on: строка «false» из канала выключила бы чужие туннели.
            return self._set_enabled(tid, payload.get("on"), payload.get("replace") is True)
        if op == "list-profiles":
            return {"ok": True, "profiles": self._profiles(), "corp": self._corp()}
        if op == "check":
            return self._check()
        if op == "set-autostart":
            self.set_autostart(bool(payload.get("on")))
            return {"ok": True, "autostart": self.autostart_enabled()}
        if op == "add-config":
            reply = self._add_config(payload.get("name", ""),
                                     payload.get("text", ""),
                                     payload.get("kind", ""), tid,
                                     payload.get("place", ""))
            if reply.get("ok"):
                self._test_conf(reply["tunnel"], reply["name"], wait=False)
            return reply
        if op == "test-config":
            return self._test_conf(tid, payload.get("name", ""))
        if op == "remove-config":
            return self._remove_config(payload.get("name", ""),
                                       payload.get("kind", ""), tid,
                                       bool(payload.get("drop_tunnel")))
        if op == "move-config":
            return self._move_config(tid, payload.get("name", ""),
                                     payload.get("to", ""),
                                     bool(payload.get("drop_tunnel")))
        if op == "read-config":
            return self._read_config(payload.get("name", ""),
                                     payload.get("kind", ""), tid)
        if op == "get-tunnels":
            return self._get_tunnels()
        if op == "add-tunnel":
            return self._add_tunnel(payload.get("name", ""),
                                    payload.get("mode", "list"))
        if op == "set-tunnel":
            reply = self._set_tunnel(tid, payload)
            # Итог rules зависит от домена проверки из «пускать» и режима туннеля.
            # Ушёл запасным — проверка по туннелю, а у основного свой id.
            moved = reply.get("moved")
            if moved:
                self._test_conf(moved["tunnel"], moved["name"], wait=False)
            elif reply.get("ok") and ("include" in payload or "mode" in payload):
                self._test_active(tid)
            return reply
        if op == "remove-tunnel":
            return self._remove_tunnel(tid)
        if op == "set-log-level":
            return self._set_log_level(payload.get("level", ""))
        if op == "set-site":
            return self._set_site(payload.get("text", ""))
        if op == "get-site":
            return {"ok": True, "text": self._read_site()}
        if op == "log":
            return {"ok": True, "lines": self._tail_log(int(payload.get("lines", 200)))}
        return {"ok": False, "error": f"неизвестная команда: {op}"}

    def _status(self):
        st = self.prober.snapshot()
        st["up"] = bool(st.get("tun")) and bool(st.get("r_low"))
        st["busy"] = self.busy
        # Идёт ли сетевая проверка — и та, что сама после подъёма туннеля:
        # без этого окно до её ответа показывало «корп молчит».
        st["checking"] = self.prober.slow_busy.is_set()
        # И по сторонам: личный проверен раньше корпа — его кружок уже свежий.
        for side in probe.LEGACY_SIDES:
            st[f"checking_{side}"] = (st["checking"] and st.get(f"{side}_seq", 0)
                                      < st.get("check_seq", 0))
        checks = st.pop("checks", None) or {}
        st["last_error"] = self.last_error
        st["autostart"] = self.autostart_enabled()
        data = self._tunnels()
        # Туннели без списков правил: в них рабочая сеть, а статус читает
        # любой (get-tunnels — администратору). Окну хватает числа записей (rules):
        # есть ли что терять при удалении. full — у выбранного конфига 0.0.0.0/0:
        # такой туннель «по списку» можно вернуть в основной (move-config).
        in_use = self._in_use(data)
        st["tunnels"] = [{"id": t["id"], "name": t["name"], "mode": t["mode"],
                          "active": t["active"], "enabled": t["enabled"],
                          "confs": tunnels.list_confs(t["id"]),
                          "rules": len(t["include"]) + len(t["exclude"]),
                          "full": _conf_full(t["id"], in_use[t["id"]])}
                         for t in data["tunnels"]]
        # Итог проверки каждого туннеля; checking — как у сторон: туннель
        # проверен раньше соседей, его кружок уже свежий.
        last = self._last_results(data)
        for t in st["tunnels"]:
            c = checks.get(t["id"]) or {}
            seq = c.get("seq", 0)
            t.update(check=c.get("result", ""), answer=c.get("answer", ""),
                     seq=seq, last=last.get(t["id"], ""),
                     checking=st["checking"] and seq < st.get("check_seq", 0),
                     tests=self._tests_of(t["id"], t["confs"]))
        # Раздельное туннелирование включено, когда у рабочего туннеля
        # есть правила; иначе кнопка в окне говорит «выключено».
        work = self._kind_tunnel("corp", data)
        st["split"] = bool(work and (work["include"] or work["exclude"]))
        st["version"] = paths.version()
        st["singbox"] = self._singbox_version()
        # Галочка «подробный журнал» в окне: set-log-level пишет, читать — любому.
        st["log_level"] = data["log_level"]
        st["profiles"] = self._profiles(data)
        st["corp"] = self._corp(data)
        # Старые стороны окна — до шага окна.
        st["last"] = {}
        for kind in tunnels.LEGACY:
            t = self._kind_tunnel(kind, data)
            st["last"][kind] = last.get(t["id"], "") if t else ""
        return st

    @staticmethod
    def _howto(is_admin):
        """Что собрано, для «Как подключиться» в окне: собранные конфиги
        лежат в state\\run\\, окну без прав туда не заглянуть. Ключи и пароли
        не отдаются; подсети и домены туннеля — только администратору,
        как списки правил в get-tunnels: в них рабочая сеть."""
        main_cfg = buildconfig.read_json(paths.CONFIG_JSON)
        # Выключенный собран без процесса: подключения через него нет.
        try:
            off = {t["id"] for t in tunnels.load()["tunnels"] if not t["enabled"]}
        except ValueError:
            off = set()
        ids = [tid for tid in buildconfig.side_ids(main_cfg) if tid not in off]
        endpoints = []
        for tid in ids:
            for ep in buildconfig.read_json(buildconfig.side_json(tid)).get("endpoints", []):
                peers = ep.get("peers") or [{}]
                endpoints.append({
                    "tag": ep.get("tag", ""),
                    "address": ", ".join(ep.get("address") or []),
                    "mtu": ep.get("mtu"),
                    "awg": any(k in ep for k in ("jc", "s1", "h1")),
                    "peer": peers[0].get("address", ""),
                })
        nets, domains = [], []
        if is_admin:
            # Рабочий — первый не основной: пока окно знает один туннель
            # «по списку».
            main_id = buildconfig.main_id(main_cfg)
            work = next((tid for tid in ids if tid != main_id), None)
            nets = buildconfig.tunnel_nets(main_cfg, work) if work else []
            domains = buildconfig.tunnel_domains(main_cfg)
        return {"endpoints": endpoints, "corp_nets": nets, "corp_domains": domains}

    @staticmethod
    def _conf_stamp(tid, name):
        """Отпечаток файла конфига: заменили файл — прошлый итог не про него."""
        try:
            return os.stat(tunnels.conf_path(tid, name)).st_mtime_ns
        except (OSError, ValueError):
            return None

    def _in_use(self, data=None):
        """{id: имя} конфигов каждого туннеля, с которыми соберётся
        включение; имя '' — не выбран. Как tunnels.active_conf: без выбора
        единственный конфиг и есть активный."""
        data = data if data is not None else self._tunnels()
        out = {}
        for t in data["tunnels"]:
            confs = tunnels.list_confs(t["id"])
            out[t["id"]] = t["active"] or (confs[0] if len(confs) == 1 else "")
        return out

    def _last_results(self, data=None):
        """{id: 'up'|'error'|''} — прошлый итог файлов, что лежат сейчас."""
        try:
            with open(LAST_CHECK_FILE, encoding="utf-8") as fh:
                saved = json.load(fh)
        except (OSError, ValueError):
            saved = {}
        out = {}
        for tid, name in self._in_use(data).items():
            rec = saved.get(tid) or {}
            fresh = (name and rec.get("name") == name
                     and rec.get("stamp") == self._conf_stamp(tid, name))
            out[tid] = rec.get("result", "") if fresh else ""
        return out

    def _remember_check(self, st):
        """Запоминает итог проверки при поднятом туннеле: up и error из
        st["tunnels"]; «не с чем проверить» и не поднятый — без итога."""
        # rules — сервер отвечал, не подошли правила: конфиг работал.
        result = {t["id"]: {"up": "up", "rules": "up", "error": "error"}.get(t.get("check"), "")
                  for t in st.get("tunnels") or []}
        data = {tid: {"name": n, "stamp": self._conf_stamp(tid, n),
                      "result": result.get(tid, "")}
                for tid, n in self._in_use().items() if n}
        try:
            paths.ensure_dirs()
            with open(LAST_CHECK_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
        except OSError:
            pass

    def _check(self):
        """Проверяет туннели сейчас и отдаёт статус.

        При выключенном VPN проверять нечем: WireGuard без рукопожатия не
        отвечает. Итог каждого туннеля — в st["tunnels"][i]["check"].
        """
        st = self.prober.snapshot()
        if st.get("tun") and st.get("r_low") and not self.busy:
            self.prober.check_now()
        st = self._status()
        if st["up"] and not self.busy:
            self._remember_check(st)
            # last в статусе — уже из только что записанного.
            st = self._status()
        return {"ok": True, "status": st}

    # ------------------------------------------------- проверка конфига

    def _tests_of(self, tid, confs):
        """{имя: {result, answer, at, checking}} проверок конфигов туннеля tid,
        что лежат сейчас: заменённый файл — уже не тот конфиг."""
        out = {}
        for (owner, name), rec in self._conf_checks.items():
            if (owner == tid and name in confs
                    and rec.get("stamp") == self._conf_stamp(tid, name)):
                out[name] = {k: rec.get(k) for k in ("result", "answer", "at", "checking")}
        return out

    def _note_test(self, key, **rec):
        """Запись проверки key: новым словарём, прежний итог — если файл тот же."""
        with self._tests_lock:
            old = self._conf_checks.get(key) or {}
            base = old if old.get("stamp") == rec.get("stamp") else {}
            self._conf_checks = {**self._conf_checks, key: {**base, **rec}}

    def _test_active(self, tunnel):
        """В фоне проверяет конфиг, с которым туннель соберётся на включении."""
        data = self._tunnels()
        try:
            tid = self._target(data, tunnel)["id"]
        except ValueError:
            return
        name = self._in_use(data)[tid]
        if name:
            self._test_conf(tid, name, wait=False)

    def _test_conf(self, tunnel, name, wait=True):
        """Проверяет конфиг name туннеля: отвечает ли его сервер, — и при
        выключенном VPN, и для запасного. Итог — в статусе (tunnels[].tests),
        wait — и в ответе; без wait проверка идёт в потоке, а статус уже
        показывает checking. Имя приходит через канал от кого угодно — сверяем
        со списком, а не склеиваем в путь."""
        try:
            t = self._target(self._tunnels(), tunnel)
            if name not in tunnels.list_confs(t["id"]):
                raise ValueError(f"нет конфига {name}.conf в туннеле «{t['name']}»")
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        key = (t["id"], name)
        self._note_test(key, stamp=self._conf_stamp(*key), checking=True)
        if not wait:
            threading.Thread(target=self._finish_test, args=(t, name),
                             daemon=True).start()
            return {"ok": True}
        return {"ok": True, "test": self._finish_test(t, name)}

    def _finish_test(self, t, name):
        """Проверка после _test_conf: итог в _conf_checks и в журнал, его же — наружу."""
        key = (t["id"], name)
        stamp = self._conf_stamp(*key)
        try:
            with self._trial_lock:
                result, answer = self._run_test(t, name)
        except Exception as exc:
            self.log(f"!! проверка {name}.conf упала: {exc!r}")
            result, answer = "error", "проверка упала"
        rec = {"result": result, "answer": answer, "at": time.time()}
        self._note_test(key, stamp=stamp, checking=False, **rec)
        self.log(f"→ проверка {name}.conf («{t['name']}»): {result or 'нет итога'}"
                 + (f", {answer}" if answer else ""))
        return {**rec, "checking": False}

    def _run_test(self, t, name):
        """(итог, ответ) конфига name туннеля t.

        Тот же ключ уже работает в боковом процессе — проверка этого туннеля
        пробером: второй процесс с ним увёл бы у живого сервер. Иначе —
        временный sing-box (Tunnel.trial). Полный — конфиг основного туннеля или с
        0.0.0.0/0; «по списку» без DNS и домена в «пускать» — none без запуска.
        """
        conf = _read_conf(t["id"], name)
        if conf is None:
            return "error", "конфиг не читается"
        twin = self.tunnel.side_with_key(conf["interface"].get("privatekey"))
        if twin:
            return self.prober.check_one(twin, self.tunnel.delay)
        full = t["mode"] == "all" or buildconfig.is_full(conf)
        host = probe._probe_host(t) if t["mode"] == "list" else ""
        dns = next(iter(buildconfig.conf_dns(conf)), "")
        if not (full or dns or host):
            return "none", ""
        with self.tunnel.trial(t["id"], conf) as (link, err):
            if err:
                return "error", err
            return probe.trial_check(link, full, host, dns)

    _singbox_cached = None

    @classmethod
    def _singbox_version(cls):
        """Версия sing-box. Спрашиваем один раз: бинарник между запусками
        службы не меняется, а запуск процесса на каждый опрос статуса —
        это раз в две секунды на пустом месте."""
        if cls._singbox_cached is not None:
            return cls._singbox_cached
        cls._singbox_cached = ""
        try:
            out = subprocess.run(
                [paths.SINGBOX, "version"], capture_output=True, text=True,
                timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            first = (out.stdout or "").strip().splitlines()
            if first:
                # «sing-box version 1.14.0-lx.35» → «1.14.0-lx.35»
                parts = first[0].split()
                cls._singbox_cached = parts[-1] if parts else ""
        except Exception:
            pass
        return cls._singbox_cached

    def _do_start(self, profile="", reconnect=False, retries=0, wake=False):
        """Поднимает туннель. reconnect — сначала снять текущий: без этого
        start принял бы живой процесс за «уже работает» и ничего не сделал.
        retries — сколько повторов взвести, если не поднимется. Взводим под
        замком: иначе переподключение, заставшее «Выключить» человека, потом
        включило бы VPN обратно. wake — «Включить» человека или автозапуск:
        ничего не включено — включить всё (_wake_all). apply его не ставит:
        выключенный последним туннель включился бы обратно."""
        if not self.lock.acquire(blocking=False):
            return {"ok": False, "error": f"уже идёт: {self.busy or 'операция'}"}
        try:
            # Круг сторожа мог начаться до остановки службы и дождаться замка
            # после неё: поднятый тогда туннель уже некому было бы снять.
            if reconnect and self.prober.stop_event.is_set():
                return {"ok": False, "error": "служба останавливается"}
            if reconnect and self._round_human != self._human:
                return {"ok": False, "error": "человек уже решил сам"}
            if not reconnect:
                self._human += 1
                self._retry_left = 0
            self.busy = "переподключаю" if reconnect else "включаю"
            if reconnect:
                self._flush_paths()
                self.tunnel.stop()
            began = time.monotonic()
            err = self._wake_all() if wake else ""
            err = err or self.tunnel.start(profile)
            took = time.monotonic() - began
            self.last_error = err
            if err:
                self.log(f"!! {err} (за {took:.1f} с)")
                if retries:
                    self._retry_left = retries
                # Наполовину поднятое состояние опаснее выключенного: маршруты
                # уже могли встать. Убираем за собой сразу, а не ждём человека.
                self.tunnel.stop()
                return {"ok": False, "error": err}
            self.log(f"→ туннель поднят за {took:.1f} с")
            # Туннель новый: таймауты и паузы перезапуска прошлого сеанса — от
            # старой сети. Иначе два таймаута через мёртвый кабель и один на Wi-Fi
            # перезапускали свежий туннель, а упавший на новой сети ждал DEAD_GAP.
            self._dead_hits = ()
            self._side_after, self._side_noted = {}, {}
            self._side_said = set()
            self._back_at = 0.0
            # Личный мог не подняться: проверка выхода на подъёме должна знать
            # это до первого круга сторожа, иначе увидит «утечку».
            self.prober.set(out=self.tunnel.out_now())
            return {"ok": True}
        finally:
            self._probe_now()
            self.busy = ""
            self.lock.release()

    def _wake_all(self):
        """Нет включённого туннеля с конфигом — включает все «по списку», кроме
        пересекающихся с уже включённым (_clashing), а
        основного нет — им становится первый полный без «пускать» (_promote;
        решение пользователя 10.10.2026). Есть хоть один — флаги как
        сохранены. '' или текст ошибки записи; испорченный файл скажет start."""
        try:
            data = tunnels.load()
        except ValueError:
            return ""
        if any(t["enabled"] and tunnels.list_confs(t["id"]) for t in data["tunnels"]):
            return ""
        off = [t for t in data["tunnels"] if not t["enabled"]]
        if not off:
            return ""
        for t in off:
            # Пересекающиеся — только первый по файлу: второй — заменой из окна.
            t["enabled"] = t["mode"] != "list" or not self._clashing(data, t)
        woke = [t["id"] for t in off if t["enabled"]]
        if not woke:
            return ""
        up = self._promote(data)
        r = self._save_tunnels(data, "включённых туннелей нет — включаю все «по списку»: "
                                     + ", ".join(woke))
        if not r["ok"]:
            return f"флаги туннелей не записать: {r['error']}"
        self._log_promoted(up)
        return ""

    def _apply(self, ask=False):
        """Правка конфигов — на живой VPN (решение #14): боковые со сменившимся
        конфигом, вкл/выкл туннеля, списки и смена основного — на лету
        (Tunnel.reload_sides), tun и интернет не падают. Сменилось то, что держит
        основной процесс, — выключение и включение; с ask вместо него ответ
        applied "ask": окно спрашивает человека и повторяет без ask, правка
        уже записана. Выключенный VPN не включаем: правка подхватится на
        включении."""
        if not self.lock.acquire(blocking=False):
            return {"ok": False, "error": f"уже идёт: {self.busy or 'операция'}"}
        try:
            if self.tunnel.uplink is None:
                return {"ok": True, "applied": "off"}
            plan = self.tunnel.live_plan()
            if plan is None and ask:
                return {"ok": True, "applied": "ask"}
            # Круг сторожа, начатый до правки, увидел бы перезапускаемый
            # процесс лежащим и перезапустил бы его сам.
            self._human += 1
            main = self.tunnel.main_id
            done = self.tunnel.reload_sides(plan) if plan else None
            if done is not None:
                errs = [err for _, err in done if err]
                for side, err in done:
                    if err:
                        self.log(f"!! {err}")
                    self._forget_side(side)
                # Выход мог смениться и без процессов: основной стал «по списку».
                if done or self.tunnel.main_id != main:
                    self.prober.set(out=self.tunnel.out_now())
                    self.prober.remeasure()
                return {"ok": not errs, "applied": "sides",
                        "restarted": [side.tid for side, _ in done],
                        **({"error": "; ".join(errs)} if errs else {})}
        finally:
            self.lock.release()
        self.log("→ сменилось то, что держит основной процесс, — перезапускаю VPN")
        reply = self._do_stop()
        if not reply.get("ok"):
            return reply
        return {**self._do_start(), "applied": "full"}

    def _forget_side(self, side):
        """Таймауты и пауза перезапуска процесса — от старого конфига."""
        self._dead_hits = tuple(h for h in self._dead_hits if h[1] != side.tag)
        self._side_after.pop(side.tid, None)
        self._side_noted.pop(side.tid, None)
        self._side_said.discard(side.tid)

    def _do_stop(self):
        if not self.lock.acquire(blocking=False):
            return {"ok": False, "error": f"уже идёт: {self.busy or 'операция'}"}
        try:
            self._human += 1
            self._retry_left = 0
            self.busy = "выключаю"
            self._flush_paths()
            self.tunnel.stop()
            self.last_error = ""
            return {"ok": True}
        finally:
            self._probe_now()
            self.busy = ""
            self.lock.release()

    # ------------------------------------------------------------ сторож

    def _watch(self):
        """Переподключение, когда сеть под туннелем уже не та или sing-box упал.

        Туннель собирается под конкретную сеть: host-маршруты пиров идут
        через её шлюз, а имя корп-сервера в офисе резолвится во внутренний
        адрес, дома — во внешний. После перехода с кабеля на Wi-Fi или сна
        в другом месте старый сеанс висел полумёртвым, пока его не перезапустят
        руками. Сеть не опрашиваем заново: аплинк уже есть в снимке пробера.
        """
        seen, streak, retry_at = None, 0, 0.0
        # По часам стены: monotonic на Windows сон может не считать.
        # Отсчёт — от конца круга: долгое переподключение сном не считаем.
        last = time.time()
        while not self.prober.stop_event.wait(probe.FAST_EVERY):
            self._note_sleep(last, time.time())
            try:
                seen, streak, retry_at = self._watch_once(seen, streak, retry_at)
            except Exception as exc:                       # noqa: BLE001
                # Умри сторож — смену сети снова придётся лечить руками.
                self.log(f"!! сторож сети: {exc}")
            last = time.time()

    def _note_sleep(self, last, now):
        """Отметка в журнале, если между кругами сторожа компьютер спал."""
        if now - last > SLEEP_GAP:
            since = datetime.datetime.fromtimestamp(last).strftime("%H:%M:%S")
            self.log(f"→ компьютер спал {(now - last) / 60:.1f} мин (с {since})")

    def _watch_once(self, seen, streak, retry_at):
        """Один круг сторожа. Принимает и возвращает его состояние:
        какую новую сеть видим, сколько кругов подряд и когда следующий повтор."""
        # Замок без busy — правка конфигов (_apply): трей не сереет, а сторож ждёт.
        if self.busy or self.lock.locked():
            return None, 0, retry_at
        self._round_human = self._human
        st = self.prober.snapshot()
        cur = (st.get("iface"), st.get("gw") or "")
        had = self.tunnel.uplink
        if not had and st.get("out"):
            self.prober.set(out="")

        if self._retry_left:
            if had:                       # туннель уже подняли — повторы не нужны
                self._retry_left = 0
            elif cur[1] and time.monotonic() >= retry_at:
                # Не ниже нуля: «Выключить» между проверкой и уменьшением обнуляет
                # счётчик, и -1 взводил бы повторы без конца.
                self._retry_left = max(self._retry_left - 1, 0)
                self.log(f"→ ещё раз поднимаю туннель: повтор "
                         f"{RECONNECT_TRIES - self._retry_left} из {RECONNECT_TRIES}")
                retry_at = self._reconnect(retries=0)
            return None, 0, retry_at

        if not had:
            return None, 0, retry_at
        proc = self.tunnel.proc
        if proc is not None and proc.poll() is not None:
            self.log(f"!! sing-box завершился сам (код {proc.returncode}) — "
                     f"поднимаю заново")
            return None, 0, self._reconnect()
        with self.log_lock:
            lines, side_lines = self._read_logs()
            self._count_paths(lines)
            if time.monotonic() >= self._paths_at:
                self._save_paths()
        if cur[1]:
            # Маршрут к пиру — раньше разбора таймаутов: без него пакеты
            # туннеля уходят в tun петлёй, и таймауты не от процесса. На новой
            # сети маршруты поставит переподключение.
            if cur == had:
                self.tunnel.mend_peer_routes()
            # Смену сети после этого всё равно проверяем ниже, счёт её
            # кругов не сбрасываем.
            self._mind_sides(side_lines)
        else:
            # Без шлюза таймауты — от сети, а не от туннеля: не копим, иначе
            # они сработают сразу после её возвращения, и не перезапускаем —
            # без сети туннель не оживёт.
            self._dead_hits = ()
        if not cur[1] or cur == had:
            if seen:
                self.log(f"→ сеть моргнула: интерфейс {seen[0]}, шлюз {seen[1]} "
                         f"продержалась {streak} из {UPLINK_SETTLE} кругов — "
                         f"остаюсь на прежней")
            return None, 0, retry_at
        streak = streak + 1 if cur == seen else 1
        if streak < UPLINK_SETTLE:
            if streak == 1:
                self.log(f"→ вижу новую сеть: интерфейс {cur[0]}, шлюз {cur[1]} "
                         f"— жду {UPLINK_SETTLE} кругов, прежде чем переподключать")
            return cur, streak, retry_at
        self.log(f"→ сеть сменилась: интерфейс {had[0]}, шлюз {had[1]} → "
                 f"интерфейс {cur[0]}, шлюз {cur[1]} — переподключаю")
        return None, 0, self._reconnect()

    def _read_logs(self):
        """Новые строки: (основного журнала, журналов обоих туннелей). Порознь:
        трафик туннелей виден в обоих, и в статистику адресов идёт только основной."""
        starts = [self.tunnel.log_start] + [s.log_start for s in self.tunnel.sides]
        # Позиции прошлых запусков больше не нужны.
        self._log_at = {k: v for k, v in self._log_at.items() if k in starts}
        return (self._read_log(starts[0]),
                [line for start in starts[1:] for line in self._read_log(start)])

    def _read_log(self, start):
        """Новые целые строки журнала sing-box с прошлого круга, только запуска
        start (log_start процесса): старые ошибки прошлого сеанса в том же
        файле не в счёт."""
        if start is None:
            return []
        pos = self._log_at.get(start, start[1])
        try:
            with open(start[0], "rb") as fh:
                fh.seek(pos)
                data = fh.read(LOG_TAIL_BYTES)
        except OSError:
            return []
        # Недописанную строку оставляем до следующего круга; кусок без единого
        # перевода строки во всю длину пропускаем, иначе чтение встанет.
        end = data.rfind(b"\n") + 1
        if not end and len(data) == LOG_TAIL_BYTES:
            end = len(data)
        self._log_at[start] = pos + end
        return data[:end].decode("utf-8", "replace").splitlines()

    def _dead_tunnels(self, lines):
        """{тег: таймауты (время круга, тег, адрес)} туннелей, через которые за
        DEAD_WINDOW не открылось DEAD_HITS соединений.
        Паузу DEAD_GAP не смотрит: это решает сторож."""
        now = time.monotonic()
        hits = [h for h in self._dead_hits if now - h[0] < DEAD_WINDOW]
        for line in lines:
            m = DEAD_RE.search(line)
            if m:
                hits.append((now, m.group(2), m.group(1).rpartition(":")[0]))
        self._dead_hits = tuple(hits)
        dead = {}
        for tag in {h[1] for h in hits}:
            mine = [h for h in hits if h[1] == tag]
            if len(mine) >= DEAD_HITS:
                dead[tag] = mine
        return dead

    def _mind_sides(self, lines):
        """Упавший или мёртвый туннель — перезапуск только его процесса, не чаще
        DEAD_GAP. Пока основной не везёт, выход наружу напрямую: главное — чтобы
        интернет работал; везёт снова — выход обратно через него."""
        # Круг идёт секундами. Выключили, включили или правили конфиги за это время —
        # его таймауты и замеры от прежних процессов: 9 октября так сторож после
        # перезапуска назвал свежий процесс «не запущенным» и увёл выход на 17 с напрямую.
        if self._round_human != self._human:
            return
        dead = self._dead_tunnels(lines)
        main = self.tunnel.main
        out, carries = self.tunnel.out_now(), None
        if main and out == buildconfig.DIRECT_TAG and main.alive():
            out, carries = self._try_back(main)
        self.prober.set(out=out)
        for side in self.tunnel.sides:
            if self._round_human != self._human:
                return
            hits = dead.get(side.tag)
            # Живой основной, через который проверка не дошла: трафика через
            # него нет, и таймаутов в журнале не будет.
            stuck = side is main and carries is False
            if side.alive() and not hits and not stuck:
                continue
            if (side is main and hits and not stuck and side.alive()
                    and out != buildconfig.DIRECT_TAG
                    and self.tunnel.delay(buildconfig.socks_tag(side.tid)) is not None):
                # Лежит чужой адрес, а не туннель: выход не трогаем.
                self._dead_hits = tuple(h for h in self._dead_hits
                                        if h[1] != side.tag)
                continue
            if side is main and out != buildconfig.DIRECT_TAG:
                # Выход уводим сразу, без паузы: интернет не должен ждать перезапуска.
                if self.tunnel.set_out(buildconfig.DIRECT_TAG):
                    out = buildconfig.DIRECT_TAG
                    # Назад — не раньше BACK_EVERY: 7 октября одна удачная проверка
                    # через 2 с после увода возвращала трафик в полуживой туннель,
                    # и выход за 40 с метался пять раз.
                    self._back_at = time.monotonic() + BACK_EVERY
                    self.prober.set(out=out)
                    self.prober.remeasure()
            now = time.monotonic()
            after = self._side_after.get(side.tid, 0.0)
            if now < after:
                if self._side_noted.get(side.tid) != after:
                    self._side_noted[side.tid] = after
                    self.log(f"!! туннель «{side.title}» не работает, но с прошлого "
                             f"перезапуска нет {DEAD_GAP:.0f} с, жду")
                continue
            # Таймауты того туннеля разобраны: чем бы ни кончилось, счёт заново.
            self._dead_hits = tuple(h for h in self._dead_hits if h[1] != side.tag)
            why = self._side_down(side, hits)
            if why:
                self._side_after[side.tid] = now + DEAD_GAP
                self.log(f"!! {why} — перезапускаю процесс «{side.title}»")
                self._restart_side(side)

    def _side_down(self, side, hits):
        """Что с туннелем, для журнала, или '' — туннель «по списку» всё-таки
        отвечает: его DNS ответил хоть чем-то. Таймауты тогда — к адресам, до
        которых этот сервер не достаёт (правила от другой сети), и перезапуск
        их не вылечит: раньше так процесс перезапускался каждые DEAD_GAP."""
        if not side.alive():
            if side.proc is None:
                return f"процесс «{side.title}» не запущен"
            return (f"процесс «{side.title}» завершился сам "
                    f"(код {side.proc.returncode})")
        if not hits:
            return f"через {side.tag} не дошла проверка выхода"
        now = time.monotonic()
        what = (f"через {side.tag} соединения не открываются: таймаутов "
                f"{len(hits)} за {now - hits[0][0]:.0f} с, "
                f"адреса: {', '.join(sorted({h[2] for h in hits}))}")
        if side is not self.tunnel.main:
            said = self.prober.tunnel_answer(side.tid)
            if said:
                if side.tid not in self._side_said:
                    self._side_said.add(side.tid)
                    self.log(f"!! {what} — но «{side.title}» отвечает (DNS {said} за "
                             f"{time.monotonic() - now:.1f} с), не перезапускаю")
                return ""
            self._side_said.discard(side.tid)
        return what

    def _try_back(self, main):
        """Выход напрямую, процесс основного main жив: если задержка
        через него дошла — вернуть выход на него. (выход, везёт ли): None —
        не проверяли, рано по BACK_EVERY."""
        now = time.monotonic()
        if now < self._back_at:
            return buildconfig.DIRECT_TAG, None
        self._back_at = now + BACK_EVERY
        tag = buildconfig.socks_tag(main.tid)
        ms = self.tunnel.delay(tag)
        if ms is None:
            return buildconfig.DIRECT_TAG, False
        if not self.tunnel.set_out(tag):
            return buildconfig.DIRECT_TAG, True
        self.log(f"→ «{main.title}» везёт (проверка за {ms} мс) — выход снова через него")
        self.prober.remeasure()
        return tag, True

    def _restart_side(self, side):
        """Перезапуск процесса одного туннеля — под замком start/stop: «Выключить»
        посреди него оставило бы процесс, который уже никто не снимет."""
        if not self.lock.acquire(blocking=False):
            return
        try:
            if (self.tunnel.uplink is None or self.prober.stop_event.is_set()
                    or self._round_human != self._human):
                return
            self.busy = f"перезапускаю туннель «{side.title}»"
            err = self.tunnel.restart_side(side)
            if err:
                self.log(f"!! {err}")
            elif side is not self.tunnel.main:
                self.prober.remeasure()
        finally:
            self.busy = ""
            self.lock.release()

    # ------------------------------------------------------ куда что ходит

    def _count_paths(self, lines):
        """Соединения из строк журнала — в счётчик по тегу и адресу (домену, если
        его уже видели в DNS-ответе)."""
        asked = {}                # номер DNS-запроса → спрошенное имя
        for line in lines:
            m = DNS_RE.search(line)
            if m:
                name = asked.setdefault(m.group(1), m.group(2))
                if m.group(3) in ("A", "AAAA"):
                    if len(self._ip_names) >= PATHS_NAMES:
                        self._ip_names.clear()
                    self._ip_names[m.group(4)] = name
                continue
            m = CONN_RE.search(line)
            if m:
                tag, (host, _, port) = m.group(1), m.group(2).rpartition(":")
                if port == "53":
                    continue
                host = host.strip("[]")
            else:
                m = PREMATCH_RE.search(line)
                if not m:
                    continue
                host, tag = m.group(1), m.group(2)
            dest = self._ip_names.get(host, host)
            # Туннели живут в своих процессах: в журнале основного их трафик
            # идёт через socks-выходы. В статистику — под тегом самого туннеля.
            tag = buildconfig.ep_of_socks(tag)
            self._paths.setdefault(tag, collections.Counter())[dest] += 1

    def _save_paths(self):
        """Счётчик с прошлой записи — прибавить к PATHS_FILE: статистика копится
        между запусками службы, иначе редкие, но нужные адреса не дожили бы до
        разбора. В файле по тегу — адреса по убыванию числа соединений."""
        self._paths_at = time.monotonic() + PATHS_EVERY
        if not self._paths:
            return
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        try:
            with open(PATHS_FILE, encoding="utf-8") as fh:
                saved = json.load(fh)
        except (OSError, ValueError):
            saved = {}
        if not isinstance(saved, dict) or not isinstance(saved.get("tags"), dict):
            saved = {"since": now, "tags": {}}
        try:
            for tag, fresh in self._paths.items():
                total = collections.Counter(saved["tags"].get(tag) or {})
                total.update(fresh)
                saved["tags"][tag] = dict(total.most_common(PATHS_KEEP))
        except (TypeError, AttributeError):
            # В файле не числа (правили руками) — счёт заново, а не ошибка каждый раз.
            saved = {"since": now, "tags": {
                tag: dict(fresh.most_common(PATHS_KEEP))
                for tag, fresh in self._paths.items()}}
        saved["updated"] = now
        try:
            paths.ensure_dirs()
            tmp = PATHS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(saved, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, PATHS_FILE)
        except OSError as exc:
            self.log(f"!! статистика адресов не записана: {exc}")
            return
        self._paths = {}

    def _flush_paths(self):
        """Перед остановкой туннеля: дочитать журнал и записать статистику —
        Tunnel.stop сбрасывает log_start, и хвост потом уже не прочесть.
        Не бросает: статистика не должна мешать выключить VPN."""
        try:
            with self.log_lock:
                self._count_paths(self._read_log(self.tunnel.log_start))
                self._save_paths()
        except Exception as exc:                           # noqa: BLE001
            self.log(f"!! статистика адресов: {exc}")

    def _reconnect(self, retries=RECONNECT_TRIES):
        """Туннель заново на текущей сети; не поднялся — взводит retries
        повторов. Возвращает, когда пробовать в следующий раз."""
        if self._do_start(reconnect=True, retries=retries).get("ok"):
            self.prober.remeasure()
        return time.monotonic() + RECONNECT_GAP

    def _probe_now(self):
        """Снимок сети сразу по окончании start/stop, пока busy ещё стоит.

        up в статусе берётся из снимка Prober, а тот обновляется раз в
        FAST_EVERY. Без этого трей и окно после «включаю»/«выключаю» ещё до
        двух секунд видели прежнее состояние: жёлтый, серый, потом зелёный.
        """
        try:
            self.prober.probe_fast()
        except Exception:                                  # noqa: BLE001
            pass                                           # догонит цикл Prober

    # -------------------------------------------------------------- конфиги

    @staticmethod
    def _tunnels():
        """tunnels.json для чтения. Испорченный — пустой: статус не должен
        падать, причину скажет «Включить». Пишущим командам нужен
        tunnels.load: пустой поверх испорченного стёр бы туннели."""
        try:
            return tunnels.load()
        except ValueError:
            return tunnels.empty()

    @staticmethod
    def _kind_tunnel(kind, data=None):
        """Туннель старого типа corp|personal (tunnels.by_kind), иначе None."""
        data = data if data is not None else Core._tunnels()
        return tunnels.by_kind(data["tunnels"], kind)

    @staticmethod
    def _kind_confs(kind, data=None):
        t = Core._kind_tunnel(kind, data)
        return tunnels.list_confs(t["id"]) if t else []

    @staticmethod
    def _profiles(data=None):
        """Конфиги основного туннеля — из них выбирают профиль."""
        return Core._kind_confs("personal", data)

    @staticmethod
    def _corp(data=None):
        """Конфиги первого туннеля «по списку» — бывшего рабочего."""
        return Core._kind_confs("corp", data)

    def _migrate(self):
        """Старая установка — в туннели, один раз после обновления: плоский
        conf\\ (до 0.3) — по папкам типов, папки типов и site.env (до 0.4) — в
        tunnels.json. Именно в таком порядке: второй шаг берёт то, что разложил первый."""
        try:
            moved = buildconfig.migrate_flat()
        except OSError as exc:
            self.log(f"!! не перенести конфиги по папкам: {exc}")
            return
        for name, kind in moved:
            self.log(f"→ {name}.conf перенесён в conf\\{kind}")
        # Собранные конфиги прошлой версии в открытом state\\ — сразу, не
        # дожидаясь включения: в них ключи.
        buildconfig.drop_legacy()
        try:
            tunnels.migrate(log=self.log)
        except (OSError, ValueError) as exc:
            self.log(f"!! не перенести настройки в tunnels.json: {exc}")

    @staticmethod
    def _target(data, tunnel="", kind=""):
        """Туннель команды в data: по id, затем по имени без учёта регистра
        (`tunnelvpn use Работа nl-1`); без tunnel — по старому типу corp|personal.
        Иначе ValueError с причиной."""
        if tunnel:
            key = str(tunnel)
            t = tunnels.find(data, key) or next(
                (x for x in data["tunnels"]
                 if x["name"].casefold() == key.casefold()), None)
            if t is None:
                raise ValueError(f"нет туннеля {key!r}")
            return t
        if kind not in tunnels.LEGACY:
            raise ValueError(f"неизвестный тип конфига: {kind!r}")
        t = tunnels.by_kind(data["tunnels"], kind)
        if t is None:
            raise ValueError(f"нет туннеля для конфига типа {kind}")
        return t

    @staticmethod
    def _load_target(tunnel="", kind=""):
        """(tunnels.json, туннель) для правки или ValueError с причиной."""
        data = tunnels.load()
        return data, Core._target(data, tunnel, kind)

    @staticmethod
    def _new_tid(data):
        """Свободный id нового туннеля (t1, t2…): имя человека — кириллица,
        а id — имя папки и часть тегов sing-box."""
        ids = {t["id"] for t in data["tunnels"]}
        n = 1
        # Папка без туннеля — конфиги после оборванного удаления: их не подбираем.
        while f"t{n}" in ids or os.path.exists(tunnels.conf_dir(f"t{n}")):
            n += 1
        return f"t{n}"

    @staticmethod
    def _write_conf(tid, name, text):
        """Кладёт конфиг в папку туннеля через временный файл: оборванная
        запись не оставит полконфига."""
        paths.ensure_dirs()
        os.makedirs(tunnels.conf_dir(tid), exist_ok=True)
        path = tunnels.conf_path(tid, name)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)

    @staticmethod
    def _keep_active(t, before, name):
        """Конфиг name лёг в t запасным: выбранный остаётся. Без выбора
        единственный прежний и был активным (tunnels.active_conf) — фиксируем
        его, иначе сборка упёрлась бы в «конфигов несколько»."""
        t["active"] = t["active"] or (before[0] if len(before) == 1 else name)

    def _list_confs(self, data):
        """[(туннель, разобранный выбранный конфиг)] туннелей «по списку»;
        без выбранного или нечитаемого — пропущены."""
        in_use = self._in_use(data)
        out = [(t, _read_conf(t["id"], in_use[t["id"]]))
               for t in data["tunnels"] if t["mode"] == "list" and in_use[t["id"]]]
        return [(t, c) for t, c in out if c]

    def _place(self, conf, data):
        """Куда «Добавить конфиг…» без туннеля кладёт conf, по его AllowedIPs:

        ("all", t|None) — 0.0.0.0/0: запасным в основной (None — его нет, новый);
        ("replace", t) — тот же частный DNS, что у конфига туннеля «по списку»:
        новый доступ туда же, заменяем молча; ("ask", t) — сети пересекаются, а
        DNS не общий: решает человек; ("list", None) — новый туннель «по списку».
        Сравнивается с выбранным конфигом каждого туннеля. Иначе ValueError.
        """
        if buildconfig.is_full(conf):
            return "all", tunnels.main_tunnel(data)
        nets = [ipaddress.ip_network(n) for n in buildconfig.allowed_nets(conf)]
        if not nets:
            raise ValueError("в AllowedIPs конфига ни 0.0.0.0/0, ни подсетей — "
                             "не понять, что через него пускать")
        others = self._list_confs(data)
        # Общий DNS — признак сильнее пересечения сетей: смотрим его у всех.
        for t, other in others:
            if _same_dns(conf, other):
                return "replace", t
        for t, other in others:
            if any(a.overlaps(ipaddress.ip_network(b)) for a in nets
                   for b in buildconfig.allowed_nets(other)):
                return "ask", t
        return "list", None

    def _add_config(self, name, text, kind="", tunnel="", place=""):
        """Кладёт конфиг в туннель.

        С tunnel или kind — в этот туннель, добавленный выбирается; place
        "replace" (и старый пункт «рабочий») — вместо его конфигов, туннель
        берёт имя файла, правила остаются; так же с одним tunnel, если у
        конфига общий частный DNS с выбранным в туннеле. place "new" —
        новый туннель «по списку». Без них место выбирает _place; при ask ничего не пишется, а
        ответ несёт ask: окно спрашивает и повторяет команду с replace или new.

        Файл ложится под именем файла человека, очищенным от недопустимых
        знаков (buildconfig.safe_name), а не отклонённым из-за них.
        """
        # BOM от Блокнота: с ним «[Interface]» в первой строке не узнаётся.
        text = (text or "").lstrip("\ufeff")
        bad = buildconfig.check_conf_text(text)
        if bad:
            return {"ok": False, "error": bad}
        name = buildconfig.safe_name(name)
        try:
            data = tunnels.load()
            if place == "new":
                where, t = "list", None
            elif tunnel or kind or place == "replace":
                # replace без туннеля — отказ _target, а не авто: заменять — значит где-то.
                t = self._target(data, tunnel, kind)
                # У старого «рабочего» конфиг один, как до туннелей.
                replace = place == "replace" or (kind == "corp" and not tunnel)
                if tunnel and not place and not kind:
                    # Трей: новый доступ в ту же сеть — вместо прежнего, как авто в окне.
                    conf = buildconfig.parse_text(text)
                    replace = any(u is t and _same_dns(conf, other)
                                  for u, other in self._list_confs(data))
                where = "replace" if replace else "to"
            else:
                where, t = self._place(buildconfig.parse_text(text), data)
            if where == "replace" and t["mode"] != "list":
                raise ValueError(f"«{t['name']}» — не туннель «по списку», "
                                 f"заменять в нём нечего")
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if where == "ask":
            return {"ok": False,
                    "ask": {"id": t["id"], "name": t["name"],
                            "conf": self._in_use(data)[t["id"]]},
                    "error": f"похоже на «{t['name']}»: заменить его конфиг "
                             f"или добавить отдельным туннелем?"}
        new = t is None
        if new:
            # До записи файла: иначе отказ tunnels.save оставил бы конфиг без туннеля.
            if len(data["tunnels"]) >= tunnels.MAX_TUNNELS:
                return {"ok": False, "error": f"туннелей уже {tunnels.MAX_TUNNELS}, "
                                               f"больше нельзя"}
            t = {"id": self._new_tid(data), "name": name,
                 "mode": "all" if where == "all" else "list",
                 "active": "", "include": [], "exclude": []}
            data["tunnels"].append(t)
        before = tunnels.list_confs(t["id"])
        try:
            self._write_conf(t["id"], name, text)
        except OSError as exc:
            return {"ok": False, "error": f"конфиг не записать: {exc}"}
        self.log(f"→ в туннель «{t['name']}» ({t['id']}) добавлен конфиг {name}.conf")
        if where == "all":
            self._keep_active(t, before, name)
        else:
            # Добавленный — сразу активный: его и добавляли, чтобы включить.
            t["active"] = name
        if where == "replace":
            # В окне туннель зовётся своим конфигом (решение #12).
            t["name"] = name
        if new and t["mode"] == "list":
            # «Отдельным туннелем» в те же сети: включённым он делил бы их с
            # прежним по порядку в файле. Выключенный включается заменой (_set_enabled).
            clash = self._clashing(data, t)
            t["enabled"] = not clash
            if clash:
                names = ", ".join(f"«{o['name']}»" for o in clash)
                self.log(f"→ «{t['name']}» ведёт в сети {names} — добавлен выключенным")
        try:
            data = tunnels.save(data)
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": f"конфиг лёг, но не выбран: {exc}"}
        if where == "replace":
            # После записи: сбой оставит прежние файлы, а не туннель без конфига.
            for old in before:
                if old == name:
                    continue
                try:
                    os.remove(tunnels.conf_path(t["id"], old))
                    self.log(f"→ удалён прежний конфиг {old}.conf")
                except OSError as exc:
                    self.log(f"→ не удалить {old}.conf: {exc}")
        return {"ok": True, "name": name, "tunnel": t["id"], "place": where,
                "profiles": self._profiles(data), "corp": self._corp(data)}

    def _read_config(self, name, kind="", tunnel=""):
        """Отдаёт конфиг целиком, вместе с ключами.

        Каталог conf\\ закрыт от обычного пользователя, поэтому прочитать файл
        может только служба. Права проверяет ipc.Server: команды нет ни в
        READ_OPS, ни в USER_OPS, значит нужен администратор.
        """
        try:
            path = tunnels.conf_path(
                self._target(self._tunnels(), tunnel, kind)["id"], name)
            with open(path, encoding="utf-8", errors="replace") as fh:
                return {"ok": True, "text": fh.read()}
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    def _remove_config(self, name, kind="", tunnel="", drop_tunnel=False):
        """Удаляет конфиг; drop_tunnel — и сам туннель, если конфигов в нём
        не осталось. Без него пустой туннель хранит правила до нового конфига."""
        try:
            data, t = self._load_target(tunnel, kind)
            os.remove(tunnels.conf_path(t["id"], name))
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}
        self.log(f"→ из туннеля «{t['name']}» удалён конфиг {name}.conf")
        if drop_tunnel and not tunnels.list_confs(t["id"]):
            data["tunnels"].remove(t)
            up = self._promote(data) if t["mode"] == "all" else None
            try:
                data = tunnels.save(data)
            except (OSError, ValueError) as exc:
                return {"ok": False, "error": f"конфиг удалён, но туннель остался: {exc}"}
            self.log(f"→ удалён туннель {t['id']}")
            self._log_promoted(up)
            self._drop_conf_dir(t["id"])
        elif t["active"] == name:
            # Активный указывал бы на удалённый файл, и следующее «Включить»
            # падало бы с «нет конфига». Берём другой, а без него — пусто:
            # сборка тогда пропустит пустой туннель.
            rest = tunnels.list_confs(t["id"])
            t["active"] = rest[0] if rest else ""
            try:
                data = tunnels.save(data)
            except (OSError, ValueError) as exc:
                return {"ok": False, "error": f"конфиг удалён, но выбор не записать: {exc}"}
        return {"ok": True, "profiles": self._profiles(data), "corp": self._corp(data)}

    def _move_config(self, tunnel, name, to, drop_tunnel=False):
        """Полный конфиг (0.0.0.0/0) — между основным туннелем и своим «по списку».

        to "new" — из основного в новый туннель «по списку» («только YouTube
        через NL»); to "all" — из «по списку» в основной запасным (нет
        основного — новым основным). Конфиг без 0.0.0.0/0 в основной не идёт:
        его сервер отбросил бы чужой трафик. drop_tunnel — как у remove-config.
        """
        try:
            if to not in ("new", "all"):
                raise ValueError(f"переносить можно в new или all, а не {to!r}")
            data, src = self._load_target(tunnel)
            path = tunnels.conf_path(src["id"], name)
            need = "all" if to == "new" else "list"
            if src["mode"] != need:
                raise ValueError(f"«{src['name']}» — не туннель "
                                 + ("«весь остальной трафик»" if need == "all"
                                    else "«по списку»"))
            conf = _read_conf(src["id"], name)
            if conf is None:
                raise ValueError(f"нет конфига {name}.conf в туннеле «{src['name']}»")
            if not buildconfig.is_full(conf):
                raise ValueError(f"у {name}.conf в AllowedIPs нет 0.0.0.0/0: переносится "
                                 f"только конфиг на весь трафик")
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        rest = [c for c in tunnels.list_confs(src["id"]) if c != name]
        drop = drop_tunnel and not rest
        dst = tunnels.main_tunnel(data) if to == "all" else None
        if dst is not None and name in tunnels.list_confs(dst["id"]):
            return {"ok": False, "error": f"в «{dst['name']}» уже есть {name}.conf"}
        if dst is None and len(data["tunnels"]) - drop >= tunnels.MAX_TUNNELS:
            return {"ok": False, "error": f"туннелей уже {tunnels.MAX_TUNNELS}, больше нельзя"}
        if drop:
            data["tunnels"].remove(src)
        elif src["active"] == name:
            src["active"] = rest[0] if rest else ""
        if dst is None:
            dst = {"id": self._new_tid(data), "name": name,
                   "mode": "list" if to == "new" else "all",
                   "active": "", "include": [], "exclude": []}
            data["tunnels"].append(dst)
        self._keep_active(dst, tunnels.list_confs(dst["id"]), name)
        # Ушёл последний конфиг основного вместе с ним. Сам перенесённый в dst
        # не повышается: его и вынесли из основного «по списку».
        up = self._promote(data, skip=dst) if drop and src["mode"] == "all" else None
        moved = tunnels.conf_path(dst["id"], name)
        try:
            os.makedirs(tunnels.conf_dir(dst["id"]), exist_ok=True)
            os.replace(path, moved)
        except OSError as exc:
            return {"ok": False, "error": f"конфиг не перенести: {exc}"}
        try:
            tunnels.save(data)
        except (OSError, ValueError) as exc:
            # Файл — обратно: tunnels.json прежний и ждёт его на старом месте.
            try:
                os.replace(moved, path)
            except OSError:
                pass
            return {"ok": False, "error": str(exc)}
        self.log(f"→ конфиг {name}.conf из «{src['name']}» перенесён в «{dst['name']}» "
                 f"({dst['id']})")
        if drop:
            self.log(f"→ удалён туннель {src['id']}")
            self._log_promoted(up)
            self._drop_conf_dir(src["id"])
        return {"ok": True, "tunnel": dst["id"], "name": name}

    def _set_active(self, name, tunnel="", kind=""):
        """Делает name активным конфигом туннеля; '' — снять выбор."""
        try:
            data, t = self._load_target(tunnel, kind)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if name and name not in tunnels.list_confs(t["id"]):
            return {"ok": False, "error": f"нет конфига {name}.conf в туннеле «{t['name']}»"}
        t["active"] = name
        try:
            tunnels.save(data)
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "tunnel": t["id"], "active": name}

    def _set_enabled(self, tunnel, on, replace=False):
        """Включает или выключает туннель «по списку»: у выключенного нет
        процесса и rule-set пустой, конфиги и правила остаются. На живой VPN переносит apply
        отправителя, как после set-active и правки правил. Основной так не
        выключается: «Всё остальное напрямую».

        Записи включаемого уже забирает включённый (_clashing) — отказ с clash
        [{id, name}]: окно предлагает замену и повторяет с replace: мешающие
        выключаются в той же записи, и reload_sides опустошает их rule-set вместе с
        заполнением нового."""
        if not isinstance(on, bool):
            return {"ok": False, "error": "on должен быть true или false"}
        try:
            data, t = self._load_target(tunnel)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if t["mode"] != "list":
            return {"ok": False, "error": f"«{t['name']}» — основной: его выключает "
                                           f"«Всё остальное напрямую»"}
        if t["enabled"] == on:
            return {"ok": True, "tunnel": t["id"], "enabled": on}
        off = self._clashing(data, t) if on else []
        if off and not replace:
            names = ", ".join(f"«{o['name']}»" for o in off)
            return {"ok": False, "clash": [{"id": o["id"], "name": o["name"]} for o in off],
                    "error": f"«{t['name']}» забирает те же адреса, что {names}: "
                             f"вместе их не включить"}
        for o in off:
            o["enabled"] = False
        t["enabled"] = on
        r = self._save_tunnels(data, f"туннель {t['id']} "
                                     f"{'включён' if on else 'выключен'}"
                                     + (f" вместо {', '.join(o['id'] for o in off)}"
                                        if off else ""))
        return {**r, "tunnel": t["id"], "enabled": on} if r["ok"] else r

    def _set_profile(self, name):
        """Профиль — активный конфиг основного туннеля (`tunnelvpn profile`)."""
        r = self._set_active(name, kind="personal")
        return {"ok": True, "profile": name} if r["ok"] else r

    # ------------------------------------------------------------- туннели

    @staticmethod
    def _rules(text):
        """Поле списка правил → (записи, непонятые) или ValueError."""
        if not isinstance(text, str):
            raise ValueError("список правил должен быть текстом")
        entries, rejected = routelist.parse(text)
        if len(entries) > MAX_RULES:
            raise ValueError(f"в списке {len(entries)} записей, "
                             f"больше {MAX_RULES} нельзя")
        return entries, rejected

    def _save_tunnels(self, data, done):
        """Пишет tunnels.json; done — строка в журнал службы."""
        try:
            tunnels.save(data)
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}
        self.log(f"→ {done}")
        return {"ok": True}

    @staticmethod
    def _get_tunnels():
        """tunnels.json со списками правил и конфигами каждого туннеля.

        Только администратору: в списках адреса и домены рабочей сети. Испорченный
        файл — ошибка, а не пустой: редактор поверх пустого затёр бы туннели.
        """
        try:
            data = tunnels.load()
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        for t in data["tunnels"]:
            t["confs"] = tunnels.list_confs(t["id"])
        return {"ok": True, **data}

    def _add_tunnel(self, name, mode):
        """Новый туннель в конце списка. id выдаёт служба (t1, t2…): имя
        человека — кириллица, а id — имя папки и часть тегов sing-box."""
        try:
            data = tunnels.load()
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        tid = self._new_tid(data)
        data["tunnels"].append({"id": tid, "name": name, "mode": mode,
                                "active": "", "include": [], "exclude": []})
        r = self._save_tunnels(data, f"добавлен туннель {tid}")
        return {**r, "id": tid} if r["ok"] else r

    def _set_tunnel(self, tunnel, payload):
        """Меняет у туннеля то, что пришло: name, mode, include, exclude.

        Списки — текстом поля, как его ввёл человек (routelist.parse).
        Понятое сохраняется, непонятое возвращается в rejected: окно его
        покажет, молча ничего не пропадает.

        mode all — «всё остальное через этот туннель»: прежний основной
        становится «по списку», как переключатель; list у основного — всё
        остальное напрямую. Запись, которую уже забирает другой туннель «по
        списку», — отказ с problems [{field, text}]: окно ставит их под поля.

        «Пускать» стёрто у полного конфига «по списку»: 0.0.0.0/0 в списке не
        берётся (allowed_nets), и такой туннель не вёз бы ничего. Основного нет —
        становится им (в ответе mode); есть — конфиг уходит к нему запасным, а
        туннель — вместе с ним (в ответе moved). Непустой «не пускать» так не
        переносится: у запасного своих списков нет, молча его не теряем.
        """
        try:
            data, t = self._load_target(tunnel)
            rejected = {}
            for key in ("include", "exclude"):
                if key in payload:
                    t[key], rejected[key] = self._rules(payload[key])
            changed = [t]
            if payload.get("mode") == "all" and t["mode"] != "all":
                changed += self._make_main(data, t)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        for key in ("name", "mode"):
            if key in payload:
                t[key] = payload[key]
        main = tunnels.main_tunnel(data)
        idle = "include" in payload and self._idle_full(data, t)
        if idle and main is None:
            t["mode"] = "all"
        spare = idle and main is not None
        problems = self._clash_of(data, changed)
        if spare:
            problems += self._spare_blocks(t, main, rejected)
        if not problems and spare:
            r = self._to_spare(data, t, main)
            if r["ok"]:
                return r
            problems = [{"field": "include", "text": r["error"]}]
        if problems:
            return {"ok": False, "problems": problems,
                    "error": "; ".join(p["text"] for p in problems)}
        r = self._save_tunnels(data, f"изменён туннель {t['id']}"
                               + (" — без «пускать» стал основным"
                                  if idle and main is None else ""))
        # Сохранённые списки — окну: поля показывают записи в том виде, как
        # их понял routelist, рядом с непонятыми; mode — туннель мог стать основным.
        return ({**r, "rejected": rejected, "include": t["include"],
                 "exclude": t["exclude"], "mode": t["mode"]} if r["ok"] else r)

    @staticmethod
    def _spare_blocks(t, main, rejected):
        """Почему полный конфиг t без «пускать» не уходит запасным к main —
        [{field, text}] для листа окна. Непонятое в полях тоже держит: с
        удалённым туннелем оно пропало бы молча."""
        out = [{"field": k, "text": "не понял: " + ", ".join(bad)}
               for k, bad in rejected.items() if bad]
        texts = []
        if t["exclude"]:
            texts.append(f"без «пускать» конфиг станет запасным к «{main['name']}», а у "
                       f"запасного своих списков нет — очисти и «не пускать» или "
                       f"впиши, что пускать через него")
        if len(tunnels.list_confs(t["id"])) > 1:
            texts.append(f"у «{t['name']}» несколько конфигов — запасным к "
                       f"«{main['name']}» уходит только единственный: убери лишние "
                       f"или впиши, что пускать через него")
        return out + [{"field": "include", "text": x} for x in texts]

    def _to_spare(self, data, t, main):
        """Единственный конфиг t — запасным к основному main, туннель t уходит
        (как move-config to all с drop_tunnel). Ответ — moved для окна."""
        name = self._in_use(data)[t["id"]]
        r = self._move_config(t["id"], name, "all", drop_tunnel=True)
        if not r["ok"]:
            return r
        return {"ok": True, "moved": {"tunnel": r["tunnel"], "name": name,
                                      "main": main["name"]}}

    def _idle_full(self, data, t):
        """Полный конфиг «по списку» с пустым «пускать»: такой не везёт ничего."""
        return (t["mode"] == "list" and not t["include"]
                and _conf_full(t["id"], self._in_use(data)[t["id"]]))

    def _promote(self, data, skip=None):
        """Основной ушёл (удалён или перенесён) — им становится первый по
        tunnels.json полный конфиг «по списку» без «пускать», кроме skip:
        иначе он так и не вёз бы ничего. Остальные такие — как есть. Вызывать
        до tunnels.save, только если основной был и ушёл этой командой: «Всё
        остальное напрямую» — выбор человека, его не отменяем. Исключение —
        _wake_all: «Включить», когда не включено ничего. Новый основной
        или None — в журнал его пишет вызвавший, после записи файла."""
        if tunnels.main_tunnel(data) is not None:
            return None
        for t in data["tunnels"]:
            # Выключенный — тоже выбор человека: основным его не включаем.
            if t is not skip and t["enabled"] and self._idle_full(data, t):
                t["mode"] = "all"
                return t
        return None

    def _log_promoted(self, t):
        if t is not None:
            self.log(f"→ основного нет: «{t['name']}» без «пускать» стал основным")

    def _make_main(self, data, t):
        """Готовит t к режиму all: конфиг должен забирать весь трафик, иначе
        его сервер отбросил бы чужой. Прежний основной → list; он и
        возвращается — его записи тоже проверяются на дубль."""
        if not _conf_full(t["id"], self._in_use(data)[t["id"]]):
            raise ValueError(f"у «{t['name']}» нет конфига с 0.0.0.0/0 в AllowedIPs — "
                             f"весь остальной трафик его сервер отбросил бы")
        main = tunnels.main_tunnel(data)
        if main is None:
            return []
        main["mode"] = "list"
        return [main]

    def _clash_of(self, data, changed):
        """Все дубли записей «пускать» между туннелями «по списку», где
        хоть один из changed, — [{field: "include", text}] для листа окна; [] —
        дублей нет. Старые дубли других пар правку не держат: их порядок в
        файле не менялся. Изменённые — первыми: одна и та же запись у двух
        туннелей — одна причина, словами листа изменённого («уже в «Лаб»»)."""
        confs = {t["id"]: c for t, c in self._list_confs(data)}
        in_use = self._in_use(data)
        ids = {t["id"] for t in changed}
        # Выключенный ничего не забирает: «Офис» и «Офис-2» с одной сетью
        # лежат рядом, включён один; второй — заменой (_set_enabled).
        lists = sorted((t for t in data["tunnels"] if t["mode"] == "list" and t["enabled"]),
                       key=lambda t: t["id"] not in ids)
        seen, texts = set(), []
        for t in lists:
            for other in lists:
                if other is t or not {t["id"], other["id"]} & ids:
                    continue
                # Неизменённый t — только против AllowedIPs изменённого: «пускать»
                # пары уже сверены с его стороны, а вторая причина на то же
                # пересечение (x.a.ru и a.ru) звала бы убрать чужую запись.
                if t["id"] not in ids:
                    other = {**other, "include": []}
                for entry, why in _clash(t, other, confs.get(other["id"]),
                                         in_use[other["id"]]):
                    key = (frozenset((t["id"], other["id"])), entry)
                    if key not in seen:
                        seen.add(key)
                        texts.append(why)
        return [{"field": "include", "text": w} for w in texts]

    def _clashing(self, data, t):
        """Включённые туннели «по списку», чьи записи пересекаются с
        записями t — «пускать» и сетями конфига с обеих сторон: включённый вместе
        с ними t отдал бы общее тому, что выше в файле. В отличие от _clash_of, сети
        конфига t тоже сверяются: новый туннель из «отдельным туннелем» ведёт
        только ими."""
        confs = {u["id"]: c for u, c in self._list_confs(data)}
        in_use = self._in_use(data)
        conf = confs.get(t["id"])
        own = {**t, "include": t["include"]
               + (buildconfig.allowed_nets(conf, v6=True) if conf else [])}
        return [o for o in data["tunnels"]
                if o is not t and o["mode"] == "list" and o["enabled"]
                and _clash(own, o, confs.get(o["id"]), in_use[o["id"]])]

    def _remove_tunnel(self, tunnel):
        """Убирает туннель вместе с папкой его конфигов."""
        try:
            data, t = self._load_target(tunnel)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        data["tunnels"].remove(t)
        up = self._promote(data) if t["mode"] == "all" else None
        r = self._save_tunnels(data, f"удалён туннель {t['id']}")
        if r["ok"]:
            self._log_promoted(up)
            self._drop_conf_dir(t["id"])
        return r

    def _drop_conf_dir(self, tid):
        """Папка конфигов удалённого туннеля — после записи tunnels.json: сбой
        оставит папку без туннеля, а не туннель без конфигов. Такую папку
        _new_tid обходит."""
        try:
            shutil.rmtree(tunnels.conf_dir(tid))
        except FileNotFoundError:
            pass
        except OSError as exc:
            self.log(f"!! не удалить конфиги туннеля {tid}: {exc}")

    def _set_log_level(self, level):
        try:
            data = tunnels.load()
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        data["log_level"] = level
        return self._save_tunnels(data, f"уровень журнала sing-box: {level}")

    # ------------------------------- поля site.env старого окна, до шага окна

    def _read_site(self):
        """Поля окна «Раздельное туннелирование» из tunnels.json в виде site.env.

        Домены и исключения — первого туннеля «по списку»; CORP_PROBE — чем
        служба проверяет рабочую сеть, только показ. CORP_HOSTS не читал никто.
        """
        data = self._tunnels()
        work = self._kind_tunnel("corp", data)
        values = {
            "CORP_DOMAINS": " ".join(work["include"]) if work else "",
            "CORP_PROBE": probe.Prober.corp_probe(),
            "SB_CORP_EXCLUDE": " ".join(work["exclude"]) if work else "",
            "SB_LOG_LEVEL": "" if data["log_level"] == "info" else data["log_level"],
        }
        return "".join(f'{k}="{v}"\n' for k, v in values.items() if v)

    def _set_site(self, text):
        """Поля окна — обратно в tunnels.json: CORP_DOMAINS в include,
        SB_CORP_EXCLUDE в exclude первого туннеля «по списку», SB_LOG_LEVEL в
        log_level. Непонятая запись — отказ с причиной: в старом окне её
        негде показать, а молча выкинуть нельзя."""
        text = (text or "").lstrip("\ufeff")
        env = paths.parse_env(text)
        try:
            data, t = self._load_target(kind="corp")
            include, bad = self._rules(env.get("CORP_DOMAINS", ""))
            exclude, bad_ex = self._rules(env.get("SB_CORP_EXCLUDE", ""))
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        bad += [b for b in bad_ex if b not in bad]
        if bad:
            return {"ok": False, "error": f"не понял: {', '.join(bad)}"}
        t["include"], t["exclude"] = include, exclude
        data["log_level"] = env.get("SB_LOG_LEVEL", "").strip().lower() or "info"
        return self._save_tunnels(data, "обновлены настройки рабочей сети")

    def _tail_log(self, lines):
        """Последние строки журналов sing-box — основного и туннелей, по
        времени. Их показывает окно; строки туннеля помечены его именем.
        Туннели — те, что подняли при включении, а до него — из tunnels.json."""
        sides = [(s.log_prefix, f"[{s.title}] ") for s in self.tunnel.sides]
        if not sides:
            sides = [(tunnel.log_prefix(t["id"]), f"[{t['name']}] ")
                     for t in self._tunnels()["tunnels"]]
        out = []
        for prefix, mark in (("vpn", ""), *sides):
            stamp = ""
            for line in _tail_file(prefix):
                m = STAMP_RE.search(line[:40])
                # Строка без штампа (трассировка, обрывок) — за предыдущей своего журнала.
                stamp = m.group(1) if m else stamp
                out.append((stamp, mark + line))
        out.sort(key=lambda item: item[0])        # устойчиво: порядок журнала цел
        return [line for _, line in out[-lines:]]


def _tail_file(prefix):
    """Хвост свежего журнала <prefix>-*.log строками.

    Читаем только хвост файла: за долгую сессию журнал вырастает
    до мегабайт, а окно спрашивает его раз в две секунды — целиком это
    было бы чтение и разбор всего файла на каждый опрос.
    """
    files = paths.log_files(prefix)
    if not files:
        return []
    try:
        with open(files[-1], "rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            fh.seek(max(0, size - LOG_TAIL_BYTES))
            data = fh.read()
    except OSError:
        return []
    out = data.decode("utf-8", errors="replace").splitlines()
    if size > LOG_TAIL_BYTES:
        out = out[1:]          # первая строка хвоста обрезана посередине
    return out


# ------------------------------------------------------- обвязка Windows

def _service_class():
    """Класс службы собираем лениво: pywin32 нужен только здесь."""
    # Класс кладём в модуль под его именем: win32serviceutil строит строку
    # класса через pickle.whichmodule, а с Python 3.14 тот проверяет, что
    # tunnelvpn.service.TunnelVPNService существует, и иначе падают все команды
    # service install/remove/start/stop.
    global TunnelVPNService
    import win32event
    import win32service
    import win32serviceutil

    class TunnelVPNService(win32serviceutil.ServiceFramework):
        _svc_name_ = paths.SERVICE_NAME
        _svc_display_name_ = paths.SERVICE_DISPLAY
        _svc_description_ = ("Два туннеля WireGuard одновременно: рабочий и "
                             "личный. Держит маршруты и убирает их за собой.")

        # В собранном виде службу запускает не python.exe со скриптом, а наш
        # собственный exe. Диспетчеру служб нужно сказать об этом явно, иначе
        # он пропишет в реестр путь к несуществующему pythonservice.exe и
        # служба не стартует вовсе — с невнятной ошибкой 1053.
        if getattr(sys, "frozen", False):
            _exe_name_ = sys.executable
            _exe_args_ = "service run"

        def __init__(self, args):
            super().__init__(args)
            self.wait_stop = win32event.CreateEvent(None, 0, 0, None)
            self.core = Core()

        def SvcStop(self):
            # Останов может занять секунды: уборка маршрутов ходит в
            # PowerShell. Предупреждаем диспетчер, иначе он решит, что служба
            # зависла, и убьёт её посреди уборки.
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING,
                                     waitHint=60000)
            try:
                self.core.shutdown()
            finally:
                win32event.SetEvent(self.wait_stop)

        def SvcDoRun(self):
            # В журнал событий Windows не пишем: источником сообщений там
            # прописан _internal\win32\servicemanager.pyd, и служба журнала,
            # показав запись, держит его загруженным до перезагрузки — после
            # удаления программы в Program Files оставалась папка с ним.
            # Запуск и так виден в нашем логе (Core.start).
            self.core.start()
            win32event.WaitForSingleObject(self.wait_stop, win32event.INFINITE)

    return TunnelVPNService


def run_in_console():
    """Тот же Core, но в консоли — для отладки без установки службы."""
    import time
    core = Core()
    core.start()
    print(f"TunnelVPN {paths.version()}: служба работает в консоли, Ctrl+C — выход")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        core.shutdown()


def run_dispatcher():
    """Точка входа, которую зовёт диспетчер служб у собранного exe.

    Из исходников этот путь не используется: там службу запускает
    pythonservice.exe, и win32serviceutil разбирается сам.
    """
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_service_class())
    servicemanager.StartServiceCtrlDispatcher()


def handle_command_line():
    """install / remove / start / stop / restart через win32serviceutil."""
    import win32serviceutil
    win32serviceutil.HandleCommandLine(_service_class())
