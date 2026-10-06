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
import json
import os
import re
import subprocess
import sys
import threading
import time

from . import buildconfig, ipc, paths, probe, tunnel, winnet

AUTOSTART_FILE = os.path.join(paths.STATE, "autostart")
SERVICE_LOG = os.path.join(paths.LOGS, "service.log")
# Сколько читать с конца журнала sing-box: окно просит 400 строк, это
# десятки КБ. Запас — на длинные строки с адресами и ошибками TLS.
LOG_TAIL_BYTES = 256 * 1024
# Итог последней проверки по каждому конфигу: без туннеля мерить нечем, но
# «как он отработал в прошлый раз» видно и при выключенном VPN.
LAST_CHECK_FILE = os.path.join(paths.STATE, "last-check.json")
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
# Туннели живут в своих процессах: в журнале основного их трафик идёт через
# socks-выходы. В статистику — под тегом самого туннеля, как до разделения.
SOCKS_TAGS = {socks: tag for tag, socks in buildconfig.SIDES.values()}


class Core:
    """Логика службы, отделённая от обвязки Windows.

    Отдельным классом — чтобы её можно было запустить и в консоли
    (`dualvpn.exe run-service`) при отладке, не устанавливая службу.
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

    # Сколько ещё попыток поднять туннель после неудачного переподключения.
    # Команда человека (start/stop) их отменяет: он уже решил сам.
    _retry_left = 0

    # Таймауты (время, тег, адрес) за DEAD_WINDOW.
    _dead_hits = ()
    # Когда в следующий раз проверять, везёт ли личный, пока выход напрямую.
    _back_at = 0.0
    # Когда статистику адресов снова писать в PATHS_FILE.
    _paths_at = 0.0

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
        self._migrate()
        threading.Thread(target=self.prober.run, daemon=True).start()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()
        if self.autostart_enabled():
            self.log("→ автоподключение включено")
            threading.Thread(target=self._do_start, daemon=True).start()

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
        winnet.PS.close()

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
        """Обработчик команд из канала. Права уже проверены в ipc.Server."""
        if op == "status":
            return {"ok": True, "status": self._status()}
        if op == "start":
            return self._do_start(payload.get("profile", ""))
        if op == "stop":
            return self._do_stop()
        if op == "set-profile":
            return self._set_profile(payload.get("profile", ""))
        if op == "list-profiles":
            return {"ok": True, "profiles": self._profiles(), "corp": self._corp()}
        if op == "check":
            return self._check()
        if op == "set-autostart":
            self.set_autostart(bool(payload.get("on")))
            return {"ok": True, "autostart": self.autostart_enabled()}
        if op == "add-config":
            return self._add_config(payload.get("name", ""),
                                    payload.get("text", ""),
                                    payload.get("kind", ""))
        if op == "remove-config":
            return self._remove_config(payload.get("name", ""),
                                       payload.get("kind", ""))
        if op == "read-config":
            return self._read_config(payload.get("name", ""),
                                     payload.get("kind", ""))
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
        st["last_error"] = self.last_error
        st["autostart"] = self.autostart_enabled()
        st["version"] = paths.version()
        st["singbox"] = self._singbox_version()
        st["profiles"] = self._profiles()
        st["corp"] = self._corp()
        st["last"] = self._last_results()
        return st

    @staticmethod
    def _conf_stamp(kind, name):
        """Отпечаток файла конфига: заменили файл — прошлый итог не про него."""
        try:
            return os.stat(buildconfig.conf_path(kind, name)).st_mtime_ns
        except (OSError, ValueError):
            return None

    def _last_results(self):
        """{'corp': 'up'|'error'|'', 'personal': …} для файлов, что лежат сейчас."""
        try:
            with open(LAST_CHECK_FILE, encoding="utf-8") as fh:
                saved = json.load(fh)
        except (OSError, ValueError):
            saved = {}
        cur = {"corp": (self._corp() or [""])[0],
               "personal": probe.Prober.current_profile()}
        out = {}
        for kind, name in cur.items():
            rec = saved.get(kind) or {}
            fresh = (name and rec.get("name") == name
                     and rec.get("stamp") == self._conf_stamp(kind, name))
            out[kind] = rec.get("result", "") if fresh else ""
        return out

    def _remember_check(self, st, corp_probe):
        """Запоминает итог проверки при поднятом туннеле — по тем же правилам,
        что красит кружки трей."""
        cur = {"corp": (self._corp() or [""])[0],
               "personal": probe.Prober.current_profile()}
        result = {
            # Запасной выход напрямую — личный не работает, хоть интернет и есть.
            "personal": ("up" if st.get("exit_ip")
                         and st.get("exit_state") not in ("leak", "direct")
                         else "error"),
            "corp": ("up" if st.get("corp_ip") or st.get("corp_http")
                     else "error" if corp_probe else ""),
        }
        data = {k: {"name": n, "stamp": self._conf_stamp(k, n),
                    "result": result[k]} for k, n in cur.items() if n}
        try:
            paths.ensure_dirs()
            with open(LAST_CHECK_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
        except OSError:
            pass

    def _check(self):
        """Проверяет туннели сейчас и отдаёт статус.

        При выключенном VPN проверять нечем: WireGuard без рукопожатия не
        отвечает. corp_probe — задан ли хост проверки рабочей сети: без него
        «корп молчит» значит «не с чем сравнить», а не «не работает».
        """
        st = self.prober.snapshot()
        if st.get("tun") and st.get("r_low") and not self.busy:
            self.prober.check_now()
        corp_probe = bool(paths.site_env().get("CORP_PROBE"))
        st = self._status()
        if st["up"] and not self.busy:
            self._remember_check(st, corp_probe)
            st["last"] = self._last_results()
        return {"ok": True, "status": st, "corp_probe": corp_probe}

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

    def _do_start(self, profile="", reconnect=False, retries=0):
        """Поднимает туннель. reconnect — сначала снять текущий: без этого
        start принял бы живой процесс за «уже работает» и ничего не сделал.
        retries — сколько повторов взвести, если не поднимется. Взводим под
        замком: иначе переподключение, заставшее «Выключить» человека, потом
        включило бы VPN обратно."""
        if not self.lock.acquire(blocking=False):
            return {"ok": False, "error": f"уже идёт: {self.busy or 'операция'}"}
        try:
            # Круг сторожа мог начаться до остановки службы и дождаться замка
            # после неё: поднятый тогда туннель уже некому было бы снять.
            if reconnect and self.prober.stop_event.is_set():
                return {"ok": False, "error": "служба останавливается"}
            if not reconnect:
                self._retry_left = 0
            self.busy = "переподключаю" if reconnect else "включаю"
            if reconnect:
                self._flush_paths()
                self.tunnel.stop()
            if not profile:
                profile = probe.Prober.current_profile()
            began = time.monotonic()
            err = self.tunnel.start(profile)
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
            # Личный мог не подняться: проверка выхода на подъёме должна знать
            # это до первого круга сторожа, иначе увидит «утечку».
            self.prober.set(out=self.tunnel.out_now())
            return {"ok": True}
        finally:
            self._probe_now()
            self.busy = ""
            self.lock.release()

    def _do_stop(self):
        if not self.lock.acquire(blocking=False):
            return {"ok": False, "error": f"уже идёт: {self.busy or 'операция'}"}
        try:
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
        if self.busy:
            return None, 0, retry_at
        st = self.prober.snapshot()
        cur = (st.get("iface"), st.get("gw") or "")
        had = self.tunnel.uplink
        if not had and st.get("out"):
            self.prober.set(out="")

        if self._retry_left:
            if had:                       # туннель уже подняли — повторы не нужны
                self._retry_left = 0
            elif cur[1] and time.monotonic() >= retry_at:
                self._retry_left -= 1
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
        DEAD_GAP. Пока личный не везёт, выход наружу напрямую: главное — чтобы
        интернет работал; везёт снова — выход обратно через него."""
        dead = self._dead_tunnels(lines)
        personal = self.tunnel.personal
        out, carries = self.tunnel.out_now(), None
        if out == buildconfig.DIRECT_TAG and personal.alive():
            out, carries = self._try_back()
        self.prober.set(out=out)
        for side in self.tunnel.sides:
            hits = dead.get(side.tag)
            # Живой личный, через который проверка не дошла: трафика через него
            # нет, и таймаутов в журнале не будет.
            stuck = side is personal and carries is False
            if side.alive() and not hits and not stuck:
                continue
            if (side is personal and hits and not stuck and side.alive()
                    and out != buildconfig.DIRECT_TAG
                    and self.tunnel.delay(buildconfig.PERSONAL_SOCKS_TAG) is not None):
                # Лежит чужой адрес, а не туннель: выход не трогаем.
                self._dead_hits = tuple(h for h in self._dead_hits
                                        if h[1] != side.tag)
                continue
            if side is personal and out != buildconfig.DIRECT_TAG:
                # Выход уводим сразу, без паузы: интернет не должен ждать перезапуска.
                if self.tunnel.set_out(buildconfig.DIRECT_TAG):
                    out = buildconfig.DIRECT_TAG
                    self.prober.set(out=out)
                    self.prober.remeasure()
            now = time.monotonic()
            after = self._side_after.get(side.kind, 0.0)
            if now < after:
                if self._side_noted.get(side.kind) != after:
                    self._side_noted[side.kind] = after
                    self.log(f"!! {side.title} туннель не работает, но с прошлого "
                             f"перезапуска нет {DEAD_GAP:.0f} с, жду")
                continue
            # Таймауты того туннеля разобраны: чем бы ни кончилось, счёт заново.
            self._dead_hits = tuple(h for h in self._dead_hits if h[1] != side.tag)
            why = self._side_down(side, hits)
            if why:
                self._side_after[side.kind] = now + DEAD_GAP
                self.log(f"!! {why} — перезапускаю {side.title} процесс")
                self._restart_side(side)

    def _side_down(self, side, hits):
        """Что с туннелем, для журнала, или '' — корп всё-таки отвечает."""
        if not side.alive():
            if side.proc is None:
                return f"{side.title} процесс не запущен"
            return f"{side.title} процесс завершился сам (код {side.proc.returncode})"
        if not hits:
            return f"через {side.tag} не дошла проверка выхода"
        now = time.monotonic()
        what = (f"через {side.tag} соединения не открываются: таймаутов "
                f"{len(hits)} за {now - hits[0][0]:.0f} с, "
                f"адреса: {', '.join(sorted({h[2] for h in hits}))}")
        if side is self.tunnel.corp:
            ip = self.prober.corp_answer()
            if ip:
                self.log(f"!! {what} — но корп отвечает (DNS {ip} за "
                         f"{time.monotonic() - now:.1f} с), не перезапускаю")
                return ""
        return what

    def _try_back(self):
        """Выход напрямую, личный процесс жив: если задержка через него
        дошла — вернуть выход на него. (выход, везёт ли): None — не проверяли,
        рано по BACK_EVERY."""
        now = time.monotonic()
        if now < self._back_at:
            return buildconfig.DIRECT_TAG, None
        self._back_at = now + BACK_EVERY
        ms = self.tunnel.delay(buildconfig.PERSONAL_SOCKS_TAG)
        if ms is None:
            return buildconfig.DIRECT_TAG, False
        if not self.tunnel.set_out(buildconfig.PERSONAL_SOCKS_TAG):
            return buildconfig.DIRECT_TAG, True
        self.log(f"→ личный везёт (проверка за {ms} мс) — выход снова через него")
        self.prober.remeasure()
        return buildconfig.PERSONAL_SOCKS_TAG, True

    def _restart_side(self, side):
        """Перезапуск процесса одного туннеля — под замком start/stop: «Выключить»
        посреди него оставило бы процесс, который уже никто не снимет."""
        if not self.lock.acquire(blocking=False):
            return
        try:
            if self.tunnel.uplink is None or self.prober.stop_event.is_set():
                return
            self.busy = f"перезапускаю {side.title} туннель"
            err = self.tunnel.restart_side(side)
            if err:
                self.log(f"!! {err}")
            elif side is self.tunnel.corp:
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
            tag = SOCKS_TAGS.get(tag, tag)
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
    def _profiles():
        """Личные конфиги — из них выбирают профиль."""
        return buildconfig.list_confs("personal")

    @staticmethod
    def _corp():
        """Рабочие конфиги. Больше одного бывает только после переезда
        старой установки — сборка тогда попросит оставить один."""
        return buildconfig.list_confs("corp")

    def _migrate(self):
        """Конфиги из плоского conf\\ — по папкам типов, один раз после
        обновления. Профиль, если он был пуст, — тот, что сборка брала сама."""
        try:
            moved = buildconfig.migrate_flat()
        except OSError as exc:
            self.log(f"!! не перенести конфиги по папкам: {exc}")
            return
        for name, kind in moved:
            self.log(f"→ {name}.conf перенесён в conf\\{kind}")
        cur = probe.Prober.current_profile()
        personal = self._profiles()
        if moved and cur not in personal:
            self._set_profile(buildconfig.legacy_default_personal(personal))

    def _add_config(self, name, text, kind):
        """Кладёт конфиг в conf\\.

        Тип задаёт пункт, через который конфиг добавили, а не имя: файл
        ложится в папку своего типа под именем файла человека, очищенным от
        недопустимых знаков (buildconfig.safe_name), а не отклонённым из-за них.
        Рабочий заменяет прежний, личный ложится рядом с другими и выбирается.
        """
        if kind not in buildconfig.KINDS:
            return {"ok": False, "error": f"неизвестный тип конфига: {kind!r}"}
        # BOM от Блокнота: с ним «[Interface]» в первой строке не узнаётся.
        text = (text or "").lstrip("\ufeff")
        bad = buildconfig.check_conf_text(text)
        if bad:
            return {"ok": False, "error": bad}
        name = buildconfig.safe_name(name)
        paths.ensure_dirs()
        path = buildconfig.conf_path(kind, name)
        # Через временный файл: оборванная запись не оставит полконфига.
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
        self.log(f"→ добавлен {kind} конфиг {name}.conf")

        if kind == "corp":
            # Рабочий может быть только один: при двух сборка не пройдёт.
            for old in self._corp():
                if old == name:
                    continue
                try:
                    os.remove(buildconfig.conf_path("corp", old))
                    self.log(f"→ удалён прежний рабочий конфиг {old}.conf")
                except OSError as exc:
                    self.log(f"→ не удалить {old}.conf: {exc}")
        else:
            self._set_profile(name)
        return {"ok": True, "name": name, "profiles": self._profiles(),
                "corp": self._corp()}

    def _read_config(self, name, kind):
        """Отдаёт конфиг целиком, вместе с ключами.

        Каталог conf\\ закрыт от обычного пользователя, поэтому прочитать файл
        может только служба. Права проверяет ipc.Server: команды нет ни в
        READ_OPS, ни в USER_OPS, значит нужен администратор.
        """
        try:
            with open(buildconfig.conf_path(kind, name),
                      encoding="utf-8", errors="replace") as fh:
                return {"ok": True, "text": fh.read()}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    def _remove_config(self, name, kind):
        try:
            os.remove(buildconfig.conf_path(kind, name))
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        self.log(f"→ удалён {kind} конфиг {name}.conf")
        if kind == "personal" and name == probe.Prober.current_profile():
            # Выбранный профиль указывал бы на удалённый файл, и следующее
            # «Включить» падало бы с «нет профиля». Берём другой личный, а без
            # него — пусто: сборка тогда попросит добавить личный.
            rest = self._profiles()
            self._set_profile(rest[0] if rest else "")
        return {"ok": True, "profiles": self._profiles(), "corp": self._corp()}

    def _set_profile(self, name):
        if name and name not in self._profiles():
            return {"ok": False, "error": f"нет личного конфига {name}.conf"}
        paths.ensure_dirs()
        with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
            fh.write(name)
        return {"ok": True, "profile": name}

    @staticmethod
    def _read_site():
        try:
            with open(os.path.join(paths.CONF, "site.env"), encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    def _set_site(self, text):
        text = (text or "").lstrip("\ufeff")
        paths.ensure_dirs()
        with open(os.path.join(paths.CONF, "site.env"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        self.log("→ обновлены настройки рабочей сети")
        return {"ok": True}

    @staticmethod
    def _tail_log(lines):
        """Последние строки журналов sing-box — основного и обоих туннелей,
        по времени. Их показывает окно; строки туннеля помечены его именем."""
        out = []
        for prefix, mark in (("vpn", ""), ("corp", "[корп] "),
                             ("personal", "[личный] ")):
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
    try:
        files = sorted(f for f in os.listdir(paths.LOGS)
                       if f.startswith(f"{prefix}-") and f.endswith(".log"))
        if not files:
            return []
        with open(os.path.join(paths.LOGS, files[-1]), "rb") as fh:
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
    # dualvpn.service.DualVPNService существует, и иначе падают все команды
    # service install/remove/start/stop.
    global DualVPNService
    import win32event
    import win32service
    import win32serviceutil

    class DualVPNService(win32serviceutil.ServiceFramework):
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

    return DualVPNService


def run_in_console():
    """Тот же Core, но в консоли — для отладки без установки службы."""
    import time
    core = Core()
    core.start()
    print(f"DualVPN {paths.version()}: служба работает в консоли, Ctrl+C — выход")
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
