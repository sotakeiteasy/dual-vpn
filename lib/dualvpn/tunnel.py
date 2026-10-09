"""Подъём и остановка туннеля. Всё, что трогает систему, проходит здесь.

Главное правило файла — **чужое не трогаем**. Половинки дефолтного маршрута
(0.0.0.0/1 и 128.0.0.0/1) это общий ресурс: ровно их же ставят себе Amnezia,
официальный клиент WireGuard и любой другой VPN. Безусловное удаление на
выключении сносило бы маршруты чужого поднятого туннеля — «выключил своё,
сломал соседнее». Поэтому у каждого снятия есть проверка владельца.

Второе правило — **журнал пишется до применения**. Если процесс убьют посреди
операции, лишняя запись безобидна (удаление несуществующего маршрута — no-op),
а потерянная означала бы маршрут, который потом никто не снимет. Журнал
переживает и падение службы, и перезагрузку, поэтому «аварийно выключился»
лечится следующим включением, а не руками.
"""

import ctypes
import datetime
import json
import os
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import buildconfig, paths, tunnels, winnet

KEEP_LOGS = 10

# Обе половины адресного пространства. Пишем именно так, а не 0.0.0.0/0:
# более специфичный префикс выигрывает у маршрута по умолчанию, не удаляя его,
# и исходная картина сети возвращается сама, как только мы уберём свои строки.
HALVES = ("0.0.0.0/1", "128.0.0.0/1")

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Сколько ждём, пока боковой процесс откроет socks на loopback.
SIDE_WAIT = 15

# Чем clash_api меряет выход. Только по имени: голый 1.1.1.1 sing-box
# через selector не меряет и отвечает таймаутом даже живому туннелю.
DELAY_URL = "http://cp.cloudflare.com/generate_204"

# Сколько ждём реальный адрес от запуска запроса. Обычно он приходит за
# секунду, но на плохой сети запрос висел до 15 с и держал всё включение.
REAL_IP_WAIT = 6

# Пока туннель поднят, не даём системе засыпать по простою: во сне keepalive
# не уходит, WG-сессия протухает, а TCP-соединения, открытые до сна, после
# пробуждения уже мертвы — их не воскрешает ничто. Крышку это не покрывает.
_ES_CONTINUOUS = 0x80000000
_ES_SYSTEM_REQUIRED = 0x00000001


def log_prefix(tid):
    """Префикс журнала бокового процесса туннеля tid."""
    return f"tunnel-{tid}"


class Side:
    """Боковой процесс sing-box — один туннель за socks на loopback.

    У каждого свой журнал tunnel-<id>-<дата>.log: сторож читает оттуда
    таймауты туннеля и перезапускает процесс один, не трогая tun.
    """

    def __init__(self, tid, title):
        self.tid = tid            # id туннеля из tunnels.json
        self.title = title        # имя туннеля — для журнала службы
        self.proc = None
        self.logfile = None
        # (путь, смещение) начала текущего запуска в его журнале.
        self.log_start = None

    @property
    def tag(self):
        """Тег endpoint туннеля: wg-<id>."""
        return buildconfig.ep_tag(self.tid)

    @property
    def log_prefix(self):
        return log_prefix(self.tid)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None


class Tunnel:
    """Один туннель на процесс службы. Методы зовутся из одного потока."""

    def __init__(self, log):
        self.log = log
        # Основной процесс: tun, маршрутизация и DNS.
        self.proc = None
        self.logfile = None
        # (путь, смещение) начала текущего запуска в журнале sing-box: сторож
        # службы читает оттуда соединения. None — туннель не запущен.
        self.log_start = None
        # Туннели — в своих процессах: их перезапускают по одному. Список
        # строит start из собранного конфига; до первого включения он пуст.
        self.sides = []
        # id основного туннеля (за selector out) и его активный конфиг, с
        # которым собран запуск. None — ещё не собирали.
        self.main_id = None
        self.profile = None
        # Индекс нашего tun, каким мы его запомнили. Нужен уборке после того,
        # как интерфейс исчез, а журнал уже удалён.
        self._tun_hint = None
        # (интерфейс, шлюз), на которых поднят туннель, или None. На них
        # завязаны host-маршруты пиров и адрес корп-сервера: служба сверяет
        # их с текущим аплинком и при смене сети переподключается.
        self.uplink = None

    @property
    def main(self):
        """Боковой процесс основного туннеля, иначе None."""
        return next((s for s in self.sides if s.tid == self.main_id), None)

    @property
    def first_list(self):
        """Первый туннель «по списку», иначе None. Пока сторож и проверка
        знают один рабочий туннель, это он."""
        return next((s for s in self.sides if s.tid != self.main_id), None)

    # ------------------------------------------------------ журнал владения

    def own(self, *parts):
        """Записывает в журнал то, что мы собираемся навесить на систему."""
        paths.ensure_dirs()
        with open(paths.OWNED_FILE, "a", encoding="utf-8") as fh:
            fh.write(" ".join(str(p) for p in parts) + "\n")

    def owned_lines(self):
        try:
            with open(paths.OWNED_FILE, encoding="utf-8") as fh:
                return [l.strip().split() for l in fh if l.strip()]
        except OSError:
            return []

    def _our_tun_index(self):
        """Индекс tun из журнала, если он там есть."""
        for parts in self.owned_lines():
            if parts[0] == "tun" and len(parts) > 1:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
        return None

    def is_ours(self, if_index):
        """Наш ли это интерфейс.

        Наш — либо несущий адрес нашего tun, либо уже исчезнувший: маршрут на
        мёртвый интерфейс не может принадлежать работающему соседу. Проверки по
        одному индексу мало — Windows их переиспользует ровно так же, как macOS
        переиспользует номера utun, и именно так уборка попадала бы по чужому
        туннелю, занявшему освободившийся номер.

        Подсказку об индексе берём из self._tun_hint, а не из журнала: журнал
        удаляется в середине stop(), а проверять владельца надо и после этого.
        """
        if if_index is None:
            return False
        live = winnet.tun_index(paths.TUN_IP)
        if live is not None:
            # Туннель жив — своим считаем ровно его интерфейс.
            return if_index == live
        if self._tun_hint is not None and if_index == self._tun_hint:
            return True
        # Интерфейса нет вовсе: маршрут на него ничей и мешает всем.
        return not winnet.interface_exists(if_index)

    # ------------------------------------------------------------ снятие

    def del_net_ours(self, prefix):
        """Снимает сетевой маршрут, только если он указывает на наш tun."""
        rows = winnet.routes_for(prefix)
        ours = [r for r in rows if self.is_ours(r.get("InterfaceIndex"))]
        alien = [r for r in rows if not self.is_ours(r.get("InterfaceIndex"))]
        if not ours:
            if alien:
                self.log(f"→ {prefix} есть, но он не наш — не трогаю")
            return
        for r in ours:
            winnet.del_route(prefix, r.get("InterfaceIndex"))
        # Успех определяем по таблице, а не по коду возврата: командлет бодро
        # отчитывается и тогда, когда снял не ту строку.
        left = [r for r in winnet.routes_for(prefix)
                if self.is_ours(r.get("InterfaceIndex"))]
        if left:
            self.log(f"!! {prefix} снять не удалось")
            self.log(f"   вручную: Remove-NetRoute -DestinationPrefix {prefix}")
        else:
            self.log(f"→ убран маршрут {prefix}")

    def del_host_ours(self, ip, want_gw=""):
        """Снимает host-маршрут на пира, если он всё ещё наш.

        want_gw — шлюз, через который мы его ставили. Сменился шлюз, значит
        сменилась сеть и маршрут уже не тот, что мы заводили.
        """
        prefix = f"{ip}/32"
        rows = winnet.routes_for(prefix)
        if not rows:
            return
        for r in rows:
            gw = r.get("NextHop", "")
            idx = r.get("InterfaceIndex")
            if want_gw and gw != want_gw:
                self.log(f"→ маршрут на {ip} теперь через {gw}, "
                         f"а мы ставили через {want_gw} — не трогаю")
                continue
            if not want_gw and self.is_ours(idx):
                # Наш host-маршрут на пира всегда идёт мимо туннеля, через
                # физический аплинк. Указывает на tun — значит ставили не мы.
                self.log(f"→ маршрут на {ip} живёт на туннеле — не наш, не трогаю")
                continue
            winnet.del_route(prefix, idx)
        if not winnet.routes_for(prefix):
            self.log(f"→ убран маршрут на {ip}")

    # -------------------------------------------------------------- логи

    def open_log(self, prefix="vpn"):
        """Свежий файл лога <prefix>-<дата>.log, открытый на дозапись;
        старые сверх KEEP_LOGS удаляются — у каждого префикса свои десять.

        При битом конфиге sing-box падает, служба поднимает его снова, и каждый
        заход создавал бы новый файл: за две минуты история из десяти запусков
        вытеснялась бы циклом перезапуска. Свежий лог в такой ситуации
        продолжаем, а не заводим ещё один.
        """
        paths.ensure_dirs()
        existing = paths.log_files(prefix)
        if existing and time.time() - os.path.getmtime(existing[-1]) < 60:
            path = existing[-1]
        else:
            stamp = datetime.datetime.now().strftime(paths.LOG_STAMP)
            path = os.path.join(paths.LOGS, f"{prefix}-{stamp}.log")
            existing.append(path)
        # Имя — это дата, поэтому сортировка по имени хронологическая.
        for old in existing[:-KEEP_LOGS]:
            try:
                os.remove(old)
            except OSError:
                pass
        fh = open(path, "a", encoding="utf-8", errors="replace")
        fh.write(
            f"\n=== {datetime.datetime.now():%Y-%m-%d %H:%M:%S} DualVPN ===\n")
        fh.flush()
        return fh

    # -------------------------------------------------------------- старт

    def start(self, profile=""):
        """Поднимает туннель. Возвращает '' или текст ошибки.

        profile — конфиг основного туннеля: становится его active в
        tunnels.json. Пустой — тот, что там уже выбран.
        """
        paths.ensure_dirs()
        try:
            data = tunnels.load()
        except ValueError as exc:
            return str(exc)
        main = tunnels.main_tunnel(data)
        if profile:
            # Имя приходит через канал — сравниваем со списком, а не склеиваем
            # в путь: «..\\» здесь вывел бы за пределы conf\. Проверяем до
            # остановки: опечатка в имени не должна ронять живой туннель.
            if main is None:
                return (f"нет туннеля для всего остального трафика — "
                        f"профиль «{profile}» некуда поставить")
            if profile not in tunnels.list_confs(main["id"]):
                return f"нет профиля «{profile}» у туннеля «{main['name']}»"
        want = profile or (main["active"] if main else "")

        # Уже работает: второе «Включить» (двойной клик по значку, окно и
        # трей разом) раньше принимало свой же живой туннель за следы
        # прошлого запуска, сносило его и поднимало заново.
        if (self.proc is not None and self.proc.poll() is None
                and want == self.profile
                and winnet.tun_index(paths.TUN_IP) is not None):
            self.log("→ уже работает")
            # Основной жив, а туннель упал: поднимаем только его, иначе
            # «Включить» отвечало бы «работает» при мёртвом туннеле.
            for side in self.sides:
                if not side.alive():
                    self.log(f"→ процесс «{side.title}» не работает, поднимаю")
                    err = self._start_side(side)
                    self._report_side(side, err)
                    if side is self.main and not err:
                        self.set_out(buildconfig.socks_tag(side.tid))
            return ""

        # Уборка за прошлым запуском — до того, как поднимем свой. Прошлый мог
        # уйти в KILL, упасть вместе с машиной или потерять питание: следы
        # тогда остаются, и разгрести их некому, кроме нас.
        if self.leftovers():
            self.log("→ вижу следы прошлого запуска, сначала убираю")
            self.stop()
            self.log("")

        if profile:
            if main["active"] != profile:
                main["active"] = profile
                try:
                    tunnels.save(data)
                except (OSError, ValueError) as exc:
                    return f"профиль не записать: {exc}"
            self.log(f"→ профиль «{main['name']}»: {profile}")

        if not os.path.isfile(paths.SINGBOX):
            return f"нет {paths.SINGBOX} — переустанови приложение"
        if not os.path.isfile(paths.WINTUN):
            return (f"нет {paths.WINTUN}: без wintun.dll sing-box не создаст "
                    f"сетевой адаптер")

        # Реальный адрес спрашиваем в фоне, пока собирается и проверяется
        # конфиг: туннеля ещё нет, ответ придёт мимо него.
        real_ip = []
        fetch = threading.Thread(
            target=lambda: real_ip.append(self._fetch_real_ip()), daemon=True)
        fetch.start()
        fetch_deadline = time.time() + REAL_IP_WAIT

        self.log("→ собираю конфиг из conf\\…")
        try:
            built = buildconfig.main(log=self.log)
        except SystemExit as exc:
            # buildconfig сообщает об ошибках через sys.exit с текстом.
            return str(exc) or "не удалось собрать конфиг — правь conf\\*.conf"
        self.profile = want
        self.main_id = buildconfig.main_id(_load_json(paths.CONFIG_JSON))
        self.sides = [Side(tid, name) for tid, name in built]

        # Отдельной строкой: сборка и проверка шли под одной, и по журналу
        # нельзя было сказать, кто из них ест до 11 с включения.
        self.log("→ проверяю конфиг (sing-box check)…")

        # timeout обязателен: без него зависший sing-box повесил бы
        # весь start навсегда, а клиент ждёт ответ по каналу без таймаута —
        # снаружи это ровно ««Включить» зависло».
        for cfg_path in (paths.CONFIG_JSON,
                         *(buildconfig.side_json(s.tid) for s in self.sides)):
            try:
                check = subprocess.run(
                    [paths.SINGBOX, "check", "-c", cfg_path],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace",
                    timeout=20, creationflags=_NO_WINDOW)
            except subprocess.TimeoutExpired:
                return "sing-box check не ответил за 20с"
            if check.returncode != 0:
                return (f"конфиг {os.path.basename(cfg_path)} не прошёл "
                        f"проверку: {(check.stderr or '').strip()}")

        # Шлюз по умолчанию определяем ДО старта, пока туннель не перебил
        # маршруты. Ничего не захардкожено: работает и на Wi-Fi, и на раздаче.
        up_idx, gw = winnet.default_route()
        if not gw:
            return "нет маршрута по умолчанию — сеть не поднята?"
        self.log(f"→ аплинк: интерфейс {up_idx}, шлюз {gw}")

        # До старта туннеля: иначе первые же запросы браузера уйдут по v6 мимо.
        self.own("v6block")
        if winnet.v6_block(up_idx):
            self.log("→ исходящий IPv6 мимо туннеля заблокирован на время сеанса")
        else:
            self.log(f"!! IPv6 заблокировать не вышло: {winnet.last_error or 'без причины'}")

        peers = self._peer_ips()
        if not peers:
            return "не определить адреса пиров — прерываю, иначе будет петля"
        self.log(f"→ пиры (пойдут мимо туннеля): {', '.join(peers)}")

        # Порядок важен: сперва вывести пиров из-под туннеля, потом ставить
        # половинки. Иначе трафик к серверу сам уходит в туннель — петля.
        for ip in peers:
            self.own("host", ip, gw, up_idx)
        winnet.add_routes([(f"{ip}/32", up_idx, gw, 1) for ip in peers])

        # Дожидаемся адреса до старта sing-box: после него запрос ушёл бы в
        # туннель, и адрес выхода записался бы как «реальный» — пробер видел бы
        # утечку в рабочем туннеле. Опоздавший ответ поэтому отбрасываем.
        fetch.join(max(0.0, fetch_deadline - time.time()))
        # Наших половинок ещё нет — значит, эти стоят у другого поднятого VPN
        # (Amnezia, WireGuard). Запрос ушёл через него, и его выход записался бы
        # как «реальный»: пробер потом звал бы адрес провайдера туннелем.
        foreign = sorted({r.get("InterfaceIndex") for half in HALVES
                          for r in winnet.routes_for(half)})
        if foreign:
            real_ip = []
            self.log(f"!! поднят другой VPN (интерфейс "
                     f"{', '.join(map(str, foreign))}): его маршруты спорят с "
                     f"нашими, реальный адрес не записываю")
        elif not real_ip:
            self.log(f"→ реальный адрес не узнал за {REAL_IP_WAIT}с — "
                     f"утечку сравнить будет не с чем")
        self._save_real_ip(real_ip[0] if real_ip else "")

        # Туннели — до основного: тот сразу начнёт отдавать им трафик
        # и DNS в socks. Упал туннель — включение идёт дальше: без туннеля
        # «по списку» работает интернет, без основного — выход напрямую, а упавший
        # поднимет сторож. Все сразу: каждый ждёт свой socks ~0.8 с, по очереди
        # ожидания складывались. Журналы у них разные, общего состояния
        # нет; map пробрасывает исключение потока сюда, как и при запуске по очереди.
        with ThreadPoolExecutor(max(1, len(self.sides))) as pool:
            side_err = dict(zip([side.tid for side in self.sides],
                                pool.map(self._start_side, self.sides)))
        for side in self.sides:
            self._report_side(side, side_err[side.tid])

        self.logfile = self.open_log()
        log_path = self.logfile.name
        self.log_start = (log_path, self.logfile.tell())
        self.log(f"→ журнал sing-box: {log_path}")
        self.log("→ запускаю sing-box…")
        self.proc = subprocess.Popen(
            # --disable-color: лог читает окно, а не терминал. С цветом каждая
            # строка в окне шла с мусором вида «[36mINFO[0m».
            [paths.SINGBOX, "run", "-c", paths.CONFIG_JSON, "--disable-color"],
            cwd=paths.BIN,          # рядом лежит wintun.dll, его ищут здесь
            stdout=self.logfile, stderr=subprocess.STDOUT,
            creationflags=_NO_WINDOW,
        )

        tun_idx = None
        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(0.25)
            if self.proc.poll() is not None:
                # Туннели без основного никому не нужны: в socks никто не зайдёт.
                for side in self.sides:
                    self._stop_side(side)
                return f"sing-box упал на старте: {_fatal_line(log_path)}"
            tun_idx = winnet.tun_index(paths.TUN_IP)
            if tun_idx is not None:
                break
        if tun_idx is None:
            self.stop()
            return "tun не поднялся за 30с"
        self.log(f"→ tun: интерфейс {tun_idx}")
        self.own("tun", tun_idx)
        self._tun_hint = tun_idx

        # Половинки ставит и сам sing-box через auto_route. Записываем их как
        # своё в любом случае: снимать их всё равно нам, иначе половина
        # интернета останется смотреть в мёртвый tun.
        missing = []
        for half in HALVES:
            self.own("net", half, tun_idx)
            if not any(r.get("InterfaceIndex") == tun_idx
                       for r in winnet.routes_for(half)):
                missing.append((half, tun_idx, "0.0.0.0", 1))
        winnet.add_routes(missing)
        self.log("→ маршруты выставлены")
        # Первый запуск после старта службы бывал мёртвым: ни один туннель
        # не делал рукопожатия. Подозрение — host-маршрута к пиру к этому
        # моменту нет, и WireGuard уходит в tun петлёй. Сверяем и пишем в журнал.
        self.mend_peer_routes((up_idx, gw))

        names = self._corp_domains()
        if names and winnet.nrpt_set(names, paths.TUN_DNS):
            self.log(f"→ корп-домены спрашиваю только у DNS туннеля: {', '.join(names)}")
        elif names:
            self.log("!! правило NRPT не встало: несуществующие корп-имена "
                     "будут отвечать по 12 с")

        # Основной не поднялся — выход напрямую сразу, не дожидаясь сторожа:
        # socks без процесса за ним отказывал бы каждому соединению.
        if self.main and side_err[self.main.tid]:
            self.set_out(buildconfig.DIRECT_TAG)

        self._keep_awake(True)
        self.uplink = (up_idx, gw)
        self.log("→ работает")
        return ""

    def _fetch_real_ip(self):
        """Настоящий адрес провайдера, пока туннель не поднят, или ''.

        Утечкой считается совпадение с ним. Сравнивать с адресом сервера
        ненадёжно: он может выходить не тем адресом, на котором принимает
        соединения, и тогда рабочий туннель показывался бы как утечка.
        """
        try:
            import urllib.request
            with urllib.request.urlopen("https://ifconfig.me/ip", timeout=4) as r:
                ip = r.read().decode("ascii", "replace").strip()
        except Exception:
            return ""
        if not all(c in "0123456789." for c in ip) or not ip:
            return ""            # не ответили — не гадаем
        return ip

    def _save_real_ip(self, ip):
        try:
            with open(paths.REAL_IP_FILE, "w", encoding="utf-8") as fh:
                fh.write(ip)
        except OSError:
            pass

    def _peer_ips(self):
        """Адреса пиров из всех собранных конфигов, имена резолвим сейчас.

        Пока DNS ещё системный: после подъёма туннеля он уйдёт внутрь, и имя
        сервера станет нерезолвимым ровно тогда, когда оно нужнее всего.
        Боковые — по основному конфигу, а не по self.sides: после перезапуска
        службы список пуст, а stop без журнала чистит именно по ним.
        """
        out = []
        endpoints = []
        main_cfg = _load_json(paths.CONFIG_JSON)
        for cfg_path in (paths.CONFIG_JSON,
                         *(buildconfig.side_json(tid)
                           for tid in buildconfig.side_ids(main_cfg))):
            endpoints += _load_json(cfg_path).get("endpoints", [])
        for ep in endpoints:
            for peer in ep.get("peers", []):
                host = (peer.get("address") or "").strip()
                if not host:
                    continue
                if all(c in "0123456789." for c in host):
                    out.append(host)
                else:
                    ip = winnet.resolve4(host)
                    if ip:
                        out.append(ip)
        return sorted(set(out))

    @staticmethod
    def _corp_domains():
        """Домены, которые собранный конфиг отдаёт DNS туннелей."""
        return buildconfig.tunnel_domains(_load_json(paths.CONFIG_JSON))

    # ---------------------------------------------------- боковые процессы

    def _start_side(self, side):
        """Запускает боковой процесс и ждёт, пока он откроет socks. '' или ошибка.

        Ждём именно socks, а не просто живой процесс: основной отдаёт трафик
        на этот порт, и до его открытия первые запросы получили бы отказ.
        """
        link = buildconfig.side_link(_load_json(paths.CONFIG_JSON), side.tid)
        if not link or not link.get("port"):
            return f"в собранном конфиге нет связи с процессом {side.tag}"
        self._stop_side(side)
        side.logfile = self.open_log(side.log_prefix)
        log_path = side.logfile.name
        side.log_start = (log_path, side.logfile.tell())
        self.log(f"→ запускаю процесс «{side.title}», журнал: {log_path}")
        side.proc = subprocess.Popen(
            [paths.SINGBOX, "run", "-c", buildconfig.side_json(side.tid),
             "--disable-color"],
            cwd=paths.BIN,
            stdout=side.logfile, stderr=subprocess.STDOUT,
            creationflags=_NO_WINDOW,
        )
        deadline = time.time() + SIDE_WAIT
        while time.time() < deadline:
            if side.proc.poll() is not None:
                return f"процесс «{side.title}» упал на старте: {_fatal_line(log_path)}"
            if _port_open(link["port"]):
                return ""
            time.sleep(0.25)
        self._stop_side(side)
        return f"процесс «{side.title}» не открыл socks за {SIDE_WAIT}с"

    def _report_side(self, side, err):
        if err:
            what = ("выход напрямую" if side is self.main
                    else f"туннель «{side.title}» недоступен")
            self.log(f"!! {err} — {what}, интернет работает")

    def _stop_side(self, side):
        """Гасит один боковой процесс и закрывает его журнал."""
        _end(side.proc)
        side.proc = None
        if side.logfile is not None:
            try:
                side.logfile.close()
            except OSError:
                pass
            side.logfile = None
        side.log_start = None

    def restart_side(self, side):
        """Перезапускает один боковой процесс. '' или текст ошибки.

        tun, маршруты и второй туннель не трогаем: интернет на это время не
        падает. Пира заново не резолвим: DNS сейчас туннельный, а не сети, и
        7 октября в офисе отдал корп-имя внешним адресом вместо внутреннего —
        корп час перезапускался вхолостую. Адрес, взятый при включении у DNS
        самой сети, верен, пока сеть та же; сменилась — переподключает сторож.
        Выход наружу не переключает: на личный его возвращает тот, кто проверил,
        что туннель снова везёт.
        """
        if self.uplink is None:
            return "туннель не поднят"
        self._stop_side(side)
        err = self._start_side(side)
        if not err:
            self.log(f"→ процесс «{side.title}» перезапущен")
        return err

    def mend_peer_routes(self, uplink=None):
        """Ставит заново пропавшие host-маршруты к пирам. Список их адресов.

        Пиров берём из журнала своего: там и включение, и перезапуск туннеля
        со сменившимся адресом.
        """
        uplink = uplink or self.uplink
        if uplink is None:
            return []
        up_idx, gw = uplink
        peers = sorted({parts[1] for parts in self.owned_lines()
                        if parts[0] == "host" and len(parts) >= 4
                        and parts[2] == gw and parts[3] == str(up_idx)})
        lost = []
        for ip in peers:
            if not any(r.get("NextHop") == gw
                       and str(r.get("InterfaceIndex")) == str(up_idx)
                       for r in winnet.routes_for(f"{ip}/32")):
                lost.append(ip)
        for ip in lost:
            self.log(f"!! маршрут к пиру {ip} пропал — ставлю заново")
        winnet.add_routes([(f"{ip}/32", up_idx, gw, 1) for ip in lost])
        return lost

    # ----------------------------------------------------- выход наружу

    def _clash(self, path, method="GET", body=None, timeout=5):
        """Запрос к clash_api основного процесса; ответ — разобранный JSON.

        Прокси обходим явно: urllib берёт системный прокси Windows, и запрос
        на 127.0.0.1 ушёл бы к нему. Ошибки — OSError (HTTPError тоже он).
        """
        api = buildconfig.api_of(_load_json(paths.CONFIG_JSON))
        if api is None:
            raise OSError("в конфиге нет clash_api")
        addr, secret = api
        req = urllib.request.Request(
            f"http://{addr}{path}", method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {secret}",
                     "Content-Type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read()
        return json.loads(data) if data else {}

    def set_out(self, tag):
        """Переключает выход наружу на tag без перезапуска. True — вышло."""
        try:
            self._clash(f"/proxies/{buildconfig.OUT_TAG}", "PUT", {"name": tag})
        except (OSError, ValueError) as exc:
            self.log(f"!! выход на {tag} не переключить: {exc}")
            return False
        self.log(f"→ выход наружу: {tag}")
        return True

    def out_now(self):
        """Текущий выход наружу или '', если основной процесс не ответил."""
        try:
            return self._clash(f"/proxies/{buildconfig.OUT_TAG}").get("now", "")
        except (OSError, ValueError):
            return ""

    def delay(self, tag, timeout_ms=3000):
        """Задержка до DELAY_URL через выход tag в мс; None — не дошло."""
        query = urllib.parse.urlencode({"url": DELAY_URL, "timeout": timeout_ms})
        try:
            reply = self._clash(
                f"/proxies/{urllib.parse.quote(tag)}/delay?{query}",
                timeout=timeout_ms / 1000 + 2)
        except (OSError, ValueError):
            return None
        ms = reply.get("delay")
        return ms if isinstance(ms, int) and ms > 0 else None

    def _keep_awake(self, on):
        try:
            flags = _ES_CONTINUOUS | (_ES_SYSTEM_REQUIRED if on else 0)
            ctypes.windll.kernel32.SetThreadExecutionState(flags)
        except Exception:
            pass

    # --------------------------------------------------------------- стоп

    def leftovers(self):
        """Есть ли следы прошлого запуска: журнал, живой процесс или наш tun."""
        if os.path.exists(paths.OWNED_FILE) and os.path.getsize(paths.OWNED_FILE):
            return True
        if winnet.pids_of(paths.SINGBOX):
            return True
        if winnet.tun_index(paths.TUN_IP) is not None:
            return True
        return winnet.v6_blocked()

    def stop(self):
        """Снимает процесс и всё, что мы навесили на систему.

        Каждый шаг независим и переживает падение предыдущего: stop зовут
        именно тогда, когда всё уже сломано, и он обязан доводить уборку
        до конца.
        """
        self.uplink = None
        self._keep_awake(False)

        # Индекс tun поднимаем из журнала до того, как начнём его разбирать:
        # дальше уборка спрашивает «наш ли этот маршрут» уже без журнала.
        if self._tun_hint is None:
            self._tun_hint = self._our_tun_index()

        # 1. Процессы. Сначала свои, потом любой оставшийся от прошлых запусков.
        _end(self.proc)
        self.proc = None
        for side in self.sides:
            self._stop_side(side)
        self._kill_strays()

        if self.logfile is not None:
            try:
                self.logfile.close()
            except OSError:
                pass
            self.logfile = None
        self.log_start = None

        # 2. Маршруты — по журналу, в порядке, обратном постановке. Там
        # записано ровно то, что навесили мы, включая пиров прошлого профиля.
        lines = self.owned_lines()
        if lines:
            for parts in reversed(lines):
                kind = parts[0]
                if kind == "host" and len(parts) >= 3:
                    self.del_host_ours(parts[1], parts[2])
                elif kind == "net" and len(parts) >= 2:
                    self.del_net_ours(parts[1])
            # Журнал убираем только после полного прохода: если stop прервут
            # на середине, следующий запуск увидит его и доуберёт остальное.
            try:
                os.remove(paths.OWNED_FILE)
            except OSError:
                pass
        else:
            self.log("→ журнала нет — чищу по конфигу, что найду")
            for ip in self._peer_ips():
                self.del_host_ours(ip)

        # 3. Обе половинки — ещё раз, уже без журнала. sing-box ставит их сам
        # через auto_route, и после жёсткого падения они остаются висеть.
        for half in HALVES:
            self.del_net_ours(half)

        # 4. Всё, что ещё висит на нашем tun. Страховка на случай, если
        # sing-box успел прописать что-то помимо двух половинок.
        tun_idx = winnet.tun_index(paths.TUN_IP)
        if tun_idx is not None:
            for prefix in winnet.routes_on_interface(tun_idx):
                if prefix not in ("0.0.0.0/0",):
                    winnet.del_route(prefix, tun_idx)
                    self.log(f"→ убран остаточный маршрут {prefix}")

        # 5. IPv6 — на случай, если прошлый запуск убили жёстко.
        winnet.v6_unblock()
        # Правило NRPT смотрит на DNS туннеля, которого после стопа нет:
        # оставшись, оно сломало бы корп-домены без туннеля совсем.
        winnet.nrpt_clear()

        # 6. Кеш резолвера: в нём осели ответы корп-DNS, недоступного без
        # туннеля, и без сброса корп-домены висят ещё несколько минут.
        winnet.flush_dns()

        self._verify_clean()
        # Индекс переиспользуется системой — держать его до следующего запуска
        # значит однажды принять за свой чужой интерфейс с тем же номером.
        self._tun_hint = None

    def _kill_strays(self):
        """Добивает sing-box из нашей папки, оставшийся от прошлых запусков."""
        pids = winnet.pids_of(paths.SINGBOX)
        if not pids:
            return
        for sig, wait in (("", 10), ("/F", 5)):
            for pid in pids:
                subprocess.run(["taskkill", "/PID", str(pid)] + ([sig] if sig else []),
                               capture_output=True, creationflags=_NO_WINDOW)
            for _ in range(wait * 2):
                time.sleep(0.5)
                pids = winnet.pids_of(paths.SINGBOX)
                if not pids:
                    self.log("→ sing-box остановлен")
                    return
            if sig == "":
                self.log("→ не отвечает, добиваю принудительно")
        self.log(f"!! sing-box не умер даже принудительно: pid {pids}")
        self.log("   маршруты всё равно уберу, но процесс придётся снять вручную")

    def _verify_clean(self):
        """Проверяем, что вышли в чистое состояние, а не отчитались вслепую.

        Ругаемся только на свои остатки: чужие половинки при поднятом соседнем
        туннеле — норма, и пугать ими незачем.
        """
        stuck = []
        for half in HALVES:
            for r in winnet.routes_for(half):
                if self.is_ours(r.get("InterfaceIndex")):
                    stuck.append(f"{half}({r.get('InterfaceIndex')})")
        if stuck:
            self.log(f"!! наши половинки дефолтного маршрута на месте: {' '.join(stuck)}")
            self.log("   снять вручную: Remove-NetRoute -DestinationPrefix 0.0.0.0/1")
            return
        _, gw = winnet.default_route()
        if gw:
            self.log(f"→ готово, сеть вернулась в исходное состояние (шлюз {gw})")
        else:
            self.log("!! маршрут по умолчанию отсутствует — сеть не поднята?")


def _load_json(path):
    """Собранный конфиг как словарь; нет или битый — пустой."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _port_open(port):
    """Принимает ли кто-то TCP на этом порту loopback."""
    try:
        socket.create_connection(("127.0.0.1", port), 0.5).close()
        return True
    except OSError:
        return False


def _end(proc):
    """Гасит наш процесс sing-box: по-хорошему, потом принудительно."""
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        # Дожидаемся смерти: новый боковой процесс займёт тот же порт socks.
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _fatal_line(log_path):
    """Причина падения sing-box из его лога — одной строкой, для окна и трея.

    Раньше в статус уходил только путь к логу: человек видел «упал, смотри
    vpn-<дата>.log», а сам лог в ProgramData из-под обычного пользователя
    ещё и не открыть.
    """
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()[-40:]
    except OSError:
        return f"смотри {log_path}"
    for word in ("FATAL", "ERROR"):
        for line in reversed(lines):
            if word in line:
                return line.split(word, 1)[1].strip(" []:")[:200]
    return f"смотри {log_path}"
