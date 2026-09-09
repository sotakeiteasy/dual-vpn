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
import subprocess
import time

from . import buildconfig, paths, winnet

KEEP_LOGS = 10

# Обе половины адресного пространства. Пишем именно так, а не 0.0.0.0/0:
# более специфичный префикс выигрывает у маршрута по умолчанию, не удаляя его,
# и исходная картина сети возвращается сама, как только мы уберём свои строки.
HALVES = ("0.0.0.0/1", "128.0.0.0/1")

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Пока туннель поднят, не даём системе засыпать по простою: во сне keepalive
# не уходит, WG-сессия протухает, а TCP-соединения, открытые до сна, после
# пробуждения уже мертвы — их не воскрешает ничто. Крышку это не покрывает.
_ES_CONTINUOUS = 0x80000000
_ES_SYSTEM_REQUIRED = 0x00000001


class Tunnel:
    """Один туннель на процесс службы. Методы зовутся из одного потока."""

    def __init__(self, log):
        self.log = log
        self.proc = None
        self.logfile = None
        # Индекс нашего tun, каким мы его запомнили. Нужен уборке после того,
        # как интерфейс исчез, а журнал уже удалён.
        self._tun_hint = None

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

    def open_log(self):
        """Свежий файл лога, старые сверх KEEP_LOGS удаляются.

        При битом конфиге sing-box падает, служба поднимает его снова, и каждый
        заход создавал бы новый файл: за две минуты история из десяти запусков
        вытеснялась бы циклом перезапуска. Свежий лог в такой ситуации
        продолжаем, а не заводим ещё один.
        """
        paths.ensure_dirs()
        existing = sorted(
            (os.path.join(paths.LOGS, f) for f in os.listdir(paths.LOGS)
             if f.startswith("vpn-") and f.endswith(".log")),
        )
        if existing and time.time() - os.path.getmtime(existing[-1]) < 60:
            path = existing[-1]
        else:
            stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
            path = os.path.join(paths.LOGS, f"vpn-{stamp}.log")
            existing.append(path)
        # Имя — это дата, поэтому сортировка по имени хронологическая.
        for old in existing[:-KEEP_LOGS]:
            try:
                os.remove(old)
            except OSError:
                pass
        self.logfile = open(path, "a", encoding="utf-8", errors="replace")
        self.logfile.write(
            f"\n=== {datetime.datetime.now():%Y-%m-%d %H:%M:%S} DualVPN ===\n")
        self.logfile.flush()
        return path

    # -------------------------------------------------------------- старт

    def start(self, profile=""):
        """Поднимает туннель. Возвращает '' или текст ошибки."""
        paths.ensure_dirs()

        # Уборка за прошлым запуском — до того, как поднимем свой. Прошлый мог
        # уйти в KILL, упасть вместе с машиной или потерять питание: следы
        # тогда остаются, и разгрести их некому, кроме нас.
        if self.leftovers():
            self.log("→ вижу следы прошлого запуска, сначала убираю")
            self.stop()
            self.log("")

        if profile:
            conf = os.path.join(paths.CONF, f"{profile}.conf")
            if not os.path.isfile(conf):
                return f"нет профиля «{profile}»: не найден {conf}"
            os.environ["SB_PERSONAL"] = profile
            self.log(f"→ личный профиль: {profile}")

        # Настройки рабочей сети — в окружение: buildconfig читает их оттуда.
        for k, v in paths.site_env().items():
            os.environ.setdefault(k, v)

        if not os.path.isfile(paths.SINGBOX):
            return f"нет {paths.SINGBOX} — переустанови приложение"
        if not os.path.isfile(paths.WINTUN):
            return (f"нет {paths.WINTUN}: без wintun.dll sing-box не создаст "
                    f"сетевой адаптер")

        self.log("→ собираю конфиг из conf\\…")
        try:
            buildconfig.main()
        except SystemExit as exc:
            # buildconfig сообщает об ошибках через sys.exit с текстом.
            return str(exc) or "не удалось собрать конфиг — правь conf\\*.conf"

        # timeout обязателен: без него зависший sing-box повесил бы
        # весь start навсегда, а клиент ждёт ответ по каналу без таймаута —
        # снаружи это ровно ««Включить» зависло».
        try:
            check = subprocess.run(
                [paths.SINGBOX, "check", "-c", paths.CONFIG_JSON],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=20, creationflags=_NO_WINDOW)
        except subprocess.TimeoutExpired:
            return "sing-box check не ответил за 20с"
        if check.returncode != 0:
            return f"конфиг не прошёл проверку: {(check.stderr or '').strip()}"

        # Шлюз по умолчанию определяем ДО старта, пока туннель не перебил
        # маршруты. Ничего не захардкожено: работает и на Wi-Fi, и на раздаче.
        up_idx, gw = winnet.default_route()
        if not gw:
            return "нет маршрута по умолчанию — сеть не поднята?"
        self.log(f"→ аплинк: интерфейс {up_idx}, шлюз {gw}")

        self._save_real_ip()

        # До старта туннеля: иначе первые же запросы браузера уйдут по v6 мимо.
        self.own("v6block")
        winnet.v6_block()
        self.log("→ исходящий IPv6 заблокирован на время сеанса")

        peers = self._peer_ips()
        if not peers:
            return "не определить адреса пиров — прерываю, иначе будет петля"
        self.log(f"→ пиры (пойдут мимо туннеля): {', '.join(peers)}")

        # Порядок важен: сперва вывести пиров из-под туннеля, потом ставить
        # половинки. Иначе трафик к серверу сам уходит в туннель — петля.
        for ip in peers:
            self.own("host", ip, gw, up_idx)
            winnet.add_route(f"{ip}/32", up_idx, gw, metric=1)

        log_path = self.open_log()
        self.log(f"→ журнал sing-box: {log_path}")
        self.log("→ запускаю sing-box…")
        self.proc = subprocess.Popen(
            [paths.SINGBOX, "run", "-c", paths.CONFIG_JSON],
            cwd=paths.BIN,          # рядом лежит wintun.dll, его ищут здесь
            stdout=self.logfile, stderr=subprocess.STDOUT,
            creationflags=_NO_WINDOW,
        )

        tun_idx = None
        for _ in range(30):
            time.sleep(1)
            if self.proc.poll() is not None:
                return f"sing-box упал на старте, смотри {log_path}"
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
        for half in HALVES:
            self.own("net", half, tun_idx)
            if not any(r.get("InterfaceIndex") == tun_idx
                       for r in winnet.routes_for(half)):
                winnet.add_route(half, tun_idx, "0.0.0.0", metric=1)
        self.log("→ маршруты выставлены")

        self._keep_awake(True)
        self.log("→ работает")
        return ""

    def _save_real_ip(self):
        """Настоящий адрес провайдера, пока туннель не поднят.

        Утечкой считается совпадение с ним. Сравнивать с адресом сервера
        ненадёжно: он может выходить не тем адресом, на котором принимает
        соединения, и тогда рабочий туннель показывался бы как утечка.
        """
        ip = ""
        try:
            import urllib.request
            with urllib.request.urlopen("https://ifconfig.me/ip", timeout=4) as r:
                ip = r.read().decode("ascii", "replace").strip()
        except Exception:
            ip = ""
        if not all(c in "0123456789." for c in ip) or not ip:
            ip = ""              # не ответили — не гадаем
        try:
            with open(paths.REAL_IP_FILE, "w", encoding="utf-8") as fh:
                fh.write(ip)
        except OSError:
            pass

    def _peer_ips(self):
        """Адреса пиров из собранного конфига, имена резолвим сейчас.

        Пока DNS ещё системный: после подъёма туннеля он уйдёт внутрь, и имя
        сервера станет нерезолвимым ровно тогда, когда оно нужнее всего.
        """
        out = []
        try:
            with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError):
            return out
        for ep in cfg.get("endpoints", []):
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
        self._keep_awake(False)

        # Индекс tun поднимаем из журнала до того, как начнём его разбирать:
        # дальше уборка спрашивает «наш ли этот маршрут» уже без журнала.
        if self._tun_hint is None:
            self._tun_hint = self._our_tun_index()

        # 1. Процесс. Сначала свой, потом любой оставшийся от прошлых запусков.
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        self._kill_strays()

        if self.logfile is not None:
            try:
                self.logfile.close()
            except OSError:
                pass
            self.logfile = None

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
