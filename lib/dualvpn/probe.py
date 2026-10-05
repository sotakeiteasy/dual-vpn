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

from . import paths, winnet

# Быстрый опрос — несколько WMI-запросов по 10–20 мс (см. winnet). Пока они
# шли через запуск PowerShell, цикл стоил секунды и приходилось реже.
FAST_EVERY = 2.0
# Сколько check_now ждёт уже идущую проверку: при плохой сети она до ~30 с —
# столько стоит адрес выхода со всеми запасными сервисами.
CHECK_WAIT = 40.0
# Корп-проверка: пакет через WireGuard теряется и при живом туннеле, поэтому
# одна неудача ещё не «молчит» — повторяем. Попытки короче прежних 12 с, и
# худший случай не дольше прежнего.
CORP_TRIES = 2
CORP_DNS_TIMEOUT = 2.5
CORP_HTTP_TIMEOUT = 6.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Редирект — тоже ответ корп-сайта: 302 на страницу входа уже значит,
    что сервер достижим. Идти по нему — значит мерить чужой хост."""

    def redirect_request(self, *args, **kwargs):
        return None


class Prober:
    def __init__(self):
        self.st = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        # При плохой сети probe_slow идёт до ~30 с (самая долгая часть). Без
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
        """Адреса пиров из собранного конфига: {tag: address}."""
        out = {}
        try:
            with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
                cfg = json.load(fh)
            for e in cfg.get("endpoints", []):
                peers = e.get("peers") or []
                if peers:
                    out[e.get("tag", "")] = peers[0].get("address", "")
        except Exception:
            pass
        return out

    def corp_dns(self):
        """Корп-DNS берём из собранного конфига, а не хардкодим."""
        try:
            with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
                cfg = json.load(fh)
            for s in cfg.get("dns", {}).get("servers", []):
                if s.get("tag") == "dns-corp":
                    return s.get("server", "")
        except Exception:
            pass
        return ""

    def _exit_info(self):
        """Внешний адрес и страна. Несколько сервисов по очереди.

        Выход VPN — общий адрес на многих клиентов, и ipinfo.io с него быстро
        начинает отвечать 429 Too Many Requests. С одним сервисом адрес выхода
        тогда не определялся никогда, и окно вечно показывало «проверяю».
        """
        try:
            info = json.loads(self._get("https://ipinfo.io/json", 8) or "{}")
            if info.get("ip"):
                return info
        except ValueError:
            pass
        try:
            raw = json.loads(self._get("https://ipwho.is/", 8) or "{}")
            if raw.get("ip"):
                return {"ip": raw["ip"], "country": raw.get("country_code", ""),
                        "city": raw.get("city", ""),
                        "org": (raw.get("connection") or {}).get("org", "")}
        except ValueError:
            pass
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
            ip = self._get(url, 6)
            if re.match(r"^[\d.]+$", ip or ""):
                return {"ip": ip}
        return {}

    def probe_slow(self):
        """Сетевая проверка. Части независимы и идут параллельно: по очереди
        их таймауты складывались, и проверка «висела» до минуты, хотя каждая
        часть по отдельности укладывается в секунды."""
        parts = [threading.Thread(target=fn, daemon=True)
                 for fn in (self._slow_exit, self._slow_v6,
                            self._slow_corp_dns, self._slow_corp_http)]
        for t in parts:
            t.start()
        for t in parts:
            t.join()

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
            elif ip == peers.get("awg-personal"):
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

    def _slow_corp_dns(self):
        probe_host = paths.site_env().get("CORP_PROBE", "")
        dns = self.corp_dns()
        if dns and probe_host:
            self.set(corp_dns=dns, corp_ip=self._dns_ask(dns, probe_host))
        else:
            self.set(corp_dns=dns, corp_ip="")

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
