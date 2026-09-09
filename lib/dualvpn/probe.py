"""Пробер состояния: что сейчас поднято и работает ли оно на самом деле.

Живёт в службе и пишет результат в state\\status.json. Трей и окно только
читают этот файл — так они остаются обычным пользовательским процессом и не
лезут в сеть сами.

Проверки разделены на две скорости. Локальные (интерфейсы, маршруты, процесс)
дёшевы и идут раз в две секунды. Сетевые (внешний адрес, корп-DNS, корп-HTTPS)
ходят наружу с таймаутами до 12 секунд, поэтому идут раз в двадцать и в
отдельном потоке: в общем цикле они останавливали бы обновление статуса на
полминуты, и снаружи это выглядело как «туннель отвалился и вернулся».
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

from . import paths, winnet

FAST_EVERY = 2.0
SLOW_EVERY = 20.0


class Prober:
    def __init__(self):
        self.st = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

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

    def probe_slow(self):
        raw = self._get("https://ipinfo.io/json", 12)
        peers = self.peer_addrs()
        try:
            info = json.loads(raw)
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

        # IPv6: любой ответ здесь означает, что трафик идёт мимо туннеля.
        v6 = self._get("https://api6.ipify.org", 6)
        self.set(v6_leak=v6 if re.match(r"^[0-9a-fA-F:]+$", v6 or "") else "")

        probe_host = paths.site_env().get("CORP_PROBE", "")
        dns = self.corp_dns()
        if dns and probe_host:
            self.set(corp_dns=dns, corp_ip=self._dns_ask(dns, probe_host))
        else:
            self.set(corp_dns=dns, corp_ip="")

        if probe_host:
            self.set(corp_http=self._http_code(f"https://{probe_host}"))
        else:
            self.set(corp_http="")

    @staticmethod
    def _dns_ask(server, name):
        ip = winnet.resolve4_via(name, server)
        return ip if re.match(r"^[\d.]+$", ip or "") else ""

    @staticmethod
    def _http_code(url):
        """Код ответа корп-сайта. Нас устраивает любой — важно, что он есть.

        Даже 403 значит, что до сервера дошли: без туннеля не было бы и его.
        """
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=12) as r:
                return str(r.status)
        except urllib.error.HTTPError as exc:
            return str(exc.code)
        except Exception:
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
        last_slow = 0.0
        was_up = False
        while not self.stop_event.is_set():
            try:
                self.probe_fast()
            except Exception:
                pass
            s = self.snapshot()
            up = bool(s.get("tun")) and bool(s.get("r_low"))

            # До того как поднялся tun и встали маршруты, мерить выход наружу
            # бессмысленно: получим свой реальный адрес и покажем его ещё
            # двадцать секунд, как будто туннель не работает.
            if up and not was_up:
                last_slow = 0.0
            was_up = up

            if up and time.time() - last_slow > SLOW_EVERY:
                last_slow = time.time()
                threading.Thread(target=self._slow_guarded, daemon=True).start()
            elif not up:
                self.set(exit_ip="", corp_ip="", corp_http="", v6_leak="",
                         exit_is_peer=False, exit_state="unknown")
            self.write_status()
            self.stop_event.wait(FAST_EVERY)

    def _slow_guarded(self):
        try:
            self.probe_slow()
        except Exception:
            pass
