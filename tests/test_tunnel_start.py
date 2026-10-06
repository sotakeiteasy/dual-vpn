"""Включение: реальный адрес, два процесса sing-box и их раздельная судьба.

Реальный адрес спрашиваем в фоне, но до старта sing-box. На плохой сети
запрос к ifconfig.me висел до 15 с и держал всё включение. Ждать его после
старта sing-box нельзя: запрос ушёл бы в туннель, адрес выхода записался бы
как «реальный», и пробер показывал бы утечку в рабочем туннеле.

Корп и основной — разные процессы: корп перезапускается один, его
падение не срывает включение, а выход наружу переключается через clash_api.

Систему подменяем целиком: winnet, sing-box и сеть — границы. clash_api
изображает настоящий HTTP-сервер на loopback.
"""

import http.server
import json
import threading
import time
import urllib.request

import pytest

from dualvpn import buildconfig, paths, tunnel


class FakeNet:
    last_error = ""

    def __init__(self):
        self.singbox_running = False
        self.added = []

    def tun_index(self, _ip):
        return 45 if self.singbox_running else None

    def pids_of(self, _exe):
        return []

    def v6_blocked(self):
        return False

    def default_route(self):
        return 18, "192.168.0.1"

    def v6_block(self, _idx):
        return True

    def add_routes(self, routes):
        self.added += routes

    def routes_for(self, _prefix):
        return []


class FakeProc:
    def __init__(self, cfg):
        self.cfg = cfg
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 1

    def kill(self):
        self.returncode = 1

    def wait(self, timeout=None):
        return self.returncode


class FakeBuild:
    """Сборка без conf\\: остальное — настоящий buildconfig."""

    def __init__(self):
        self.on_main = lambda: None
        self.corp_ip = "203.0.113.20"
        self.personal_ip = "203.0.113.10"

    def main(self, log=print):
        self.on_main()

    def refresh_peer(self, kind, log=print):
        return self.corp_ip if kind == "corp" else self.personal_ip

    def __getattr__(self, name):
        return getattr(buildconfig, name)


class FakeIfconfig:
    """ifconfig.me: отвечает, когда отпустят, или по таймауту падает."""

    def __init__(self, ip):
        self.ip = ip
        self.called = threading.Event()
        self.release = threading.Event()

    def __call__(self, _url, timeout=None):
        self.called.set()
        if not self.release.wait(2):
            raise OSError("timed out")
        return self

    def read(self):
        return self.ip.encode()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name in ("SINGBOX", "WINTUN"):
        f = tmp_path / name
        f.write_text("")
        monkeypatch.setattr(paths, name, str(f))
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "outbounds": [{"type": "socks", "tag": buildconfig.CORP_SOCKS_TAG,
                       "server_port": 1080},
                      {"type": "socks", "tag": buildconfig.PERSONAL_SOCKS_TAG,
                       "server_port": 1081}],
    }))
    monkeypatch.setattr(paths, "CONFIG_JSON", str(cfg))
    for name, ip in (("corp", "203.0.113.20"), ("personal", "203.0.113.10")):
        side = tmp_path / f"{name}.json"
        side.write_text(json.dumps(
            {"endpoints": [{"peers": [{"address": ip}]}]}))
        monkeypatch.setattr(paths, f"{name.upper()}_JSON", str(side))
    monkeypatch.setattr(paths, "OWNED_FILE", str(tmp_path / "owned"))
    monkeypatch.setattr(paths, "REAL_IP_FILE", str(tmp_path / "real-ip"))
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setattr(paths, "LOGS", str(logs))

    net = FakeNet()
    monkeypatch.setattr(tunnel, "winnet", net)
    build = FakeBuild()
    monkeypatch.setattr(tunnel, "buildconfig", build)
    seen = {"checked": [], "started": [], "dies": set(), "socks": [],
            "socks_open": True}

    def run(cmd, **_k):
        if "check" in cmd:
            seen["checked"].append(cmd[-1])
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr(tunnel.subprocess, "run", run)
    monkeypatch.setattr(tunnel, "REAL_IP_WAIT", 0.3)
    monkeypatch.setattr(tunnel, "SIDE_WAIT", 0.5)

    # Что лежит в real-ip в момент старта sing-box — это и увидит пробер.
    def popen(cmd, **_k):
        cfg_path = cmd[cmd.index("-c") + 1]
        seen["started"].append(cfg_path)
        proc = FakeProc(cfg_path)
        if cfg_path == paths.CONFIG_JSON:
            with open(paths.REAL_IP_FILE, encoding="utf-8") as fh:
                seen["real_ip"] = fh.read()
            net.singbox_running = True
        elif any(buildconfig.side_json(k) == cfg_path for k in seen["dies"]):
            proc.returncode = 1
        return proc

    def port_open(port):
        seen["socks"].append(port)
        return seen["socks_open"]

    monkeypatch.setattr(tunnel.subprocess, "Popen", popen)
    monkeypatch.setattr(tunnel, "_port_open", port_open)

    lines = []
    tun = tunnel.Tunnel(log=lines.append)
    seen["log"] = lines
    seen["net"] = net
    monkeypatch.setattr(tun, "_keep_awake", lambda _on: None)
    yield tun, build, seen
    for fh in (tun.logfile, tun.corp.logfile, tun.personal.logfile):
        if fh is not None:
            fh.close()


def test_адрес_спрашивается_пока_собирается_конфиг(env, monkeypatch):
    tun, build, seen = env
    ifconfig = FakeIfconfig("198.51.100.7")
    monkeypatch.setattr(urllib.request, "urlopen", ifconfig)
    asked = []

    def build_main():
        asked.append(ifconfig.called.wait(1))
        ifconfig.release.set()

    build.on_main = build_main

    assert tun.start() == ""

    assert asked == [True]
    assert seen["real_ip"] == "198.51.100.7"


def test_медленная_сеть_не_держит_включение(env, monkeypatch):
    tun, _build, seen = env
    ifconfig = FakeIfconfig("198.51.100.7")
    monkeypatch.setattr(urllib.request, "urlopen", ifconfig)

    began = time.time()
    assert tun.start() == ""

    assert time.time() - began < 1.5
    assert seen["real_ip"] == ""


def test_опоздавший_ответ_не_записывается(env, monkeypatch):
    """Ответ после старта sing-box мог прийти через туннель — это не реальный адрес."""
    tun, _build, _seen = env
    ifconfig = FakeIfconfig("198.51.100.7")
    monkeypatch.setattr(urllib.request, "urlopen", ifconfig)
    assert tun.start() == ""

    ifconfig.release.set()
    time.sleep(0.2)

    with open(paths.REAL_IP_FILE, encoding="utf-8") as fh:
        assert fh.read() == ""


# ---------------------------------------------------------- три процесса


def test_проверяются_все_конфиги_и_туннели_стартуют_первыми(env):
    """Основной сразу отдаёт трафик в socks — туннели должны уже слушать."""
    tun, _build, seen = env

    assert tun.start() == ""

    assert seen["checked"] == [paths.CONFIG_JSON, paths.CORP_JSON,
                               paths.PERSONAL_JSON]
    assert seen["started"] == [paths.CORP_JSON, paths.PERSONAL_JSON,
                               paths.CONFIG_JSON]
    assert seen["socks"] == [1080, 1081]
    for side in tun.sides:
        assert side.log_start[0].startswith(paths.LOGS)
        assert f"{side.kind}-" in side.log_start[0]
    assert "vpn-" in tun.log_start[0]


def test_порт_открыт_только_когда_его_слушают():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        assert tunnel._port_open(port)
    assert not tunnel._port_open(port)


def test_пиры_берутся_из_конфигов_туннелей(env):
    tun, _build, seen = env

    assert tun.start() == ""

    hosts = {r[0] for r in seen["net"].added}
    assert {"203.0.113.10/32", "203.0.113.20/32"} <= hosts


def test_упавший_корп_не_срывает_включение(env):
    """Интернету корп не нужен: без него включение идёт дальше."""
    tun, _build, seen = env
    seen["dies"] = {"corp"}

    assert tun.start() == ""

    assert tun.proc is not None
    assert any("корп процесс упал" in l for l in seen["log"])


def test_упавший_личный_включает_выход_напрямую(env, monkeypatch):
    """Интернет работает и без личного: socks без процесса отказывал бы всем."""
    tun, _build, seen = env
    seen["dies"] = {"personal"}
    outs = []
    monkeypatch.setattr(tun, "set_out", outs.append)

    assert tun.start() == ""

    assert tun.proc is not None
    assert outs == [buildconfig.DIRECT_TAG]
    assert any("личный процесс упал" in l and "выход напрямую" in l
               for l in seen["log"])


def test_туннель_не_открыл_socks_гасим_его(env, monkeypatch):
    tun, _build, seen = env
    seen["socks_open"] = False
    monkeypatch.setattr(tun, "set_out", lambda _tag: True)

    assert tun.start() == ""

    assert tun.corp.proc is None and tun.personal.proc is None
    assert any("не открыл socks" in l for l in seen["log"])


def test_повторное_включение_поднимает_мёртвый_корп(env):
    tun, _build, seen = env
    assert tun.start() == ""
    tun.corp.proc.returncode = 1
    main = tun.proc

    assert tun.start() == ""

    assert tun.proc is main
    assert seen["started"][-1] == paths.CORP_JSON
    assert tun.corp.alive()


def test_повторное_включение_возвращает_выход_на_личный(env, monkeypatch):
    tun, _build, seen = env
    assert tun.start() == ""
    tun.personal.proc.returncode = 1
    outs = []
    monkeypatch.setattr(tun, "set_out", outs.append)

    assert tun.start() == ""

    assert seen["started"][-1] == paths.PERSONAL_JSON
    assert tun.personal.alive() and tun.corp.alive()
    assert outs == [buildconfig.PERSONAL_SOCKS_TAG]


@pytest.mark.parametrize("kind, ip_attr", [("corp", "corp_ip"),
                                          ("personal", "personal_ip")])
def test_перезапуск_туннеля_не_трогает_остальные(env, kind, ip_attr):
    tun, build, seen = env
    assert tun.start() == ""
    side = getattr(tun, kind)
    other = tun.personal if side is tun.corp else tun.corp
    main, old, other_proc = tun.proc, side.proc, other.proc
    setattr(build, ip_attr, "203.0.113.99")

    assert tun.restart_side(side) == ""

    assert old.terminated
    assert not main.terminated and not other_proc.terminated
    assert tun.proc is main and other.proc is other_proc
    assert side.proc is not old and side.alive()
    # Новый адрес пира — мимо туннеля, через тот же аплинк.
    assert ("203.0.113.99/32", 18, "192.168.0.1", 1) in seen["net"].added
    assert ["host", "203.0.113.99", "192.168.0.1", "18"] in tun.owned_lines()


def test_перезапуск_туннеля_без_туннеля_отказ(env):
    tun, _build, seen = env

    assert tun.restart_side(tun.corp) == "туннель не поднят"
    assert seen["started"] == []


def test_стоп_гасит_все_процессы(env, monkeypatch):
    tun, _build, _seen = env
    assert tun.start() == ""
    procs = [tun.proc] + [side.proc for side in tun.sides]
    for name in ("routes_on_interface", "v6_unblock", "nrpt_clear",
                 "flush_dns", "del_route"):
        monkeypatch.setattr(tunnel.winnet, name, lambda *_a: [], raising=False)
    monkeypatch.setattr(tunnel.winnet, "interface_exists", lambda _i: False,
                        raising=False)

    tun.stop()

    assert all(p.terminated for p in procs)
    for side in tun.sides:
        assert side.proc is None and side.logfile is None
        assert side.log_start is None
    assert tun.log_start is None


# ------------------------------------------------------------ выход наружу


class FakeClash(http.server.BaseHTTPRequestHandler):
    """clash_api основного процесса: selector out и замер задержки."""

    secret = "s3cret"
    now = buildconfig.PERSONAL_SOCKS_TAG
    delays = {buildconfig.PERSONAL_SOCKS_TAG: 0, buildconfig.DIRECT_TAG: 42}
    paths_seen = []

    def _auth(self):
        if self.headers.get("Authorization") != f"Bearer {self.secret}":
            self._send(401, {"message": "Unauthorized"})
            return False
        return True

    def _send(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        FakeClash.paths_seen.append(self.path)
        if not self._auth():
            return
        if self.path == f"/proxies/{buildconfig.OUT_TAG}":
            self._send(200, {"name": "out", "now": FakeClash.now})
            return
        tag = self.path.split("/")[2]
        ms = self.delays.get(tag)
        if ms:
            self._send(200, {"delay": ms})
        else:
            self._send(504, {"message": "Timeout"})

    def do_PUT(self):
        if not self._auth():
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeClash.now = body["name"]
        self._send(204)

    def log_message(self, *_a):
        pass


@pytest.fixture
def clash(env):
    tun, _build, seen = env
    server = http.server.HTTPServer(("127.0.0.1", 0), FakeClash)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    FakeClash.now = buildconfig.PERSONAL_SOCKS_TAG
    FakeClash.paths_seen = []
    with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
        cfg = json.load(fh)
    cfg["experimental"] = {"clash_api": {
        "external_controller": f"127.0.0.1:{server.server_port}",
        "secret": FakeClash.secret}}
    with open(paths.CONFIG_JSON, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    yield tun, seen
    server.shutdown()
    server.server_close()


def test_переключение_выхода_на_direct_и_обратно(clash):
    tun, _seen = clash

    assert tun.out_now() == buildconfig.PERSONAL_SOCKS_TAG
    assert tun.set_out(buildconfig.DIRECT_TAG)
    assert tun.out_now() == buildconfig.DIRECT_TAG
    assert tun.set_out(buildconfig.PERSONAL_SOCKS_TAG)
    assert tun.out_now() == buildconfig.PERSONAL_SOCKS_TAG


def test_задержка_живого_и_мёртвого_выхода(clash):
    tun, _seen = clash

    assert tun.delay(buildconfig.DIRECT_TAG) == 42
    assert tun.delay(buildconfig.PERSONAL_SOCKS_TAG) is None
    # Мерить по имени: голый адрес sing-box через selector не меряет.
    assert "cp.cloudflare.com" in FakeClash.paths_seen[-1]


def test_чужой_секрет_это_отказ_а_не_исключение(clash, monkeypatch):
    tun, seen = clash
    monkeypatch.setattr(FakeClash, "secret", "другой")

    assert tun.set_out(buildconfig.DIRECT_TAG) is False
    assert tun.out_now() == ""
    assert tun.delay(buildconfig.DIRECT_TAG) is None
    assert any("не переключить" in l for l in seen["log"])


def test_системный_прокси_не_перехватывает_clash_api(clash, monkeypatch):
    tun, _seen = clash
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")

    assert tun.out_now() == buildconfig.PERSONAL_SOCKS_TAG


def test_без_clash_api_выход_не_переключается(env):
    tun, _build, _seen = env

    assert tun.set_out(buildconfig.DIRECT_TAG) is False
    assert tun.out_now() == ""
