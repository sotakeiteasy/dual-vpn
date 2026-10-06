"""Реальный адрес при включении: спрашиваем в фоне, но до старта sing-box.

На плохой сети запрос к ifconfig.me висел до 15 с и держал всё включение.
Ждать его после старта sing-box нельзя: запрос ушёл бы в туннель, адрес выхода
записался бы как «реальный», и пробер показывал бы утечку в рабочем туннеле.

Систему подменяем целиком: winnet, sing-box и сеть — границы, проверяется
только порядок шагов в Tunnel.start.
"""

import json
import threading
import time
import urllib.request

import pytest

from dualvpn import paths, tunnel


class FakeNet:
    last_error = ""

    def __init__(self):
        self.singbox_running = False

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

    def add_routes(self, _routes):
        pass

    def routes_for(self, _prefix):
        return []


class FakeProc:
    def poll(self):
        return None


class FakeBuild:
    def __init__(self):
        self.on_main = lambda: None

    def main(self, log=print):
        self.on_main()


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
    cfg.write_text(json.dumps(
        {"endpoints": [{"peers": [{"address": "203.0.113.10"}]}]}))
    monkeypatch.setattr(paths, "CONFIG_JSON", str(cfg))
    monkeypatch.setattr(paths, "OWNED_FILE", str(tmp_path / "owned"))
    monkeypatch.setattr(paths, "REAL_IP_FILE", str(tmp_path / "real-ip"))
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setattr(paths, "LOGS", str(logs))

    net = FakeNet()
    monkeypatch.setattr(tunnel, "winnet", net)
    build = FakeBuild()
    monkeypatch.setattr(tunnel, "buildconfig", build)
    monkeypatch.setattr(tunnel.subprocess, "run",
                        lambda *a, **k: type("R", (), {"returncode": 0})())
    monkeypatch.setattr(tunnel, "REAL_IP_WAIT", 0.3)

    # Что лежит в real-ip в момент старта sing-box — это и увидит пробер.
    seen = {}

    def popen(*_a, **_k):
        with open(paths.REAL_IP_FILE, encoding="utf-8") as fh:
            seen["real_ip"] = fh.read()
        net.singbox_running = True
        return FakeProc()

    monkeypatch.setattr(tunnel.subprocess, "Popen", popen)

    tun = tunnel.Tunnel(log=lambda _line: None)
    monkeypatch.setattr(tun, "_keep_awake", lambda _on: None)
    yield tun, build, seen
    if tun.logfile is not None:
        tun.logfile.close()


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
