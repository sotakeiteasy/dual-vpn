"""Статус службы сразу после start/stop: up уже новый, а не из снимка
двухсекундной давности — иначе трей после «выключаю» снова зеленел."""

import threading
import types

from dualvpn import probe, service


class _Tunnel:
    log_start = None

    def __init__(self, net):
        self.net = net

    def start(self, _profile):
        self.net.up = True
        return ""

    def stop(self):
        self.net.up = False

    def out_now(self):
        return "personal-socks" if self.net.up else ""


def _core(monkeypatch, up):
    """Core без службы: туннель и опрос сети подменены одной «сетью»."""
    net = types.SimpleNamespace(up=up)
    core = service.Core.__new__(service.Core)
    core.lock = threading.Lock()
    core.busy = ""
    core.last_error = ""
    core.log_lock = threading.Lock()
    core._paths, core._ip_names = {}, {}
    core._log_at, core._side_after, core._side_noted = {}, {}, {}
    core.tunnel = _Tunnel(net)
    core.prober = probe.Prober()
    monkeypatch.setattr(core.prober, "probe_fast", lambda: core.prober.set(
        tun=7 if net.up else None, r_low=net.up))
    core.prober.probe_fast()
    return core


def test_после_выключения_снимок_уже_без_туннеля(monkeypatch):
    core = _core(monkeypatch, up=True)

    assert core._do_stop() == {"ok": True}

    snap = core.prober.snapshot()
    assert snap["tun"] is None and not snap["r_low"]
    assert core.busy == ""


def test_после_включения_снимок_уже_с_туннелем(monkeypatch):
    core = _core(monkeypatch, up=False)

    assert core._do_start("personal") == {"ok": True}

    snap = core.prober.snapshot()
    assert snap["tun"] == 7 and snap["r_low"]
