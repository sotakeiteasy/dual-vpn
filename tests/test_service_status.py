"""Статус службы сразу после start/stop: up уже новый, а не из снимка
двухсекундной давности — иначе трей после «выключаю» снова зеленел."""

import threading
import types

from dualvpn import probe, service, tunnels


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


def _quiet(monkeypatch, core):
    """Поля статуса, которые читают систему и conf\\, — пустые."""
    for name, value in (("autostart_enabled", False), ("_singbox_version", ""),
                        ("_profiles", []), ("_corp", []), ("_last_results", {})):
        monkeypatch.setattr(core, name, lambda *_a, value=value: value)


def _with_tunnels(monkeypatch, *items):
    data = tunnels.validate({"tunnels": list(items)})
    monkeypatch.setattr(service.Core, "_tunnels", staticmethod(lambda: data))


def test_статус_по_сторонам_личный_проверен_корп_ещё_нет(monkeypatch):
    core = _core(monkeypatch, up=True)
    _quiet(monkeypatch, core)
    core.prober._take_slow()
    core.prober.set(personal_seq=core.prober.snapshot()["check_seq"])

    st = core._status()
    assert st["checking"] and st["checking_corp"] and not st["checking_personal"]

    core.prober.slow_busy.clear()
    st = core._status()
    assert not st["checking_corp"] and not st["checking_personal"]


def test_раздельное_туннелирование_включено_когда_у_рабочего_есть_правила(monkeypatch):
    core = _core(monkeypatch, up=False)
    _quiet(monkeypatch, core)
    home = {"id": "home", "name": "Личный", "mode": "all",
            "exclude": ["203.0.113.9"]}

    _with_tunnels(monkeypatch, {"id": "work", "name": "Работа", "mode": "list",
                                "include": ["corp.example"]}, home)
    assert core._status()["split"] is True

    _with_tunnels(monkeypatch, {"id": "work", "name": "Работа", "mode": "list",
                                "exclude": ["198.51.100.7"]}, home)
    assert core._status()["split"] is True

    # «Мимо VPN» у основного — не раздельное туннелирование рабочей сети.
    _with_tunnels(monkeypatch, {"id": "work", "name": "Работа", "mode": "list"}, home)
    assert core._status()["split"] is False

    _with_tunnels(monkeypatch, home)
    assert core._status()["split"] is False


def test_статус_отдаёт_туннели_без_их_правил(monkeypatch):
    core = _core(monkeypatch, up=False)
    _quiet(monkeypatch, core)
    _with_tunnels(monkeypatch, {"id": "work", "name": "Работа", "mode": "list",
                                "active": "corp", "include": ["corp.example"]})
    monkeypatch.setattr(service.tunnels, "list_confs",
                        lambda tid: ["corp", "old"] if tid == "work" else [])

    assert core._status()["tunnels"] == [
        {"id": "work", "name": "Работа", "mode": "list", "active": "corp",
         "confs": ["corp", "old"]}]


def test_после_включения_снимок_уже_с_туннелем(monkeypatch):
    core = _core(monkeypatch, up=False)

    assert core._do_start("personal") == {"ok": True}

    snap = core.prober.snapshot()
    assert snap["tun"] == 7 and snap["r_low"]
