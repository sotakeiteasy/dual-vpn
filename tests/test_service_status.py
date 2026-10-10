"""Статус службы сразу после start/stop: up уже новый, а не из снимка
двухсекундной давности — иначе трей после «выключаю» снова зеленел."""

import json
import threading
import types

import pytest

from tunnelvpn import buildconfig, paths, probe, service, tunnels


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
    core._side_said = set()
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
                                "active": "corp", "include": ["corp.example"],
                                "enabled": False})
    monkeypatch.setattr(service.tunnels, "list_confs",
                        lambda tid: ["corp", "old"] if tid == "work" else [])

    assert core._status()["tunnels"] == [
        {"id": "work", "name": "Работа", "mode": "list", "active": "corp",
         "enabled": False, "confs": ["corp", "old"], "rules": 1, "full": False,
         "check": "", "answer": "", "seq": 0, "last": "", "checking": False,
         "tests": {}}]


def test_статус_отдаёт_уровень_журнала_для_галочки_окна(monkeypatch):
    core = _core(monkeypatch, up=False)
    _quiet(monkeypatch, core)
    data = tunnels.validate({"log_level": "debug", "tunnels": []})
    monkeypatch.setattr(service.Core, "_tunnels", staticmethod(lambda: data))

    assert core._status()["log_level"] == "debug"


def test_итог_проверки_по_туннелям_проверенный_уже_не_ждёт(monkeypatch):
    core = _core(monkeypatch, up=True)
    _quiet(monkeypatch, core)
    _with_tunnels(monkeypatch, {"id": "work", "name": "Работа", "mode": "list"},
                  {"id": "home", "name": "Личный", "mode": "all"})
    core.prober._take_slow()
    seq = core.prober.snapshot()["check_seq"]
    core.prober.set(checks={"home": {"result": "up", "answer": "185.1.2.3", "seq": seq},
                            "work": {"result": "error", "answer": "", "seq": seq - 1}})

    st = core._status()

    work, home = st["tunnels"]
    assert (home["check"], home["answer"], home["checking"]) == ("up", "185.1.2.3", False)
    assert (work["check"], work["checking"]) == ("error", True)
    assert "checks" not in st


def test_прошлый_итог_по_id_туннеля_до_замены_файла(monkeypatch, tmp_path):
    core = _core(monkeypatch, up=True)
    monkeypatch.setattr(service, "LAST_CHECK_FILE", str(tmp_path / "last-check.json"))
    _with_tunnels(monkeypatch, {"id": "work", "name": "Работа", "mode": "list"},
                  {"id": "home", "name": "Личный", "mode": "all"},
                  {"id": "lab", "name": "Лаб", "mode": "list"})
    monkeypatch.setattr(service.tunnels, "list_confs", lambda tid: [f"{tid}-1"])
    stamp = {"work-1": 1, "home-1": 1, "lab-1": 1}
    monkeypatch.setattr(service.Core, "_conf_stamp",
                        staticmethod(lambda tid, name: stamp[name]))

    core._remember_check({"tunnels": [{"id": "work", "check": "up"},
                                      {"id": "home", "check": "error"},
                                      {"id": "lab", "check": "none"}]})

    assert core._last_results() == {"work": "up", "home": "error", "lab": ""}
    stamp["work-1"] = 2
    assert core._last_results() == {"work": "", "home": "error", "lab": ""}


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    """Собранные конфиги в state\\run\\: рабочий «по списку» и личный основной."""
    monkeypatch.setattr(paths, "RUN", str(tmp_path))
    monkeypatch.setattr(paths, "CONFIG_JSON", str(tmp_path / "config.json"))
    sets = {"rules-work": {"ip_cidr": ["10.10.0.0/16"]},
            "names-work": {"domain_suffix": ["corp.example"]}}
    for tag, rule in sets.items():
        buildconfig.write_json(buildconfig.rule_set_json(tag), buildconfig.rule_set(rule))
    (tmp_path / "config.json").write_text(json.dumps({
        "outbounds": [
            {"type": "socks", "tag": "socks-work", "password": "секрет"},
            {"type": "socks", "tag": "socks-home", "password": "секрет"},
            {"type": "selector", "tag": "out", "default": "socks-home",
             "outbounds": ["socks-home", "direct"]}],
        "route": {"rules": [{"rule_set": ["rules-work"], "outbound": "socks-work"}],
                  "rule_set": [{"type": "local", "tag": tag, "format": "source",
                                 "path": buildconfig.rule_set_json(tag)} for tag in sets]},
        "dns": {"rules": [{"rule_set": ["names-work"], "server": "dns-work"}]},
    }), encoding="utf-8")
    for tid, extra in (("work", {}), ("home", {"jc": 4})):
        buildconfig.write_json(buildconfig.side_json(tid), {"endpoints": [{
            "tag": f"wg-{tid}", "address": ["10.8.0.2/32"], "mtu": 1280,
            "private_key": "ключ", **extra,
            "peers": [{"address": "203.0.113.9", "public_key": "ключ"}]}]})
    return tmp_path


def test_howto_отдаёт_собранное_без_ключей(run_dir, monkeypatch):
    """Окно больше не читает state\\run\\ само — служба отдаёт только показ."""
    reply = _core(monkeypatch, up=False).handle("howto", {}, True)

    assert reply == {"ok": True, "howto": {
        "endpoints": [
            {"tag": "wg-work", "address": "10.8.0.2/32", "mtu": 1280, "awg": False,
             "peer": "203.0.113.9"},
            {"tag": "wg-home", "address": "10.8.0.2/32", "mtu": 1280, "awg": True,
             "peer": "203.0.113.9"}],
        "corp_nets": ["10.10.0.0/16"],
        "corp_domains": ["corp.example"]}}
    assert "секрет" not in json.dumps(reply) and "ключ" not in json.dumps(reply)


def test_howto_без_прав_без_списков_рабочей_сети(run_dir, monkeypatch):
    """Подсети и домены туннеля — как get-tunnels, только администратору."""
    howto = _core(monkeypatch, up=False).handle("howto", {}, False)["howto"]

    assert howto["corp_nets"] == [] and howto["corp_domains"] == []
    assert [e["tag"] for e in howto["endpoints"]] == ["wg-work", "wg-home"]


def test_howto_без_выключенного_туннеля(run_dir, monkeypatch):
    """Выключенный собран без процесса — в «Как подключиться» его нет."""
    monkeypatch.setattr(paths, "TUNNELS_JSON", str(run_dir / "tunnels.json"))
    (run_dir / "tunnels.json").write_text(json.dumps({"tunnels": [
        {"id": "work", "name": "Работа", "mode": "list", "enabled": False},
        {"id": "home", "name": "Дом", "mode": "all"}]}), encoding="utf-8")

    howto = service.Core._howto(True)

    assert [e["tag"] for e in howto["endpoints"]] == ["wg-home"]
    assert howto["corp_nets"] == []


def test_howto_до_первой_сборки_пуст(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_JSON", str(tmp_path / "нет.json"))

    assert service.Core._howto(True) == {
        "endpoints": [], "corp_nets": [], "corp_domains": []}


def test_после_включения_снимок_уже_с_туннелем(monkeypatch):
    core = _core(monkeypatch, up=False)

    assert core._do_start("personal") == {"ok": True}

    snap = core.prober.snapshot()
    assert snap["tun"] == 7 and snap["r_low"]
