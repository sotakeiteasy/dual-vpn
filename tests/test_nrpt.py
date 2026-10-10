"""Правило NRPT для корп-доменов: домены из конфига превращаются в суффиксы,
а всё, что не похоже на домен, до правила не доходит. Ставится и снимается
правило только через WMI (PS_DnsClientNrptRule), без PowerShell."""

import json

import pytest

from tunnelvpn import paths, winnet
from tunnelvpn.tunnel import Tunnel


@pytest.fixture(autouse=True)
def no_wmi(monkeypatch):
    """По умолчанию WMI «не отвечает»: прогон на Windows не должен трогать
    живое правило туннеля. Тесты пути через WMI подменяют его сами."""
    monkeypatch.setattr(winnet, "_nrpt_call", lambda method, **args: None)


def test_домены_становятся_суффиксами_nrpt():
    assert winnet.nrpt_namespaces(["corp.example", "Intra.Example."]) == [
        ".corp.example", ".intra.example"]


def test_дубли_схлопываются():
    assert winnet.nrpt_namespaces(["corp.example", ".corp.example"]) == [
        ".corp.example"]


def test_не_домен_отбрасывается():
    """tunnels.json правит пользователь: мусор из него не должен попасть в правило."""
    bad = ["a'; Remove-Item C:\\ #", "x y", "", "-corp.example", "a$(b).example"]
    assert winnet.nrpt_namespaces(bad + ["ok.example"]) == [".ok.example"]


def test_nrpt_set_без_доменов_правило_не_ставит(monkeypatch):
    wmi = FakeNrptWmi()
    monkeypatch.setattr(winnet, "_nrpt_call", wmi)

    assert winnet.nrpt_set(["x y"], paths.TUN_DNS) is False
    assert not any(m == "Add" for m, _a in wmi.calls)


def test_nrpt_set_не_принимает_не_адрес_сервера(monkeypatch):
    wmi = FakeNrptWmi()
    monkeypatch.setattr(winnet, "_nrpt_call", wmi)

    assert winnet.nrpt_set(["corp.example"], "1.1.1.1'; calc") is False
    assert not any(m == "Add" for m, _a in wmi.calls)


class FakeNrptWmi:
    """PS_DnsClientNrptRule: правила в памяти, вызовы методов — в журнал."""

    def __init__(self, rules=()):
        self.rules = list(rules)
        self.calls = []

    def __call__(self, method, **args):
        self.calls.append((method, args))
        if method == "Get":
            return list(self.rules)
        if method == "Remove":
            self.rules = [r for r in self.rules if r.Name != args["Name"]]
        if method == "Add":
            self.rules.append(Rule("{new}", args["Comment"]))
        return []


class Rule:
    def __init__(self, name, comment):
        self.Name, self.Comment = name, comment


def test_nrpt_set_меняет_своё_правило_на_dns_туннеля(monkeypatch):
    wmi = FakeNrptWmi([Rule("{old}", "TunnelVPN"), Rule("{чужое}", "Corp IT")])
    monkeypatch.setattr(winnet, "_nrpt_call", wmi)

    assert winnet.nrpt_set(["corp.example"], paths.TUN_DNS) is True

    assert ("Remove", {"Name": "{old}", "Force": True}) in wmi.calls
    assert ("Add", {"Namespace": [".corp.example"], "NameServers": [paths.TUN_DNS],
                    "Comment": "TunnelVPN"}) in wmi.calls
    assert [r.Name for r in wmi.rules] == ["{чужое}", "{new}"]


def test_nrpt_clear_через_wmi_снимает_только_свои(monkeypatch):
    wmi = FakeNrptWmi([Rule("{a}", "TunnelVPN"), Rule("{b}", "Corp IT")])
    monkeypatch.setattr(winnet, "_nrpt_call", wmi)

    assert winnet.nrpt_clear() is True

    assert [r.Name for r in wmi.rules] == ["{b}"]


def test_nrpt_clear_снимает_и_правило_старого_имени(monkeypatch):
    """Упавшая DualVPN оставила бы своё правило навсегда."""
    wmi = FakeNrptWmi([Rule("{old}", "DualVPN"), Rule("{b}", "Corp IT")])
    monkeypatch.setattr(winnet, "_nrpt_call", wmi)

    assert winnet.nrpt_clear() is True

    assert [r.Name for r in wmi.rules] == ["{b}"]


class FakeFirewall:
    """HNetCfg.FwPolicy2: имена правил в памяти, дубли допустимы."""

    def __init__(self, names):
        self.Rules = self
        self.names = list(names)

    def Item(self, name):
        if name not in self.names:
            raise KeyError(name)

    def Remove(self, name):
        self.names.remove(name)


def test_v6_unblock_снимает_новое_и_старое_правило(monkeypatch):
    fw = FakeFirewall(["TunnelVPN-block-IPv6", "TunnelVPN-block-IPv6",
                       "DualVPN-block-IPv6", "Чужое"])
    monkeypatch.setattr(winnet, "_firewall", lambda: fw)

    winnet.v6_unblock()

    assert fw.names == ["Чужое"]


def test_без_wmi_правило_не_ставится_и_это_видно(monkeypatch):
    """PowerShell больше не запасной путь: отказ WMI — честный False."""
    assert winnet.nrpt_clear() is False
    assert winnet.nrpt_set(["corp.example"], paths.TUN_DNS) is False


def test_домены_для_nrpt_берутся_из_правил_dns_туннелей(tmp_path, monkeypatch):
    sets = {"names-other": ["чужой.example"],
            "names-work": ["corp.example", "intra.example"],
            "names-lab": [".lab.example"]}
    for tag, domains in sets.items():
        (tmp_path / f"{tag}.json").write_text(json.dumps(
            {"version": 3, "rules": [{"domain_suffix": domains}]}), encoding="utf-8")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "route": {"rule_set": [
            {"type": "local", "tag": tag, "path": str(tmp_path / f"{tag}.json")}
            for tag in sets]},
        "dns": {"rules": [
            {"rule_set": ["names-other"], "server": "dns"},
            {"rule_set": ["names-work"], "server": "dns-work"},
            {"rule_set": ["names-lab"], "server": "dns-lab"},
        ]}}), encoding="utf-8")
    monkeypatch.setattr(paths, "CONFIG_JSON", str(cfg))

    assert Tunnel._corp_domains() == ["corp.example", "intra.example", ".lab.example"]


def test_нет_конфига_нет_доменов(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_JSON", str(tmp_path / "нет.json"))
    assert Tunnel._corp_domains() == []
