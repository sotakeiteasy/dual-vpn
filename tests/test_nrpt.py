"""Правило NRPT для корп-доменов: домены из конфига превращаются в суффиксы,
а всё, что не похоже на домен, не доходит до командной строки PowerShell."""

import json

import pytest

from dualvpn import paths, winnet
from dualvpn.tunnel import Tunnel


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
    """site.env правит пользователь: кавычка не должна попасть в PowerShell."""
    bad = ["a'; Remove-Item C:\\ #", "x y", "", "-corp.example", "a$(b).example"]
    assert winnet.nrpt_namespaces(bad + ["ok.example"]) == [".ok.example"]


def test_nrpt_set_без_доменов_ничего_не_запускает(monkeypatch):
    calls = []
    monkeypatch.setattr(winnet.PS, "run", lambda script, timeout=30: calls.append(script) or "")

    assert winnet.nrpt_set(["x y"], paths.TUN_DNS) is False
    assert not any("Add-DnsClientNrptRule" in c for c in calls)


def test_nrpt_set_не_принимает_не_адрес_сервера(monkeypatch):
    calls = []
    monkeypatch.setattr(winnet.PS, "run", lambda script, timeout=30: calls.append(script) or "")

    assert winnet.nrpt_set(["corp.example"], "1.1.1.1'; calc") is False
    assert not any("Add-DnsClientNrptRule" in c for c in calls)


def test_nrpt_set_ставит_правило_на_dns_туннеля(monkeypatch):
    calls = []

    def run(script, timeout=30):
        calls.append(script)
        return "ok" if "Add-DnsClientNrptRule" in script else ""

    monkeypatch.setattr(winnet.PS, "run", run)

    assert winnet.nrpt_set(["corp.example"], paths.TUN_DNS) is True
    add = next(c for c in calls if "Add-DnsClientNrptRule" in c)
    assert "'.corp.example'" in add and f"'{paths.TUN_DNS}'" in add
    assert "-Comment 'DualVPN'" in add


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


def test_nrpt_set_через_wmi_без_powershell(monkeypatch):
    """PowerShell с модулем DnsClient стоил ~1.7 с на вызов, включение ждало два."""
    wmi = FakeNrptWmi([Rule("{old}", "DualVPN"), Rule("{чужое}", "Corp IT")])
    monkeypatch.setattr(winnet, "_nrpt_call", wmi)
    ps = []
    monkeypatch.setattr(winnet.PS, "run", lambda script, timeout=30: ps.append(script) or "")

    assert winnet.nrpt_set(["corp.example"], paths.TUN_DNS) is True

    assert ps == []
    assert ("Remove", {"Name": "{old}", "Force": True}) in wmi.calls
    assert ("Add", {"Namespace": [".corp.example"], "NameServers": [paths.TUN_DNS],
                    "Comment": "DualVPN"}) in wmi.calls
    assert [r.Name for r in wmi.rules] == ["{чужое}", "{new}"]


def test_nrpt_clear_через_wmi_снимает_только_свои(monkeypatch):
    wmi = FakeNrptWmi([Rule("{a}", "DualVPN"), Rule("{b}", "Corp IT")])
    monkeypatch.setattr(winnet, "_nrpt_call", wmi)
    ps = []
    monkeypatch.setattr(winnet.PS, "run", lambda script, timeout=30: ps.append(script) or "")

    winnet.nrpt_clear()

    assert ps == []
    assert [r.Name for r in wmi.rules] == ["{b}"]


def test_nrpt_set_без_wmi_снимает_и_ставит_одним_powershell(monkeypatch):
    calls = []
    monkeypatch.setattr(winnet.PS, "run",
                        lambda script, timeout=30: calls.append(script) or "ok")

    assert winnet.nrpt_set(["corp.example"], paths.TUN_DNS) is True

    assert len(calls) == 1
    clear, add = (calls[0].index("Remove-DnsClientNrptRule"),
                  calls[0].index("Add-DnsClientNrptRule"))
    assert clear < add
    assert "$_.Comment -eq 'DualVPN'" in calls[0]


def test_nrpt_clear_снимает_только_свои_по_комментарию(monkeypatch):
    calls = []
    monkeypatch.setattr(winnet.PS, "run", lambda script, timeout=30: calls.append(script) or "")

    winnet.nrpt_clear()

    assert "$_.Comment -eq 'DualVPN'" in calls[0]
    assert "Remove-DnsClientNrptRule" in calls[0]


def test_домены_для_nrpt_берутся_из_правила_корп_dns(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"dns": {"rules": [
        {"domain_suffix": ["чужой.example"], "server": "dns-personal"},
        {"domain_suffix": ["corp.example", "intra.example"], "server": "dns-corp"},
    ]}}), encoding="utf-8")
    monkeypatch.setattr(paths, "CONFIG_JSON", str(cfg))

    assert Tunnel._corp_domains() == ["corp.example", "intra.example"]


def test_нет_конфига_нет_доменов(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_JSON", str(tmp_path / "нет.json"))
    assert Tunnel._corp_domains() == []
