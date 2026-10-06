"""Правило NRPT для корп-доменов: домены из конфига превращаются в суффиксы,
а всё, что не похоже на домен, не доходит до командной строки PowerShell."""

import json

from dualvpn import paths, winnet
from dualvpn.tunnel import Tunnel


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
