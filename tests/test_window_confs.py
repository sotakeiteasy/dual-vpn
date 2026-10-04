"""Раскладка конфигов для окна: что подсвечено и когда просим выбрать один."""

from dualvpn.window import Api


def test_единственный_личный_подсвечен_без_профиля():
    r = Api._confs({"profiles": ["nl-1"], "corp": ["office"]})
    assert r["personal"] == [{"name": "nl-1", "active": True}]
    assert r["corp"] == [{"name": "office", "active": False}]
    assert not r["personal_ambiguous"] and not r["corp_ambiguous"]


def test_несколько_личных_без_выбора_просят_выбрать():
    r = Api._confs({"profiles": ["nl-1", "nl-2"]})
    assert [c["active"] for c in r["personal"]] == [False, False]
    assert r["personal_ambiguous"]


def test_выбранный_личный_подсвечен():
    r = Api._confs({"profiles": ["nl-1", "nl-2"], "profile": "nl-2"})
    assert [c["active"] for c in r["personal"]] == [False, True]
    assert not r["personal_ambiguous"]


def test_два_рабочих_после_переезда_просят_оставить_один():
    assert Api._confs({"corp": ["a", "b"]})["corp_ambiguous"]


def test_пустой_статус():
    r = Api._confs({})
    assert r["corp"] == [] and r["personal"] == []
    assert not r["personal_ambiguous"] and not r["corp_ambiguous"]
