"""Командная строка: что уходит в канал и что видит человек.

Служба здесь — подменённый ipc.call: CLI сам систему не трогает, его дело —
собрать команду канала и показать ответ.
"""

import pytest

from dualvpn import cli

STATUS = {"tunnels": [
    {"id": "work", "name": "Работа", "mode": "list", "active": "corp",
     "confs": ["corp"]},
    {"id": "home", "name": "Личный", "mode": "all", "active": "nl-2",
     "confs": ["nl-1", "nl-2"]},
    {"id": "t3", "name": "Пустой", "mode": "list", "active": "", "confs": []},
]}


@pytest.fixture
def sent(monkeypatch):
    """Команды, ушедшие в канал; ответ — из replies по имени команды."""
    class Calls(list):
        pass

    calls = Calls()
    calls.replies = {"status": {"ok": True, "status": STATUS}}

    def call(op, **payload):
        calls.append((op, payload))
        return calls.replies.get(op, {"ok": True})

    monkeypatch.setattr(cli.ipc, "call", call)
    return calls


def test_use_выбирает_конфиг_туннеля(sent, capsys):
    sent.replies["set-active"] = {"ok": True, "tunnel": "home", "active": "nl-1"}

    assert cli.main(["use", "Личный", "nl-1"]) == 0

    assert sent[0] == ("set-active", {"tunnel": "Личный", "name": "nl-1"})
    assert "home: nl-1" in capsys.readouterr().out


def test_use_отказ_службы_код_ошибки_и_не_применяет(sent, capsys):
    sent.replies["set-active"] = {"ok": False, "error": "нет туннеля 'x'"}

    assert cli.main(["use", "x", "nl-1"]) == 1

    assert "нет туннеля 'x'" in capsys.readouterr().out
    assert [op for op, _ in sent] == ["set-active"]


def test_use_без_конфига_не_зовёт_службу(sent):
    assert cli.main(["use", "home"]) == 1
    assert sent == []


def test_profile_остаётся_алиасом(sent):
    assert cli.main(["profile", "nl-1"]) == 0
    assert sent[0] == ("set-profile", {"profile": "nl-1"})


@pytest.mark.parametrize("argv, first", [
    (["use", "home", "nl-1"], "set-active"),
    (["profile", "nl-1"], "set-profile"),
])
def test_выбор_конфига_сразу_применяется(sent, argv, first):
    assert cli.main(argv) == 0
    assert [op for op, _ in sent] == [first, "apply"]


@pytest.mark.parametrize("reply, shown", [
    ({"ok": True, "applied": "off"}, "применится при включении"),
    ({"ok": True, "applied": "sides", "restarted": ["home"]}, "перезапущен процесс: home"),
    ({"ok": True, "applied": "sides", "restarted": []}, "перезапускать нечего"),
    ({"ok": True, "applied": "full"}, "VPN перезапущен"),
])
def test_use_показывает_как_применилось(sent, capsys, reply, shown):
    sent.replies["apply"] = reply

    assert cli.main(["use", "home", "nl-1"]) == 0

    assert shown in capsys.readouterr().out


def test_ошибка_применения_код_ошибки(sent, capsys):
    sent.replies["apply"] = {"ok": False, "applied": "sides", "restarted": ["home"],
                             "error": "процесс «Личный» не поднялся"}

    assert cli.main(["profile", "nl-1"]) == 1
    assert "не вышло: процесс «Личный» не поднялся" in capsys.readouterr().out


def test_list_по_туннелям_с_активным(sent, capsys):
    assert cli.main(["list"]) == 0

    out = capsys.readouterr().out.splitlines()
    assert out[out.index("Личный [home], весь остальной трафик:") + 1:][:2] == [
        "    nl-1", "  * nl-2"]
    assert "Пустой [t3], по списку:" in out
    assert "    (нет конфигов)" in out


def test_статус_показывает_туннели(sent, capsys):
    assert cli.main(["status"]) == 0
    assert "Работа [work], по списку — corp" in capsys.readouterr().out
