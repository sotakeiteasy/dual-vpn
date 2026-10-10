"""Именованный канал: ответ доходит до трея целиком.

Сам канал здесь не поднять, поэтому pywin32 подменяем в sys.modules —
модуль импортирует его внутри функций, и подмена срабатывает при вызове.
Проверяем не WinAPI, а то, как мы им пользуемся: порядок вызовов и склейку.
"""

import json
import sys
import threading
import types

import pytest

from tunnelvpn import ipc


class _WinError(Exception):
    def __init__(self, winerror, strerror=""):
        super().__init__(winerror, strerror)
        self.winerror = winerror
        self.strerror = strerror


@pytest.fixture
def win(monkeypatch):
    """Поддельные pywintypes/win32file/win32pipe; calls — журнал вызовов."""
    calls = []
    reads = []

    win32file = types.SimpleNamespace(
        GENERIC_READ=1, GENERIC_WRITE=2, OPEN_EXISTING=3,
        CreateFile=lambda *a: calls.append("CreateFile") or "h",
        WriteFile=lambda h, data: calls.append("WriteFile"),
        ReadFile=lambda h, n: _next_read(reads, n),
        CloseHandle=lambda h: calls.append("CloseHandle"),
        FlushFileBuffers=lambda h: calls.append("FlushFileBuffers"),
    )
    win32pipe = types.SimpleNamespace(
        WaitNamedPipe=lambda *a: None,
        DisconnectNamedPipe=lambda h: calls.append("DisconnectNamedPipe"),
    )
    pywintypes = types.SimpleNamespace(error=_WinError)
    for name, mod in (("win32file", win32file), ("win32pipe", win32pipe),
                      ("pywintypes", pywintypes)):
        monkeypatch.setitem(sys.modules, name, mod)
    return types.SimpleNamespace(calls=calls, reads=reads)


def _next_read(reads, n):
    item = reads.pop(0)
    if isinstance(item, Exception):
        raise item
    assert len(item) <= n
    return 0, item


def test_ответ_склеивается_из_двух_чтений(win):
    raw = json.dumps({"ok": True, "status": {"up": True}}).encode() + b"\n"
    win.reads.extend([raw[:7], raw[7:]])
    assert ipc.call("status") == {"ok": True, "status": {"up": True}}


def test_ответ_больше_буфера_читается_целиком(win):
    """Лог на 400 строк легко больше 64 КБ — раньше он обрезался."""
    lines = ["x" * 300] * 400
    raw = json.dumps({"ok": True, "lines": lines}).encode() + b"\n"
    assert len(raw) > ipc._BUF
    win.reads.extend(raw[i:i + ipc._BUF] for i in range(0, len(raw), ipc._BUF))
    assert ipc.call("log", lines=400)["lines"] == lines


def test_закрытый_канал_после_ответа_не_ошибка(win):
    win.reads.extend([b'{"ok": true}', _WinError(109)])
    assert ipc.call("status") == {"ok": True}


def test_закрытый_канал_без_ответа_значит_служба_не_отвечает(win):
    win.reads.append(_WinError(109, "broken pipe"))
    with pytest.raises(ipc.NotRunning):
        ipc.call("status")


def test_сервер_сбрасывает_буфер_до_отключения(win, monkeypatch):
    """Иначе DisconnectNamedPipe выбросил бы ещё не прочитанный ответ."""
    server = ipc.Server(handler=None, log=lambda _m: None)
    monkeypatch.setattr(server, "_exchange", lambda pipe: None)
    server._serve_one("pipe")
    assert win.calls == ["FlushFileBuffers", "DisconnectNamedPipe",
                         "CloseHandle"]


def _status(check_seq, checking, home, work):
    return {"check_seq": check_seq, "checking": checking,
            "tunnels": [{"id": "work", "seq": work}, {"id": "home", "seq": home}]}


def _seq(st, tid):
    return next(t["seq"] for t in st["tunnels"] if t["id"] == tid)


def _fake_service(monkeypatch, st, drop_work=False):
    """Служба без канала: check ставит основной готовым и ждёт release,
    а рабочий отмечает только после него (drop_work — рабочий удалили)."""
    release = threading.Event()

    def call(op, **_payload):
        if op == "check":
            seq = st["check_seq"] if st["checking"] else st["check_seq"] + 1
            st.update(_status(seq, True, home=seq, work=_seq(st, "work")))
            if drop_work:
                st["tunnels"] = st["tunnels"][1:]
            release.wait(2)
            st.update(checking=False)
            for t in st["tunnels"]:
                t["seq"] = seq
        return {"ok": True, "status": {**st, "tunnels": [dict(t) for t in st["tunnels"]]}}

    monkeypatch.setattr(ipc, "call", call)
    return release


@pytest.mark.parametrize("st", [
    _status(3, False, home=3, work=3),
    # Проверка уже шла — check её дождётся, её ответ тоже свежий.
    _status(3, True, home=2, work=2),
])
def test_check_by_side_отдаёт_основной_не_дожидаясь_рабочего(monkeypatch, st):
    need = st["check_seq"] + (0 if st["checking"] else 1)
    release = _fake_service(monkeypatch, st)
    seen = []

    def on_side(got, pending):
        seen.append((_seq(got, "home"), pending))
        release.set()

    reply = ipc.check_by_side(on_side, poll=0.01)

    assert seen[0] == (need, frozenset({"work"}))
    assert _seq(reply["status"], "work") == need


def test_check_by_side_прошлый_итог_не_считает_свежим(monkeypatch):
    st = _status(3, False, home=3, work=3)
    release = _fake_service(monkeypatch, st)
    seen = []
    threading.Timer(0.2, release.set).start()

    ipc.check_by_side(lambda got, pending: seen.append(_seq(got, "home")),
                      poll=0.01)

    assert all(seq == 4 for seq in seen)


def test_check_by_side_удалённый_туннель_не_ждёт(monkeypatch):
    st = _status(3, False, home=3, work=3)
    release = _fake_service(monkeypatch, st, drop_work=True)
    seen = []

    def on_side(got, pending):
        seen.append(pending)
        release.set()

    ipc.check_by_side(on_side, poll=0.01)

    assert seen[0] == frozenset()
