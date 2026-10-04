"""Именованный канал: ответ доходит до трея целиком.

Сам канал здесь не поднять, поэтому pywin32 подменяем в sys.modules —
модуль импортирует его внутри функций, и подмена срабатывает при вызове.
Проверяем не WinAPI, а то, как мы им пользуемся: порядок вызовов и склейку.
"""

import json
import sys
import types

import pytest

from dualvpn import ipc


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
