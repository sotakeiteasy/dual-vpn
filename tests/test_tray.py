"""Трей: одно окно панели и выход, не вешающий значок.

pystray и окно здесь не поднять — подменяем значок, процесс окна и ipc.call
и проверяем только решения трея: запускать ли окно и кто ждёт службу.
"""

import ctypes
import subprocess
import sys
import threading
import time
import types

import pytest

from dualvpn import ipc, tray


class _Icon:
    def __init__(self):
        self.visible = True
        self.stopped = threading.Event()

    def stop(self):
        self.stopped.set()


def _no_popen(*_a, **_kw):
    raise AssertionError("второй Popen при живом окне")


def test_повторное_открытие_поднимает_окно_а_не_запускает_второе(monkeypatch):
    raised = []
    monkeypatch.setattr(tray, "_raise_window",
                        lambda title: raised.append(title) or True)
    monkeypatch.setattr(subprocess, "Popen", _no_popen)

    t = tray.Tray()
    t._window_proc = types.SimpleNamespace(poll=lambda: None)
    t.on_window()
    assert raised and raised[0].startswith("DualVPN ")


def test_окно_которое_ещё_стартует_не_дублируется(monkeypatch):
    monkeypatch.setattr(tray, "_raise_window", lambda _t: False)
    monkeypatch.setattr(subprocess, "Popen", _no_popen)

    t = tray.Tray()
    t._window_proc = types.SimpleNamespace(poll=lambda: None)
    t._window_started = tray.time.monotonic()
    t.on_window()


def test_процесс_без_окна_слишком_долго_заменяется(monkeypatch):
    """Зависший WebView2 не должен навсегда запереть панель."""
    monkeypatch.setattr(tray, "_raise_window", lambda _t: False)
    launched = []
    monkeypatch.setattr(subprocess, "Popen",
                        lambda cmd, **_kw: launched.append(cmd) or "new")

    terminated = []
    t = tray.Tray()
    t._window_proc = types.SimpleNamespace(
        poll=lambda: None, terminate=lambda: terminated.append(True))
    t._window_started = tray.time.monotonic() - tray.WINDOW_START_WAIT - 1
    t.on_window()
    assert terminated and launched and t._window_proc == "new"


def test_выход_не_ждёт_службу_в_потоке_значка(monkeypatch):
    """stop идёт до сорока секунд — поток значка должен освободиться сразу."""
    release = threading.Event()
    calls = []

    def call(op, **_kw):
        calls.append(op)
        release.wait(5)
        return {"ok": True}
    monkeypatch.setattr(ipc, "call", call)

    t = tray.Tray()
    t.icon = _Icon()
    t.on_quit()

    assert not t.icon.visible
    assert not t.icon.stopped.is_set()
    release.set()
    assert t.icon.stopped.wait(5)
    assert calls == ["stop"]


def test_выход_закрывает_значок_и_окно_даже_при_сбое_вызова(monkeypatch):
    def broken(*_a, **_kw):
        raise RuntimeError("сбой")
    monkeypatch.setattr(ipc, "call", broken)
    # Сбой уходит из рабочего потока уже после finally. Ловим его здесь, иначе
    # pytest припишет его тому тесту, который будет идти в этот момент.
    escaped = []
    thread_done = threading.Event()

    def excepthook(args):
        escaped.append(args.exc_type)
        thread_done.set()
    monkeypatch.setattr(threading, "excepthook", excepthook)

    terminated = threading.Event()
    t = tray.Tray()
    t.icon = _Icon()
    t._window_proc = types.SimpleNamespace(poll=lambda: None,
                                           terminate=terminated.set)
    t.on_quit()
    assert t.icon.stopped.wait(5)
    assert terminated.is_set()
    assert thread_done.wait(5)
    assert escaped == [RuntimeError]


def _wait_state(t, state):
    deadline = time.monotonic() + 5
    while t.state != state and time.monotonic() < deadline:
        time.sleep(0.01)
    return t.state


def test_пока_идёт_включение_значок_жёлтый_а_после_ошибки_красный(monkeypatch):
    release = threading.Event()

    def call(op, **_kw):
        if op == "start":
            release.wait(5)
            return {"ok": False, "error": "нет конфига"}
        return {"ok": True, "status": {"last_error": "нет конфига"}}
    monkeypatch.setattr(ipc, "call", call)
    monkeypatch.setattr(tray.Tray, "_notify", lambda _self, _text: None)
    t = tray.Tray()

    t.on_toggle()
    assert t.state == "busy"
    # Опрос посреди команды не сбрасывает жёлтый, хотя служба ещё не занята.
    t._poll_once()
    assert t.state == "busy"

    release.set()
    assert _wait_state(t, "error") == "error"


def test_после_включения_значок_зелёный_без_ожидания_опроса(monkeypatch):
    started = threading.Event()

    def call(op, **_kw):
        if op == "start":
            started.set()
            return {"ok": True}
        return {"ok": True, "status": {"up": started.is_set()}}
    monkeypatch.setattr(ipc, "call", call)
    t = tray.Tray()

    t.on_toggle()

    assert _wait_state(t, "up") == "up"


def test_левый_клик_по_значку_не_включает_vpn():
    pytest.importorskip("pystray")

    menu = tray.Tray()._menu()

    assert not any(item.default for item in menu.items)


class _Uxtheme:
    """uxtheme по ordinal: записывает, что и с чем позвали."""

    def __init__(self):
        self.calls = []

    def __getitem__(self, ordinal):
        return lambda *args: self.calls.append((ordinal, args))


def _fake_windows(monkeypatch, build):
    uxtheme = _Uxtheme()
    monkeypatch.setattr(ctypes, "windll",
                        types.SimpleNamespace(uxtheme=uxtheme), raising=False)
    monkeypatch.setattr(sys, "getwindowsversion",
                        lambda: types.SimpleNamespace(build=build), raising=False)
    return uxtheme.calls


def test_тёмное_меню_включается_с_windows_1903(monkeypatch):
    calls = _fake_windows(monkeypatch, 18362)

    tray._dark_menus()

    assert calls == [(135, (2,)), (136, ())]


def test_на_сборке_до_1903_ordinal_135_не_зовётся(monkeypatch):
    calls = _fake_windows(monkeypatch, 17763)

    tray._dark_menus()

    assert calls == []


def test_без_windll_тёмное_меню_ничего_не_делает(monkeypatch):
    monkeypatch.delattr(ctypes, "windll", raising=False)
    monkeypatch.setattr(sys, "getwindowsversion",
                        lambda: types.SimpleNamespace(build=26300), raising=False)

    tray._dark_menus()


def test_кружки_без_vpn_берут_итог_прошлой_проверки():
    st = {"up": False, "last": {"corp": "error", "personal": "up"}}

    assert tray._conf_colors(st, True, False) == ("error", "up")


def test_кружки_без_vpn_и_без_итога_серые():
    assert tray._conf_colors({"up": False}, True, False) == ("off", "off")
    st = {"up": False, "last": {"corp": "", "personal": ""}}
    assert tray._conf_colors(st, True, False) == ("off", "off")
