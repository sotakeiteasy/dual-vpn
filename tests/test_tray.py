"""Трей: одно окно панели и выход, не вешающий значок.

pystray и окно здесь не поднять — подменяем значок, процесс окна и ipc.call
и проверяем только решения трея: запускать ли окно и кто ждёт службу.
"""

import subprocess
import threading
import types

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
