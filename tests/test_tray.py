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


def _live(**kw):
    return types.SimpleNamespace(pid=42, poll=lambda: None, **kw)


def _launches(monkeypatch, code=0):
    """Подменённый Popen: команды запусков; процесс сразу выходит с code."""
    launched = []

    def popen(cmd, **_kw):
        launched.append(cmd)
        return types.SimpleNamespace(pid=7, poll=lambda: code, wait=lambda: code)
    monkeypatch.setattr(subprocess, "Popen", popen)
    return launched


def _signals(monkeypatch, listened=True, visible=True):
    sent = []
    monkeypatch.setattr(tray.instance, "signal",
                        lambda name, wait=0: sent.append(name) or listened)
    monkeypatch.setattr(tray.instance, "allow_foreground", lambda pid=0: None)
    monkeypatch.setattr(tray, "_wait_visible", lambda pid, timeout: visible)
    return sent


def test_живое_окно_показывается_сигналом_а_не_вторым_процессом(monkeypatch):
    sent = _signals(monkeypatch)
    monkeypatch.setattr(subprocess, "Popen", _no_popen)

    t = tray.Tray()
    t._window_proc = _live()
    t._open_window()
    assert sent == [tray.instance.WINDOW_SHOW]


def test_живой_процесс_без_окна_заменяется(monkeypatch):
    """Зависший WebView2 не должен навсегда запереть панель."""
    _signals(monkeypatch, visible=False)
    launched = _launches(monkeypatch)
    terminated = []

    t = tray.Tray()
    t._window_proc = _live(terminate=lambda: terminated.append(True))
    t._open_window()
    assert terminated and len(launched) == 1
    assert launched[0][-1] == "--resident"


def test_без_окна_запускается_показываемое_окно_трея(monkeypatch):
    launched = _launches(monkeypatch)

    tray.Tray()._open_window()
    assert launched[0][-2:] == ["window", "--resident"]


def test_прогрев_запускает_спрятанное_окно_один_раз(monkeypatch):
    launched = _launches(monkeypatch)

    t = tray.Tray()
    t._warm()
    assert launched[0][-3:] == ["window", "--resident", "--hidden"]
    t._window_proc = _live()
    t._warm()
    assert len(launched) == 1


def test_после_выхода_окно_не_запускается(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _no_popen)

    t = tray.Tray()
    t.stop_event.set()
    t._open_window()
    t._warm()


def _settle(launched, want):
    """Ждёт, пока сторожа окон перестанут запускать новые."""
    deadline = time.monotonic() + 5
    while len(launched) < want and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.2)                         # лишний запуск успел бы случиться
    return len(launched)


def test_окно_без_webview2_перезапускается_один_раз(monkeypatch):
    launched = _launches(monkeypatch, code=tray.window.READY_LOST)

    tray.Tray()._open_window()
    # Первый запуск и единственный повтор; повтор, вышедший так же, — всё.
    assert _settle(launched, 2) == 2


def test_прогретое_окно_без_webview2_не_перезапускается(monkeypatch):
    launched = _launches(monkeypatch, code=tray.window.READY_LOST)

    tray.Tray()._warm()
    assert _settle(launched, 1) == 1


def _admin(monkeypatch, admin=True):
    monkeypatch.setattr(tray.window, "_is_admin", lambda: admin)


def test_второй_запуск_ярлыка_открывает_окно_первого(monkeypatch):
    _admin(monkeypatch)
    monkeypatch.setattr(tray.instance, "claim", lambda: False)
    sent = _signals(monkeypatch)

    assert tray.already_running() is True
    assert sent == [tray.instance.TRAY_OPEN]


def test_второй_запуск_при_входе_окно_не_открывает(monkeypatch):
    _admin(monkeypatch)
    monkeypatch.setattr(tray.instance, "claim", lambda: False)
    sent = _signals(monkeypatch)

    assert tray.already_running(background=True) is True
    assert sent == []


@pytest.mark.skipif(sys.platform != "win32", reason="Toolhelp32 есть только в Windows")
def test_окно_ищется_и_у_дочернего_процесса():
    """onefile-exe портативной версии: окно у Python-ребёнка загрузчика."""
    import os
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        assert tray._child_pids(os.getpid()) >= {os.getpid(), child.pid}
    finally:
        child.kill()
        child.wait()


def _no_claim():
    raise AssertionError("процесс без прав занял мьютекс трея")


def _no_tray(*_a, **_kw):
    raise AssertionError("трей поднят без прав")


def test_ярлык_без_прав_при_живом_трее_открывает_окно_без_uac(monkeypatch):
    _admin(monkeypatch, admin=False)
    monkeypatch.setattr(tray.instance, "claim", _no_claim)
    monkeypatch.setattr(tray.instance, "exists", lambda: True)
    sent = _signals(monkeypatch)
    elevated = []
    monkeypatch.setattr(tray, "_relaunch_elevated", lambda: elevated.append(True))
    monkeypatch.setattr(tray, "Tray", _no_tray)

    tray.run()
    assert sent == [tray.instance.TRAY_OPEN]
    assert elevated == []


def test_ярлык_без_прав_без_трея_перезапускается_с_правами(monkeypatch):
    _admin(monkeypatch, admin=False)
    monkeypatch.setattr(tray.instance, "claim", _no_claim)
    monkeypatch.setattr(tray.instance, "exists", lambda: False)
    sent = _signals(monkeypatch)
    elevated = []
    monkeypatch.setattr(tray, "_relaunch_elevated", lambda: elevated.append(True))
    monkeypatch.setattr(tray, "Tray", _no_tray)

    tray.run()
    assert elevated == [True]
    assert sent == []


def test_первый_запуск_и_сбой_мьютекса_запускают_трей(monkeypatch):
    _admin(monkeypatch)
    monkeypatch.setattr(tray.instance, "claim", lambda: True)
    assert tray.already_running() is False

    def broken():
        raise OSError("сбой")
    monkeypatch.setattr(tray.instance, "claim", broken)
    assert tray.already_running() is False


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


def test_опрос_начинается_только_после_показа_значка(monkeypatch):
    """Цвет, сменённый до visible=True, pystray терял: значок серел при up."""
    seen = []
    t = tray.Tray()
    icon = _Icon()
    icon.visible = False
    t.icon = icon
    monkeypatch.setattr(t, "poll", lambda: seen.append(icon.visible))

    t._setup(icon)

    for _ in range(100):
        if seen:
            break
        time.sleep(0.01)
    assert seen == [True]


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

    assert tray._conf_colors(st, True, frozenset()) == ("error", "up")


def test_кружки_без_vpn_и_без_итога_серые():
    assert tray._conf_colors({"up": False}, True, frozenset()) == ("off", "off")
    st = {"up": False, "last": {"corp": "", "personal": ""}}
    assert tray._conf_colors(st, True, frozenset()) == ("off", "off")
