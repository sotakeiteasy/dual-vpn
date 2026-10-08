"""Окно: заголовок тёмный независимо от темы Windows, анимаций DWM нет.

dwmapi здесь не настоящий: ctypes.windll подменяем, чтобы тест шёл и на
Linux в CI, где windll нет вовсе.
"""

import ctypes
import types

from dualvpn import window


def _fake_dwm(monkeypatch):
    calls = []

    def set_attr(hwnd, attr, value, size):
        calls.append((hwnd, attr, value._obj.value, size))
        return 0

    dwmapi = types.SimpleNamespace(DwmSetWindowAttribute=set_attr)
    monkeypatch.setattr(ctypes, "windll",
                        types.SimpleNamespace(dwmapi=dwmapi), raising=False)
    return calls


def _form(hwnd):
    handle = types.SimpleNamespace(ToInt32=lambda: hwnd)
    return types.SimpleNamespace(native=types.SimpleNamespace(Handle=handle))


def test_включает_тёмный_заголовок_у_окна(monkeypatch):
    calls = _fake_dwm(monkeypatch)

    window._dark_title(_form(0x1234))

    assert calls == [(0x1234, 20, 1, ctypes.sizeof(ctypes.c_int))]


def test_выключает_анимации_окна(monkeypatch):
    """Иначе спрятанное окно мелькает белым при создании (Opacity=0, Show, Hide)."""
    calls = _fake_dwm(monkeypatch)

    window._no_transitions(_form(0x1234))

    assert calls == [(0x1234, 3, 1, ctypes.sizeof(ctypes.c_int))]


def test_окно_без_формы_не_роняет_вызов(monkeypatch):
    calls = _fake_dwm(monkeypatch)

    window._dark_title(types.SimpleNamespace(native=None))
    window._dark_title(None)

    assert calls == []
