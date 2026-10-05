"""Окно: «Редактировать» открывает конфиг в Блокноте с правами.

Имя приходит со страницы, поэтому путь собирается только из имён, которые
служба сама отдала в статусе.
"""

import os

from dualvpn import ipc, paths, window


class _SyncThread:
    """Поток, который выполняет цель сразу: тесту нечего ждать."""

    def __init__(self, target, args=(), daemon=None):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)


def _setup(monkeypatch, status):
    runs, shown = [], []
    monkeypatch.setattr(window.threading, "Thread", _SyncThread)
    monkeypatch.setattr(ipc, "call", lambda op, **_kw: {"ok": True, "status": status})
    monkeypatch.setattr(window, "_run_elevated",
                        lambda exe, args, show=False: runs.append((exe, args, show)))
    api = window.Api({})
    monkeypatch.setattr(api, "js", lambda fn, arg=None: shown.append((fn, arg)))
    return api, runs, shown


def test_личный_конфиг_открывается_в_блокноте_с_правами(monkeypatch):
    api, runs, _ = _setup(monkeypatch, {"profiles": ["nl-1"], "corp": ["corp"]})

    api.send("edit_config", {"name": "nl-1", "kind": "personal"})

    exe, args, show = runs[0]
    assert os.path.isabs(exe) and exe.lower().endswith("system32\\notepad.exe")
    assert args == [os.path.join(paths.CONF_PERSONAL, "nl-1.conf")] and show


def test_рабочий_конфиг_берётся_из_своей_папки(monkeypatch):
    api, runs, _ = _setup(monkeypatch, {"profiles": [], "corp": ["corp"]})

    api.send("edit_config", {"name": "corp", "kind": "corp"})

    assert runs[0][1] == [os.path.join(paths.CONF_CORP, "corp.conf")]


def test_имя_не_из_статуса_не_открывается(monkeypatch):
    api, runs, shown = _setup(monkeypatch, {"profiles": ["nl-1"], "corp": []})

    api.send("edit_config", {"name": "..\\..\\Windows\\win", "kind": "personal"})

    assert runs == []
    assert shown[0][0] == "failed"


def _no_pipe(op, **_kw):
    raise ipc.NotRunning("служба не отвечает")


def test_без_канала_окно_сообщает_стоит_ли_служба(monkeypatch):
    monkeypatch.setattr(ipc, "call", _no_pipe)
    monkeypatch.setattr(window, "_service_installed", lambda: False)
    api, shown = window.Api({}), []
    monkeypatch.setattr(api, "js", lambda fn, arg=None: shown.append((fn, arg)))

    api.refresh()

    assert shown == [("render", {"up": False, "no_service": True, "daemon": False})]
