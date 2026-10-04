"""Окно: команда в conf\\ идёт через UAC без промежуточного PowerShell.

UAC здесь не поднять, поэтому pywin32 подменяем в sys.modules: ShellExecuteEx
либо «отрабатывает» как процесс admin-op (пишет файл ответа), либо падает,
как при отказе в UAC.
"""

import json
import re
import subprocess
import sys
import types

from dualvpn import window


class _WinError(Exception):
    pass


def _fake_win32(monkeypatch, execute):
    calls = []

    def shell_execute(**kw):
        calls.append(("execute", kw))
        return execute(kw)

    shell = types.SimpleNamespace(ShellExecuteEx=shell_execute)
    shellcon = types.SimpleNamespace(SEE_MASK_NOCLOSEPROCESS=0x40)
    win32com_shell = types.ModuleType("win32com.shell")
    win32com_shell.shell, win32com_shell.shellcon = shell, shellcon
    modules = {
        "win32com.shell": win32com_shell,
        "win32con": types.SimpleNamespace(SW_HIDE=0),
        "win32event": types.SimpleNamespace(
            INFINITE=-1,
            WaitForSingleObject=lambda h, t: calls.append(("wait", h, t))),
        "win32api": types.SimpleNamespace(
            CloseHandle=lambda h: calls.append(("close", h))),
        "pywintypes": types.SimpleNamespace(error=_WinError),
    }
    for name, mod in modules.items():
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.setattr(window, "_is_admin", lambda: False)
    monkeypatch.setattr(subprocess, "run", _no_powershell)
    return calls


def _no_powershell(*_a, **_kw):
    raise AssertionError("права просятся через PowerShell")


def _args(params):
    """Разбор строки list2cmdline: в путях бывают пробелы, но не кавычки."""
    return [a or b for a, b in re.findall(r'"([^"]*)"|(\S+)', params)]


def test_команда_с_правами_идёт_через_shellexecute_и_ждёт_процесс(monkeypatch):
    def admin_op(kw):
        args = _args(kw["lpParameters"])
        with open(args[-2], encoding="utf-8") as fh:
            payload = json.load(fh)
        with open(args[-1], "w", encoding="utf-8") as fh:
            json.dump({"ok": True, "text": payload["name"]}, fh)
        return {"hProcess": 77}
    calls = _fake_win32(monkeypatch, admin_op)

    reply = window.Api({})._admin_call("read-config", name="corp")

    assert reply == {"ok": True, "text": "corp"}
    kw = calls[0][1]
    assert kw["lpVerb"] == "runas" and kw["lpFile"] == sys.executable
    assert _args(kw["lpParameters"])[:4] == ["-m", "dualvpn.cli", "admin-op", "read-config"]
    assert calls[1:] == [("wait", 77, -1), ("close", 77)]


def test_отказ_в_uac_даёт_ошибку_а_не_исключение(monkeypatch):
    def cancelled(_kw):
        raise _WinError(1223, "ShellExecuteEx", "Операция отменена пользователем")
    calls = _fake_win32(monkeypatch, cancelled)

    reply = window.Api({})._admin_call("set-site", text="")

    assert reply["ok"] is False and "отменён" in reply["error"]
    assert [c[0] for c in calls] == ["execute"]
