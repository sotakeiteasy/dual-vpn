"""Окно трея: спрятанное не проверяет туннели, флажок автозапуска доходит
до службы и всегда отпускается на странице, разбор аргументов CLI.
"""

from dualvpn import cli, ipc, window


class _SyncThread:
    """Поток, который выполняет цель сразу: тесту нечего ждать."""

    def __init__(self, target, args=(), daemon=None):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)


def _api(monkeypatch, reply=None):
    calls, shown = [], []
    monkeypatch.setattr(window.threading, "Thread", _SyncThread)

    def call(op, **kw):
        calls.append((op, kw))
        if op == "set-autostart":
            return reply if reply is not None else {"ok": True}
        return {"ok": True, "status": {}}
    monkeypatch.setattr(ipc, "call", call)
    monkeypatch.setattr(ipc, "check_by_side",
                        lambda _cb: calls.append(("check", {})) or {})
    api = window.Api({})
    monkeypatch.setattr(api, "js", lambda fn, arg=None: shown.append(fn))
    monkeypatch.setattr(api, "jsn", lambda fn, args: shown.append(fn))
    return api, calls, shown


def test_спрятанное_окно_на_ready_не_проверяет_туннели(monkeypatch):
    api, calls, _ = _api(monkeypatch)
    api.hidden = True

    api.send("ready")
    assert api.ready.is_set()
    assert "check" not in [op for op, _ in calls]


def test_показанное_окно_на_ready_проверяет_туннели(monkeypatch):
    api, calls, _ = _api(monkeypatch)

    api.send("ready")
    assert "check" in [op for op, _ in calls]


def test_флажок_автозапуска_уходит_в_службу(monkeypatch):
    monkeypatch.setattr(window, "_is_admin", lambda: True)
    api, calls, shown = _api(monkeypatch)

    api.send("set_autostart", True)
    assert ("set-autostart", {"on": True}) in calls
    assert "autostartDone" in shown


def test_отказ_службы_тоже_отпускает_флажок(monkeypatch):
    monkeypatch.setattr(window, "_is_admin", lambda: True)
    api, _, shown = _api(monkeypatch, reply={"ok": False, "error": "нет"})

    api.send("set_autostart", False)
    assert "autostartDone" in shown and "failed" in shown


def test_cli_передаёт_режимы_окна_и_трея(monkeypatch):
    seen = {}
    monkeypatch.setattr(window, "open_window",
                        lambda **kw: seen.setdefault("window", kw))
    from dualvpn import tray
    monkeypatch.setattr(tray, "run", lambda **kw: seen.setdefault("tray", kw))

    cli.main(["window", "--resident", "--hidden"])
    cli.main(["tray", "--background"])
    assert seen == {"window": {"resident": True, "hidden": True},
                    "tray": {"background": True}}
