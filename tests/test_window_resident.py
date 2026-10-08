"""Окно трея: спрятанное не проверяет туннели, холодное показывается на ready,
флажок автозапуска доходит до службы и всегда отпускается на странице, разбор
аргументов CLI.
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


class _Window:
    def __init__(self, shown):
        self.shown = shown

    def show(self):
        self.shown.append("show")


def test_холодное_окно_показывается_на_ready_уже_отрисованным(monkeypatch):
    api, calls, shown = _api(monkeypatch)
    api.holder["window"] = _Window(shown)
    api.cold = True

    api.send("ready")
    assert shown.index("render") < shown.index("show")
    assert "check" in [op for op, _ in calls]
    api.reveal()                    # запасной таймер после ready — уже ничего
    assert shown.count("show") == 1


def test_прогретое_окно_на_ready_остаётся_спрятанным(monkeypatch):
    api, _, shown = _api(monkeypatch)
    api.holder["window"] = _Window(shown)
    api.hidden = True

    api.send("ready")
    assert "show" not in shown


def test_включение_сразу_перерисовывает_статус(monkeypatch):
    """Не ждёт следующего опроса: иначе «работает» запаздывает на POLL_EVERY."""
    api, calls, shown = _api(monkeypatch)

    api.send("start")
    ops = [op for op, _ in calls]
    assert ops == ["start", "status"] and "render" in shown


def test_отказ_включения_тоже_перерисовывает_статус(monkeypatch):
    api, calls, shown = _api(monkeypatch)
    monkeypatch.setattr(ipc, "call", lambda op, **kw: calls.append((op, kw)) or
                        ({"ok": False, "error": "нет"} if op == "start" else {"status": {}}))

    api.send("restart")
    assert [op for op, _ in calls] == ["stop", "start", "status"]
    assert "failed" in shown and "render" in shown


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
