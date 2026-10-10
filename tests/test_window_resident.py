"""Окно трея: спрятанное не проверяет туннели, холодное показывается на ready,
флажок автозапуска доходит до службы и всегда отпускается на странице, разбор
аргументов CLI.
"""

import sys
import types

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


def test_проверка_окна_отдаёт_странице_ждущие_id_туннелей(monkeypatch):
    """Плитки — по id туннеля: каждый перекрашивается, как только проверен он сам."""
    api, _, _ = _api(monkeypatch)
    sent = []
    monkeypatch.setattr(api, "jsn", lambda fn, args: sent.append((fn, args[1])))
    st = {"tunnels": [{"id": "work", "mode": "list"}, {"id": "lab", "mode": "list"},
                      {"id": "home", "mode": "all"}]}

    def check_by_side(on_side):
        for pending in ({"lab", "home"}, {"work"}, set()):
            on_side(st, frozenset(pending))
        return {}
    monkeypatch.setattr(ipc, "check_by_side", check_by_side)

    api._check()

    assert sent == [("checkSides", ["home", "lab"]), ("checkSides", ["work"]),
                    ("checkSides", [])]


def test_статус_cli_пишет_итог_проверки_у_туннеля(capsys):
    st = {"up": True, "tunnels": [
        {"id": "work", "name": "Работа", "mode": "list", "active": "corp",
         "check": "up", "answer": "10.0.0.8"},
        {"id": "lab", "name": "Лаб", "mode": "list", "check": "none"},
        {"id": "dev", "name": "Дев", "mode": "list", "check": "error", "checking": True},
        {"id": "home", "name": "Личный", "mode": "all", "active": "nl-1", "check": "error"},
        {"id": "own", "name": "Свой", "mode": "list", "check": "rules",
         "answer": "corp.example"}]}

    cli._print_status(st)
    cli._print_status({**st, "up": False})

    lines = [l for l in capsys.readouterr().out.splitlines() if "туннель" in l]
    assert lines[0].endswith("— corp; отвечает 10.0.0.8")
    assert lines[1].endswith("; не с чем проверить: ни DNS в конфиге, ни домена в «пускать»")
    assert lines[2].endswith("; проверяю…")
    assert lines[3].endswith("— nl-1; молчит")
    assert lines[4].endswith("; отвечает, но «corp.example» через него не открывается "
                             "— проверь туннелирование")
    assert lines[5].endswith("— corp")


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


def test_открытое_окно_по_сигналу_только_выходит_вперёд(monkeypatch):
    api, calls, shown = _api(monkeypatch)
    api.ready.set()

    window._show(_Window(shown), api)
    assert shown == ["show"] and calls == []


def test_спрятанное_окно_по_сигналу_обновляется(monkeypatch):
    api, calls, shown = _api(monkeypatch)
    api.ready.set()
    api.hidden = True

    window._show(_Window(shown), api)
    assert "render" in shown and "check" in [op for op, _ in calls]


class _Form:
    Location = (52, 52)
    Width, Height = 1040, 720
    StartPosition = None

    def Invoke(self, action):
        action()


def _parked(monkeypatch, shown):
    # Заглушка .NET: в CI тесты идут на Linux, где pythonnet нет.
    monkeypatch.setitem(sys.modules, "System",
                        types.SimpleNamespace(Action=lambda f: f))
    win = _Window(shown)
    win.native = _Form()
    return win


def test_холодное_окно_встаёт_на_место_до_показа(monkeypatch):
    api, _, shown = _api(monkeypatch)
    win = _parked(monkeypatch, shown)
    api.holder["window"] = win
    api.cold, api._home = True, (440, 180)
    win.show = lambda: shown.append(("show", win.native.Location))

    api.reveal()
    assert shown == [("show", (440, 180))]


def test_место_возвращается_только_при_первом_показе(monkeypatch):
    api, _, shown = _api(monkeypatch)
    win = _parked(monkeypatch, shown)
    api._home = (440, 180)

    window._show(win, api)
    win.native.Location = (900, 300)          # пользователь передвинул окно
    api.hidden = True                         # и закрыл крестиком
    window._show(win, api)
    assert win.native.Location == (900, 300)


def _forms(monkeypatch):
    """Заглушки WinForms для _park: рабочий стол 2560×1400."""
    monkeypatch.setitem(sys.modules, "System.Drawing",
                        types.SimpleNamespace(Point=lambda x, y: (x, y)))
    area = types.SimpleNamespace(X=0, Y=0, Width=2560, Height=1400)
    monkeypatch.setitem(sys.modules, "System.Windows.Forms", types.SimpleNamespace(
        FormStartPosition=types.SimpleNamespace(Manual="manual"),
        Screen=types.SimpleNamespace(
            PrimaryScreen=types.SimpleNamespace(WorkingArea=area))))


def test_прогретое_окно_по_сигналу_встаёт_в_центр(monkeypatch):
    api, _, shown = _api(monkeypatch)
    win = _parked(monkeypatch, shown)
    _forms(monkeypatch)
    api.hidden = True

    window._park(win, api)
    assert win.native.Location == (-32000, -32000)
    window._show(win, api)
    assert win.native.Location == (760, 340)


def test_показ_раньше_before_show_не_оставляет_окно_за_краем(monkeypatch):
    """9 октября двойной клик сразу после входа пришёл раньше before_show:
    _unpark было нечего вернуть, _park увёл форму за край, и окно в панели
    задач есть, а на экране нет."""
    api, _, shown = _api(monkeypatch)
    win = _parked(monkeypatch, shown)
    _forms(monkeypatch)
    api.hidden = True

    window._show(win, api)
    window._park(win, api)

    assert win.native.Location == (52, 52)


def test_место_окна_мосту_pywebview_не_видно():
    """Публичные атрибуты js_api pywebview обходит рекурсивно: .NET Point
    давал home.Empty.Empty… до переполнения стека на каждой загрузке."""
    api = window.Api({})

    assert not [n for n in vars(api) if "home" in n and not n.startswith("_")]


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
