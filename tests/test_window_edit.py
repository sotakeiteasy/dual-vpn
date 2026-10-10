"""Окно: «Редактировать» открывает конфиг в Блокноте с правами.

Имя приходит со страницы, поэтому путь собирается только из имён, которые
служба сама отдала в статусе.
"""

import ntpath
import os

from dualvpn import ipc, paths, window

WORK = {"id": "work", "name": "Работа", "mode": "list", "active": "corp",
        "confs": ["corp"]}
HOME = {"id": "home", "name": "Личный", "mode": "all", "active": "nl-1",
        "confs": ["nl-1"]}


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


def test_конфиг_открывается_в_блокноте_с_правами(monkeypatch):
    api, runs, _ = _setup(monkeypatch, {"tunnels": [WORK, HOME]})

    api.send("edit_config", {"tunnel": "home", "name": "nl-1"})

    exe, args, show = runs[0]
    # Путь Windows: на Linux-раннере os.path его не разберёт.
    assert ntpath.isabs(exe) and ntpath.normpath(exe).lower().endswith("system32\\notepad.exe")
    assert args == [os.path.join(paths.CONF_TUNNELS, "home", "nl-1.conf")] and show


def test_конфиг_берётся_из_папки_своего_туннеля(monkeypatch):
    api, runs, _ = _setup(monkeypatch, {"tunnels": [WORK, HOME]})

    api.send("edit_config", {"tunnel": "work", "name": "corp"})

    assert runs[0][1] == [os.path.join(paths.CONF_TUNNELS, "work", "corp.conf")]


def test_без_туннеля_в_статусе_не_открывается(monkeypatch):
    api, runs, shown = _setup(monkeypatch, {"tunnels": [HOME]})

    api.send("edit_config", {"tunnel": "work", "name": "corp"})

    assert runs == []
    assert shown[0][0] == "failed"


def test_имя_не_из_статуса_не_открывается(monkeypatch):
    api, runs, shown = _setup(monkeypatch, {"tunnels": [WORK, HOME]})

    api.send("edit_config", {"tunnel": "home", "name": "..\\..\\Windows\\win"})

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


def _save_rules(monkeypatch, up, reply=None):
    """Сохранить правила туннеля; вернуть команды службе и вызовы страницы."""
    ops, admin, shown = [], [], []

    def call(op, **_kw):
        ops.append(op)
        if op == "start":
            return {"ok": False, "error": "нет конфига"}
        return {"ok": True, "status": {"up": up}}

    def admin_call(op, **kw):
        admin.append((op, kw))
        return reply or {"ok": True, "include": ["a.ru"], "exclude": [],
                         "rejected": {"include": ["foo_bar"]}}

    monkeypatch.setattr(ipc, "call", call)
    api = window.Api({})
    monkeypatch.setattr(api, "_admin_call", admin_call)
    monkeypatch.setattr(api, "js", lambda fn, arg=None: shown.append((fn, arg)))
    api.send("save_rules", {"tunnel": "work", "include": "a.ru foo_bar"})
    return ops, admin, shown


def test_правила_уходят_текстом_поля_а_ответ_со_списками_на_страницу(monkeypatch):
    _, admin, shown = _save_rules(monkeypatch, up=False)

    # Только присланные поля: exclude не пришёл — служба его не трогает.
    assert admin == [("set-tunnel", {"tunnel": "work", "include": "a.ru foo_bar"})]
    assert ("rulesSaved", {"include": ["a.ru"], "exclude": [],
                           "rejected": {"include": ["foo_bar"]}, "mode": ""}) in shown


def test_отказ_службы_показан_в_листе_и_ничего_не_применяется(monkeypatch):
    ops, _, shown = _save_rules(monkeypatch, up=True,
                                reply={"ok": False, "error": "«a.ru» уже в «Лаб»"})

    # Строка состояния — под листом: отказ должен стоять в самом листе.
    assert ("rulesFailed", {"error": "«a.ru» уже в «Лаб»", "problems": []}) in shown
    assert "rulesSaved" not in [fn for fn, _ in shown]
    assert "apply" not in ops


def test_проблемы_по_полям_доходят_до_листа(monkeypatch):
    problems = [{"field": "include", "text": "«a.ru» уже в «Лаб»"},
                {"field": "include", "text": "очисти и «не пускать»"}]
    _, _, shown = _save_rules(monkeypatch, up=True,
                              reply={"ok": False, "error": "x", "problems": problems})

    # По полям, а не одной строкой: лист красит поле и пишет причины под ним.
    assert ("rulesFailed", {"error": "x", "problems": problems}) in shown


def test_ушёл_запасным_лист_закрывается_и_применяется(monkeypatch):
    moved = {"tunnel": "home", "name": "nl", "main": "Личный"}
    ops, _, shown = _save_rules(monkeypatch, up=True, reply={"ok": True, "moved": moved})

    # Туннеля листа больше нет: не rulesSaved с его полями, а закрыть и пересобрать.
    assert ("rulesMoved", moved) in shown
    assert "rulesSaved" not in [fn for fn, _ in shown]
    assert "apply" in ops


def test_правка_при_выключенном_vpn_не_включает_его(monkeypatch):
    ops, _, shown = _save_rules(monkeypatch, up=False)

    # Без конфигов «Включить» падало бы с «нет конфига» — его и не зовём.
    assert "start" not in ops and "stop" not in ops
    assert "failed" not in [fn for fn, _ in shown]
    assert "restarting" not in [fn for fn, _ in shown]


def test_правка_при_включённом_vpn_применяет_её_службой_без_выключения(monkeypatch):
    ops, _, shown = _save_rules(monkeypatch, up=True)

    # Что перезапускать — процесс туннеля или всё, — решает служба (apply):
    # окно само VPN не выключает, иначе интернет падал на каждую правку.
    assert "apply" in ops
    assert "start" not in ops and "stop" not in ops
    assert "restarting" not in [fn for fn, _ in shown]
