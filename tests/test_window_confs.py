"""Окно: конфиги и правила по id туннеля — вопрос о месте конфига, удаление
последнего, списки правил из файла."""

from dualvpn import ipc, window

WG = "[Interface]\nAddress = 10.53.0.4/32\n[Peer]\nAllowedIPs = 10.53.0.0/16\n"


def _api(monkeypatch, replies):
    """Окно с подменёнными каналом и UAC: replies — ответы админ-команд по очереди."""
    admin, shown = [], []
    monkeypatch.setattr(ipc, "call", lambda op, **_kw: {"ok": True, "status": {}})
    api = window.Api({})

    def admin_call(op, **kw):
        admin.append((op, kw))
        return replies.pop(0) if replies else {"ok": True}
    monkeypatch.setattr(api, "_admin_call", admin_call)
    monkeypatch.setattr(api, "js", lambda fn, arg=None: shown.append((fn, arg)))
    return api, admin, shown


def test_вопрос_о_месте_и_замена_без_повторного_диалога(monkeypatch, tmp_path):
    conf = tmp_path / "office-2.conf"
    conf.write_text(WG, encoding="utf-8")
    ask = {"id": "work", "name": "office", "conf": "office"}
    api, admin, shown = _api(monkeypatch, [{"ok": False, "ask": ask, "error": "…"}])
    monkeypatch.setattr(api, "_pick", lambda _types: str(conf))

    api.send("add_config", {})
    api.send("place_config", {"place": "replace", "tunnel": "work"})

    assert ("askPlace", {**ask, "file": "office-2"}) in shown
    assert "failed" not in [fn for fn, _ in shown]
    # Место выбирает служба; ответ человека несёт тот же файл.
    assert admin == [
        ("add-config", {"name": "office-2", "text": WG, "tunnel": "", "place": ""}),
        ("add-config", {"name": "office-2", "text": WG, "tunnel": "work",
                        "place": "replace"})]


def test_ответ_на_вопрос_без_вопроса_ничего_не_шлёт(monkeypatch):
    api, admin, _ = _api(monkeypatch, [])

    api.send("place_config", {"place": "new"})

    assert admin == []


def test_удаление_последнего_передаёт_выбор_о_туннеле(monkeypatch):
    api, admin, shown = _api(monkeypatch, [])

    api.send("del_config", {"tunnel": "work", "name": "office", "drop_tunnel": True})

    assert admin == [("remove-config", {"tunnel": "work", "name": "office",
                                        "drop_tunnel": True})]
    assert ("closeSheet", None) in shown


def test_выбор_конфига_без_прав_по_id_туннеля(monkeypatch):
    api, admin, _ = _api(monkeypatch, [])
    calls = []
    monkeypatch.setattr(ipc, "call", lambda op, **kw: calls.append((op, kw)) or
                        {"ok": True, "status": {}})

    api.send("use_config", {"tunnel": "home", "name": "de-2"})

    # set-active в USER_OPS: клик по запасному не спрашивает UAC.
    assert ("set-active", {"tunnel": "home", "name": "de-2"}) in calls
    assert admin == []


def test_команды_плитки_уходят_администратору_с_id_туннеля(monkeypatch):
    api, admin, shown = _api(monkeypatch, [])

    api.send("move_config", {"tunnel": "home", "name": "nl-1", "to": "new"})
    api.send("set_mode", {"tunnel": "t3", "mode": "all"})
    api.send("del_tunnel", "work")

    assert admin == [
        ("move-config", {"tunnel": "home", "name": "nl-1", "to": "new",
                         "drop_tunnel": False}),
        ("set-tunnel", {"tunnel": "t3", "mode": "all"}),
        ("remove-tunnel", {"tunnel": "work"})]
    assert "failed" not in [fn for fn, _ in shown]


def test_галочка_журнала_отпускается_и_при_отказе(monkeypatch):
    api, admin, shown = _api(monkeypatch, [{"ok": False, "error": "отменено"}])

    api.send("log_level", True)

    assert admin == [("set-log-level", {"level": "debug"})]
    fns = [fn for fn, _ in shown]
    assert "logLevelDone" in fns and "failed" in fns


def test_лист_правил_получает_только_поля_туннеля(monkeypatch):
    work = {"id": "work", "name": "Работа", "mode": "list", "active": "corp",
            "include": ["corp.example"], "exclude": ["198.51.100.7/32"], "lab": 1}
    api, admin, shown = _api(monkeypatch, [{"ok": True, "tunnels": [work]},
                                           {"ok": True, "tunnels": [work]}])

    api.send("tunnel_rules", "work")
    api.send("tunnel_rules", "gone")

    assert admin == [("get-tunnels", {}), ("get-tunnels", {})]
    assert shown[0] == ("showRules", {k: v for k, v in work.items() if k != "lab"})
    assert shown[1][0] == "failed"


def test_экспорт_правил_читается_обратно_загрузкой(monkeypatch, tmp_path):
    out = tmp_path / "rules.json"
    asked = {}

    class Win:
        def create_file_dialog(self, _kind, **kw):
            asked.update(kw)
            return (str(out),)
    api, _, shown = _api(monkeypatch, [])
    api.holder["window"] = Win()

    api.send("export_rules", {"name": "Работа", "include": ["corp.example"],
                              "exclude": ["198.51.100.7/32"]})

    assert asked["save_filename"] == "Работа.json"
    assert "failed" not in [fn for fn, _ in shown]
    assert window._rules_from_file(out.read_text(encoding="utf-8")) == {
        "include": "corp.example", "exclude": "198.51.100.7/32"}


def test_файл_экспорта_раскладывается_по_полям():
    text = '﻿{"include": ["corp.example", "198.51.100.7/32"], "exclude": []}'

    assert window._rules_from_file(text) == {"include": "corp.example\n198.51.100.7/32",
                                             "exclude": ""}


def test_простой_текст_идёт_в_первое_поле_целиком():
    assert window._rules_from_file("a.ru, 1.2.3.4") == {"text": "a.ru, 1.2.3.4"}
    # JSON, но не наш: ни include, ни exclude — тоже просто текст.
    assert window._rules_from_file('["a.ru"]') == {"text": '["a.ru"]'}
    assert window._rules_from_file('{"exclude": 5}') == {"include": "", "exclude": ""}
