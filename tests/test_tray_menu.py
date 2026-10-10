"""Пункты конфигов в меню трея: подписи и цвета кружков из статуса службы."""

import sys
import types

import pytest

from dualvpn import tray

NONE = frozenset()


def _work(**over):
    return {"id": "work", "name": "Работа", "mode": "list", "check": "up", **over}


def _home(**over):
    return {"id": "home", "name": "Личный", "mode": "all", "check": "up", **over}


def _up(*items, **st):
    return {"up": True, "exit_ip": "1.2.3.4", "exit_state": "tunnel",
            "tunnels": list(items or (_work(), _home())), **st}


def test_выключенный_vpn_серый_даже_во_время_проверки():
    st = {**_up(), "up": False}
    assert tray._conf_colors(st, frozenset({"work", "home"})) == {"work": "off", "home": "off"}


def test_во_время_проверки_рыжий():
    assert tray._conf_colors(_up(), frozenset({"work", "home"})) == {"work": "busy",
                                                                    "home": "busy"}


def test_все_работают_зелёные():
    st = _up(_work(), _work(id="lab"), _home())
    assert tray._conf_colors(st, NONE) == {"work": "up", "lab": "up", "home": "up"}


def test_проверенный_основной_зелёный_пока_рабочий_ещё_рыжий():
    st = _up(_work(check=""), _home())
    assert tray._conf_colors(st, frozenset({"work"})) == {"work": "busy", "home": "up"}


def test_проверка_службы_по_туннелям_тоже_рыжая():
    st = _up(_work(checking=True), _home(checking=False))
    assert tray._conf_colors(st, NONE) == {"work": "busy", "home": "up"}


def test_идет_включение_все_рыжие():
    assert set(tray._conf_colors(_up(busy="включаю"), NONE).values()) == {"busy"}


def test_туннели_в_lparam_и_обратно():
    ids = ("work", "lab", "home")
    for pending in (NONE, frozenset({"lab"}), frozenset({"work", "home"}), frozenset(ids)):
        assert tray._sides_of(tray._side_bits(pending, ids), ids) == pending


def test_удалённый_туннель_в_lparam_не_попадает():
    assert tray._side_bits(frozenset({"gone", "home"}), ("work", "home")) == 0b10


def test_основной_на_запасном_выходе_красный_даже_с_итогом_up():
    """Сторож переключает выход раньше, чем проверка его перемерит."""
    colors = tray._conf_colors(_up(out="direct"), NONE)
    assert colors == {"work": "up", "home": "error"}


@pytest.mark.parametrize("check, color", [("error", "error"), ("none", "off"), ("", "off"),
                                          ("rules", "busy")])
def test_молчит_красный_а_без_домена_проверки_серый(check, color):
    assert tray._conf_colors(_up(_work(check=check)), NONE) == {"work": color}


def test_запасной_выход_в_подсказке_значка():
    app = tray.Tray.__new__(tray.Tray)
    app.status = _up(_work(), _home(name="Дом"), out="direct", exit_state="direct")

    assert "запасной выход" in app._title()
    assert "«Дом» не работает" in app._title()
    assert "УТЕЧКА" not in app._title()


def test_без_основного_подсказка_всё_остальное_напрямую():
    app = tray.Tray.__new__(tray.Tray)
    app.status = _up(_work(), exit_ip="5.6.7.8", exit_state="direct")

    assert app._title() == "DualVPN — работает · всё остальное напрямую"


@pytest.mark.parametrize("t, name", [
    ({}, None),
    ({"confs": ["nl-1"]}, "nl-1"),
    ({"confs": ["nl-1", "nl-2"], "active": "nl-2"}, "nl-2"),
    # Из нескольких без выбора сборка не возьмёт ни один — и меню не покажет.
    ({"confs": ["nl-1", "nl-2"]}, None),
    ({"confs": ["nl-1"], "active": "удалённый"}, None),
])
def test_имя_конфига_туннеля(t, name):
    assert tray._conf_name(t) == name


def _hooked(calls, monkeypatch):
    # Заглушка вместо pystray: в CI тесты идут на Linux, где его нет.
    win32 = types.SimpleNamespace(WM_NOTIFY=0x401, WM_LBUTTONUP=0x0202,
                                  WM_RBUTTONUP=0x0205)
    util = types.SimpleNamespace(win32=win32)
    monkeypatch.setitem(sys.modules, "pystray", types.SimpleNamespace(_util=util))
    monkeypatch.setitem(sys.modules, "pystray._util", util)
    monkeypatch.setitem(sys.modules, "pystray._util.win32", win32)

    class Icon:
        _message_handlers = {win32.WM_NOTIFY: lambda w, l: calls.append(("orig", l))}

    app = tray.Tray.__new__(tray.Tray)
    app.icon = Icon()
    app.on_window = lambda: calls.append(("window", None))
    app._hook_menu()
    return app.icon._message_handlers[win32.WM_NOTIFY], win32


def test_одиночный_левый_клик_открывает_окно(monkeypatch):
    calls = []
    notify, win32 = _hooked(calls, monkeypatch)

    notify(0, win32.WM_LBUTTONUP)

    assert calls == [("window", None)]


def test_двойной_левый_клик_сам_окно_не_открывает(monkeypatch):
    calls = []
    notify, _ = _hooked(calls, monkeypatch)

    notify(0, tray.WM_LBUTTONDBLCLK)

    assert calls == []


def test_подпись_имя_конфига_без_имени_туннеля():
    """Как на плитке окна: единица — конфиг, а не «рабочий/личный»."""
    assert tray._conf_label(_work(confs=["office", "lab"], active="lab")) == "lab"


def test_длинное_имя_обрезается_а_пустое_зовёт_добавить():
    long = tray._conf_label(_work(confs=["x" * 100]))
    assert long.endswith("…") and len(long) == tray.NAME_MAX
    assert tray._conf_label(_home()) == "Личный: добавить конфиг…"


class _Item:
    """Пункт pystray без pystray: подпись и действие как есть."""

    def __init__(self, text, action, enabled=None):
        self.text, self.action, self.enabled = text, action, enabled


def _menu_app(st):
    app = tray.Tray.__new__(tray.Tray)
    app.status = st
    app._tunnel_items = {}
    app._menu_ids = tuple(t["id"] for t in st["tunnels"])
    app.added = []
    app.on_add_config = app.added.append
    return app


def test_пункты_туннелей_по_порядку_с_подписью_и_своим_туннелем():
    app = _menu_app(_up(_work(confs=["office"]), _home()))
    stub = types.SimpleNamespace(MenuItem=_Item)

    work, home = app._conf_items(stub)
    work.action()
    home.action()

    assert work.text(work) == "office"
    assert home.text(home) == "Личный: добавить конфиг…"
    assert app.added == ["work", "home"]


def test_пункты_туннелей_те_же_объекты_а_удалённый_забыт():
    app = _menu_app(_up(_work(), _work(id="lab", name="Лаб"), _home()))
    stub = types.SimpleNamespace(MenuItem=_Item)
    work, lab, home = app._conf_items(stub)

    app.status = _up(_home(), _work(confs=["office"]))
    app._menu_ids = ("home", "work")
    again = app._conf_items(stub)

    assert again == (home, work)
    assert set(app._tunnel_items) == {"home", "work"}
    assert work.text(work) == "office"

