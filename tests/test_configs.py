"""Конфиги: куда и под каким именем ложится файл, что убирается и что выбрано.

Конфиг лежит в папке своего туннеля (conf\\tunnels\\<id>), а туннель — тот,
через чей пункт конфиг добавили: «рабочий» — первый туннель «по списку»,
«личный» — основной. Ошибка здесь не падает сразу: второй рабочий или не тот
личный ломают сборку только при следующем включении, когда человек уже не
помнит, что менял.
"""

import os
import shutil

import pytest

from dualvpn import buildconfig, paths, tunnels
from dualvpn.service import Core

WG = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = y\n"

WORK = {"id": "work", "name": "Работа", "mode": "list"}
HOME = {"id": "home", "name": "Личный", "mode": "all"}


def _clean():
    for d in (paths.CONF_TUNNELS, paths.CONF_CORP, paths.CONF_PERSONAL):
        shutil.rmtree(d, ignore_errors=True)
    for f in os.listdir(paths.CONF):
        if os.path.isfile(os.path.join(paths.CONF, f)):
            os.remove(os.path.join(paths.CONF, f))
    if os.path.exists(paths.PROFILE_FILE):
        os.remove(paths.PROFILE_FILE)


def _core():
    # Без __init__: туннель и пробер здесь не нужны, нужна только работа с conf\.
    core = Core.__new__(Core)
    core.logged = []
    core.log = core.logged.append
    return core


@pytest.fixture
def core():
    """Установка 0.4: tunnels.json с рабочим и личным, конфигов нет."""
    _clean()
    tunnels.save({"tunnels": [WORK, HOME]})
    yield _core()
    _clean()


@pytest.fixture
def old():
    """Установка до 0.4: tunnels.json ещё нет."""
    _clean()
    yield _core()
    _clean()


def _files(tid):
    try:
        return sorted(os.listdir(tunnels.conf_dir(tid)))
    except FileNotFoundError:
        return []


def _put(tid, name):
    os.makedirs(tunnels.conf_dir(tid), exist_ok=True)
    with open(os.path.join(tunnels.conf_dir(tid), name), "w", encoding="utf-8") as fh:
        fh.write(WG)


def _put_in(folder, name):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), "w", encoding="utf-8") as fh:
        fh.write(WG)


def _active(tid):
    return tunnels.find(tunnels.load(), tid)["active"]


@pytest.mark.parametrize("given, expected", [
    ("nl-1", "nl-1"),
    ("nl-1.conf", "nl-1"),
    ("wg0 ivanov.CONF", "wg0 ivanov"),
    ("Офис Иванов", "Офис Иванов"),
    ('a<b>c:d"e/f\\g|h?i*j', "a_b_c_d_e_f_g_h_i_j"),
    ("tab\tname", "tab_name"),
    ("../secret", "_secret"),
    ("nl.", "nl"),
    ("  nl  ", "nl"),
    ("CON", "_CON"),
    ("nul.conf", "_nul"),
    ("com1.backup", "_com1.backup"),
    ("", "config"),
    ("...", "config"),
    ("x" * 100, "x" * buildconfig.NAME_MAX),
])
def test_имя_чистится_а_не_отклоняется(given, expected):
    assert buildconfig.safe_name(given) == expected


def test_замена_рабочего_убирает_прежние(core):
    _put("work", "wg0-old.conf")
    _put("work", "wg.conf")
    _put("home", "nl-1.conf")

    r = core._add_config("Офис Иванов", WG, kind="corp")

    assert r["ok"] and r["name"] == "Офис Иванов"
    assert r["corp"] == ["Офис Иванов"] and r["profiles"] == ["nl-1"]
    # Рабочий ровно один, со своим именем и выбран; личные не тронуты.
    assert _files("work") == ["Офис Иванов.conf"]
    assert _active("work") == "Офис Иванов"
    assert _files("home") == ["nl-1.conf"]


def test_тип_задаёт_пункт_а_не_имя(core):
    """wg-home раньше стал бы рабочим по имени; теперь он личный, раз его
    добавили как личный, и имя своё сохраняет."""
    _put("work", "corp.conf")

    r = core._add_config("wg-home", WG, kind="personal")

    assert r["ok"] and r["name"] == "wg-home"
    assert _files("home") == ["wg-home.conf"]
    assert _files("work") == ["corp.conf"]
    assert _active("home") == "wg-home"


def test_добавленный_личный_ложится_рядом_и_выбирается(core):
    _put("home", "nl-1.conf")

    core._add_config("nl-2", WG, kind="personal")

    assert _files("home") == ["nl-1.conf", "nl-2.conf"]
    assert _active("home") == "nl-2"
    # Профиль больше не в state\profile, а в tunnels.json.
    assert not os.path.exists(paths.PROFILE_FILE)


def test_недопустимые_знаки_не_ломают_добавление(core):
    r = core._add_config("my:vpn?", WG, kind="personal")
    assert r["ok"] and r["name"] == "my_vpn_"
    assert _files("home") == ["my_vpn_.conf"]


@pytest.mark.parametrize("kind", ["", "home", "../corp"])
def test_неизвестный_тип_не_ложится(core, kind):
    r = core._add_config("nl-1", WG, kind=kind)
    assert not r["ok"]
    assert _files("work") == [] and _files("home") == []


def test_без_туннеля_этого_типа_конфиг_не_ложится(core):
    tunnels.save({"tunnels": [HOME]})

    r = core._add_config("corp", WG, kind="corp")

    assert not r["ok"] and "нет туннеля" in r["error"]
    assert _files("work") == []


def test_испорченный_tunnels_json_не_затирается(core):
    with open(paths.TUNNELS_JSON, "w", encoding="utf-8") as fh:
        fh.write("{не json")

    for r in (core._add_config("nl-1", WG, kind="personal"),
              core._remove_config("nl-1", "personal"),
              core._set_profile("nl-1")):
        assert not r["ok"] and "tunnels.json" in r["error"]

    with open(paths.TUNNELS_JSON, encoding="utf-8") as fh:
        assert fh.read() == "{не json"
    assert _files("home") == []


def test_личный_с_тем_же_именем_перезаписывается(core):
    core._add_config("nl-1", WG, kind="personal")
    core._add_config("nl-1", WG.replace("x", "z"), kind="personal")
    assert _files("home") == ["nl-1.conf"]
    r = core._read_config("nl-1", "personal")
    assert r["ok"] and "PrivateKey = z" in r["text"]


def test_чтение_конфига_неизвестного_типа_отказывает(core):
    _put("home", "nl-1.conf")
    assert not core._read_config("nl-1", "home")["ok"]


def test_удаление_выбранного_личного_переключает_на_другой(core):
    _put("work", "corp.conf")
    core._add_config("nl-2", WG, kind="personal")
    core._add_config("nl-1", WG, kind="personal")

    r = core._remove_config("nl-1", "personal")

    assert r["ok"] and r["profiles"] == ["nl-2"]
    # Не corp: рабочий личным туннелем не бывает.
    assert _active("home") == "nl-2"


def test_удаление_последнего_личного_сбрасывает_выбор(core):
    _put("work", "corp.conf")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-1", "personal")

    assert _active("home") == ""


def test_удаление_невыбранного_выбор_не_трогает(core):
    core._add_config("nl-2", WG, kind="personal")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-2", "personal")

    assert _active("home") == "nl-1"


def test_удаление_рабочего_профиль_не_трогает(core):
    """Имя рабочего может совпасть с выбранным личным — папки разные."""
    _put("work", "nl-1.conf")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-1", "corp")

    assert _files("work") == [] and _files("home") == ["nl-1.conf"]
    assert _active("home") == "nl-1"


def test_удаление_несуществующего_ничего_не_меняет(core):
    core._add_config("nl-1", WG, kind="personal")

    r = core._remove_config("nl-2", "personal")

    assert not r["ok"]
    assert _active("home") == "nl-1"


def test_профиль_это_активный_конфиг_основного(core):
    _put("home", "nl-1.conf")
    _put("home", "nl-2.conf")

    assert core._set_profile("nl-2") == {"ok": True, "profile": "nl-2"}
    assert _active("home") == "nl-2"

    r = core._set_profile("nl-3")
    assert not r["ok"] and "nl-3" in r["error"]
    assert _active("home") == "nl-2"
    assert not os.path.exists(paths.PROFILE_FILE)


def test_bom_от_блокнота_не_мешает(core):
    r = core._add_config("nl-1", "﻿" + WG, kind="personal")
    assert r["ok"]
    assert core._read_config("nl-1", "personal")["text"].startswith("[Interface]")


@pytest.mark.parametrize("text", ["", "CORP_DOMAINS=\"x.local\"\n", "[Interface]\n"])
def test_не_конфиг_не_ложится_и_ничего_не_удаляет(core, text):
    _put("work", "wg0-old.conf")
    r = core._add_config("corp", text, kind="corp")
    assert not r["ok"]
    assert _files("work") == ["wg0-old.conf"]
    assert _active("work") == ""


# ------------------------------------------------- переезд старой установки

def test_плоский_conf_переезжает_в_туннели(old):
    for f in ("corp.conf", "wg0-ivanov.conf", "personal.conf", "awg-home.conf",
              "nl-1.conf"):
        _put_in(paths.CONF, f)
    with open(os.path.join(paths.CONF, "site.env"), "w", encoding="utf-8") as fh:
        fh.write("CORP_DOMAINS=corp.example\n")

    old._migrate()

    assert _files("work") == ["corp.conf", "wg0-ivanov.conf"]
    assert _files("home") == ["awg-home.conf", "nl-1.conf", "personal.conf"]
    # site.env остаётся рядом копией, старых папок типов нет.
    assert sorted(os.listdir(paths.CONF)) == ["site.env.bak", "tunnels", "tunnels.json"]
    data = tunnels.load()
    # Профиль был пуст — берём тот, что сборка до 0.3 взяла бы сама.
    assert tunnels.find(data, "home")["active"] == "personal"
    assert tunnels.find(data, "work")["include"] == ["corp.example"]


def test_переезд_не_меняет_выбранный_профиль(old):
    _put_in(paths.CONF, "personal.conf")
    _put_in(paths.CONF, "nl-1.conf")
    with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
        fh.write("nl-1")

    old._migrate()

    assert _active("home") == "nl-1"


def test_папки_типов_переезжают_в_туннели(old):
    """Установка 0.3: конфиги уже по папкам corp и personal."""
    _put_in(paths.CONF_CORP, "corp.conf")
    _put_in(paths.CONF_PERSONAL, "nl-1.conf")
    _put_in(paths.CONF_PERSONAL, "nl-2.conf")
    with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
        fh.write("nl-2")

    old._migrate()

    assert _files("work") == ["corp.conf"] and _files("home") == ["nl-1.conf", "nl-2.conf"]
    assert _active("work") == "corp" and _active("home") == "nl-2"
    assert not os.path.exists(paths.CONF_CORP) and not os.path.exists(paths.CONF_PERSONAL)


def test_повторный_переезд_ничего_не_трогает(core):
    _put("home", "nl-1.conf")
    _put_in(paths.CONF_PERSONAL, "nl-2.conf")
    before = tunnels.load()

    core._migrate()

    assert tunnels.load() == before
    assert _files("home") == ["nl-1.conf"]
    assert os.listdir(paths.CONF_PERSONAL) == ["nl-2.conf"]
    assert not os.path.exists(paths.PROFILE_FILE)


def test_сбой_переезда_в_журнале_а_не_падением(old, monkeypatch):
    def broken(log=print):
        raise ValueError("туннелей 9, больше 8 нельзя")
    monkeypatch.setattr(tunnels, "migrate", broken)

    old._migrate()

    assert any("не перенести" in line and "больше 8" in line for line in old.logged)
