"""Конфиги: куда и под каким именем ложится файл, что убирается и что берёт сборка.

Тип туннеля задаёт папка (conf\\corp, conf\\personal), а папку — пункт, через
который конфиг добавили. Ошибка здесь не падает сразу: второй рабочий или
не тот личный ломают сборку только при следующем включении, когда человек
уже не помнит, что менял.
"""

import os
import sys

import pytest

from dualvpn import buildconfig, paths
from dualvpn.service import Core

WG = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = y\n"


@pytest.fixture
def core():
    paths.ensure_dirs()
    for d in (paths.CONF, paths.CONF_CORP, paths.CONF_PERSONAL):
        for f in os.listdir(d):
            if os.path.isfile(os.path.join(d, f)):
                os.remove(os.path.join(d, f))
    if os.path.exists(paths.PROFILE_FILE):
        os.remove(paths.PROFILE_FILE)
    # Без __init__: туннель и пробер здесь не нужны, нужна только работа с conf\.
    return Core.__new__(Core)


def _files(kind):
    return sorted(os.listdir(buildconfig.conf_dir(kind)))


def _put(kind, name):
    with open(os.path.join(buildconfig.conf_dir(kind), name), "w",
              encoding="utf-8") as fh:
        fh.write(WG)


def _put_flat(name):
    with open(os.path.join(paths.CONF, name), "w", encoding="utf-8") as fh:
        fh.write(WG)


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
    _put("corp", "wg0-old.conf")
    _put("corp", "wg.conf")
    _put("personal", "nl-1.conf")
    r = core._add_config("Офис Иванов", WG, kind="corp")
    assert r["ok"] and r["name"] == "Офис Иванов"
    # Рабочий ровно один и со своим именем, личные не тронуты.
    assert _files("corp") == ["Офис Иванов.conf"]
    assert _files("personal") == ["nl-1.conf"]


def test_тип_задаёт_пункт_а_не_имя(core):
    """wg-home раньше стал бы рабочим по имени; теперь он личный, раз его
    добавили как личный, и имя своё сохраняет."""
    _put("corp", "corp.conf")
    r = core._add_config("wg-home", WG, kind="personal")
    assert r["ok"] and r["name"] == "wg-home"
    assert _files("personal") == ["wg-home.conf"]
    assert _files("corp") == ["corp.conf"]
    assert _profile() == "wg-home"


def test_недопустимые_знаки_не_ломают_добавление(core):
    r = core._add_config("my:vpn?", WG, kind="personal")
    assert r["ok"] and r["name"] == "my_vpn_"
    assert _files("personal") == ["my_vpn_.conf"]


def test_неизвестный_тип_не_ложится(core):
    r = core._add_config("nl-1", WG, kind="")
    assert not r["ok"]
    assert _files("corp") == [] and _files("personal") == []


def test_личный_с_тем_же_именем_перезаписывается(core):
    core._add_config("nl-1", WG, kind="personal")
    core._add_config("nl-1", WG.replace("x", "z"), kind="personal")
    assert _files("personal") == ["nl-1.conf"]
    r = core._read_config("nl-1", "personal")
    assert r["ok"] and "PrivateKey = z" in r["text"]


def _profile():
    with open(paths.PROFILE_FILE, encoding="utf-8") as fh:
        return fh.read()


def test_удаление_выбранного_личного_переключает_на_другой(core):
    _put("corp", "corp.conf")
    core._add_config("nl-2", WG, kind="personal")
    core._add_config("nl-1", WG, kind="personal")

    r = core._remove_config("nl-1", "personal")

    assert r["ok"]
    # Не corp: рабочий личным туннелем не бывает.
    assert _profile() == "nl-2"


def test_удаление_последнего_личного_сбрасывает_выбор(core):
    _put("corp", "corp.conf")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-1", "personal")

    assert _profile() == ""


def test_удаление_невыбранного_выбор_не_трогает(core):
    core._add_config("nl-2", WG, kind="personal")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-2", "personal")

    assert _profile() == "nl-1"


def test_удаление_рабочего_профиль_не_трогает(core):
    """Имя рабочего может совпасть с выбранным личным — папки разные."""
    _put("corp", "nl-1.conf")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-1", "corp")

    assert _files("corp") == [] and _files("personal") == ["nl-1.conf"]
    assert _profile() == "nl-1"


def test_bom_от_блокнота_не_мешает(core):
    r = core._add_config("nl-1", "\ufeff" + WG, kind="personal")
    assert r["ok"]
    assert core._read_config("nl-1", "personal")["text"].startswith("[Interface]")


@pytest.mark.parametrize("text", ["", "CORP_DOMAINS=\"x.local\"\n", "[Interface]\n"])
def test_не_конфиг_не_ложится_и_ничего_не_удаляет(core, text):
    _put("corp", "wg0-old.conf")
    r = core._add_config("corp", text, kind="corp")
    assert not r["ok"]
    assert _files("corp") == ["wg0-old.conf"]


# ------------------------------------------------- переезд старой установки

def test_плоский_conf_разкладывается_по_старым_правилам(core):
    for f in ("corp.conf", "wg0-ivanov.conf", "personal.conf", "awg-home.conf",
              "nl-1.conf"):
        _put_flat(f)
    with open(os.path.join(paths.CONF, "site.env"), "w", encoding="utf-8") as fh:
        fh.write("CORP_PROBE=x\n")

    core._migrate()

    assert _files("corp") == ["corp.conf", "wg0-ivanov.conf"]
    assert _files("personal") == ["awg-home.conf", "nl-1.conf", "personal.conf"]
    # site.env остаётся на месте, в корне — только он и папки.
    assert sorted(os.listdir(paths.CONF)) == ["corp", "personal", "site.env"]
    # Профиль был пуст — берём тот, что сборка до 0.3 взяла бы сама.
    assert _profile() == "personal"


def test_переезд_не_меняет_выбранный_профиль(core):
    _put_flat("personal.conf")
    _put_flat("nl-1.conf")
    with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
        fh.write("nl-1")

    core._migrate()

    assert _profile() == "nl-1"


def test_без_старых_файлов_переезда_нет(core):
    _put("personal", "nl-1.conf")
    core._migrate()
    assert _files("personal") == ["nl-1.conf"]
    assert not os.path.exists(paths.PROFILE_FILE)


# ------------------------------------------------------ что берёт сборка

@pytest.fixture
def no_profile(monkeypatch):
    monkeypatch.delenv("SB_PERSONAL", raising=False)
    monkeypatch.setattr(sys, "argv", ["buildconfig"])


def test_без_профиля_берётся_единственный_личный(core, no_profile):
    _put("personal", "nl-1.conf")
    assert buildconfig.pick_personal() == buildconfig.conf_path("personal", "nl-1")


def test_несколько_личных_без_выбора_ошибка(core, no_profile):
    _put("personal", "nl-1.conf")
    _put("personal", "nl-2.conf")
    with pytest.raises(SystemExit, match="выбери один"):
        buildconfig.pick_personal()


def test_профиль_выбирает_личный(core, no_profile, monkeypatch):
    _put("personal", "nl-1.conf")
    _put("personal", "nl-2.conf")
    monkeypatch.setenv("SB_PERSONAL", "nl-2")
    assert buildconfig.pick_personal() == buildconfig.conf_path("personal", "nl-2")
    monkeypatch.setenv("SB_PERSONAL", "nl-3")
    with pytest.raises(SystemExit, match="нет личного"):
        buildconfig.pick_personal()


def test_рабочий_должен_быть_ровно_один(core):
    with pytest.raises(SystemExit, match="не добавлен"):
        buildconfig.pick_corp()
    _put("corp", "a.conf")
    assert buildconfig.pick_corp() == buildconfig.conf_path("corp", "a")
    _put("corp", "b.conf")
    with pytest.raises(SystemExit, match="несколько"):
        buildconfig.pick_corp()
