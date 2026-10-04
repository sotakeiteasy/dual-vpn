"""Добавление конфигов: под каким именем ложится файл и что убирается.

Имя файла решает, каким туннелем он станет (buildconfig.CORP_PAT). Ошибка
здесь не падает сразу: второй рабочий или личный с именем wg-* ломают сборку
только при следующем включении, когда человек уже не помнит, что менял.
"""

import os

import pytest

from dualvpn import buildconfig, paths
from dualvpn.service import Core

WG = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = y\n"


@pytest.fixture
def core():
    for f in os.listdir(paths.CONF):
        os.remove(os.path.join(paths.CONF, f))
    if os.path.exists(paths.PROFILE_FILE):
        os.remove(paths.PROFILE_FILE)
    # Без __init__: туннель и пробер здесь не нужны, нужна только работа с conf\.
    return Core.__new__(Core)


def _files():
    return sorted(os.listdir(paths.CONF))


def _put(name):
    with open(os.path.join(paths.CONF, name), "w", encoding="utf-8") as fh:
        fh.write(WG)


@pytest.mark.parametrize("name, corp", [
    ("corp", True), ("wg", True), ("wg0-ivanov", True), ("wg-office", True),
    ("wg_x", True), ("WG0-Ivanov.conf", True),
    ("personal", False), ("nl-1", False), ("awg-home", False), ("wgood", False),
])
def test_рабочий_узнаётся_по_имени(name, corp):
    assert buildconfig.is_corp_name(name) is corp


@pytest.mark.parametrize("kind, given, expected", [
    ("corp", "wg0-ivanov", "corp"),
    ("corp", "что угодно", "corp"),
    ("personal", "nl-1", "nl-1"),
    ("personal", "nl-1.conf", "nl-1"),
    ("personal", "wg-home", "personal-wg-home"),
    ("personal", "corp", "personal-corp"),
    ("personal", "", "personal"),
])
def test_имя_подгоняется_под_тип(kind, given, expected):
    assert buildconfig.stored_name(kind, given) == expected


def test_замена_рабочего_убирает_прежние(core):
    _put("wg0-old.conf")
    _put("wg.conf")
    _put("nl-1.conf")
    r = core._add_config("wg0-new", WG, kind="corp")
    assert r["ok"] and r["name"] == "corp"
    # Рабочий ровно один, личные не тронуты.
    assert _files() == ["corp.conf", "nl-1.conf"]


def test_личный_с_именем_рабочего_переименовывается_и_выбирается(core):
    _put("corp.conf")
    r = core._add_config("wg-home", WG, kind="personal")
    assert r["ok"] and r["name"] == "personal-wg-home"
    assert _files() == ["corp.conf", "personal-wg-home.conf"]
    with open(paths.PROFILE_FILE, encoding="utf-8") as fh:
        assert fh.read() == "personal-wg-home"


def test_личный_с_тем_же_именем_перезаписывается(core):
    core._add_config("nl-1", WG, kind="personal")
    core._add_config("nl-1", WG.replace("x", "z"), kind="personal")
    assert _files() == ["nl-1.conf"]
    with open(os.path.join(paths.CONF, "nl-1.conf"), encoding="utf-8") as fh:
        assert "PrivateKey = z" in fh.read()


def _profile():
    with open(paths.PROFILE_FILE, encoding="utf-8") as fh:
        return fh.read()


def test_удаление_выбранного_личного_переключает_на_другой(core):
    _put("corp.conf")
    core._add_config("nl-2", WG, kind="personal")
    core._add_config("nl-1", WG, kind="personal")

    r = core._remove_config("nl-1")

    assert r["ok"]
    # Не corp: рабочий личным туннелем не бывает.
    assert _profile() == "nl-2"


def test_удаление_последнего_личного_сбрасывает_выбор(core):
    _put("corp.conf")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-1")

    assert _profile() == ""


def test_удаление_невыбранного_выбор_не_трогает(core):
    core._add_config("nl-2", WG, kind="personal")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-2")

    assert _profile() == "nl-1"


def test_bom_от_блокнота_не_мешает(core):
    r = core._add_config("nl-1", "\ufeff" + WG, kind="personal")
    assert r["ok"]
    with open(os.path.join(paths.CONF, "nl-1.conf"), encoding="utf-8") as fh:
        assert fh.read().startswith("[Interface]")


@pytest.mark.parametrize("text", ["", "CORP_DOMAINS=\"x.local\"\n", "[Interface]\n"])
def test_не_конфиг_не_ложится_и_ничего_не_удаляет(core, text):
    _put("wg0-old.conf")
    r = core._add_config("corp", text, kind="corp")
    assert not r["ok"]
    assert _files() == ["wg0-old.conf"]
