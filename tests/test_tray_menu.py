"""Пункты конфигов в меню трея: подписи и цвета кружков из статуса службы."""

import pytest

from dualvpn import tray

UP = {"up": True, "exit_ip": "1.2.3.4", "exit_state": "tunnel", "corp_ip": "10.0.0.1"}


def test_выключенный_vpn_серый_даже_во_время_проверки():
    assert tray._conf_colors({"up": False}, True, True) == ("off", "off")


def test_во_время_проверки_рыжий():
    assert tray._conf_colors(UP, True, True) == ("busy", "busy")


def test_оба_работают_зелёные():
    assert tray._conf_colors(UP, True, False) == ("up", "up")


@pytest.mark.parametrize("st", [
    {**UP, "exit_ip": ""},
    {**UP, "exit_state": "leak"},
])
def test_личный_без_выхода_или_с_утечкой_красный(st):
    assert tray._conf_colors(st, True, False)[1] == "error"


def test_рабочий_по_http_тоже_зелёный():
    st = {**UP, "corp_ip": "", "corp_http": "200"}
    assert tray._conf_colors(st, True, False)[0] == "up"


@pytest.mark.parametrize("corp_probe, color", [(True, "error"), (False, "off")])
def test_рабочий_молчит_красный_а_без_хоста_проверки_серый(corp_probe, color):
    st = {**UP, "corp_ip": "", "corp_http": ""}
    assert tray._conf_colors(st, corp_probe, False)[0] == color


@pytest.mark.parametrize("st, names", [
    ({}, (None, None)),
    ({"corp": ["office"], "profiles": ["nl-1"]}, ("office", "nl-1")),
    ({"profiles": ["nl-1", "nl-2"], "profile": "nl-2"}, (None, "nl-2")),
    # Из нескольких без выбора сборка не возьмёт ни один — и меню не покажет.
    ({"profiles": ["nl-1", "nl-2"]}, (None, None)),
    ({"profiles": ["nl-1"], "profile": "удалённый"}, (None, None)),
])
def test_имена_конфигов(st, names):
    assert tray._conf_names(st) == names


def test_длинное_имя_обрезается_а_пустое_зовёт_добавить():
    corp, personal = tray._conf_labels({"corp": ["x" * 100]})
    assert len(corp) == tray.NAME_MAX and corp.endswith("…")
    assert personal == "Добавить личный конфиг…"
