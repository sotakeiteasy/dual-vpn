"""Списки «Пускать» и «Не пускать»: что человек ввёл и что из этого вышло.

Поле принимает текст из любого источника: адрес из письма, ссылку из
браузера, строку из чужого конфига. Ошибка разбора не видна сразу — туннель
просто не заберёт адрес. Поэтому каждая форма записи проверена отдельно, а
непонятое обязано вернуться, а не исчезнуть.
"""

import pytest

from dualvpn import routelist


@pytest.mark.parametrize("text", [
    "a.ru 1.2.3.4",
    "a.ru\n1.2.3.4",
    "a.ru\r\n1.2.3.4",
    "a.ru\t1.2.3.4",
    "a.ru,1.2.3.4",
    "a.ru;1.2.3.4",
    "  a.ru ,; \n 1.2.3.4 ;",
])
def test_каждый_разделитель_делит_записи(text):
    assert routelist.parse(text) == (["a.ru", "1.2.3.4/32"], [])


def test_двоеточие_не_разделитель():
    """Иначе «host:port» стал бы двумя записями, а IPv6 — кашей."""
    assert routelist.parse("git.x.su:22") == (["git.x.su"], [])
    assert routelist.parse("2001:db8::1") == (["2001:db8::1/128"], [])


@pytest.mark.parametrize("given, expected", [
    ("1.2.3.4", "1.2.3.4/32"),
    ("10.0.0.5/8", "10.0.0.0/8"),
    ("192.168.1.0/24", "192.168.1.0/24"),
    ("1.2.3.4:443", "1.2.3.4/32"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("[2001:db8::1]:443", "2001:db8::1/128"),
    ("git.x.su", "git.x.su"),
    ("GIT.X.SU", "git.x.su"),
    ("git.x.su.", "git.x.su"),
    ("*.x.su", "*.x.su"),
    ("*.X.SU.", "*.x.su"),
    ("https://git.x.su/a/b?c=1", "git.x.su"),
    ("http://git.x.su:8080/", "git.x.su"),
    ("https://user@git.x.su", "git.x.su"),
    ("https://1.2.3.4/x", "1.2.3.4/32"),
    ("git.x.su:22", "git.x.su"),
    ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ("ПРИМЕР.РФ", "xn--e1afmkfd.xn--p1ai"),
    ("*.пример.рф", "*.xn--e1afmkfd.xn--p1ai"),
    ("xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"),
    ("a-b.c-d.ru", "a-b.c-d.ru"),
])
def test_форма_записи_нормализуется(given, expected):
    assert routelist.parse(given) == ([expected], [])


@pytest.mark.parametrize("token", [
    "foo_bar",       # подчёркивание в имени хоста
    "localhost",     # без точки — скорее опечатка, чем домен
    "1.2.3",         # недописанный адрес
    "300.1.1.1",     # не адрес, а зона из цифр
    "1.2.3.4/33",
    "-a.ru",
    "a-.ru",
    "a..ru",
    "*.",
    "*.1.2.3.4",
    "**.a.ru",
    "a.*.ru",
    "https://",
    "git.x.su:port",
    "a" * 64 + ".ru",
])
def test_непонятное_возвращается_как_есть(token):
    assert routelist.parse(token) == ([], [token])


def test_дубли_схлопываются_после_нормализации():
    text = "a.ru A.RU a.ru. https://a.ru/x 1.2.3.4 1.2.3.4/32 1.2.3.4:80"
    assert routelist.parse(text) == (["a.ru", "1.2.3.4/32"], [])


def test_непонятые_тоже_без_повторов_и_в_порядке_ввода():
    assert routelist.parse("x_1 a.ru x_2 x_1") == (["a.ru"], ["x_1", "x_2"])


def test_домен_и_его_поддомены_разные_записи():
    """a.ru — с поддоменами, *.a.ru — только поддомены: смысл разный."""
    assert routelist.parse("a.ru *.a.ru") == (["a.ru", "*.a.ru"], [])


def test_пример_из_окна():
    text = "a.ru, 1.2.3.4; *.b.ru  foo_bar"
    assert routelist.parse(text) == (["a.ru", "1.2.3.4/32", "*.b.ru"], ["foo_bar"])


@pytest.mark.parametrize("text", ["", "   ", "\n,;\n", None])
def test_пустое_поле_даёт_пустой_список(text):
    assert routelist.parse(text) == ([], [])


def test_готовый_список_разбирается_так_же():
    assert routelist.parse_list(["a.ru", "1.2.3.4", "x_y"]) == (
        ["a.ru", "1.2.3.4/32"], ["x_y"])
    assert routelist.parse_list(None) == ([], [])
