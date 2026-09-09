"""Границы доступа: кому что можно и что нельзя подсунуть службе.

Служба работает от SYSTEM и пишет в каталог, закрытый от обычного
пользователя. Значит два вопроса безопасности решаются здесь: какие команды
вообще требуют прав администратора и что считается допустимым именем файла.
Оба — тихие: ошибка не падает, а просто открывает лишнее.
"""

import pytest

from dualvpn import ipc
from dualvpn.service import Core


# ---------------------------------------------------- кому что разрешено

@pytest.mark.parametrize("op", ["status", "list-profiles", "log"])
def test_чтение_состояния_доступно_всем(op):
    """Трей опрашивает статус от обычного пользователя, без всякого UAC."""
    assert not ipc.requires_admin(op)


@pytest.mark.parametrize("op", ["start", "stop", "set-profile"])
def test_управление_туннелем_доступно_вошедшему(op):
    """Включить и выключить — это кнопка в трее, а не повышение прав."""
    assert not ipc.requires_admin(op)


@pytest.mark.parametrize("op", [
    "add-config", "remove-config", "read-config", "get-site", "set-site",
])
def test_работа_с_конфигами_требует_администратора(op):
    """В conf\\ лежат приватные ключи WireGuard.

    Читать их через канал обычный пользователь не должен: иначе именованный
    канал становится обходным путём вокруг прав на сам каталог.
    """
    assert ipc.requires_admin(op)


def test_незнакомая_команда_закрыта_по_умолчанию():
    """Новая команда должна быть закрытой, пока её явно не открыли."""
    assert ipc.requires_admin("что-то-новое")


# ------------------------------------------------------------ имя файла

@pytest.mark.parametrize("name", [
    "..",
    ".",
    "../secret",
    "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "sub/dir",
    "sub\\dir",
    "C:name",
    "na*me",
    "na?me",
    'na"me',
    "na|me",
    "na<me",
    "na>me",
    "",
    "   ",
])
def test_подозрительное_имя_конфига_отклоняется(name):
    """Через канал сюда приходит текст от пользователя, а пишем мы от SYSTEM.

    Без этой проверки «..\\..\\Windows\\System32» был бы обычной записью
    файла с правами системы.
    """
    with pytest.raises(ValueError):
        Core._safe_name(name)


@pytest.mark.parametrize("given,expected", [
    ("personal", "personal"),
    ("personal.conf", "personal"),
    ("nl-1", "nl-1"),
    ("wg0-ivanov.conf", "wg0-ivanov"),
    ("  corp  ", "corp"),
])
def test_нормальное_имя_проходит_и_чистится(given, expected):
    assert Core._safe_name(given) == expected
