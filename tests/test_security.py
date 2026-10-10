"""Границы доступа: кому что можно и что нельзя подсунуть службе.

Служба работает от SYSTEM и пишет в каталог, закрытый от обычного
пользователя. Значит два вопроса безопасности решаются здесь: какие команды
вообще требуют прав администратора и что считается допустимым именем файла.
Оба — тихие: ошибка не падает, а просто открывает лишнее.
"""

import pytest

from tunnelvpn import buildconfig, ipc


# ---------------------------------------------------- кому что разрешено

@pytest.mark.parametrize("op", ["status", "list-profiles", "log", "check", "howto"])
def test_чтение_состояния_доступно_всем(op):
    """Трей опрашивает статус и просит проверку от обычного пользователя,
    без всякого UAC. howto — окно на каждом открытии; списки правил в нём
    служба отдаёт только администратору (service.Core._howto)."""
    assert not ipc.requires_admin(op)


@pytest.mark.parametrize("op", ["start", "stop", "apply", "set-profile", "set-active",
                                "test-config", "set-enabled"])
def test_управление_туннелем_доступно_вошедшему(op):
    """Включить и выключить — это кнопка в трее, а не повышение прав. apply
    только применяет уже записанное администратором — не больше, чем
    выключить и включить. test-config проверяет уже лежащий конфиг и отдаёт
    только итог. set-enabled — то же выключить, только один туннель."""
    assert not ipc.requires_admin(op)


@pytest.mark.parametrize("op", [
    "add-config", "remove-config", "move-config", "read-config", "get-site", "set-site",
    "get-tunnels", "add-tunnel", "set-tunnel", "remove-tunnel",
    "set-log-level",
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
    "  corp  ",
    "personal.conf",
    "nl.",
    "CON",
])
def test_подозрительное_имя_конфига_отклоняется(name):
    """Через канал сюда приходит текст от пользователя, а пишем мы от SYSTEM.

    Без этой проверки «..\\..\\Windows\\System32» был бы обычной записью
    файла с правами системы. Имя из канала должно быть уже чистым —
    тем, что служба сама отдала в списке; чистить его здесь значило бы
    удалить или прочитать соседний файл.
    """
    with pytest.raises(ValueError):
        buildconfig.check_name(name)


@pytest.mark.parametrize("name", [
    "personal", "nl-1", "wg0-ivanov", "Офис Иванов", "my_vpn_", "_CON",
])
def test_чистое_имя_проходит_как_есть(name):
    assert buildconfig.check_name(name) == name
