"""Проверка владения маршрутами — самое опасное место в проекте.

Половинки дефолтного маршрута (0.0.0.0/1 и 128.0.0.0/1) ставят себе и
Amnezia, и официальный клиент WireGuard, и любой другой VPN. Ошибка здесь не
«что-то не работает», а «выключил своё — оторвал сеть у соседнего туннеля»,
причём заметит это человек далеко не сразу.

Сеть подменяем целиком: настоящий winnet ходит в PowerShell, которого на
Linux нет, да и проверять надо не его, а решение «наш маршрут или нет».
"""

import pytest

from dualvpn import paths, tunnel


class FakeNet:
    """Таблица маршрутов в памяти + журнал снятий."""

    def __init__(self, tun_index=None, routes=None, live_ifaces=()):
        self._tun_index = tun_index
        self.routes = dict(routes or {})       # prefix -> [ {InterfaceIndex, NextHop} ]
        self.live_ifaces = set(live_ifaces)
        self.deleted = []                      # (prefix, if_index)

    def tun_index(self, _ip):
        return self._tun_index

    def interface_exists(self, if_index):
        return if_index in self.live_ifaces

    def routes_for(self, prefix):
        return list(self.routes.get(prefix, []))

    def del_route(self, prefix, if_index=None):
        self.deleted.append((prefix, if_index))
        self.routes[prefix] = [r for r in self.routes.get(prefix, [])
                               if r["InterfaceIndex"] != if_index]

    def routes_on_interface(self, if_index):
        return [p for p, rows in self.routes.items()
                if any(r["InterfaceIndex"] == if_index for r in rows)]


@pytest.fixture
def net(monkeypatch):
    fake = FakeNet()
    monkeypatch.setattr(tunnel, "winnet", fake)
    return fake


@pytest.fixture
def tun(net):
    return tunnel.Tunnel(log=lambda _line: None)


# ------------------------------------------------------------- is_ours

def test_живой_туннель_свой_интерфейс(tun, net):
    net._tun_index = 42
    assert tun.is_ours(42)


def test_живой_туннель_чужой_интерфейс_не_наш(tun, net):
    """Главная защита: сосед поднят, его интерфейс трогать нельзя."""
    net._tun_index = 42
    assert not tun.is_ours(17)


def test_туннеля_нет_но_индекс_запомнен(tun, net):
    """После падения интерфейс исчез — убрать за собой всё равно надо."""
    net._tun_index = None
    tun._tun_hint = 42
    assert tun.is_ours(42)


def test_туннеля_нет_подсказки_нет_интерфейс_жив_значит_чужой(tun, net):
    net._tun_index = None
    net.live_ifaces = {17}
    assert not tun.is_ours(17)


def test_маршрут_на_исчезнувший_интерфейс_считаем_своим(tun, net):
    """Мёртвый интерфейс не может принадлежать работающему соседу."""
    net._tun_index = None
    net.live_ifaces = set()
    assert tun.is_ours(17)


def test_none_никогда_не_наш(tun):
    assert not tun.is_ours(None)


# -------------------------------------------------------- del_net_ours

def test_снимаем_только_свою_строку_чужую_оставляем(tun, net):
    """Обе половинки висят и у нас, и у соседа — снять надо ровно нашу."""
    net._tun_index = 42
    net.routes["0.0.0.0/1"] = [
        {"InterfaceIndex": 42, "NextHop": "0.0.0.0"},   # наш
        {"InterfaceIndex": 17, "NextHop": "0.0.0.0"},   # соседний VPN
    ]

    tun.del_net_ours("0.0.0.0/1")

    assert net.deleted == [("0.0.0.0/1", 42)]
    assert [r["InterfaceIndex"] for r in net.routes["0.0.0.0/1"]] == [17]


def test_только_чужой_маршрут_не_трогаем_вовсе(tun, net):
    net._tun_index = 42
    net.routes["0.0.0.0/1"] = [{"InterfaceIndex": 17, "NextHop": "0.0.0.0"}]

    tun.del_net_ours("0.0.0.0/1")

    assert net.deleted == []


def test_пустая_таблица_ничего_не_ломает(tun, net):
    net._tun_index = 42
    tun.del_net_ours("0.0.0.0/1")
    assert net.deleted == []


# ------------------------------------------------------- del_host_ours

def test_шлюз_сменился_маршрут_не_наш(tun, net):
    """Сеть переключили — маршрут на пира уже не тот, что мы ставили."""
    net.routes["198.51.100.7/32"] = [
        {"InterfaceIndex": 5, "NextHop": "192.168.1.1"},
    ]

    tun.del_host_ours("198.51.100.7", want_gw="10.0.0.1")

    assert net.deleted == []


def test_шлюз_совпал_снимаем(tun, net):
    net.routes["198.51.100.7/32"] = [
        {"InterfaceIndex": 5, "NextHop": "10.0.0.1"},
    ]

    tun.del_host_ours("198.51.100.7", want_gw="10.0.0.1")

    assert net.deleted == [("198.51.100.7/32", 5)]


def test_без_журнала_маршрут_на_туннеле_не_наш(tun, net):
    """Свой host-маршрут на пира всегда идёт мимо туннеля, через аплинк.

    Указывает на tun — значит ставил кто-то другой.
    """
    net._tun_index = 42
    net.routes["198.51.100.7/32"] = [
        {"InterfaceIndex": 42, "NextHop": "0.0.0.0"},
    ]

    tun.del_host_ours("198.51.100.7")

    assert net.deleted == []


# ------------------------------------------------------- журнал владения

def test_журнал_переживает_перезапуск(tmp_path, monkeypatch):
    """Индекс tun поднимается из журнала — иначе после падения службы
    убирать за собой было бы нечем."""
    owned = tmp_path / "owned"
    monkeypatch.setattr(paths, "OWNED_FILE", str(owned))
    monkeypatch.setattr(paths, "ensure_dirs", lambda: None)

    first = tunnel.Tunnel(log=lambda _l: None)
    first.own("tun", 42)
    first.own("net", "0.0.0.0/1", 42)

    second = tunnel.Tunnel(log=lambda _l: None)
    assert second._our_tun_index() == 42
