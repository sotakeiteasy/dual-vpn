"""Постановка маршрутов: только WMI, PowerShell не запускается вовсе.

Настоящие маршруты без прав администратора не поставить — подменяем
подключение WMI и проверяем, что оно получило.
"""

import types

from dualvpn import winnet


class _Prop:
    def __init__(self, params, name):
        self.params, self.name = params, name

    @property
    def Value(self):
        return self.params[self.name]

    @Value.setter
    def Value(self, v):
        self.params[self.name] = v


class _Params(dict):
    def Properties_(self, name):
        return _Prop(self, name)


class _RouteClass:
    """MSFT_NetRoute: Create отвечает кодом из fail_with по префиксу."""

    def __init__(self, fail_with=None):
        self.fail_with = fail_with or {}
        self.created = []
        self.tries = []

    def Methods_(self, _name):
        return types.SimpleNamespace(InParameters=types.SimpleNamespace(
            SpawnInstance_=_Params))

    def ExecMethod_(self, _name, params):
        self.tries.append(params["DestinationPrefix"])
        code = self.fail_with.get(params["DestinationPrefix"], 0)
        if isinstance(code, Exception):
            raise code
        if code == 0:
            self.created.append((params["DestinationPrefix"],
                                 params["InterfaceIndex"], params["NextHop"],
                                 params["RouteMetric"], params["PolicyStore"]))
        return types.SimpleNamespace(ReturnValue=code)


def _setup(monkeypatch, cls, table=None):
    """Подменяет WMI; возвращает список сбоев, о которых winnet сообщил журналу."""
    reported = []
    monkeypatch.setattr(winnet, "_wmi",
                        lambda: types.SimpleNamespace(Get=lambda _n: cls))
    monkeypatch.setattr(winnet, "on_error", reported.append)
    monkeypatch.setattr(winnet, "_reported", "")
    monkeypatch.setattr(winnet, "routes_for",
                        lambda prefix: (table or {}).get(prefix, []))
    return reported


def test_маршруты_ставятся_через_wmi(monkeypatch):
    cls = _RouteClass()
    reported = _setup(monkeypatch, cls)

    winnet.add_routes([("1.2.3.4/32", 18, "192.168.0.1", 1),
                       ("0.0.0.0/1", 45, "0.0.0.0", 1)])

    assert cls.created == [("1.2.3.4/32", 18, "192.168.0.1", 1, "ActiveStore"),
                           ("0.0.0.0/1", 45, "0.0.0.0", 1, "ActiveStore")]
    assert reported == []


def test_успех_с_пустым_returnvalue_не_считается_сбоем(monkeypatch):
    """MSFT_NetRoute.Create на Windows 11 при успехе отдаёт None, а не 0."""
    cls = _RouteClass(fail_with={"1.2.3.4/32": None})
    reported = _setup(monkeypatch, cls)
    monkeypatch.setattr(winnet, "routes_for",
                        lambda _p: (_ for _ in ()).throw(AssertionError("лишняя проверка")))
    winnet.last_error = ""

    winnet.add_routes([("1.2.3.4/32", 18, "192.168.0.1", 1)])

    assert reported == [] and winnet.last_error == ""


def test_несработавший_маршрут_пробуется_ещё_раз_и_попадает_в_журнал(monkeypatch):
    """Запасного PowerShell нет: второй заход WMI, потом — строка в журнал."""
    cls = _RouteClass(fail_with={"1.2.3.4/32": RuntimeError("сбой")})
    reported = _setup(monkeypatch, cls)

    winnet.add_routes([("1.2.3.4/32", 18, "192.168.0.1", 1),
                       ("5.6.7.8/32", 18, "192.168.0.1", 1)])

    assert cls.tries == ["1.2.3.4/32", "5.6.7.8/32", "1.2.3.4/32"]
    assert len(reported) == 1
    assert "1.2.3.4/32" in reported[0] and "5.6.7.8/32" not in reported[0]


def test_уже_стоящий_маршрут_не_сбой(monkeypatch):
    """«Такой уже есть» WMI отдаёт ошибкой, а для нас это успех."""
    cls = _RouteClass(fail_with={"0.0.0.0/1": 5})
    reported = _setup(monkeypatch, cls,
                      table={"0.0.0.0/1": [{"InterfaceIndex": 45}]})

    winnet.add_routes([("0.0.0.0/1", 45, "0.0.0.0", 1)])

    assert cls.tries == ["0.0.0.0/1"] and reported == []


def test_wmi_недоступен_все_маршруты_в_журнал(monkeypatch):
    reported = _setup(monkeypatch, None)

    def broken():
        raise RuntimeError("нет WMI")
    monkeypatch.setattr(winnet, "_wmi", broken)

    winnet.add_routes([("1.2.3.4/32", 18, "192.168.0.1", 1),
                       ("5.6.7.8/32", 18, "192.168.0.1", 1)])

    assert len(reported) == 1
    assert "1.2.3.4/32" in reported[0] and "5.6.7.8/32" in reported[0]
    assert "нет WMI" in reported[0]


def test_повтор_одного_сбоя_в_журнал_не_пишется(monkeypatch):
    """Проверки идут каждым кругом пробера — журнал не должен забиваться."""
    reported = _setup(monkeypatch, None)

    for msg in ("WMI: a", "WMI: a", "WMI: b", "WMI: a"):
        winnet._fail(msg)

    assert reported == ["WMI: a", "WMI: b", "WMI: a"]
    assert winnet.last_error == "WMI: a"
