"""Постановка маршрутов: WMI вместо PowerShell, командлет — только запасной.

Настоящие маршруты без прав администратора не поставить — подменяем
подключение WMI и PowerShell и проверяем, кто из них что получил.
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

    def Methods_(self, _name):
        return types.SimpleNamespace(InParameters=types.SimpleNamespace(
            SpawnInstance_=_Params))

    def ExecMethod_(self, _name, params):
        code = self.fail_with.get(params["DestinationPrefix"], 0)
        if isinstance(code, Exception):
            raise code
        if code == 0:
            self.created.append((params["DestinationPrefix"],
                                 params["InterfaceIndex"], params["NextHop"],
                                 params["RouteMetric"], params["PolicyStore"]))
        return types.SimpleNamespace(ReturnValue=code)


def _setup(monkeypatch, cls, table=None):
    scripts = []
    monkeypatch.setattr(winnet, "_wmi",
                        lambda: types.SimpleNamespace(Get=lambda _n: cls))
    monkeypatch.setattr(winnet.PS, "run",
                        lambda script, timeout=30: scripts.append(script) or "")
    monkeypatch.setattr(winnet, "routes_for",
                        lambda prefix: (table or {}).get(prefix, []))
    return scripts


def test_маршруты_ставятся_через_wmi_без_powershell(monkeypatch):
    cls = _RouteClass()
    scripts = _setup(monkeypatch, cls)

    winnet.add_routes([("1.2.3.4/32", 18, "192.168.0.1", 1),
                       ("0.0.0.0/1", 45, "0.0.0.0", 1)])

    assert cls.created == [("1.2.3.4/32", 18, "192.168.0.1", 1, "ActiveStore"),
                           ("0.0.0.0/1", 45, "0.0.0.0", 1, "ActiveStore")]
    assert scripts == []


def test_успех_с_пустым_returnvalue_не_считается_сбоем(monkeypatch):
    """MSFT_NetRoute.Create на Windows 11 при успехе отдаёт None, а не 0."""
    cls = _RouteClass(fail_with={"1.2.3.4/32": None})
    scripts = _setup(monkeypatch, cls)
    monkeypatch.setattr(winnet, "routes_for",
                        lambda _p: (_ for _ in ()).throw(AssertionError("лишняя проверка")))
    winnet.last_error = ""

    winnet.add_routes([("1.2.3.4/32", 18, "192.168.0.1", 1)])

    assert scripts == [] and winnet.last_error == ""


def test_несработавший_маршрут_уходит_в_powershell_один(monkeypatch):
    cls = _RouteClass(fail_with={"1.2.3.4/32": RuntimeError("сбой")})
    scripts = _setup(monkeypatch, cls)

    winnet.add_routes([("1.2.3.4/32", 18, "192.168.0.1", 1),
                       ("5.6.7.8/32", 18, "192.168.0.1", 1)])

    assert len(scripts) == 1
    assert "1.2.3.4/32" in scripts[0] and "5.6.7.8/32" not in scripts[0]


def test_уже_стоящий_маршрут_не_гоняет_powershell(monkeypatch):
    """«Такой уже есть» — успех: New-NetRoute с SilentlyContinue его глотал."""
    cls = _RouteClass(fail_with={"0.0.0.0/1": 5})
    scripts = _setup(monkeypatch, cls,
                     table={"0.0.0.0/1": [{"InterfaceIndex": 45}]})

    winnet.add_routes([("0.0.0.0/1", 45, "0.0.0.0", 1)])

    assert scripts == []


def test_wmi_недоступен_все_маршруты_пачкой_в_powershell(monkeypatch):
    scripts = _setup(monkeypatch, None)

    def broken():
        raise RuntimeError("нет WMI")
    monkeypatch.setattr(winnet, "_wmi", broken)

    winnet.add_routes([("1.2.3.4/32", 18, "192.168.0.1", 1),
                       ("5.6.7.8/32", 18, "192.168.0.1", 1)])

    assert len(scripts) == 1
    assert "1.2.3.4/32" in scripts[0] and "5.6.7.8/32" in scripts[0]
