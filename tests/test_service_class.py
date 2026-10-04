"""Класс службы: win32serviceutil должен найти его по строке модуля.

С Python 3.14 pickle.whichmodule проверяет, что класс лежит в модуле под своим
именем; без этого падают все команды dualvpn service. pywin32 есть только на
Windows — на остальных тест пропускается.
"""

import pytest

win32serviceutil = pytest.importorskip("win32serviceutil")

from dualvpn import service  # noqa: E402


def test_класс_службы_находится_по_строке_модуля():
    cls = service._service_class()

    assert service.DualVPNService is cls
    assert (win32serviceutil.GetServiceClassString(cls)
            == "dualvpn.service.DualVPNService")
