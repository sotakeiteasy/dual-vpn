"""Портативная версия: данные DualVPN переезжают под новое имя целиком."""

import sys

from tunnelvpn import portable


def test_старая_папка_данных_рядом_с_exe_переименовывается(tmp_path, monkeypatch):
    old = tmp_path / "DualVPN-Data" / "conf"
    old.mkdir(parents=True)
    (old / "tunnels.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "TunnelVPN-Portable.exe")])

    path = portable.data_dir()

    assert path == str(tmp_path / "TunnelVPN-Data")
    assert (tmp_path / "TunnelVPN-Data" / "conf" / "tunnels.json").is_file()
    assert not (tmp_path / "DualVPN-Data").exists()


def test_новая_папка_есть_старую_не_трогаем(tmp_path):
    (tmp_path / "DualVPN-Data").mkdir()
    (tmp_path / "TunnelVPN-Data").mkdir()

    path = portable._adopt(str(tmp_path / "DualVPN-Data"),
                           str(tmp_path / "TunnelVPN-Data"))

    assert path == str(tmp_path / "TunnelVPN-Data")
    assert (tmp_path / "DualVPN-Data").is_dir()


def test_нет_старой_папки_путь_прежний(tmp_path):
    path = portable._adopt(str(tmp_path / "DualVPN"), str(tmp_path / "TunnelVPN"))

    assert path == str(tmp_path / "TunnelVPN")
    assert not (tmp_path / "TunnelVPN").exists()
