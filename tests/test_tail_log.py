"""Хвост журнала sing-box: окно просит его раз в две секунды.

Журнал за долгую сессию растёт до мегабайт, поэтому важно не только что
вернулось, но и сколько прочитано с диска.
"""

import os
import types

import pytest

from tunnelvpn import paths, service, tunnels
from tunnelvpn.service import Core


@pytest.fixture
def core(monkeypatch):
    """Core без службы и без туннелей: читается только журнал vpn."""
    core = Core.__new__(Core)
    core.tunnel = types.SimpleNamespace(sides=[])
    monkeypatch.setattr(Core, "_tunnels", staticmethod(tunnels.empty))
    return core


def _log(name, lines):
    path = os.path.join(paths.LOGS, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(f"{line}\n" for line in lines)
    return path


@pytest.fixture
def big_log():
    path = os.path.join(paths.LOGS, "vpn-2099-12-31_235959.log")
    with open(path, "w", encoding="utf-8", newline="\r\n") as fh:
        for i in range(80000):
            fh.write(f"+0300 2026-10-04 12:00:00 INFO [{i}] строка номер {i:06d}\n")
    try:
        assert os.path.getsize(path) > 5 * 1024 * 1024
        yield path
    finally:
        os.remove(path)


def test_возвращает_последние_строки_большого_журнала(core, big_log):
    lines = core._tail_log(400)
    assert len(lines) == 400
    assert lines[0].endswith("строка номер 079600")
    assert lines[-1].endswith("строка номер 079999")


def test_не_читает_журнал_целиком(core, big_log, monkeypatch):
    read = []
    real_open = open

    class Spy:
        def __init__(self, fh):
            self.fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.fh.close()

        def seek(self, *a):
            return self.fh.seek(*a)

        def read(self, *a):
            data = self.fh.read(*a)
            read.append(len(data))
            return data

    monkeypatch.setattr(service, "open",
                        lambda *a, **kw: Spy(real_open(*a, **kw)),
                        raising=False)
    core._tail_log(400)
    assert sum(read) <= service.LOG_TAIL_BYTES


def test_короткий_журнал_отдаётся_с_первой_строки(core):
    path = _log("vpn-2099-12-31_235958.log", ["первая", "вторая"])
    try:
        assert core._tail_log(400) == ["первая", "вторая"]
    finally:
        os.remove(path)


def test_журналы_туннеля_не_путаются_с_соседом_по_префиксу():
    made = [_log(n, ["x"]) for n in (
        "tunnel-work-2026-10-09_120000.log",
        "tunnel-work-2-2026-10-09_130000.log",
        "tunnel-work-2026-10-09_110000.log",
        "tunnel-work-старый.log")]
    try:
        assert [os.path.basename(p) for p in paths.log_files("tunnel-work")] == [
            "tunnel-work-2026-10-09_110000.log", "tunnel-work-2026-10-09_120000.log"]
        assert [os.path.basename(p) for p in paths.log_files("tunnel-work-2")] == [
            "tunnel-work-2-2026-10-09_130000.log"]
    finally:
        for p in made:
            os.remove(p)


def test_до_первого_включения_туннели_берутся_из_tunnels_json(core, monkeypatch):
    data = tunnels.validate({"tunnels": [
        {"id": "work", "name": "Работа", "mode": "list"}]})
    monkeypatch.setattr(Core, "_tunnels", staticmethod(lambda: data))
    path = _log("tunnel-work-2099-12-31_235959.log",
                ["+0300 2026-10-04 12:00:00 INFO из туннеля"])
    try:
        assert ("[Работа] +0300 2026-10-04 12:00:00 INFO из туннеля"
                in core._tail_log(10))
    finally:
        os.remove(path)
