"""Хвост журнала sing-box: окно просит его раз в две секунды.

Журнал за долгую сессию растёт до мегабайт, поэтому важно не только что
вернулось, но и сколько прочитано с диска.
"""

import os

import pytest

from dualvpn import paths, service
from dualvpn.service import Core


@pytest.fixture
def big_log():
    path = os.path.join(paths.LOGS, "vpn-99999999.log")
    with open(path, "w", encoding="utf-8", newline="\r\n") as fh:
        for i in range(80000):
            fh.write(f"+0300 2026-10-04 12:00:00 INFO [{i}] строка номер {i:06d}\n")
    try:
        assert os.path.getsize(path) > 5 * 1024 * 1024
        yield path
    finally:
        os.remove(path)


def test_возвращает_последние_строки_большого_журнала(big_log):
    lines = Core._tail_log(400)
    assert len(lines) == 400
    assert lines[0].endswith("строка номер 079600")
    assert lines[-1].endswith("строка номер 079999")


def test_не_читает_журнал_целиком(big_log, monkeypatch):
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
    Core._tail_log(400)
    assert sum(read) <= service.LOG_TAIL_BYTES


def test_короткий_журнал_отдаётся_с_первой_строки():
    path = os.path.join(paths.LOGS, "vpn-99999998.log")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("первая\nвторая\n")
    try:
        assert Core._tail_log(400) == ["первая", "вторая"]
    finally:
        os.remove(path)
