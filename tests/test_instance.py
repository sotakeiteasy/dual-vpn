"""Один трей на сеанс: мьютекс и события на настоящих объектах ядра.

Имена — свои у каждого теста: рабочий трей на этой же машине держит
настоящие Local\\DualVPN-*, и тест не должен ни найти его, ни помешать ему.
"""

import sys
import threading
import uuid

import pytest

from dualvpn import instance

pytestmark = pytest.mark.skipif(sys.platform != "win32",
                                reason="именованные объекты ядра есть только в Windows")


def _name(what):
    return f"Local\\DualVPN-test-{what}-{uuid.uuid4().hex}"


def test_второй_захват_того_же_имени_не_проходит():
    name = _name("mutex")
    assert instance.claim(name) is True
    assert instance.claim(name) is False


def test_сигнал_доходит_до_слушателя():
    name = _name("event")
    got = threading.Event()
    instance.listen(name, got.set)

    assert instance.signal(name) is True
    assert got.wait(5)


def test_сигнал_без_слушателя_возвращает_false():
    assert instance.signal(_name("nobody"), wait=0.2) is False


def test_сигнал_дожидается_слушателя_который_появился_позже():
    name = _name("late")
    got = threading.Event()
    timer = threading.Timer(0.3, lambda: instance.listen(name, got.set))
    timer.start()

    assert instance.signal(name, wait=3) is True
    assert got.wait(5)
