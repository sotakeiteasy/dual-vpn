"""Пробер: медленные сетевые проверки не накапливаются.

Сеть и WMI здесь не трогаем — подменяем probe_fast (туннель «поднят»),
probe_slow (висит, пока тест не отпустит) и запись status.json.
"""

import threading
import time

from dualvpn import probe


def test_второй_probe_slow_не_стартует_пока_идёт_первый(monkeypatch):
    monkeypatch.setattr(probe, "FAST_EVERY", 0.01)
    monkeypatch.setattr(probe, "SLOW_EVERY", 0.0)

    release = threading.Event()
    calls = []

    def slow(self):
        calls.append(time.monotonic())
        release.wait(5)

    def fast(self):
        self.set(tun=True, r_low=True)

    monkeypatch.setattr(probe.Prober, "probe_fast", fast)
    monkeypatch.setattr(probe.Prober, "probe_slow", slow)
    monkeypatch.setattr(probe.Prober, "write_status", lambda self: None)

    p = probe.Prober()
    loop = threading.Thread(target=p.run, daemon=True)
    loop.start()
    try:
        time.sleep(0.3)
        assert len(calls) == 1

        # Первая закончилась — следующая должна пойти сразу, а не никогда.
        release.set()
        deadline = time.monotonic() + 2
        while len(calls) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(calls) >= 2
    finally:
        release.set()
        p.stop_event.set()
        loop.join(2)
        # Поток проверки не должен пережить снятие подмен monkeypatch.
        deadline = time.monotonic() + 2
        while p.slow_busy.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)


def test_check_now_при_идущей_проверке_ждёт_её_а_не_запускает_вторую(monkeypatch):
    release = threading.Event()
    calls = []

    def slow(self):
        calls.append(1)
        release.wait(5)

    monkeypatch.setattr(probe.Prober, "probe_slow", slow)
    p = probe.Prober()

    first = threading.Thread(target=p.check_now, daemon=True)
    first.start()
    time.sleep(0.1)
    second = threading.Thread(target=p.check_now, daemon=True)
    second.start()
    time.sleep(0.3)
    # Второй вызов ждёт первую проверку, своей не запускает.
    assert calls == [1] and second.is_alive()

    release.set()
    first.join(2)
    second.join(2)
    assert not second.is_alive() and calls == [1]
    assert not p.slow_busy.is_set()


def test_check_now_без_идущей_проверки_проверяет_сразу(monkeypatch):
    calls = []
    monkeypatch.setattr(probe.Prober, "probe_slow", lambda self: calls.append(1))
    p = probe.Prober()
    p.check_now()
    p.check_now()
    assert calls == [1, 1]
