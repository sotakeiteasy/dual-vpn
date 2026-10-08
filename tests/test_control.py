"""
Контроллер включения/выключения: сценарии против имитации службы.

Время — поддельное: sleep() двигает часы, поэтому таймауты в десятки секунд
проверяются мгновенно. Служба описывается расписанием событий по этим часам.

    python3 -m unittest discover -s tests
"""

import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

import control  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def now(self):
        return self.t

    def sleep(self, dt):
        self.t += dt


class FakeDaemon(control.Ops):
    """Служба и сеть как их видит контроллер. Поведение задаётся полями:

      start_mode: ok | config_error | silent_exit | hang | kick_error
      stop_mode:  ok | hang_until_direct | never | stop_error
    """

    def __init__(self, clock, start_mode="ok", stop_mode="ok"):
        self.clock = clock
        self.start_mode = start_mode
        self.stop_mode = stop_mode
        self.up = False
        self.running = False
        self.err_text = ""
        self.err_time = 0.0
        self.err_removable = True
        self.calls = []
        self.events = []            # (время, функция)
        self.session = ["=== старт ===", "→ собираю конфиг", "ValueError: '25-35'"]

    # --- расписание
    def at(self, dt, fn):
        self.events.append((self.clock.now() + dt, fn))

    def _tick(self):
        now = self.clock.now()
        due = [e for e in self.events if e[0] <= now]
        self.events = [e for e in self.events if e[0] > now]
        for _, fn in sorted(due, key=lambda e: e[0]):
            fn()

    def _set(self, **kw):
        return lambda: [setattr(self, k, v) for k, v in kw.items()]

    def _write_error(self, text):
        def fn():
            self.err_text = text
            self.err_time = self.clock.now()
        return fn

    # --- Ops
    def kickstart(self):
        self.calls.append("kickstart")
        if self.start_mode == "kick_error":
            return "нет прав: переустанови (install-daemon.sh)"
        self.running = True
        if self.start_mode == "ok":
            self.at(3, self._set(up=True))
        elif self.start_mode == "config_error":
            self.at(1, self._write_error("не удалось собрать конфиг — правь conf/*.conf\n"
                                         "ValueError: '25-35'"))
            self.at(1.5, self._set(running=False))
        elif self.start_mode == "silent_exit":
            self.at(2, self._set(running=False))
        # hang: жив, но туннель так и не поднимается
        return ""

    def stop(self):
        self.calls.append("stop")
        if self.stop_mode == "stop_error":
            return "нет прав"
        if self.stop_mode == "ok":
            self.at(2, self._set(up=False))
            self.at(4, self._set(running=False))
        return ""

    def stop_direct(self):
        self.calls.append("stop_direct")
        if self.stop_mode == "hang_until_direct":
            self.at(1, self._set(up=False, running=False))
        return ""

    def daemon_running(self):
        self._tick()
        return self.running

    def is_up(self):
        self._tick()
        return self.up

    def last_error(self, since=0.0):
        self._tick()
        if self.err_text and self.err_time >= since:
            return self.err_text
        return ""

    def clear_error(self):
        self.calls.append("clear_error")
        if self.err_removable:
            self.err_text = ""

    def session_tail(self, n):
        self._tick()
        return self.session[-n:]


def make(start_mode="ok", stop_mode="ok", up=False, running=False):
    clock = Clock()
    ops = FakeDaemon(clock, start_mode, stop_mode)
    ops.up, ops.running = up, running
    changes = []
    ctrl = control.Controller(ops, on_change=lambda: changes.append(ctrl.snapshot()),
                              clock=clock.now, sleep=clock.sleep, poll=0.5)
    return ctrl, ops, clock, changes


def run(ctrl, action):
    assert getattr(ctrl, action)(), f"{action} не запустился"
    ctrl.wait(5)
    assert not ctrl.busy(), "операция не закончилась"
    return ctrl.snapshot()


class StartTests(unittest.TestCase):
    def test_success_waits_for_tunnel(self):
        ctrl, ops, clock, _ = make("ok")
        t0 = clock.now()
        snap = run(ctrl, "start")
        self.assertEqual(snap["error"], "")
        self.assertTrue(ops.up)
        self.assertGreaterEqual(clock.now() - t0, 3, "вернулся раньше, чем поднялся туннель")
        self.assertEqual(ops.calls, ["clear_error", "kickstart"])

    def test_shows_watchdog_restart(self):
        # Сторож службы перезапустил sing-box — в шаге видно, на что ушли секунды.
        ctrl, ops, _, changes = make("ok")
        step = "перезапускаю sing-box: порт занят (попытка 1 из 3)…"
        ops.at(1, ops._set(session=["=== старт ===", "→ запускаю sing-box…",
                                    "→ перезапускаю sing-box: порт занят (попытка 1 из 3)"]))
        snap = run(ctrl, "start")
        self.assertEqual(snap["error"], "")
        steps = [c["step"] for c in changes]
        self.assertEqual(steps.count(step), 1,
                         "шага нет или он перерисовывается на каждом опросе")

    def test_already_up_does_not_kick(self):
        # kickstart -k на поднятой службе — это её убийство и перезапуск.
        ctrl, ops, _, _ = make("ok", up=True, running=True)
        snap = run(ctrl, "start")
        self.assertEqual(snap["error"], "")
        self.assertNotIn("kickstart", ops.calls)

    def test_config_error_is_reported_with_reason(self):
        ctrl, ops, clock, _ = make("config_error")
        t0 = clock.now()
        snap = run(ctrl, "start")
        self.assertIn("не удалось собрать конфиг", snap["error"])
        self.assertIn("25-35", snap["error"])
        self.assertTrue(snap["error_log"], "к ошибке не приложен лог")
        # Причину узнаём сразу, а не по таймауту.
        self.assertLess(clock.now() - t0, 5)

    def test_stale_error_from_previous_attempt_is_ignored(self):
        # Файл с причиной не удалился (чужой владелец) — старую причину нельзя
        # выдать за новую: отсекаем по времени.
        ctrl, ops, clock, _ = make("ok")
        ops.err_text, ops.err_time = "старая причина", clock.now() - 60
        ops.err_removable = False
        run(ctrl, "start")
        self.assertTrue(ops.up, "старт споткнулся о чужую старую причину")
        self.assertEqual(ctrl.error, "", "старая причина выдана за исход нового старта")

    def test_daemon_exits_silently(self):
        ctrl, ops, clock, _ = make("silent_exit")
        t0 = clock.now()
        snap = run(ctrl, "start")
        self.assertIn("служба завершилась", snap["error"])
        self.assertLess(clock.now() - t0, 10, "молчаливый выход ждали до таймаута")

    def test_hang_times_out_and_cleans_up(self):
        ctrl, ops, clock, _ = make("hang")
        snap = run(ctrl, "start")
        self.assertIn("не поднялся за 75", snap["error"])
        self.assertIn("stop", ops.calls, "после таймаута полуподнятое не убрано")

    def test_kickstart_error_is_immediate(self):
        ctrl, ops, clock, _ = make("kick_error")
        t0 = clock.now()
        snap = run(ctrl, "start")
        self.assertIn("нет прав", snap["error"])
        self.assertEqual(clock.now(), t0)


class StopTests(unittest.TestCase):
    def test_waits_until_daemon_is_gone(self):
        ctrl, ops, clock, _ = make(up=True, running=True)
        t0 = clock.now()
        snap = run(ctrl, "stop")
        self.assertEqual(snap["error"], "")
        self.assertFalse(ops.running)
        self.assertGreaterEqual(clock.now() - t0, 4, "вернулся, пока служба ещё убирала")

    def test_stop_forgets_old_error(self):
        ctrl, ops, clock, _ = make(up=True, running=True)
        ops.err_text, ops.err_time = "старое", clock.now()
        run(ctrl, "stop")
        self.assertIn("clear_error", ops.calls)
        self.assertEqual(ctrl.snapshot()["error"], "")

    def test_escalates_to_direct_cleanup(self):
        ctrl, ops, clock, _ = make(stop_mode="hang_until_direct", up=True, running=True)
        snap = run(ctrl, "stop")
        self.assertEqual(snap["error"], "")
        self.assertEqual(ops.calls.count("stop_direct"), 1)

    def test_gives_up_with_message(self):
        ctrl, ops, clock, _ = make(stop_mode="never", up=True, running=True)
        snap = run(ctrl, "stop")
        self.assertIn("не выключился", snap["error"])

    def test_stop_command_error(self):
        ctrl, ops, _, _ = make(stop_mode="stop_error", up=True, running=True)
        snap = run(ctrl, "stop")
        self.assertEqual(snap["error"], "нет прав")


class RestartTests(unittest.TestCase):
    def test_full_stop_then_start(self):
        # Перезапуск — полное выключение (служба вышла) и только потом старт.
        ctrl, ops, clock, _ = make(up=True, running=True)
        seen = []
        orig = ops.kickstart
        ops.kickstart = lambda: (seen.append(ops.running), orig())[1]
        snap = run(ctrl, "restart")
        self.assertEqual(snap["error"], "")
        self.assertTrue(ops.up)
        self.assertEqual(seen, [False], "старт при ещё живой службе")
        self.assertLess(ops.calls.index("stop"), ops.calls.index("kickstart"))

    def test_aborts_when_stop_fails(self):
        ctrl, ops, _, _ = make(stop_mode="stop_error", up=True, running=True)
        snap = run(ctrl, "restart")
        self.assertIn("не выключился", snap["error"])
        self.assertNotIn("kickstart", ops.calls)

    def test_restart_reports_start_failure(self):
        ctrl, ops, _, _ = make(start_mode="config_error", up=True, running=True)
        snap = run(ctrl, "restart")
        self.assertIn("не удалось собрать конфиг", snap["error"])


class ConcurrencyTests(unittest.TestCase):
    def test_second_command_is_rejected_while_busy(self):
        gate = threading.Event()
        ctrl, ops, _, _ = make("ok")
        orig = ops.kickstart
        ops.kickstart = lambda: (gate.wait(5), orig())[1]
        self.assertTrue(ctrl.start())
        self.assertTrue(ctrl.busy())
        self.assertFalse(ctrl.stop(), "вторая команда прошла посреди первой")
        self.assertFalse(ctrl.restart())
        gate.set()
        ctrl.wait(5)
        self.assertFalse(ctrl.busy())
        self.assertEqual(ops.calls.count("kickstart"), 1)

    def test_notifies_busy_then_idle(self):
        ctrl, _, _, changes = make("ok")
        run(ctrl, "start")
        self.assertTrue(changes[0]["busy"])
        self.assertEqual(changes[0]["phase"], control.STARTING)
        self.assertFalse(changes[-1]["busy"])

    def test_exception_in_ops_does_not_stick(self):
        ctrl, ops, _, _ = make("ok")

        def boom():
            raise RuntimeError("сломалось")
        ops.kickstart = boom
        snap = run(ctrl, "start")
        self.assertIn("сломалось", snap["error"])
        self.assertTrue(ctrl.start(), "после исключения контроллер залип в занятом")
        ctrl.wait(5)


class SnapshotTests(unittest.TestCase):
    def test_shows_daemon_error_when_idle(self):
        # Служба упала сама, пока окно было закрыто: ошибку всё равно видно.
        ctrl, ops, clock, _ = make()
        ops.err_text, ops.err_time = "tun не поднялся за 30 с", clock.now()
        snap = ctrl.snapshot()
        self.assertEqual(snap["error"], "tun не поднялся за 30 с")
        self.assertTrue(snap["error_log"])

    def test_dismiss(self):
        ctrl, ops, clock, _ = make("config_error")
        run(ctrl, "start")
        ctrl.dismiss()
        self.assertEqual(ctrl.snapshot()["error"], "")
        self.assertIn("clear_error", ops.calls)


class FileHelpersTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def write(self, name, text, mode="w"):
        p = os.path.join(self.dir, name)
        with open(p, mode, encoding=None if "b" in mode else "utf-8") as fh:
            fh.write(text)
        return p

    def test_read_tail_strips_ansi_and_limits(self):
        p = self.write("ui.log", "".join(f"\x1b[31mERROR\x1b[0m строка {i}\n" for i in range(50)))
        lines = control.read_tail(p, keep=5)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[-1], "ERROR строка 49")

    def test_read_tail_missing_file(self):
        self.assertEqual(control.read_tail(os.path.join(self.dir, "нет")), [])

    def test_last_session(self):
        lines = ["=== 1 ===", "старое", "=== 2 ===", "новое"]
        self.assertEqual(control.last_session(lines), ["=== 2 ===", "новое"])
        self.assertEqual(control.last_session(["без шапки"]), ["без шапки"])

    def test_read_last_error_respects_since(self):
        p = self.write("last-error", "причина\nподробность\n")
        self.assertEqual(control.read_last_error(p), "причина\nподробность")
        self.assertEqual(control.read_last_error(p, since=time.time() + 60), "")
        self.assertEqual(control.read_last_error(os.path.join(self.dir, "нет")), "")


if __name__ == "__main__":
    unittest.main()
