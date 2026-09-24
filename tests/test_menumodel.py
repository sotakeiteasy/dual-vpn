"""Что показывает меню-бар в каждом состоянии."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

from menumodel import menu_model  # noqa: E402

IDLE = {"phase": "idle", "step": "", "busy": False, "error": "", "error_log": []}
UP = {"tun": "utun7", "r_low": True, "exit_ip": "188.241.219.116",
      "exit_state": "tunnel", "corp_ip": "172.15.0.5",
      "exit_country": "DE", "exit_city": "Frankfurt am Main"}


def op(**kw):
    return {**IDLE, **kw}


def on(m):
    return {k for k, v in m["actions"].items() if v}


class MenuModelTests(unittest.TestCase):
    def test_off_offers_only_start(self):
        m = menu_model({}, IDLE)
        self.assertEqual(m["icon"], "off")
        self.assertEqual(m["title"], "Выключено")
        self.assertEqual(on(m), {"start"})
        self.assertEqual(m["lines"], [], "у выключенного нечего показывать построчно")

    def test_up_offers_stop_and_restart_not_start(self):
        # Раньше «Включить» при включённом делало kickstart -k — перезапуск.
        m = menu_model(UP, IDLE)
        self.assertEqual(m["icon"], "on")
        self.assertEqual(on(m), {"stop", "restart"})
        self.assertEqual(m["title"], "Включено · всё работает")
        self.assertIn("личный   ✓ 188.241.219.116", m["lines"])
        self.assertIn("выход    DE Frankfurt am Main", m["lines"])

    def test_busy_has_no_actions(self):
        for phase, title in (("starting", "Включаю…"), ("stopping", "Выключаю…"),
                             ("restarting", "Перезапускаю…")):
            m = menu_model(UP, op(phase=phase, busy=True, step="выключаю…"))
            self.assertEqual(m["icon"], "busy")
            self.assertEqual(m["title"], title)
            self.assertEqual(on(m), set(), f"{phase}: кнопки доступны посреди операции")
            self.assertEqual(m["lines"], ["выключаю…"])

    def test_error_offers_retry_and_details(self):
        m = menu_model({}, op(error="не удалось собрать конфиг — правь conf/*.conf\n"
                                    "ValueError: invalid literal"))
        self.assertEqual(m["icon"], "bad")
        self.assertEqual(m["title"], "Не удалось включить")
        self.assertEqual(on(m), {"start", "details"})
        self.assertEqual(m["start_label"], "Попробовать снова")
        self.assertEqual(m["lines"], ["не удалось собрать конфиг — правь conf/*.conf"])

    def test_error_ignored_when_up(self):
        # Туннель подняли уже после ошибки — она устарела.
        m = menu_model(UP, op(error="старое"))
        self.assertEqual(m["icon"], "on")

    def test_long_error_is_clipped(self):
        m = menu_model({}, op(error="x" * 300))
        self.assertLessEqual(len(m["lines"][0]), 64)
        self.assertTrue(m["lines"][0].endswith("…"))

    def test_corp_down(self):
        m = menu_model({**UP, "corp_ip": ""}, IDLE)
        self.assertEqual(m["icon"], "on")
        self.assertEqual(m["title"], "Включено · корп не отвечает")
        self.assertIn("корп     ✗ не отвечает", m["lines"])

    def test_leaks_are_bad(self):
        self.assertEqual(menu_model({**UP, "v6_leak": "2a00::1"}, IDLE)["icon"], "bad")
        m = menu_model({**UP, "exit_state": "leak"}, IDLE)
        self.assertEqual(m["icon"], "bad")
        self.assertEqual(m["title"], "Трафик идёт мимо туннеля")

    def test_unknown_exit_is_checking(self):
        m = menu_model({**UP, "exit_state": "unknown", "exit_ip": ""}, IDLE)
        self.assertIn("личный   проверяю…", m["lines"])

    def test_up_requires_our_routes(self):
        # tun есть, а маршрутов нет — это не «включено».
        m = menu_model({**UP, "r_low": False}, IDLE)
        self.assertEqual(m["icon"], "off")


if __name__ == "__main__":
    unittest.main()
