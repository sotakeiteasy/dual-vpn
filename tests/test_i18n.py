"""Язык интерфейса: английский при любой английской системе, иначе русский."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

import i18n  # noqa: E402
from menumodel import menu_model  # noqa: E402

IDLE = {"phase": "idle", "step": "", "busy": False, "error": "", "error_log": []}
UP = {"tun": "utun7", "r_low": True, "exit_state": "tunnel", "corp_ip": "172.15.0.5",
      "exit_country": "DE"}


class SystemLangTests(unittest.TestCase):
    def test_any_english_is_english(self):
        for first in ("en-US", "en-GB", "en-AU", "en", "en_IN"):
            self.assertEqual(i18n.system_lang([first, "ru-RU"]), "en", first)

    def test_russian_and_others_stay_russian(self):
        for first in ("ru-RU", "de-DE", "uk-UA"):
            self.assertEqual(i18n.system_lang([first, "en-US"]), "ru", first)

    def test_first_language_wins(self):
        self.assertEqual(i18n.system_lang(["ru-RU", "en-US"]), "ru")

    def test_no_system_answer_falls_back_to_locale(self):
        self.assertEqual(i18n.system_lang([], {"LANG": "en_GB.UTF-8"}), "en")
        self.assertEqual(i18n.system_lang([], {}), "ru")


class EnglishMenuTests(unittest.TestCase):
    def setUp(self):
        self.was = i18n.LANG
        i18n.LANG = "en"

    def tearDown(self):
        i18n.LANG = self.was

    def test_menu_has_no_russian(self):
        for st, op in (({}, IDLE), (UP, IDLE),
                       (UP, {**IDLE, "phase": "restarting", "busy": True}),
                       ({**UP, "corp_ip": "", "exit_state": "down"}, IDLE)):
            m = menu_model(st, op)
            text = repr({k: m[k] for k in ("title", "note", "rows")})
            self.assertNotRegex(text, "[А-Яа-яЁё]", text)

    def test_up_reads_in_english(self):
        m = menu_model(UP, IDLE)
        self.assertEqual(m["title"], "All working")
        self.assertEqual([r["name"] for r in m["rows"]], ["Personal", "Corp"])
        self.assertEqual(m["rows"][1]["value"], "connected")


if __name__ == "__main__":
    unittest.main()
