"""Окно: как сохраняются настройки рабочей сети."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

try:
    import window  # noqa: E402
except ImportError:                     # AppKit есть не везде
    window = None


@unittest.skipIf(window is None, "нет AppKit")
class SaveSiteTests(unittest.TestCase):
    def setUp(self):
        self.w = window.Window.__new__(window.Window)
        self.w.data = tempfile.mkdtemp()
        self.w.log = lambda *a: None
        self.js = []
        self.w.eval = self.js.append
        self.w.status = lambda: {"up": False}
        self.w.push = lambda: None

    def test_pasted_column_becomes_one_line(self):
        self.w.save_site({"CORP_DOMAINS": "  corp.example.com\nexample.local\t\n",
                          "CORP_PROBE": "git.corp.example.com"})
        self.assertEqual(self.w.site()["CORP_DOMAINS"], "corp.example.com example.local")
        self.assertEqual(self.js, ["closeSheet()"])

    def test_quotes_are_refused(self):
        self.w.save_site({"CORP_PROBE": 'git"x'})
        self.assertFalse(os.path.exists(self.w.site_path()))
        self.assertIn("failed(", self.js[0])


if __name__ == "__main__":
    unittest.main()
