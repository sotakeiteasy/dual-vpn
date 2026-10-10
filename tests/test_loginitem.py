"""Значок при входе в систему: что пишет LaunchAgent и чем запускает."""

import os
import plistlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

import loginitem  # noqa: E402

APP_SCRIPT = "/Applications/DualVPN.app/Contents/Resources/menubar.py"


class LoginItemTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "LaunchAgents", "agent.plist")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_bundle_is_opened_as_app(self):
        # Из .app — через open: иначе запустился бы голый python без бандла.
        self.assertEqual(loginitem.program(APP_SCRIPT, "/x/python"),
                         ["/usr/bin/open", "-a", "/Applications/DualVPN.app"])

    def test_source_runs_same_python_and_script(self):
        self.assertEqual(loginitem.program("/src/lib/scripts/menubar.py", "/v/bin/python3"),
                         ["/v/bin/python3", "/src/lib/scripts/menubar.py"])

    def test_enable_writes_agent_disable_removes_it(self):
        self.assertFalse(loginitem.enabled(self.path))
        self.assertEqual(loginitem.enable(APP_SCRIPT, "/x/python", self.path), "")
        self.assertTrue(loginitem.enabled(self.path))
        with open(self.path, "rb") as fh:
            d = plistlib.load(fh)
        self.assertEqual(d["Label"], loginitem.LABEL)
        self.assertIs(d["RunAtLoad"], True)
        self.assertNotIn("KeepAlive", d, "Выход из меню не должен поднимать значок снова")
        self.assertEqual(loginitem.disable(self.path), "")
        self.assertFalse(loginitem.enabled(self.path))
        self.assertEqual(loginitem.disable(self.path), "", "повторное выключение — не ошибка")


if __name__ == "__main__":
    unittest.main()
