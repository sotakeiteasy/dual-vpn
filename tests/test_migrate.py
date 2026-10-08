"""Переезд конфигов при установке из .app: migrate-data.sh."""

import os
import plistlib
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "lib", "scripts", "migrate-data.sh")


class MigrateTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.mkdtemp()
        self.old = os.path.join(root, "repo")             # установка из исходников
        self.new = os.path.join(root, "Application Support", "DualVPN")
        self.plist = os.path.join(root, "local.singbox-lx.plist")
        self.put(self.old, "conf/corp.conf", "[Interface]\nPrivateKey = corp\n", 0o600)
        self.put(self.old, "conf/awg-home.conf", "[Interface]\nPrivateKey = home\n", 0o600)
        self.put(self.old, "conf/site.env", 'CORP_DOMAINS="corp.example.com"\n')
        self.put(self.old, "conf/personal.conf.example", "пример\n")
        self.put(self.old, "lib/state/profile", "awg-home")
        self.service(self.old)

    @staticmethod
    def put(base, rel, text, mode=0o644):
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(path, mode)

    def service(self, data):
        with open(self.plist, "wb") as fh:
            plistlib.dump({"Label": "local.singbox-lx",
                           "ProgramArguments": ["/bin/bash", f"{self.old}/vpn", "daemon"],
                           "EnvironmentVariables": {"DUALVPN_DATA": data}}, fh)

    def run_script(self):
        return subprocess.run(["/bin/bash", SCRIPT, self.plist, self.new],
                              capture_output=True, text=True, check=True).stdout

    def files(self, sub):
        try:
            return sorted(os.listdir(os.path.join(self.new, sub)))
        except FileNotFoundError:
            return []

    def test_configs_move_from_source_install(self):
        out = self.run_script()
        self.assertIn(self.old, out)
        self.assertEqual(self.files("conf"), ["awg-home.conf", "corp.conf", "site.env"])
        self.assertEqual(self.files("lib/state"), ["profile"])
        # Приватные ключи переезжают с теми же правами.
        mode = os.stat(os.path.join(self.new, "conf", "corp.conf")).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        # Исходники не трогаем.
        self.assertTrue(os.path.exists(os.path.join(self.old, "conf", "corp.conf")))

    def test_existing_configs_are_not_overwritten(self):
        self.put(self.new, "conf/wg.conf", "своё\n")
        self.run_script()
        self.assertEqual(self.files("conf"), ["wg.conf"])

    def test_service_already_on_new_place(self):
        self.service(self.new)
        self.run_script()
        self.assertEqual(self.files("conf"), [])

    def test_no_service_no_move(self):
        os.unlink(self.plist)
        self.assertEqual(self.run_script(), "")
        self.assertEqual(self.files("conf"), [])


if __name__ == "__main__":
    unittest.main()
