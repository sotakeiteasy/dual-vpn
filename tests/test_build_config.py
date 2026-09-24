"""
Сборка config.json из .conf: AmneziaWG 2.0 и 3.x, ошибки с именем поля.

Если рядом лежит sing-box (lib/bin/sing-box), собранный конфиг ещё и
проверяется им самим: именно так ловится «сборка прошла, а ядро не приняло».
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "lib", "scripts", "build-config.py")
SING_BOX = os.path.join(ROOT, "lib", "bin", "sing-box")


def key():
    return base64.b64encode(os.urandom(32)).decode()


CORP = f"""[Interface]
PrivateKey = {key()}
Address = 10.0.1.52/32
DNS = 172.15.0.110

[Peer]
PublicKey = {key()}
Endpoint = 203.0.113.10:51830
AllowedIPs = 172.15.0.0/24, 10.13.35.0/28
PersistentKeepalive = 25
"""

# Так выглядит экспорт Amnezia с protocol_version 3.1.
AWG3 = f"""[Interface]
Address = 100.100.226.230/32
DNS = 100.64.0.1
PrivateKey = {key()}
Jc = 7
Jmin = 10
Jmax = 80
S1 = 962
S2 = 326
S3 = 524
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = {key()}
RekeyAfterTime = 100-120
RekeyTimeout = 3-8
RejectAfterTime = 150-180
KeepaliveTimeout = 7-13
MaxHandshakeAttempts = 15-20
ContentPaddingAddition = 10-100
RandomTrailers = true
DisableCookies = false
I1 = <b 0xc70000000108><r 64>
[Peer]
PublicKey = {key()}
PresharedKey = {key()}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.2:9713
PersistentKeepalive = 25-35
"""

AWG2 = f"""[Interface]
PrivateKey = {key()}
Address = 10.9.0.9/32
MTU = 1420
Jc = 9
Jmin = 40
Jmax = 70
S1 = 119
S2 = 112
H1 = 57565304-57665304
H2 = 1037727161-1037827161
H3 = 1447105519-1447205519
H4 = 1882654819-1882754819

[Peer]
PublicKey = {key()}
Endpoint = 198.51.100.3:4500
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""


class BuildConfigTests(unittest.TestCase):
    def setUp(self):
        self.data = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.data, "conf"))
        self.write("wg0-corp.conf", CORP)

    def tearDown(self):
        shutil.rmtree(self.data, ignore_errors=True)

    def write(self, name, text):
        with open(os.path.join(self.data, "conf", name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def build(self, profile):
        out = os.path.join(self.data, "config.json")
        env = {**os.environ, "DUALVPN_DATA": self.data, "LC_ALL": "C"}
        r = subprocess.run([sys.executable, SCRIPT, "--personal", profile, "--out", out],
                           capture_output=True, text=True, env=env)
        cfg = None
        if r.returncode == 0:
            with open(out, encoding="utf-8") as fh:
                cfg = json.load(fh)
        return r, cfg, out

    def personal(self, cfg):
        return next(e for e in cfg["endpoints"] if e["tag"] == "awg-personal")

    def check_with_sing_box(self, path):
        if not os.access(SING_BOX, os.X_OK):
            self.skipTest("нет lib/bin/sing-box")
        r = subprocess.run([SING_BOX, "check", "-c", path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, f"sing-box не принял конфиг:\n{r.stderr}{r.stdout}")

    def test_awg3_fields_are_mapped(self):
        self.write("de.conf", AWG3)
        r, cfg, _ = self.build("de")
        self.assertEqual(r.returncode, 0, r.stderr)
        ep = self.personal(cfg)
        self.assertEqual(ep["peers"][0]["persistent_keepalive_interval"], "25-35")
        for k, v in {"rekey_after_time": "100-120", "rekey_timeout": "3-8",
                     "reject_after_time": "150-180", "keepalive_timeout": "7-13",
                     "max_handshake_attempts": "15-20",
                     "content_padding_addition": "10-100"}.items():
            self.assertEqual(ep.get(k), v, k)
        self.assertEqual(len(base64.b64decode(ep["header_protection_key"])), 32)
        self.assertIs(ep["random_trailers"], True)
        self.assertIs(ep["disable_cookies"], False)
        self.assertEqual((ep["h1"], ep["s4"], ep["jc"]), (1, 12, 7))
        self.assertTrue(ep["i1"].startswith("<b 0x"))

    def test_awg3_accepted_by_sing_box(self):
        self.write("de.conf", AWG3)
        r, _, out = self.build("de")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_with_sing_box(out)

    def test_awg2_unchanged(self):
        self.write("personal.conf", AWG2)
        r, cfg, out = self.build("personal")
        self.assertEqual(r.returncode, 0, r.stderr)
        ep = self.personal(cfg)
        self.assertEqual(ep["h1"], "57565304-57665304")
        self.assertEqual(ep["peers"][0]["persistent_keepalive_interval"], 25)
        self.assertEqual(ep["mtu"], 1420)
        self.assertNotIn("header_protection_key", ep)
        self.check_with_sing_box(out)

    def test_bad_number_names_the_field(self):
        # Последняя строка вывода уходит в окно как причина — трейсбек там
        # ничего не скажет, имя поля скажет.
        self.write("de.conf", AWG3.replace("Jc = 7", "Jc = семь"))
        r, _, _ = self.build("de")
        self.assertNotEqual(r.returncode, 0)
        last = (r.stderr or r.stdout).strip().splitlines()[-1]
        self.assertIn("Jc", last)
        self.assertIn("семь", last)
        self.assertNotIn("Traceback", r.stderr)

    def test_bad_range_names_the_field(self):
        self.write("de.conf", AWG3.replace("PersistentKeepalive = 25-35",
                                           "PersistentKeepalive = 25-x"))
        r, _, _ = self.build("de")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PersistentKeepalive", r.stderr.strip().splitlines()[-1])


if __name__ == "__main__":
    unittest.main()
