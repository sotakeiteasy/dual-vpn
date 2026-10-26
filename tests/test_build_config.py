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
        self.write("corp/office.conf", CORP)
        os.makedirs(os.path.join(self.data, "conf", "personal"))

    def tearDown(self):
        shutil.rmtree(self.data, ignore_errors=True)

    def write(self, rel, text):
        path = os.path.join(self.data, "conf", rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def build(self, profile="", **site):
        out = os.path.join(self.data, "config.json")
        env = {**os.environ, "DUALVPN_DATA": self.data, "LC_ALL": "C"}
        for k in ("SB_PERSONAL", "CORP_VIA", "CORP_NETS", "CORP_DNS", "SB_CORP_EXCLUDE"):
            env.pop(k, None)
        env.update(site)
        args = ["--personal", profile] if profile else []
        r = subprocess.run([sys.executable, SCRIPT, *args, "--out", out],
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
        self.write("personal/de.conf", AWG3)
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
        self.write("personal/de.conf", AWG3)
        r, _, out = self.build("de")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_with_sing_box(out)

    def test_awg2_unchanged(self):
        self.write("personal/home.conf", AWG2)
        r, cfg, out = self.build("home")
        self.assertEqual(r.returncode, 0, r.stderr)
        ep = self.personal(cfg)
        self.assertEqual(ep["h1"], "57565304-57665304")
        self.assertEqual(ep["peers"][0]["persistent_keepalive_interval"], 25)
        self.assertEqual(ep["mtu"], 1420)
        self.assertNotIn("header_protection_key", ep)
        self.check_with_sing_box(out)

    def turn_off(self, which):
        state = os.path.join(self.data, "lib", "state")
        os.makedirs(state, exist_ok=True)
        with open(os.path.join(state, "off"), "w", encoding="utf-8") as fh:
            fh.write(which)

    def test_corp_off_drops_endpoint_routes_and_dns(self):
        # Истёкший корп выключен в окне: его файл даже не читаем.
        self.write("personal/home.conf", AWG2)
        self.write("corp/office.conf", "мусор")
        self.turn_off("corp")
        r, cfg, out = self.build("home")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([e["tag"] for e in cfg["endpoints"]], ["awg-personal"])
        self.assertNotIn("wg-corp", json.dumps(cfg))
        self.assertEqual(cfg["route"]["final"], "awg-personal")
        self.check_with_sing_box(out)

    def test_personal_off_sends_the_rest_direct(self):
        self.turn_off("personal")
        r, cfg, out = self.build("нет-такого")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([e["tag"] for e in cfg["endpoints"]], ["wg-corp"])
        self.assertEqual(cfg["route"]["final"], "direct")
        self.assertNotIn("awg-personal", json.dumps(cfg))
        dns = {s["tag"]: s for s in cfg["dns"]["servers"]}
        self.assertNotIn("detour", dns["dns-personal"])
        self.assertEqual(dns["dns-corp"]["detour"], "wg-corp")
        self.check_with_sing_box(out)

    def wire_rule(self, cfg):
        return next(r for r in cfg["route"]["rules"] if r.get("outbound") == "corp-wire")

    def test_wire_without_work_config(self):
        # По проводу рабочий конфиг не нужен: подсети и DNS — из настроек.
        shutil.rmtree(os.path.join(self.data, "conf", "corp"))
        self.write("personal/home.conf", AWG2)

        r, cfg, out = self.build("home", CORP_VIA="wire", CORP_NETS="172.15.0.0/24, 198.51.100.23/32",
                                 CORP_DNS="172.15.0.110", CORP_DOMAINS="corp.example.com")

        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([e["tag"] for e in cfg["endpoints"]], ["awg-personal"])
        self.assertEqual(self.wire_rule(cfg)["ip_cidr"], ["172.15.0.0/24", "198.51.100.23/32"])
        self.assertEqual(cfg["route"]["final"], "awg-personal")
        dns = {s["tag"]: s for s in cfg["dns"]["servers"]}
        self.assertEqual(dns["dns-corp"]["server"], "172.15.0.110")
        self.assertNotIn("detour", dns["dns-corp"])
        self.assertIn({"domain_suffix": ["corp.example.com"], "server": "dns-corp"}, cfg["dns"]["rules"])
        self.check_with_sing_box(out)

    def test_wire_takes_subnets_and_dns_from_work_config(self):
        self.write("personal/home.conf", AWG2)

        r, cfg, _ = self.build("home", CORP_VIA="wire")

        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("wg-corp", json.dumps(cfg))
        self.assertEqual(self.wire_rule(cfg)["ip_cidr"], ["172.15.0.0/24", "10.13.35.0/28"])
        dns = {s["tag"]: s for s in cfg["dns"]["servers"]}
        self.assertEqual(dns["dns-corp"]["server"], "172.15.0.110")

    def test_wire_routes_dns_outside_subnets_direct(self):
        self.write("personal/home.conf", AWG2)

        r, cfg, _ = self.build("home", CORP_VIA="wire", CORP_NETS="10.13.35.0/28",
                               CORP_DNS="192.0.2.53")

        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.wire_rule(cfg)["ip_cidr"], ["10.13.35.0/28", "192.0.2.53/32"])

    def test_wire_drops_bad_dns(self):
        self.write("personal/home.conf", AWG2)

        r, cfg, _ = self.build("home", CORP_VIA="wire", CORP_NETS="10.13.35.0/28",
                               CORP_DNS="999.1.1.1")

        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.wire_rule(cfg)["ip_cidr"], ["10.13.35.0/28"])
        self.assertNotIn("dns-corp", json.dumps(cfg))

    def test_wire_without_subnets_fails(self):
        shutil.rmtree(os.path.join(self.data, "conf", "corp"))
        self.write("personal/home.conf", AWG2)

        r, _, _ = self.build("home", CORP_VIA="wire", CORP_DNS="172.15.0.110")

        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no internal subnets", r.stderr)

    def test_wire_bad_subnet_names_it(self):
        self.write("personal/home.conf", AWG2)

        r, _, _ = self.build("home", CORP_VIA="wire", CORP_NETS="172.15.0.0/24 fd00::/8")

        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fd00::/8", r.stderr)

    def test_wire_with_personal_off_fails(self):
        self.write("personal/home.conf", AWG2)
        self.turn_off("personal")

        r, _, _ = self.build("home", CORP_VIA="wire")

        self.assertNotEqual(r.returncode, 0)
        self.assertIn("nothing to bring up", r.stderr)

    def test_corp_off_beats_wire(self):
        self.write("personal/home.conf", AWG2)
        self.turn_off("corp")

        r, cfg, _ = self.build("home", CORP_VIA="wire")

        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("corp-wire", json.dumps(cfg))
        self.assertNotIn("dns-corp", json.dumps(cfg))

    def endpoint_port(self, cfg, tag):
        return next(e for e in cfg["endpoints"] if e["tag"] == tag)["peers"][0]["port"]

    def test_any_names_role_comes_from_folder(self):
        # Имена, по которым раньше роль угадывалась бы наоборот.
        shutil.rmtree(os.path.join(self.data, "conf", "corp"))
        self.write("corp/awg-office.conf", CORP)
        self.write("personal/wg0-home.conf", AWG2)

        r, cfg, _ = self.build()

        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.endpoint_port(cfg, "wg-corp"), 51830)
        self.assertEqual(self.endpoint_port(cfg, "awg-personal"), 4500)

    def test_default_profile_is_first_and_saved(self):
        self.write("personal/nl.conf", AWG2)
        self.write("personal/de.conf", AWG3)

        r, cfg, _ = self.build()

        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.endpoint_port(cfg, "awg-personal"), 9713)
        with open(os.path.join(self.data, "lib", "state", "profile"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "de")

    def test_several_work_configs_fail(self):
        self.write("personal/de.conf", AWG3)
        self.write("corp/old.conf", CORP)

        r, _, _ = self.build()

        self.assertNotEqual(r.returncode, 0)
        last = r.stderr.strip().splitlines()
        self.assertIn("several work configs", r.stderr)
        self.assertIn("office, old", r.stderr)
        self.assertEqual(last[-1], "keep only one")

    def test_unknown_profile_lists_personal(self):
        self.write("personal/de.conf", AWG3)
        r, _, _ = self.build("nl")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no personal config 'nl'", r.stderr)
        self.assertIn("found: de", r.stderr)

    def test_flat_conf_without_folders_still_builds(self):
        # Windows папок не заводит: там роль по-прежнему по имени.
        shutil.rmtree(os.path.join(self.data, "conf"))
        self.write("wg0-corp.conf", CORP)
        self.write("personal.conf", AWG2)

        r, cfg, _ = self.build()

        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.endpoint_port(cfg, "wg-corp"), 51830)
        self.assertEqual(self.endpoint_port(cfg, "awg-personal"), 4500)

    def test_bad_number_names_the_field(self):
        # Последняя строка вывода уходит в окно как причина — трейсбек там
        # ничего не скажет, имя поля скажет.
        self.write("personal/de.conf", AWG3.replace("Jc = 7", "Jc = семь"))
        r, _, _ = self.build("de")
        self.assertNotEqual(r.returncode, 0)
        last = (r.stderr or r.stdout).strip().splitlines()[-1]
        self.assertIn("Jc", last)
        self.assertIn("семь", last)
        self.assertNotIn("Traceback", r.stderr)

    def test_bad_range_names_the_field(self):
        self.write("personal/de.conf", AWG3.replace("PersistentKeepalive = 25-35",
                                           "PersistentKeepalive = 25-x"))
        r, _, _ = self.build("de")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PersistentKeepalive", r.stderr.strip().splitlines()[-1])


if __name__ == "__main__":
    unittest.main()
