"""Пробер: чей маршрут считается нашим и как переживаются разовые сбои проб."""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

import tui  # noqa: E402

NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                utun5              UScg                utun5
default            192.168.1.1        UGScg                 en0
128.0/1            utun7              UScg                utun7
192.168.1          link#11            UCS                   en0      !
"""


class RouteOnTests(unittest.TestCase):
    def test_route_on_our_tun(self):
        self.assertTrue(tui.route_on(NETSTAT, "128.0/1", "utun7"))

    def test_foreign_half_is_not_ours(self):
        # 0/1 стоит на utun5 — это AmneziaVPN, а не мы.
        self.assertFalse(tui.route_on(NETSTAT, "0/1", "utun7"))

    def test_no_tun_means_no_route(self):
        self.assertFalse(tui.route_on(NETSTAT, "0/1", ""))


class ProbeSlowTests(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.patches = [mock.patch.object(tui, "STATE", self.state),
                        mock.patch.object(tui, "CORP_PROBE", "git.corp")]
        for p in self.patches:
            p.start()
        with open(os.path.join(self.state, "config.json"), "w", encoding="utf-8") as fh:
            json.dump({"endpoints": [{"tag": "awg-personal", "peers": [{"address": "1.2.3.4"}]}],
                       "dns": {"servers": [{"tag": "dns-corp", "server": "172.15.0.110"}]}}, fh)
        with tui.LOCK:
            tui.ST.clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def probe(self, ipinfo, dig):
        def sh(cmd, timeout=10):
            if "https://ipinfo.io/json" in cmd:
                return ipinfo
            if cmd[0] == "dig":
                return dig
            return ""
        with mock.patch.object(tui, "sh", sh):
            tui.probe_slow()
        with tui.LOCK:
            return dict(tui.ST)

    def test_exit_ip_survives_one_failed_probe(self):
        good = json.dumps({"ip": "1.2.3.4", "country": "DE", "city": "Frankfurt"})
        st = self.probe(good, "10.0.0.5")
        self.assertEqual((st["exit_ip"], st["exit_state"]), ("1.2.3.4", "tunnel"))
        st = self.probe("", "10.0.0.5")                 # ipinfo не ответил
        self.assertEqual((st["exit_ip"], st["exit_state"]), ("1.2.3.4", "tunnel"),
                         "разовый сбой ipinfo стёр адрес — строка «прыгает»")

    def test_first_failure_is_unknown(self):
        st = self.probe("", "")
        self.assertEqual(st["exit_state"], "unknown")
        self.assertEqual(st["exit_ip"], "")

    def test_corp_needs_two_misses(self):
        good = json.dumps({"ip": "1.2.3.4"})
        self.assertEqual(self.probe(good, "10.0.0.5")["corp_ip"], "10.0.0.5")
        self.assertEqual(self.probe(good, "")["corp_ip"], "10.0.0.5",
                         "один потерянный ответ DNS — уже «корп не отвечает»")
        self.assertEqual(self.probe(good, "")["corp_ip"], "")
        self.assertEqual(self.probe(good, "10.0.0.6")["corp_ip"], "10.0.0.6")


if __name__ == "__main__":
    unittest.main()
