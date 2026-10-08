"""Пробер: чей маршрут считается нашим и как переживаются разовые сбои проб."""

import json
import os
import sys
import tempfile
import threading
import time
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
        self.ipinfo_calls = 0

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def probe(self, exit, dig, https="200", delay=0.0, pings=None):
        # exit: что видит снаружи trace Cloudflare (JSON с ip и country);
        # "" — не ответил. pings: {адрес: средний круг в мс}; кого нет — молчит.
        pings = {tui.PING_PERSONAL: 48.6, "172.15.0.110": 8.4} if pings is None else pings
        known = json.loads(exit) if exit else {}

        def sh(cmd, timeout=10):
            if tui.TRACE_URL in cmd:
                time.sleep(delay)
                return f"h=1.1.1.1\nip={known['ip']}\nloc={known.get('country', '')}" if known else ""
            if any("ipinfo.io" in c for c in cmd):
                self.ipinfo_calls += 1
                return ""
            if cmd[0] == "dig":
                time.sleep(delay)
                return dig
            if "https://git.corp" in cmd:
                return https
            if cmd[0] == "ping":
                host = cmd[-1]
                if host not in pings:
                    return f"--- {host} ping statistics ---\n3 packets transmitted, 0 packets received, 100.0% packet loss"
                avg = pings[host]
                return (f"--- {host} ping statistics ---\n3 packets transmitted, 3 packets received, 0.0% packet loss\n"
                        f"round-trip min/avg/max/stddev = {avg - 1:.3f}/{avg:.3f}/{avg + 1:.3f}/0.600 ms")
            return ""
        with mock.patch.object(tui, "sh", sh):
            tui.probe_slow()
        with tui.LOCK:
            return dict(tui.ST)

    def test_corp_does_not_wait_for_personal(self):
        good = json.dumps({"ip": "1.2.3.4"})
        t0 = time.monotonic()
        st = self.probe(good, "10.0.0.5", delay=0.5)
        self.assertLess(time.monotonic() - t0, 0.9,
                        "корп-проба ждала личную — пробы снова идут по очереди")
        self.assertEqual((st["exit_ip"], st["corp_ip"]), ("1.2.3.4", "10.0.0.5"))

    def test_latency_is_ping_through_tunnels(self):
        st = self.probe(json.dumps({"ip": "1.2.3.4"}), "10.0.0.5")
        self.assertEqual((st["exit_ms"], st["corp_ms"]), (49, 8))
        st = self.probe("", "", https="000")
        self.assertEqual(st["corp_http"], "")

    def test_latency_survives_one_failed_ping(self):
        good = json.dumps({"ip": "1.2.3.4"})
        self.probe(good, "10.0.0.5")
        st = self.probe(good, "10.0.0.5", pings={})
        self.assertEqual((st["exit_ms"], st["corp_ms"]), (49, 8),
                         "один потерянный пинг стёр цифру — она мигает")
        st = self.probe(good, "10.0.0.5", pings={})
        self.assertEqual((st["exit_ms"], st["corp_ms"]), (None, None))
        st = self.probe(good, "10.0.0.5")
        self.assertEqual((st["exit_ms"], st["corp_ms"]), (49, 8))

    def test_ping_ms(self):
        self.assertIsNone(tui.ping_ms(""))
        with mock.patch.object(tui, "sh", return_value="round-trip min/avg/max/stddev = 7.7/8.433/9.2/0.6 ms"):
            self.assertEqual(tui.ping_ms("172.15.0.110"), 8)
        with mock.patch.object(tui, "sh", return_value="3 packets transmitted, 0 packets received"):
            self.assertIsNone(tui.ping_ms("172.15.0.110"))

    def test_exit_ip_survives_one_failed_probe(self):
        good = json.dumps({"ip": "1.2.3.4", "country": "DE"})
        st = self.probe(good, "10.0.0.5")
        self.assertEqual((st["exit_ip"], st["exit_state"]), ("1.2.3.4", "tunnel"))
        st = self.probe("", "10.0.0.5")                 # trace не ответил
        self.assertEqual((st["exit_ip"], st["exit_state"]), ("1.2.3.4", "tunnel"),
                         "разовый сбой стёр адрес — строка «прыгает»")

    def test_exit_from_trace_without_ipinfo(self):
        # Сервис с лимитом каждые 20 секунд — гарантированный 429 к вечеру.
        for _ in range(3):
            st = self.probe(json.dumps({"ip": "1.2.3.4", "country": "NL"}), "10.0.0.5")
        self.assertEqual((st["exit_ip"], st["exit_country"]), ("1.2.3.4", "NL"))
        self.assertEqual(self.ipinfo_calls, 0)

    def test_exit_info_rejects_garbage(self):
        with mock.patch.object(tui, "sh", return_value='{"status": 429}'):
            self.assertEqual(tui.exit_info(), ("", ""))

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

    def test_corp_unknown_until_answer_or_two_misses(self):
        good = json.dumps({"ip": "1.2.3.4"})
        self.assertEqual(self.probe(good, "")["corp_state"], "unknown",
                         "первый промах после включения — уже красный «молчит»")
        self.assertEqual(self.probe(good, "")["corp_state"], "silent")
        self.assertEqual(self.probe(good, "10.0.0.5")["corp_state"], "ok")


class ProbeNowTests(unittest.TestCase):
    def setUp(self):
        with tui.LOCK:
            tui.ST.clear()
            tui.ST.update(tun="utun7", r_low=True)
        self.release = threading.Event()
        self.runs = 0

        def slow():
            self.runs += 1
            self.release.wait(5)
        p = mock.patch.object(tui, "probe_slow", slow)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self.wait_idle)     # cleanup идут с конца: сперва set
        self.addCleanup(self.release.set)

    def wait_idle(self):
        # Замок отпускается в потоке проверки — ждём его, а не спим наугад.
        self.assertTrue(tui.PROBE.acquire(timeout=5))
        tui.PROBE.release()

    def test_second_check_waits_for_first(self):
        self.assertTrue(tui.probe_now())
        self.assertTrue(tui.ST["probing"])
        self.assertFalse(tui.probe_now(), "вторая проверка пошла поверх первой")
        self.release.set()
        self.wait_idle()
        self.assertFalse(tui.ST["probing"])
        self.assertEqual(self.runs, 1)
        self.assertTrue(tui.probe_now())

    def test_only_manual_check_is_marked(self):
        self.assertTrue(tui.probe_now())
        self.assertFalse(tui.ST["probing_manual"], "плановая помечена ручной")
        # Нажали посреди плановой: новой не будет, но её итог — ответ на нажатие.
        self.assertFalse(tui.probe_now(manual=True))
        self.assertTrue(tui.ST["probing_manual"])
        self.release.set()
        self.wait_idle()
        self.assertFalse(tui.ST["probing_manual"], "кнопка крутилась бы до следующей проверки")
        self.assertEqual(self.runs, 1)

    def test_no_check_while_tunnel_down(self):
        with tui.LOCK:
            tui.ST["r_low"] = False
        self.assertFalse(tui.probe_now())
        self.assertEqual(self.runs, 0)


if __name__ == "__main__":
    unittest.main()
