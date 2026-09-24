"""
vpn: отказ старта записывается словами и не заводит launchd в цикл.

Скрипт подключается с VPN_SOURCE_ONLY=1 — функции есть, команда не
выполняется. Всё, что требует root или трогает сеть, подменено заглушками:
проверяется именно путь отказа, а не поднятие туннеля.
"""

import os
import subprocess
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VPN = os.path.join(ROOT, "vpn")


class VpnFailStartTests(unittest.TestCase):
    def setUp(self):
        self.data = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.data, "conf"))
        self.fake = tempfile.mkdtemp()
        # Сборка конфига, падающая так же, как падала на «25-35»: трейсбек,
        # последняя строка — причина.
        with open(os.path.join(self.fake, "build-config.py"), "w", encoding="utf-8") as fh:
            fh.write("import sys\n"
                     "print('Traceback (most recent call last):', file=sys.stderr)\n"
                     "print(\"ValueError: invalid literal for int(): '25-35'\", file=sys.stderr)\n"
                     "sys.exit(1)\n")

    def run_vpn(self, body, daemon):
        script = f"""
set -u
VPN_SOURCE_ONLY=1 . "{VPN}"
need_root() {{ :; }}
leftovers() {{ return 1; }}
cmd_stop()  {{ echo "уборка"; }}
SCRIPTS="{self.fake}"
DAEMON={1 if daemon else 0}
{body}
"""
        env = {**os.environ, "DUALVPN_DATA": self.data}
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)

    def last_error(self):
        path = os.path.join(self.data, "lib", "state", "last-error")
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_daemon_exits_zero_and_records_reason(self):
        # Ненулевой выход launchd перезапускает (KeepAlive/SuccessfulExit) —
        # битый конфиг крутился бы по кругу каждые 10 с.
        r = self.run_vpn("cmd_start", daemon=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        err = self.last_error()
        self.assertIn("не удалось собрать конфиг", err)
        self.assertIn("25-35", err, "в причину не попала последняя строка вывода")
        self.assertIn("уборка", r.stdout, "после отказа не убрано за собой")

    def test_terminal_exits_nonzero(self):
        r = self.run_vpn("cmd_start", daemon=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("не удалось собрать конфиг", self.last_error())

    def test_missing_profile_is_recorded(self):
        r = self.run_vpn("set_profile nosuch", daemon=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("нет профиля «nosuch»", self.last_error())

    def test_start_clears_previous_reason(self):
        state = os.path.join(self.data, "lib", "state")
        os.makedirs(state, exist_ok=True)
        with open(os.path.join(state, "last-error"), "w", encoding="utf-8") as fh:
            fh.write("старая причина\n")
        self.run_vpn("cmd_start", daemon=True)
        self.assertNotIn("старая причина", self.last_error())

    def test_reason_without_detail_is_written(self):
        # Раньше группа «echo; [ -n ] && echo» без подробности возвращала 1,
        # и файл не записывался как раз в простом случае.
        r = self.run_vpn('fail_start "нет маршрута по умолчанию"', daemon=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.last_error(), "нет маршрута по умолчанию\n")

    def test_ansi_is_stripped_from_detail(self):
        self.run_vpn("fail_start \"конфиг не прошёл проверку\" "
                     "$'\\x1b[31mFATAL\\x1b[0m[0000] bad key'", daemon=True)
        err = self.last_error()
        self.assertIn("FATAL[0000] bad key", err)
        self.assertNotIn("\x1b", err)


if __name__ == "__main__":
    unittest.main()
