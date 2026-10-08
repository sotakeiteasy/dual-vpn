"""Окно: настройки рабочей сети и обновление из релиза."""

import os
import sys
import tempfile
import unittest
from unittest import mock

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

    def test_email_is_checked_and_kept(self):
        self.w.save_site({"CORP_EMAIL": "ivanov@gmail.com"})
        self.assertFalse(os.path.exists(self.w.site_path()))
        self.w.save_site({"CORP_EMAIL": " Ivanov@media-effect.ru "})
        self.assertEqual(self.w.site()["CORP_EMAIL"], "ivanov@media-effect.ru")


@unittest.skipIf(window is None, "нет AppKit")
class PutConfigTests(unittest.TestCase):
    """Один путь подмены и для файла, и для конфига с сайта."""

    def setUp(self):
        self.w = window.Window.__new__(window.Window)
        self.w.data = tempfile.mkdtemp()
        self.w.state = tempfile.mkdtemp()
        self.w.log = lambda *a: None
        self.js = []
        self.w.eval = self.js.append
        self.w.status = lambda: {"up": False}
        self.w.push = lambda: None
        self.conf = os.path.join(self.w.data, "conf")
        os.makedirs(self.conf)
        with open(os.path.join(self.conf, "wg-old.conf"), "w") as fh:
            fh.write("old")

    def write(self, text):
        def w(tmp):
            with open(tmp, "w") as fh:
                fh.write(text)
        return w

    def test_replaces_previous_corp(self):
        self.assertTrue(self.w.put_config("corp", "wg0-ivanov.conf", self.write("new")))
        self.assertEqual(sorted(os.listdir(self.conf)), ["wg0-ivanov.conf"])
        path = os.path.join(self.conf, "wg0-ivanov.conf")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_failed_write_keeps_old_and_leaves_no_tmp(self):
        def broken(tmp):
            with open(tmp, "w") as fh:
                fh.write("half")
            raise OSError("нет места")
        self.assertFalse(self.w.put_config("corp", "wg0-ivanov.conf", broken))
        self.assertEqual(os.listdir(self.conf), ["wg-old.conf"])
        self.assertIn("failed(", self.js[0])

    def test_restarts_running_tunnel(self):
        self.w.status = lambda: {"up": True}
        self.w.ctrl = mock.Mock()
        self.w.put_config("corp", "wg0-ivanov.conf", self.write("new"))
        self.w.ctrl.restart.assert_called_once()


@unittest.skipIf(window is None, "нет AppKit")
class UpdateTests(unittest.TestCase):
    INFO = {"version": "0.1.5", "name": "DualVPN-0.1.5.dmg",
            "dmg_url": "u", "sha_url": "s"}

    def setUp(self):
        self.w = window.Window.__new__(window.Window)
        self.w.base = os.path.join(window.INSTALLED_APP, "Contents", "Resources")
        self.w.log = lambda *a: None
        self.w.relaunched = False
        self.w.relaunch = lambda: setattr(self.w, "relaunched", True)
        self.w.tool = lambda name: __file__       # существующий файл вместо скрипта

    def run_update(self, apply_result):
        w = self.w
        with mock.patch.object(window.update, "download", return_value="/x.dmg"), \
             mock.patch.object(window.update, "mount", return_value="/m/DualVPN.app"), \
             mock.patch.object(window.update, "unmount") as unmount, \
             mock.patch.object(w, "_apply", return_value=apply_result, create=True):
            w._update(self.INFO)
        unmount.assert_called_once()                # образ не остаётся открытым

    def test_cancel_keeps_offer(self):
        self.run_update(None)
        self.assertEqual(self.w.upd["state"], "available")
        self.assertFalse(self.w.relaunched)

    def test_failure_is_shown(self):
        self.run_update("нет прав")
        self.assertEqual(self.w.upd["state"], "error")
        self.assertEqual(self.w.upd["error"], "нет прав")

    def test_success_relaunches(self):
        self.run_update("")
        self.assertTrue(self.w.relaunched)

    def test_unexpected_error_is_shown_and_volume_detached(self):
        # Том подключился, а mount упал не OSError — раньше поток умирал
        # молча, окно висело на «открываю образ», образ оставался открытым.
        logged = []
        self.w.log = logged.append
        with mock.patch.object(window.update, "download", return_value="/x.dmg"), \
             mock.patch.object(window.update, "mount", side_effect=ValueError("плохой вывод")), \
             mock.patch.object(window.os.path, "ismount", return_value=True), \
             mock.patch.object(window.update, "unmount") as unmount:
            self.w._update(self.INFO)
        unmount.assert_called_once()
        self.assertEqual(self.w.upd["state"], "error")
        self.assertIn("ValueError: плохой вывод", self.w.upd["error"])
        self.assertTrue(any("Traceback" in line for line in logged), logged)

    def osa(self, rc, stderr=""):
        done = mock.Mock(returncode=rc, stdout="", stderr=stderr)
        with mock.patch.object(window.subprocess, "run", return_value=done) as run:
            got = self.w._apply("/m/DualVPN.app", "0.1.5")
        return got, run.call_args[0][0][2]

    def test_osascript_quotes_are_escaped(self):
        got, osa = self.osa(0)
        self.assertEqual(got, "")
        # Без \" AppleScript падает с синтаксической ошибкой на первой же кавычке.
        self.assertIn('\\"/m/DualVPN.app\\"', osa)
        self.assertIn("with administrator privileges", osa)

    def test_password_cancel_is_not_an_error(self):
        got, _ = self.osa(1, "execution error: User canceled. (-128)")
        self.assertIsNone(got)

    def opened(self, checked_ago):
        w = self.w
        w.upd_timer = object()                      # проверки запущены
        w._upd_checked = window.time.time() - checked_ago
        w.win = mock.Mock()
        with mock.patch.object(window, "NSApp"), \
             mock.patch.object(w, "check_update", create=True) as check:
            w.show()
        return check.called

    def test_opening_window_rechecks_when_stale(self):
        # Релиз вышел после старта — окно не должно ждать плановой проверки.
        self.assertTrue(self.opened(window.UPDATE_ON_SHOW + 1))
        self.assertFalse(self.opened(5))

    def test_only_installed_app_updates(self):
        self.assertTrue(self.w.updatable())
        self.w.base = "/Users/x/repos/dual-vpn"
        self.assertFalse(self.w.updatable())


if __name__ == "__main__":
    unittest.main()
