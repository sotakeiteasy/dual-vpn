"""Обновление из релизов: выбор релиза, сравнение версий, сверка суммы."""

import hashlib
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

import update  # noqa: E402


DL = update.DOWNLOAD_PREFIX


def rel(tag, draft=False, prerelease=False, assets=None, host=DL):
    num = tag.split("v", 1)[-1]
    if assets is None:
        assets = [f"DualVPN-{num}.dmg", f"DualVPN-{num}.dmg.sha256"]
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease,
            "html_url": f"https://github.com/x/releases/tag/{tag}",
            "assets": [{"name": a, "browser_download_url": f"{host}{tag}/{a}"}
                       for a in assets]}


class VersionTests(unittest.TestCase):
    def test_numeric_not_lexical(self):
        self.assertGreater(update.parse_version("0.1.10"), update.parse_version("0.1.9"))

    def test_garbage_is_none(self):
        for s in ("", "?", "0.1", "0.1.4-beta", "v0.1.4"):
            self.assertIsNone(update.parse_version(s), s)


class PickTests(unittest.TestCase):
    def test_mac_release_among_windows_and_drafts(self):
        releases = [rel("v0.3.3-beta", assets=["DualVPN-Setup.exe"]),
                    rel("mac-v0.1.7", draft=True),
                    rel("mac-v0.1.6", prerelease=True),
                    rel("mac-v0.1.5"),
                    rel("mac-v0.1.4"),
                    rel("v9.9.9")]
        got = update.pick(releases, "0.1.4")
        self.assertEqual(got["version"], "0.1.5")
        self.assertEqual(got["name"], "DualVPN-0.1.5.dmg")
        self.assertEqual(got["dmg_url"], f"{DL}mac-v0.1.5/DualVPN-0.1.5.dmg")
        self.assertEqual(got["sha_url"], f"{DL}mac-v0.1.5/DualVPN-0.1.5.dmg.sha256")

    def test_foreign_download_host_is_ignored(self):
        releases = [rel("mac-v0.1.6", host="https://evil.example/"), rel("mac-v0.1.5")]
        self.assertEqual(update.pick(releases, "0.1.4")["version"], "0.1.5")

    def test_newest_wins_regardless_of_order(self):
        got = update.pick([rel("mac-v0.1.9"), rel("mac-v0.1.10"), rel("mac-v0.1.5")], "0.1.4")
        self.assertEqual(got["version"], "0.1.10")

    def test_release_notes_come_along(self):
        r = dict(rel("mac-v0.1.7"), body="- Новое\n")
        self.assertEqual(update.pick([r], "0.1.6")["notes"], "- Новое")

    def test_nothing_newer(self):
        self.assertIsNone(update.pick([rel("mac-v0.1.4"), rel("mac-v0.1.3")], "0.1.4"))

    def test_release_without_checksum_is_skipped(self):
        releases = [rel("mac-v0.1.6", assets=["DualVPN-0.1.6.dmg"]), rel("mac-v0.1.5")]
        self.assertEqual(update.pick(releases, "0.1.4")["version"], "0.1.5")

    def test_unknown_current_offers_nothing(self):
        self.assertIsNone(update.pick([rel("mac-v0.1.5")], "?"))


class DownloadTests(unittest.TestCase):
    INFO = {"version": "0.1.5", "name": "DualVPN-0.1.5.dmg",
            "dmg_url": "https://dl/dmg", "sha_url": "https://dl/sha"}
    BODY = b"not really a disk image"

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def fake_curl(self, sha):
        def curl(args, timeout):
            if "-o" in args:
                with open(args[args.index("-o") + 1], "wb") as fh:
                    fh.write(self.BODY)
                return b""
            return f"{sha}  DualVPN-0.1.5.dmg\n".encode()
        return curl

    def test_matching_sum_keeps_image(self):
        sha = hashlib.sha256(self.BODY).hexdigest()
        with mock.patch.object(update, "_curl", self.fake_curl(sha)):
            path = update.download(self.INFO, self.dir)
        self.assertTrue(os.path.exists(path))

    def test_wrong_sum_refuses_and_deletes(self):
        with mock.patch.object(update, "_curl", self.fake_curl("0" * 64)):
            with self.assertRaises(update.UpdateError):
                update.download(self.INFO, self.dir)
        self.assertEqual(os.listdir(self.dir), [])

    def test_sum_file_for_another_image_is_refused(self):
        with self.assertRaises(update.UpdateError):
            update.expected_sha("a" * 64 + "  DualVPN-0.1.4.dmg\n", "DualVPN-0.1.5.dmg")


if __name__ == "__main__":
    unittest.main()
