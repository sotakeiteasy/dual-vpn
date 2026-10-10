"""Конфиги по папкам: раскладка лежащих в conf/ и профиль по умолчанию."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", "scripts"))

import confdirs  # noqa: E402


class ConfDirsTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.conf = os.path.join(self.root, "conf")
        self.state = os.path.join(self.root, "lib", "state")
        os.makedirs(self.conf)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def put(self, rel, text="[Interface]\n"):
        path = os.path.join(self.conf, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def ls(self, rel=""):
        return sorted(os.listdir(os.path.join(self.conf, rel)))

    def saved(self):
        with open(os.path.join(self.state, "profile"), encoding="utf-8") as fh:
            return fh.read()

    def test_loose_configs_are_sorted_by_old_names(self):
        for name in ("wg0-ivanov.conf", "personal.conf", "de.conf", "site.env",
                     "corp.conf.example"):
            self.put(name)

        moved = confdirs.sort_out(self.conf)

        self.assertEqual(sorted(moved), [("de.conf", "personal"),
                                         ("personal.conf", "personal"),
                                         ("wg0-ivanov.conf", "corp")])
        self.assertEqual(self.ls(), ["corp", "corp.conf.example", "personal", "site.env"])
        self.assertEqual(confdirs.names(self.conf, "corp"), ["wg0-ivanov"])
        self.assertEqual(confdirs.names(self.conf, "personal"), ["de", "personal"])

    def test_sorting_twice_changes_nothing(self):
        self.put("Corp.conf")
        confdirs.sort_out(self.conf)
        self.assertEqual(confdirs.sort_out(self.conf), [])
        self.assertEqual(self.ls("corp"), ["Corp.conf"])

    def test_taken_name_stays_in_place(self):
        self.put("personal/home.conf", "старый")
        self.put("home.conf", "новый")

        self.assertEqual(confdirs.sort_out(self.conf), [])

        self.assertIn("home.conf", self.ls())
        with open(os.path.join(self.conf, "personal", "home.conf"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "старый")

    def test_empty_conf_gets_both_folders(self):
        confdirs.sort_out(self.conf)
        self.assertEqual(self.ls(), ["corp", "personal"])
        self.assertTrue(confdirs.has_dirs(self.conf))

    def test_default_profile_is_first_and_saved(self):
        self.put("personal/nl.conf")
        self.put("personal/de.conf")

        self.assertEqual(confdirs.profile(self.conf, self.state), "de")

        self.assertEqual(self.saved(), "de")
        # Новый файл впереди по алфавиту выбор уже не сбивает.
        self.put("personal/at.conf")
        self.assertEqual(confdirs.profile(self.conf, self.state), "de")

    def test_profile_of_deleted_file_falls_back_to_first(self):
        self.put("personal/nl.conf")
        confdirs.save_profile(self.state, "gone")

        self.assertEqual(confdirs.profile(self.conf, self.state), "nl")
        self.assertEqual(self.saved(), "nl")

    def test_no_personal_no_profile(self):
        self.assertEqual(confdirs.profile(self.conf, self.state), "")
        self.assertFalse(os.path.exists(os.path.join(self.state, "profile")))


if __name__ == "__main__":
    unittest.main()
