"""
App в menubar.py наследует rumps.App, и приватные поля у них общие.

Так уже падало: своё состояние значка лежало в self._icon, а rumps держит там
путь к картинке. Сеттер template перечитывал self._icon, находил там «off» и
ронял приложение на старте. Проверка статическая: сравниваем имена
`self._x = …` в нашем классе с именами в исходнике rumps.App.
"""

import ast
import inspect
import os
import re
import unittest

HERE = os.path.dirname(__file__)
MENUBAR = os.path.join(HERE, "..", "lib", "scripts", "menubar.py")


def own_private_attrs():
    tree = ast.parse(open(MENUBAR, encoding="utf-8").read())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "App")
    names = set()
    for node in ast.walk(cls):
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
                and isinstance(node.value, ast.Name) and node.value.id == "self"
                and node.attr.startswith("_")):
            names.add(node.attr)
    return names


class MenubarAttrTests(unittest.TestCase):
    def test_no_clash_with_rumps_internals(self):
        try:
            import rumps
        except Exception as e:                  # rumps есть только в venv
            self.skipTest(f"нет rumps: {e}")
        src = inspect.getsource(rumps.App)
        theirs = set(re.findall(r"self\.(_\w+)\s*=", src))
        self.assertTrue(theirs, "не нашёл полей rumps.App — проверка ничего не проверяет")
        clash = own_private_attrs() & theirs
        self.assertFalse(clash, f"поля App затирают поля rumps.App: {sorted(clash)}")


if __name__ == "__main__":
    unittest.main()
