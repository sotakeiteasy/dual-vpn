import glob
import os
import re
import unittest

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "lib", "scripts")


class SubprocessEncodingTests(unittest.TestCase):
    def test_text_mode_has_explicit_encoding(self):
        # Внутри .app локаль ASCII: text=True без encoding декодирует вывод
        # как ASCII и падает на первом не-ASCII байте. Так обновление кнопкой
        # умирало на выводе hdiutil (UnicodeDecodeError, байт 0xe2).
        bad = []
        for path in glob.glob(os.path.join(SCRIPTS, "*.py")):
            with open(path, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if re.search(r"\b(text|universal_newlines)=True", line) \
                            and "encoding=" not in line:
                        bad.append(f"{os.path.basename(path)}:{n}")
        self.assertEqual(bad, [], "subprocess в текстовом режиме без encoding")


if __name__ == "__main__":
    unittest.main()
