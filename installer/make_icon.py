"""Рисует TunnelVPN.ico для exe и установщика.

Сам значок рисует lib/tunnelvpn/icon.py: тот же ico нужен окну, запущенному из
исходников, и форма задана в одном месте. --svg переписывает его копию
assets/icon.svg — после правки рисунка (расхождение ловит tests/test_icon.py).

    python installer/make_icon.py [куда.ico]
    python installer/make_icon.py --svg
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))

from tunnelvpn import icon  # noqa: E402

# Консоль на английской Windows — cp1252, и обычный print с кириллицей падает
# с UnicodeEncodeError. Именно на этом рушилась сборка в CI: скрипт делал своё
# дело, а потом умирал на строчке «собрано».
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main():
    if sys.argv[1:] == ["--svg"]:
        out = os.path.join(ROOT, "assets", "icon.svg")
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(icon.svg())
        print(f"собрано: {out}")
        return
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        ROOT, "installer", "TunnelVPN.ico")
    icon.write_ico(out)
    print(f"собрано: {out}")


if __name__ == "__main__":
    main()
