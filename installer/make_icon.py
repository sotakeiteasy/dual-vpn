"""Рисует TunnelVPN.ico для exe и установщика.

Сам значок рисует lib/tunnelvpn/icon.py: тот же ico нужен окну, запущенному из
исходников, и форма задана в одном месте.

    python installer/make_icon.py [куда.ico]
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
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        ROOT, "installer", "TunnelVPN.ico")
    icon.write_ico(out)
    print(f"собрано: {out}")


if __name__ == "__main__":
    main()
