"""Точка входа консольного dualvpn.exe: CLI и хост службы."""

import sys

from dualvpn.cli import main

if __name__ == "__main__":
    sys.exit(main())
