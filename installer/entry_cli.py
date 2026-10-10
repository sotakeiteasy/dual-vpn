"""Точка входа консольного tunnelvpn.exe: CLI и хост службы."""

import sys

from tunnelvpn.cli import main

if __name__ == "__main__":
    sys.exit(main())
