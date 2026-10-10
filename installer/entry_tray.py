"""Точка входа TunnelVPN-Tray.exe: значок в трее.

Отдельный exe, а не аргумент к tunnelvpn.exe, потому что трей должен быть
оконным процессом (без мелькающей консоли), а служба — консольным.
"""

import sys

from tunnelvpn import tray

if __name__ == "__main__":
    # --background — задача планировщика при входе: только значок, без окна.
    tray.run(background="--background" in sys.argv[1:])
