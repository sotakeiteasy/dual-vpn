"""Точка входа портативного TunnelVPN-Portable.exe — приложение без установки.

Один файл: ядро, трей и окно внутри. Права спрашиваются один раз при запуске
(манифест requireAdministrator, см. tunnelvpn.spec), служба в систему не
ставится, данные лежат рядом с exe.

Без аргументов — обычный запуск: трей и окно, с --background — только трей.
Любая команда (`window`, `admin-op`,
что угодно, что появится в cli.py потом) идёт в общий разбор tunnelvpn.cli —
так portable ведёт себя как tunnelvpn.exe, без отдельной ветки на каждую
команду здесь.
"""

import os
import sys


def main():
    # TUNNELVPN_DATA обязан быть выставлен ДО импорта пакета: paths читает его
    # при импорте и определяет раскладку один раз на весь процесс.
    from tunnelvpn.portable import data_dir
    os.environ.setdefault("TUNNELVPN_DATA", data_dir())

    background = sys.argv[1:] == ["--background"]
    if len(sys.argv) > 1 and not background:
        from tunnelvpn.cli import main as cli_main
        return cli_main(sys.argv[1:])

    from tunnelvpn import portable
    portable.run(background=background)
    return 0


if __name__ == "__main__":
    sys.exit(main())
