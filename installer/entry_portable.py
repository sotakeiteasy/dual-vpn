"""Точка входа портативного DualVPN.exe — приложение без установки.

Один файл: ядро, трей и окно внутри. Права спрашиваются один раз при запуске
(манифест requireAdministrator, см. dualvpn.spec), служба в систему не
ставится, данные лежат рядом с exe.

Аргументов не требует. Единственный поддерживаемый — `window`: им трей
открывает окно, запуская этот же файл дочерним процессом.
"""

import os
import sys


def main():
    # DUALVPN_DATA обязан быть выставлен ДО импорта пакета: paths читает его
    # при импорте и определяет раскладку один раз на весь процесс.
    from dualvpn.portable import data_dir
    os.environ.setdefault("DUALVPN_DATA", data_dir())

    if len(sys.argv) > 1 and sys.argv[1] == "window":
        from dualvpn import window
        window.open_window()
        return 0

    from dualvpn import portable
    portable.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
