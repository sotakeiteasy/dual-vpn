#!/usr/bin/env python3
"""
Значок при входе в систему: LaunchAgent в ~/Library/LaunchAgents.

Без него значок после перезагрузки не появлялся, пока приложение не открыли
руками, — а выключить туннель или увидеть его состояние было нечем. Служба
(LaunchDaemon) от этого не зависит: туннель она по-прежнему не поднимает сама.

Агент запускает ту копию, из которой его включили: .app — через open, как
из Finder; из исходников — тем же python и тем же menubar.py. Выключение
только убирает файл: bootout снял бы и само работающее приложение, если его
поднял агент.
"""

import os
import plistlib

LABEL = "local.dualvpn.menubar"
AGENT = os.path.expanduser(f"~/Library/LaunchAgents/{LABEL}.plist")


def app_bundle(path):
    """Путь к .app, если path лежит внутри бандла, иначе ''."""
    marker = ".app/Contents/"
    i = path.find(marker)
    return path[:i + len(".app")] if i >= 0 else ""


def program(script, executable):
    """Чем запускать: open для .app, иначе python + menubar.py."""
    app = app_bundle(os.path.abspath(script))
    if app:
        return ["/usr/bin/open", "-a", app]
    return [executable, os.path.abspath(script)]


def agent_plist(script, executable):
    return {
        "Label": LABEL,
        "ProgramArguments": program(script, executable),
        "RunAtLoad": True,
        "ProcessType": "Interactive",
    }


def enabled(path=AGENT):
    return os.path.exists(path)


def enable(script, executable, path=AGENT):
    """'' или текст ошибки."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            plistlib.dump(agent_plist(script, executable), fh)
    except OSError as e:
        return str(e)
    return ""


def disable(path=AGENT):
    """'' или текст ошибки."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        return str(e)
    return ""
