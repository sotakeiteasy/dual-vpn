"""
Сборка .app: lib/venv/bin/python lib/scripts/setup.py py2app

Кладёт в dist/ приложение со значком в меню-баре. LSUIElement=1 — не показывать
в Dock и в переключателе приложений: это фоновая утилита, ей там не место.
"""

import os

from setuptools import setup

# Один источник номера: иначе версия в окне и в свойствах .app разъедутся.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Скрипты кладём файлами, а не модулями: их запускает bash, а не Python,
# и внутри zip-архива py2app они были бы недоступны.
SCRIPTS = [os.path.join(ROOT, "lib", "scripts", f)
           for f in ("build-config.py", "tui.py", "setup-resolver.sh",
                     "check.sh", "diag.sh", "install-daemon.sh")]

VERSION_FILE = os.path.join(ROOT, "VERSION")


with open(VERSION_FILE, encoding="utf-8") as fh:
    VERSION = fh.read().strip()

APP = ["menubar.py"]
APP_NAME = "DualVPN"     # имя в /Applications; папка проекта — singbox-lx

OPTIONS = {
    "argv_emulation": False,
    "iconfile": "DualVPN.icns",
    "plist": {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": "local.dualvpn",
        "CFBundleVersion": VERSION,
        "CFBundleShortVersionString": VERSION,
        "LSUIElement": 1,
        "NSHumanReadableCopyright": "",
    },
    # tui даёт логику проб, остальное — то, чем она пользуется.
    "includes": ["rumps", "tui", "window", "curses", "json", "re", "subprocess",
                 "plistlib", "shutil"],
    # WebKit и AppKit нужны окну; py2app сам их не находит через objc.
    "packages": ["WebKit", "AppKit", "Foundation", "objc"],
    # Всё, что нужно для работы, кладём внутрь .app: тогда приложение
    # самодостаточно и его можно просто скачать, а не собирать из исходников.
    # sing-box — 54 МБ, это основной вес готового DMG.
    "resources": ["ui", ROOT + "/vpn", ROOT + "/VERSION",
                  ROOT + "/lib/bin/sing-box",
                  ROOT + "/lib/launchd",
                  ROOT + "/conf/personal.conf.example",
                  ROOT + "/conf/corp.conf.example",
                  ROOT + "/conf/site.env.example"] + SCRIPTS,
}

setup(
    app=APP,
    name=APP_NAME,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
