#!/usr/bin/env python3
"""
Язык интерфейса: английский, если система на английском (любом — США,
Британия и т. д.), иначе русский, как было.

Строки не выносятся в каталог: каждая пишется на месте парой t(ru, en), чтобы
текст оставался рядом с кодом, который его показывает. Лог приложения не
переводится — его читает разработчик.
"""

import os


def system_lang(prefs=None, env=None):
    """'en' или 'ru' по первому языку в настройках системы.

    prefs — список вида ["en-GB", "ru-RU"]; без него спрашиваем систему.
    Если система не ответила (нет PyObjC — тесты, скрипты), смотрим LANG.
    """
    if prefs is None:
        try:
            from Foundation import NSLocale
            prefs = [str(p) for p in NSLocale.preferredLanguages()]
        except Exception:
            prefs = []
    if not prefs:
        env = os.environ if env is None else env
        loc = env.get("LC_ALL") or env.get("LC_MESSAGES") or env.get("LANG") or ""
        prefs = [loc] if loc else []
    first = (prefs[0] if prefs else "").lower()
    return "en" if first.startswith("en") else "ru"


# DUALVPN_LANG — принудительно, для проверки перевода без смены языка системы.
LANG = os.environ.get("DUALVPN_LANG") or system_lang()


def t(ru, en):
    return en if LANG == "en" else ru
