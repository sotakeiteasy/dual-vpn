#!/usr/bin/env python3
"""
Что показать в меню-баре: значок, строки состояния и какие кнопки доступны.

Отдельно от menubar.py, потому что там rumps и AppKit, а решение «что
показывать» — чистая функция от состояния, и её надо проверять тестами.

Раньше в меню всегда стояли все три кнопки: «Включить» при включённом,
«Выключить» при выключенном. Нажатие неподходящей делало не то, что
написано (kickstart -k — это перезапуск), и казалось, что кнопки работают
через раз. Теперь в каждом состоянии — только то, что в нём имеет смысл.
"""

import re

BUSY_TITLE = {
    "starting":   "Включаю…",
    "stopping":   "Выключаю…",
    "restarting": "Перезапускаю…",
}

# Длина строки в меню: длиннее — меню растягивается на пол-экрана.
MAX_LINE = 64


def _clip(text, n=MAX_LINE):
    """В одну строку и не длиннее n. Пробелы внутри не схлопываем: ими
    выровнены колонки «личный   ✓ …» / «корп     ✓ …»."""
    text = re.sub(r"\s*\n\s*", " ", str(text)).strip()
    return text if len(text) <= n else text[:n - 1] + "…"


def is_up(st):
    return bool(st.get("tun")) and bool(st.get("r_low"))


def menu_model(st, op):
    """st — показания пробера (tui.ST), op — Controller.snapshot().

    Возвращает:
      icon     off | on | busy | bad
      title    главная строка
      lines    строки подробностей (без действий)
      actions  {"start", "stop", "restart", "details"} → bool
      start_label  подпись кнопки включения
    """
    up = is_up(st)
    actions = {"start": False, "stop": False, "restart": False, "details": False}
    out = {"icon": "off", "title": "Выключено", "lines": [], "actions": actions,
           "start_label": "Включить"}

    if op.get("busy"):
        out["icon"] = "busy"
        out["title"] = BUSY_TITLE.get(op.get("phase"), "Подожди…")
        if op.get("step"):
            out["lines"] = [_clip(op["step"])]
        return out                      # в переходе кнопок нет: ждём результата

    if not up and op.get("error"):
        out["icon"] = "bad"
        out["title"] = "Не удалось включить"
        first = op["error"].strip().splitlines()[0] if op["error"].strip() else ""
        out["lines"] = [_clip(first)] if first else []
        actions["start"] = True
        actions["details"] = True
        out["start_label"] = "Попробовать снова"
        return out

    if not up:
        actions["start"] = True
        return out

    # Поднят. Заголовок обязан учитывать все строки ниже, иначе сверху
    # «всё работает», а в строке личного — «мимо туннеля».
    actions["stop"] = True
    actions["restart"] = True
    corp_ok = bool(st.get("corp_ip"))
    leak6 = st.get("v6_leak")
    leak = st.get("exit_state") == "leak"
    if leak6:
        out["icon"], out["title"] = "bad", "Утечка IPv6"
    elif leak:
        out["icon"], out["title"] = "bad", "Трафик идёт мимо туннеля"
    elif not corp_ok:
        out["icon"], out["title"] = "on", "Включено · корп не отвечает"
    else:
        out["icon"], out["title"] = "on", "Включено · всё работает"

    ip = st.get("exit_ip") or ""
    state = st.get("exit_state")
    if state == "tunnel":
        personal = f"личный   ✓ {ip}"
    elif state == "leak":
        personal = f"личный   ✗ мимо туннеля {ip}".rstrip()
    else:
        personal = "личный   проверяю…"
    corp = f"корп     ✓ {st['corp_ip']}" if corp_ok else "корп     ✗ не отвечает"
    place = " ".join(x for x in (st.get("exit_country"), st.get("exit_city")) if x)
    out["lines"] = [_clip(personal), _clip(corp)]
    if place:
        out["lines"].append(_clip(f"выход    {place}"))
    return out
