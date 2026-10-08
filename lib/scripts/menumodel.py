#!/usr/bin/env python3
"""
Что показать в меню-баре: значок, тумблер, состояние и какие кнопки доступны.

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
    """В одну строку и не длиннее n."""
    text = re.sub(r"\s*\n\s*", " ", str(text)).strip()
    return text if len(text) <= n else text[:n - 1] + "…"


def is_up(st):
    return bool(st.get("tun")) and bool(st.get("r_low"))


def menu_model(st, op):
    """st — показания пробера (tui.ST), op — Controller.snapshot().

    Меню устроено как системные (Wi-Fi, Bluetooth): включение — тумблером в
    шапке, под ним строка состояния, ниже по строке на туннель. Состояние —
    текст, а не пункт меню: раньше «Выключено» стояло над «Включить» и
    выглядело как ещё одна кнопка.

    Возвращает:
      icon     off | on | busy | bad
      title    строка состояния под тумблером
      note     пояснение под ней: шаг операции или причина отказа, '' если нет
      switch   положение тумблера: True — включено или включается
      rows     [{"name", "value", "ok"}] — по туннелю; ok: True | False | None
               (None — ещё не ясно). Только у поднятого.
      actions  {"start", "stop", "restart", "details"} → bool
    """
    up = is_up(st)
    actions = {"start": False, "stop": False, "restart": False, "details": False}
    out = {"icon": "off", "title": "Выключено", "note": "", "switch": False,
           "rows": [], "actions": actions}

    if op.get("busy"):
        phase = op.get("phase")
        out["icon"] = "busy"
        out["title"] = BUSY_TITLE.get(phase, "Подожди…")
        out["note"] = _clip(op.get("step") or "")
        # Тумблер сразу встаёт туда, куда едем, — как у системного Wi-Fi.
        out["switch"] = phase != "stopping" if phase in BUSY_TITLE else up
        return out                      # в переходе кнопок нет: ждём результата

    if not up and op.get("error"):
        out["icon"] = "bad"
        out["title"] = "Не удалось включить"
        first = op["error"].strip().splitlines()[0] if op["error"].strip() else ""
        out["note"] = _clip(first)
        actions["start"] = True
        actions["details"] = True
        return out

    if not up:
        actions["start"] = True
        return out

    # Поднят. Строка состояния обязана учитывать все строки ниже, иначе
    # сверху «всё работает», а в строке личного — «мимо туннеля».
    out["switch"] = True
    actions["stop"] = True
    actions["restart"] = True
    corp_ok = bool(st.get("corp_ip"))
    # До первого ответа корп ещё не проверен, а не молчит (см. view.js).
    corp_pending = not corp_ok and st.get("corp_state") == "unknown"
    leak6 = st.get("v6_leak")
    state = st.get("exit_state")
    if leak6:
        out["icon"], out["title"] = "bad", "Утечка IPv6"
    elif state == "leak":
        out["icon"], out["title"] = "bad", "Трафик идёт мимо туннеля"
    elif state == "down":
        out["icon"], out["title"] = "bad", "Туннель не работает — перезапусти"
    elif corp_pending:
        out["icon"], out["title"] = "on", "Проверяю туннели…"
    elif not corp_ok:
        out["icon"], out["title"] = "on", "Корп не отвечает"
    else:
        out["icon"], out["title"] = "on", "Всё работает"

    # Без адресов: в меню они только перегружали строки, а смотрят их
    # в окне. Для личного важнее, где выход, чем какой у него IP.
    place = st.get("exit_country") or ""
    if state == "tunnel":
        personal = {"value": place or "через туннель", "ok": True}
    elif state == "leak":
        personal = {"value": "мимо туннеля", "ok": False}
    elif state == "down":
        personal = {"value": "не отвечает", "ok": False}
    else:
        personal = {"value": "проверяю…", "ok": None}
    if corp_pending:
        corp = {"value": "проверяю…", "ok": None}
    else:
        corp = {"value": "на связи" if corp_ok else "не отвечает", "ok": corp_ok}
    out["rows"] = [{"name": "Личный", **personal}, {"name": "Корп", **corp}]
    return out
