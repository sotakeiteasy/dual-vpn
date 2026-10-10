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

from i18n import t

BUSY_TITLE = {
    "starting":   ("Включаю…", "Turning on…"),
    "stopping":   ("Выключаю…", "Turning off…"),
    "restarting": ("Перезапускаю…", "Restarting…"),
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
    out = {"icon": "off", "title": t("Выключено", "Off"), "note": "", "switch": False,
           "rows": [], "actions": actions}

    if op.get("busy"):
        phase = op.get("phase")
        out["icon"] = "busy"
        out["title"] = t(*BUSY_TITLE.get(phase, ("Подожди…", "Please wait…")))
        out["note"] = _clip(op.get("step") or "")
        # Тумблер сразу встаёт туда, куда едем, — как у системного Wi-Fi.
        out["switch"] = phase != "stopping" if phase in BUSY_TITLE else up
        return out                      # в переходе кнопок нет: ждём результата

    if not up and op.get("error"):
        out["icon"] = "bad"
        out["title"] = t("Не удалось включить", "Couldn't turn on")
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
    # Выключенный в окне туннель — не поломка: его не меряют и им не пугают.
    corp_off = st.get("corp_state") == "off"
    # До первого ответа корп ещё не проверен, а не молчит (см. view.js).
    corp_pending = not corp_ok and st.get("corp_state") == "unknown"
    leak6 = st.get("v6_leak")
    state = st.get("exit_state")
    if leak6:
        out["icon"], out["title"] = "bad", t("Утечка IPv6", "IPv6 leak")
    elif state == "leak":
        out["icon"], out["title"] = "bad", t("Трафик идёт мимо туннеля",
                                             "Traffic bypasses the tunnel")
    elif state == "down":
        out["icon"], out["title"] = "bad", t("Туннель не работает — перезапусти",
                                             "Tunnel is down — restart it")
    elif corp_pending:
        out["icon"], out["title"] = "on", t("Проверяю туннели…", "Checking tunnels…")
    elif corp_off:
        out["icon"], out["title"] = "on", t("Работает только личный", "Only personal is on")
    elif not corp_ok:
        out["icon"], out["title"] = "on", t("Корп не отвечает", "Corp isn't responding")
    elif state == "off":
        out["icon"], out["title"] = "on", t("Работает только корп", "Only corp is on")
    else:
        out["icon"], out["title"] = "on", t("Всё работает", "All working")

    # Без адресов: в меню они только перегружали строки, а смотрят их
    # в окне. Для личного важнее, где выход, чем какой у него IP.
    place = st.get("exit_country") or ""
    off, checking, silent = t("выключен", "off"), t("проверяю…", "checking…"), \
        t("не отвечает", "not responding")
    if state == "tunnel":
        personal = {"value": place or t("через туннель", "via tunnel"), "ok": True}
    elif state == "leak":
        personal = {"value": t("мимо туннеля", "bypassing tunnel"), "ok": False}
    elif state == "down":
        personal = {"value": silent, "ok": False}
    elif state == "off":
        personal = {"value": off, "ok": None}
    else:
        personal = {"value": checking, "ok": None}
    if corp_off:
        corp = {"value": off, "ok": None}
    elif corp_pending:
        corp = {"value": checking, "ok": None}
    else:
        corp = {"value": t("на связи", "connected") if corp_ok else silent, "ok": corp_ok}
    # Порядок строк постоянный: menubar.py берёт иконку по номеру строки.
    out["rows"] = [{"name": t("Личный", "Personal"), **personal},
                   {"name": t("Корп", "Corp"), **corp}]
    return out
