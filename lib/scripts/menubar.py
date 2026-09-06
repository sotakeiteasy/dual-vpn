#!/usr/bin/env python3
"""
Значок в меню-баре: состояние обоих туннелей, включение и выключение.

Туннелем не владеет — им владеет launchd-демон (см. lib/launchd). Здесь только
показ и две кнопки, поэтому root не нужен: пробер обходится route/ifconfig/
netstat, а демона дёргаем через sudo с точечным правилом в sudoers.

Логика проб не дублируется — берётся из tui.py, чтобы панель и значок не
разошлись в показаниях.
"""

import os
import plistlib
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

LABEL = "local.singbox-lx"
PLIST = f"/Library/LaunchDaemons/{LABEL}.plist"
REFRESH = 2.0
BAR_PT = 18          # высота значка в точках; меню-бар — 22
LOG = os.path.expanduser("~/Library/Logs/singbox-lx-menubar.log")


def log(msg):
    """Свой лог: у приложения без окна иначе нет способа сказать, что сломалось."""
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        # encoding обязателен: внутри .app локаль по умолчанию ASCII, и русский
        # текст роняет приложение на старте вместо того, чтобы попасть в лог.
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass                       # лог не имеет права ронять приложение


def data_from_daemon():
    """Каталог данных, прибитый в описании установленной службы.

    Он главный: служба собирает конфиг и пишет лог именно туда. Пока окно
    решало это само, оно показывало пустой лог и «рабочий молчит», хотя
    туннель работал — просто смотрели в разные места.
    """
    try:
        with open(PLIST, "rb") as fh:
            env = plistlib.load(fh).get("EnvironmentVariables") or {}
        return env.get("DUALVPN_DATA") or ""
    except Exception:
        return ""


def paths():
    """Куда смотреть за кодом и за данными.

    Код — там, где лежит программа. Данные — там, где их ждёт служба; если её
    ещё нет, то рядом с кодом, а для .app — в домашней папке, потому что
    бандл переписывается при каждом обновлении.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    in_bundle = ".app/Contents/" in here

    if in_bundle:
        code = here                                   # Contents/Resources
        while os.path.basename(code) != "Resources" and len(code) > 1:
            code = os.path.dirname(code)
        default_data = os.path.expanduser("~/Library/Application Support/DualVPN")
    else:
        code = os.path.dirname(os.path.dirname(here))  # корень проекта
        default_data = code

    data = data_from_daemon() or default_data
    os.makedirs(os.path.join(data, "conf"), exist_ok=True)
    os.makedirs(os.path.join(data, "lib", "state"), exist_ok=True)
    return code, data


BASE, DATA = paths()
# Дочерние процессы (vpn, build-config) должны знать то же самое.
os.environ["DUALVPN_DATA"] = DATA

import rumps                      # noqa: E402
import tui                        # noqa: E402
from window import Window          # noqa: E402

# Пробы берём из tui, но пути у него свои — от места, где лежит его файл.
# В бандле это не то место, поэтому переставляем до запуска пробера.
tui.BASE = BASE
tui.STATE = os.path.join(DATA, "lib", "state")


def launchctl(*args):
    """Команда демону. Возвращает текст ошибки или '' при успехе."""
    # Полный путь: у приложения, запущенного из Finder, PATH урезанный.
    r = subprocess.run(["/usr/bin/sudo", "-n", "/bin/launchctl", *args],
                       capture_output=True, text=True)
    log(f"launchctl {' '.join(args)} → {r.returncode} {(r.stderr or '').strip()}")
    if r.returncode == 0:
        return ""
    # -n не спрашивает пароль: если правила в sudoers нет, лучше честно сказать,
    # чем повесить приложение на невидимом приглашении ввести пароль.
    err = (r.stderr or r.stdout).strip()
    if "password" in err.lower() or "sudo:" in err:
        return "нет прав: переустанови (install-daemon.sh)"
    return err or f"launchctl вернул {r.returncode}"


def stop_tunnel():
    """Выключить и убрать за собой в любом состоянии.

    Штатный путь — INT службе: она сама снимает sing-box и разбирает маршруты.
    Но службы может не быть вовсе (не установлена, снята, упала до launchd),
    а маршруты при этом висят, и кнопка «Выключить» раньше в таком состоянии
    только ругалась. Поэтому вторым шагом зовём уборку напрямую: `vpn stop`
    рассчитан ровно на это и безопасен при уже выключенном туннеле.
    """
    err = launchctl("kill", "INT", f"system/{LABEL}")
    if not err:
        return ""
    log(f"служба не отозвалась ({err}) — убираю напрямую")
    r = subprocess.run(["/usr/bin/sudo", "-n", os.path.join(BASE, "vpn"), "stop"],
                       capture_output=True, text=True)
    for line in (r.stdout or "").strip().splitlines():
        log(f"vpn stop: {line}")
    if r.returncode == 0:
        return ""
    direct = (r.stderr or r.stdout).strip()
    if "password" in direct.lower() or direct.startswith("sudo:"):
        direct = "нет прав: переустанови (install-daemon.sh)"
    # Показываем обе причины: без первой непонятно, почему вообще дошло
    # до прямой уборки.
    return f"{err}; напрямую тоже не вышло: {direct}"


class App(rumps.App):
    def __init__(self):
        # Без названия: в меню-баре место общее, а состояние читается цветом.
        super().__init__("", quit_button=None)
        self._state = None
        self.m = {}
        for key, title in (
            ("state",    "…"),
            ("personal", "личный   —"),
            ("corp",     "корп     —"),
            ("exit",     "выход    —"),
        ):
            # Без callback macOS рисует пункт серым, как недоступный, — состояние
            # выглядело выключенным при поднятом туннеле. Пустой обработчик
            # оставляет строку обычной, но нажатие ничего не делает.
            it = rumps.MenuItem(title, callback=lambda _s: None)
            self.m[key] = it
            self.menu.add(it)
        self.menu.add(rumps.separator)
        self.menu.add(rumps.MenuItem("Открыть окно…", callback=self.on_window))
        self.menu.add(rumps.separator)
        self.menu.add(rumps.MenuItem("Включить", callback=self.on_start))
        self.menu.add(rumps.MenuItem("Выключить", callback=self.on_stop))
        self.menu.add(rumps.MenuItem("Перезапустить", callback=self.on_start))
        self.menu.add(rumps.separator)
        self.menu.add(rumps.MenuItem("Выход", callback=rumps.quit_application))

        self.window = Window(BASE, tui.STATE, log, launchctl, DATA, stop_tunnel)

        log(f"старт, проект: {BASE}")
        log(f"данные: {DATA}")
        # Только для selftest: открыть окно без участия человека.
        if os.environ.get("VPNLX_TEST_WINDOW"):
            rumps.Timer(lambda _t: self.on_window(None), 1.0).start()
        threading.Thread(target=tui.prober, daemon=True).start()
        rumps.Timer(self.refresh, REFRESH).start()

    # ------------------------------------------------------------ кнопки

    def on_start(self, _):
        err = launchctl("kickstart", "-k", f"system/{LABEL}")
        if err:
            rumps.notification("DualVPN", "не удалось включить", err)

    def on_stop(self, _):
        err = stop_tunnel()
        if err:
            rumps.notification("DualVPN", "не удалось выключить", err)

    def on_window(self, _):
        try:
            self.window.show()
        except Exception as e:
            log(f"окно не открылось: {e}")
            rumps.notification("DualVPN", "окно не открылось", str(e))

    def set_icon(self, state):
        """Три состояния значка. Обычный рисуется шаблоном — macOS сама
        перекрашивает его под светлую и тёмную панель; цветные шаблоном быть
        не могут, иначе цвет потеряется."""
        if state == self._state:
            return                      # иначе значок мигает при каждом опросе
        self._state = state
        name = f"menubar-{state}.png"
        for cand in (os.path.join(BASE, "ui", "icons", name),           # в .app
                     os.path.join(BASE, "lib", "scripts", "ui", "icons", name)):
            if not os.path.exists(cand):
                continue
            # Обычный — шаблоном: macOS сама сделает его белым на тёмной
            # панели и чёрным на светлой. Цветные шаблоном быть не могут,
            # иначе цвет потеряется.
            self.template = (state == "default")
            self.icon = cand
            # rumps грузит файл без размера, поэтому 44 пикселя считаются
            # 44 точками — вдвое крупнее нужного. Задаём 22 точки: пиксели
            # остаются, и на экране с двойной плотностью значок чёткий.
            img = getattr(self, "_icon_nsimage", None)
            if img is not None:
                img.setSize_((BAR_PT, BAR_PT))
                img.setTemplate_(state == "default")
            log(f"значок: {state}, шаблон={state == 'default'}")
            return
        log(f"значок не найден: {name}")

    # ------------------------------------------------------------ показ

    def refresh(self, _):
        with tui.LOCK:
            st = dict(tui.ST)
        up = bool(st.get("tun")) and bool(st.get("r_low"))

        self.set_icon("bad" if st.get("v6_leak") or st.get("exit_state") == "leak"
                      else "ok" if up else "default")

        corp_ok = bool(st.get("corp_ip"))
        if st.get("v6_leak"):
            self.m["state"].title = "⚠️ утечка IPv6"
        elif not up:
            self.m["state"].title = "выключено"
        elif not corp_ok:
            self.m["state"].title = "корп не отвечает"
        else:
            self.m["state"].title = "всё работает"

        peer_ok = st.get("exit_is_peer")
        self.m["personal"].title = (
            f"личный   ✓ {st.get('exit_ip')}" if peer_ok
            else f"личный   ✗ выход {st.get('exit_ip') or '—'}" if up
            else "личный   — выключен")

        corp_ip = st.get("corp_ip")
        self.m["corp"].title = (
            f"корп     ✓ {corp_ip}" if corp_ip
            else "корп     ✗ не отвечает" if up
            else "корп     — выключен")

        country = st.get("exit_country") or ""
        self.m["exit"].title = (
            f"выход    {country} {st.get('exit_city') or ''}".rstrip()
            if up else "выход    —")



if __name__ == "__main__":
    App().run()
