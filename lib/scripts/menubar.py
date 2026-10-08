#!/usr/bin/env python3
"""
Значок в меню-баре: состояние обоих туннелей, включение и выключение.

Туннелем не владеет — им владеет launchd-демон (см. lib/launchd). Здесь только
показ и кнопки, поэтому root не нужен: пробер обходится route/ifconfig/
netstat, а демона дёргаем через sudo с точечным правилом в sudoers.

Кнопки не зовут launchctl сами: операции ведёт control.Controller — в фоне,
по одной, с проверкой результата. Меню и окно рисуются от его состояния.

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
BLINK = 0.5          # период мигания значка, пока идёт операция
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


def vpn_from_daemon():
    """Путь к `vpn`, записанный в описании установленной службы.

    Брать его из своего BASE нельзя: приложение живёт в /Applications, а
    правило в sudoers установщик пишет на тот путь, из которого его запустили
    (обычно репозиторий). Пути не совпадали, `sudo -n` требовал пароль, и
    запасная уборка в stop_tunnel молча не срабатывала. В plist и в sudoers
    путь один и тот же — значит, спрашивать надо у plist.
    """
    try:
        with open(PLIST, "rb") as fh:
            args = plistlib.load(fh).get("ProgramArguments") or []
        # ["/bin/bash", "<base>/vpn", "daemon"] — нужен сам скрипт.
        for a in args:
            if a.endswith("/vpn"):
                return a
    except Exception:
        pass
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
from AppKit import (NSAttributedString, NSColor, NSControlSizeSmall,  # noqa: E402
                    NSControlStateValueOff, NSControlStateValueOn, NSFont,
                    NSFontAttributeName, NSFontWeightRegular,
                    NSForegroundColorAttributeName, NSImage,
                    NSImageSymbolConfiguration, NSImageView,
                    NSLineBreakByTruncatingTail, NSMutableAttributedString,
                    NSSwitch, NSTextAlignmentRight, NSTextField, NSView)
from Foundation import NSObject, NSRunLoop, NSRunLoopCommonModes  # noqa: E402
from PyObjCTools import AppHelper  # noqa: E402
import control                    # noqa: E402
import tui                        # noqa: E402
from menumodel import menu_model   # noqa: E402
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
    # Путь берём из plist, а не из своего BASE: правило в sudoers выдано
    # именно на него (см. vpn_from_daemon).
    vpn = vpn_from_daemon() or os.path.join(BASE, "vpn")
    r = subprocess.run(["/usr/bin/sudo", "-n", vpn, "stop"],
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


def stop_direct():
    """Уборка в обход службы: `vpn stop` через sudo. '' или текст ошибки.

    Нужна, когда служба получила INT, но не выходит: `vpn stop` снимает
    sing-box сам, после чего служба доходит до своей уборки и завершается.
    """
    vpn = vpn_from_daemon() or os.path.join(BASE, "vpn")
    r = subprocess.run(["/usr/bin/sudo", "-n", vpn, "stop"],
                       capture_output=True, text=True)
    for line in (r.stdout or "").strip().splitlines():
        log(f"vpn stop: {line}")
    if r.returncode == 0:
        return ""
    err = (r.stderr or r.stdout).strip()
    if "password" in err.lower() or err.startswith("sudo:"):
        return "нет прав: переустанови (install-daemon.sh)"
    return err or f"vpn stop вернул {r.returncode}"


def daemon_running():
    """Жив ли процесс службы — по launchd, без root.

    `launchctl print` читать может любой. pid у службы есть, только пока
    процесс жив; вложенные строки (сокеты и т. п.) идут с двумя табами,
    поэтому ищем строку ровно с одним.
    """
    try:
        r = subprocess.run(["/bin/launchctl", "print", f"system/{LABEL}"],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return False
    if r.returncode != 0:
        return False                    # служба не установлена
    return any(line.startswith("\tpid = ") for line in r.stdout.splitlines())


class SystemOps(control.Ops):
    """Настоящая система для контроллера."""

    def kickstart(self):
        return launchctl("kickstart", "-k", f"system/{LABEL}")

    def stop(self):
        return stop_tunnel()

    def stop_direct(self):
        return stop_direct()

    def daemon_running(self):
        return daemon_running()

    def is_up(self):
        # Свежий замер, а не показания двухсекундной давности: иначе
        # «выключено» наступало бы на две секунды позже, чем на деле.
        tui.probe_fast()
        with tui.LOCK:
            return bool(tui.ST.get("tun")) and bool(tui.ST.get("r_low"))

    def last_error(self, since=0.0):
        return control.read_last_error(os.path.join(tui.STATE, "last-error"), since)

    def clear_error(self):
        try:
            os.unlink(os.path.join(tui.STATE, "last-error"))
        except OSError:
            pass

    def session_tail(self, n):
        lines = control.read_tail(os.path.join(tui.STATE, "ui.log"))
        return control.last_session(lines)[-n:]


class App(rumps.App):
    def __init__(self):
        # Без названия: в меню-баре место общее, а состояние читается значком.
        super().__init__("", quit_button=None)
        self._icon_name = None          # у rumps свой self._icon (путь к файлу) — не путать
        self._blink = False
        self._was_busy = None           # какой операцией были заняты в прошлый раз

        self.ctrl = control.Controller(SystemOps(), on_change=self.changed, log=log)

        # Шапка — свой вид внутри пункта, как у системного Wi-Fi: тумблер,
        # состояние, строки туннелей. Обычными пунктами состояние не
        # показать: с пустым обработчиком «Выключено» над «Включить»
        # подсвечивалось и выглядело как ещё одна кнопка, а неактивный пункт
        # macOS гасит серым, какой цвет ни задай.
        self.status = StatusView(self.on_switch)
        self.status_item = rumps.MenuItem("")
        self.status_item._menuitem.setView_(self.status.view)
        self.menu.add(self.status_item)
        self.menu.add(rumps.separator)
        self.act = {
            "restart": rumps.MenuItem("Перезапустить", callback=self.on_restart),
            "details": rumps.MenuItem("Подробнее…", callback=self.on_window),
        }
        for it in self.act.values():
            self.menu.add(it)
        self.menu.add(rumps.MenuItem("Открыть окно…", callback=self.on_window))
        self.menu.add(rumps.separator)
        self.menu.add(rumps.MenuItem("Выход", callback=self.on_quit))

        self.window = Window(BASE, tui.STATE, log, self.ctrl, DATA)

        log(f"старт, проект: {BASE}")
        log(f"данные: {DATA}")
        # Только для selftest: открыть окно без участия человека.
        if os.environ.get("VPNLX_TEST_WINDOW"):
            rumps.Timer(lambda _t: self.on_window(None), 1.0).start()
        threading.Thread(target=tui.prober, daemon=True).start()
        self.window.start_update_checks()
        self.refresh(None)
        for fn, every in ((self.refresh, REFRESH), (self.blink, BLINK)):
            t = rumps.Timer(fn, every)
            t.start()
            # rumps ставит таймер только в обычный режим цикла, а пока меню
            # открыто, цикл крутится в режиме отслеживания — и тумблер с
            # состоянием замирали бы до закрытия меню.
            NSRunLoop.currentRunLoop().addTimer_forMode_(t._nstimer, NSRunLoopCommonModes)

    # ------------------------------------------------------------ кнопки
    #
    # Возвращаются мгновенно: работа идёт в потоке контроллера, а меню
    # перерисовывается по его сигналу (changed).

    def on_switch(self, on):
        if on:
            self.ctrl.start()
        else:
            self.ctrl.stop()

    def on_restart(self, _):
        self.ctrl.restart()

    def changed(self):
        """Контроллер сменил состояние. Зовётся из его потока, а трогать меню
        и окно можно только из главного — перекидываем туда."""
        AppHelper.callAfter(self._changed_main)

    def _changed_main(self):
        # Файл статуса читает окно; без записи оно ещё две секунды показывало
        # бы состояние до операции.
        tui.write_status()
        op = self.ctrl.snapshot()
        # Уведомление — только о своей операции, закончившейся неудачей, и
        # только если окно закрыто: в окне ошибка и так видна целиком.
        if self._was_busy and not op["busy"] and op["error"] and not self.window.visible():
            what = {"stopping": "выключить", "restarting": "перезапустить"}.get(
                self._was_busy, "включить")
            rumps.notification("DualVPN", f"Не удалось {what}",
                               op["error"].splitlines()[0])
        self._was_busy = op["phase"] if op["busy"] else None
        self.refresh(None)
        self.window.push()

    def on_quit(self, _):
        """Выход выключает туннель.

        Раньше здесь стоял rumps.quit_application напрямую: приложение
        закрывалось, а служба продолжала держать туннель и маршруты 0/1 и
        128.0/1 на tun. Снаружи это выглядело как «выключил», хотя весь трафик
        по-прежнему шёл через туннель, а значка, чтобы это увидеть или
        выключить, уже не было.
        """
        # Синхронно, мимо контроллера: приложение сейчас закроется, и ждать
        # полного выключения в потоке было бы некому. Служба доубирает сама.
        err = stop_tunnel()
        if err:
            # Всё равно выходим — человек попросил именно это. Но молча уйти
            # нельзя: туннель остался поднятым, и об этом надо сказать.
            log(f"выход: выключить не вышло — {err}")
            rumps.notification("DualVPN", "туннель остался поднятым", err)
        rumps.quit_application()

    def on_window(self, _):
        try:
            self.window.show()
        except Exception as e:
            log(f"окно не открылось: {e}")
            rumps.notification("DualVPN", "окно не открылось", str(e))

    def set_icon(self, name):
        """Значок-шаблон: macOS сама красит его под панель, как соседние.

        Состояние — прозрачностью: off светло-серый, on сплошной, bad со
        значком «!», busy мигает двумя кадрами (см. make-icons.py).
        """
        if name == self._icon_name:
            return                      # иначе значок мигает при каждом опросе
        self._icon_name = name
        fname = f"menubar-{name}.png"
        for cand in (os.path.join(BASE, "ui", "icons", fname),           # в .app
                     os.path.join(BASE, "lib", "scripts", "ui", "icons", fname)):
            if not os.path.exists(cand):
                continue
            self.template = True
            self.icon = cand
            # rumps грузит файл без размера, поэтому 44 пикселя считаются
            # 44 точками — вдвое крупнее нужного. Задаём размер в точках:
            # пиксели остаются, и на экране с двойной плотностью значок чёткий.
            img = getattr(self, "_icon_nsimage", None)
            if img is not None:
                img.setSize_((BAR_PT, BAR_PT))
                img.setTemplate_(True)
            return
        log(f"значок не найден: {fname}")

    def blink(self, _):
        """Мигание, пока идёт операция: 10–20 секунд без движения выглядят
        как зависание."""
        if not self.ctrl.busy():
            return
        self._blink = not self._blink
        self.set_icon("busy-b" if self._blink else "busy-a")

    # ------------------------------------------------------------ показ

    def refresh(self, _):
        with tui.LOCK:
            st = dict(tui.ST)
        m = menu_model(st, self.ctrl.snapshot())

        if m["icon"] != "busy":
            self.set_icon(m["icon"])
        elif not (self._icon_name or "").startswith("busy"):
            self.set_icon("busy-a")

        self.status.set(m)
        for key, it in self.act.items():
            show(it, m["actions"][key])


# Цвет точки у строки состояния — по значку.
DOT_COLOR = {"on": "systemGreenColor", "bad": "systemRedColor",
             "busy": "systemOrangeColor", "off": "tertiaryLabelColor"}
# Иконка туннеля (SF Symbols) и её цвет. Без кружка и не акцентным цветом:
# голубые кружки как у Wi-Fi спорили со строкой состояния и тянули взгляд на
# себя. Красной иконка становится, только когда туннель не работает.
ROW_SYMBOL = {"Личный": "globe", "Корп": "building.2"}
ROW_COLOR = {True: "secondaryLabelColor", False: "systemRedColor", None: "tertiaryLabelColor"}


class FlippedView(NSView):
    """Вид с началом координат сверху: шапку раскладываем сверху вниз."""

    def isFlipped(self):
        return True


class SwitchTarget(NSObject):
    """Получатель нажатий тумблера: у AppKit цель — объект Objective-C."""

    def toggled_(self, sender):
        self.handler(sender.state() == NSControlStateValueOn)


class StatusView:
    """Шапка меню, как у системного Wi-Fi: «DualVPN» и тумблер, под ними
    состояние с цветной точкой, ниже по строке на туннель с иконкой. Вид в
    пункте меню не подсвечивается и не нажимается — на кнопку не похож, а
    серым «недоступным» не становится."""

    W = 280         # ширина шапки; меню подстраивается под самый широкий пункт
    INSET = 14      # отступ от края меню — как у текста обычных пунктов
    ROW_H = 26
    ICON = 16       # место под иконку; сам символ — ICON_PT
    ICON_PT = 13
    NAME_W = 80     # колонка названий туннелей; значения — справа от неё

    def __init__(self, on_switch):
        self.view = FlippedView.alloc().initWithFrame_(((0, 0), (self.W, 60)))
        base = NSFont.menuFontOfSize_(0).pointSize()

        self.name = self._label(NSFont.boldSystemFontOfSize_(base))
        self.name.setStringValue_("DualVPN")
        self.target = SwitchTarget.alloc().init()
        self.target.handler = on_switch
        self.switch = NSSwitch.alloc().init()
        self.switch.setControlSize_(NSControlSizeSmall)
        self.switch.setTarget_(self.target)
        self.switch.setAction_("toggled:")
        self.view.addSubview_(self.switch)
        self.state = self._label(NSFont.menuFontOfSize_(base - 1))
        self.note = self._label(NSFont.menuFontOfSize_(base - 2))
        self.note.setTextColor_(NSColor.secondaryLabelColor())

        self.rows = []
        for _ in ROW_SYMBOL:
            icon = NSImageView.alloc().initWithFrame_(((0, 0), (self.ICON, self.ICON)))
            self.view.addSubview_(icon)
            name = self._label(NSFont.menuFontOfSize_(base))
            value = self._label(NSFont.menuFontOfSize_(base - 1))
            value.setTextColor_(NSColor.secondaryLabelColor())
            value.setAlignment_(NSTextAlignmentRight)
            self.rows.append((icon, name, value))
        self._shown = None

    def _label(self, font):
        field = NSTextField.labelWithString_("")
        field.setFont_(font)
        field.setLineBreakMode_(NSLineBreakByTruncatingTail)
        self.view.addSubview_(field)
        return field

    def set(self, m):
        # Тумблер — до проверки на изменения: если нажатие ничего не
        # запустило, модель та же, а тумблер остался бы там, куда его
        # перещёлкнули. Доступен, только когда есть что переключать: посреди
        # операции стоит там, куда едем, и ждёт результата.
        self.switch.setState_(NSControlStateValueOn if m["switch"] else NSControlStateValueOff)
        self.switch.setEnabled_(m["actions"]["start"] or m["actions"]["stop"])

        key = (m["title"], m["note"], m["icon"], repr(m["rows"]))
        if key == self._shown:
            return                      # раз в две секунды — без лишних перерисовок
        self._shown = key
        x, w = self.INSET, self.W - 2 * self.INSET

        sw, sh = self.switch.fittingSize()
        self.switch.setFrame_(((self.W - self.INSET - sw, 8), (sw, sh)))
        self.name.setFrame_(((x, 8 + (sh - 17) / 2), (w - sw - 8, 17)))
        y = 8 + sh + 2

        dot = getattr(NSColor, DOT_COLOR[m["icon"]])()
        title_color = NSColor.systemRedColor() if m["icon"] == "bad" else NSColor.secondaryLabelColor()
        text = NSMutableAttributedString.alloc().init()
        text.appendAttributedString_(_styled("●  ", self.state.font(), dot))
        text.appendAttributedString_(_styled(m["title"], self.state.font(), title_color))
        self.state.setAttributedStringValue_(text)
        self.state.setFrame_(((x, y), (w, 16)))
        y += 16

        self.note.setHidden_(not m["note"])
        if m["note"]:
            self.note.setStringValue_(m["note"])
            self.note.setToolTip_(m["note"])
            self.note.setFrame_(((x, y + 1), (w, 15)))
            y += 16

        if m["rows"]:
            y += 6
        for i, (icon, name, value) in enumerate(self.rows):
            row = m["rows"][i] if i < len(m["rows"]) else None
            for v in (icon, name, value):
                v.setHidden_(row is None)
            if row is None:
                continue
            icon.setFrameOrigin_((x, y + (self.ROW_H - self.ICON) / 2))
            icon.setContentTintColor_(getattr(NSColor, ROW_COLOR[row["ok"]])())
            img = NSImage.imageWithSystemSymbolName_accessibilityDescription_(
                ROW_SYMBOL.get(row["name"], "network"), row["name"])
            icon.setImage_(img.imageWithSymbolConfiguration_(
                NSImageSymbolConfiguration.configurationWithPointSize_weight_(
                    self.ICON_PT, NSFontWeightRegular)))
            left = x + self.ICON + 8
            name.setStringValue_(row["name"])
            name.setFrame_(((left, y + (self.ROW_H - 17) / 2), (self.NAME_W, 17)))
            value.setStringValue_(row["value"])
            right = left + self.NAME_W
            value.setFrame_(((right, y + (self.ROW_H - 16) / 2), (self.W - self.INSET - right, 16)))
            y += self.ROW_H

        self.view.setFrameSize_((self.W, y + 6))
        self.view.setNeedsDisplay_(True)


def _styled(text, font, color):
    return NSAttributedString.alloc().initWithString_attributes_(
        text, {NSFontAttributeName: font, NSForegroundColorAttributeName: color})


def show(item, visible):
    """Спрятать или показать пункт меню. У rumps своего способа нет."""
    item._menuitem.setHidden_(not visible)


if __name__ == "__main__":
    App().run()
