#!/usr/bin/env python3
"""
Окно приложения: состояние, конфиги, логи.

WKWebView, а не pywebview: главный цикл приложения держит rumps, и две
библиотеки за него подрались бы. Здесь окно создаётся внутри уже работающего
NSApp, поэтому конфликта нет.

Разметка и вся отрисовка — в ui/index.html. Сюда приходят только события
(«нажали включить», «показать конфиг») и уходят данные.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

import control
import tui
import update

import objc
from AppKit import (NSApp, NSBackingStoreBuffered, NSMakeRect, NSMakePoint,
                    NSMenu, NSMenuItem, NSOpenPanel,
                    NSTitledWindowMask, NSClosableWindowMask, NSAlert,
                    NSResizableWindowMask, NSMiniaturizableWindowMask, NSWindow)
from Foundation import NSObject, NSURL, NSTimer
from PyObjCTools import AppHelper
from WebKit import WKUserContentController, WKWebView, WKWebViewConfiguration

LABEL = "local.singbox-lx"
PLIST = f"/Library/LaunchDaemons/{LABEL}.plist"
TAIL = 400          # сколько строк лога держим в окне
POLL = 2.0
UPDATE_EVERY = 6 * 3600     # как часто спрашивать GitHub о новой версии
UPDATE_ON_SHOW = 600        # при открытии окна — если с прошлой проверки прошло столько
INSTALLED_APP = "/Applications/DualVPN.app"
NO_UPDATE = {"state": "", "version": "", "step": "", "error": ""}


def _list(v):
    """sing-box допускает и строку, и массив. JS ждёт массив всегда."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _js(value):
    """JSON внутрь evaluateJavaScript. json.dumps сам экранирует кавычки."""
    return json.dumps(value, ensure_ascii=False)


EDIT_ITEMS = (("Undo", "undo:", "z"), ("Redo", "redo:", "Z"), None,
              ("Cut", "cut:", "x"), ("Copy", "copy:", "c"),
              ("Paste", "paste:", "v"), ("Select All", "selectAll:", "a"))


def install_edit_menu():
    """Меню Edit, через которое macOS доставляет Cmd+V, Cmd+C и прочие.

    Сочетания эти — не клавиши страницы, а пункты главного меню. У приложения
    из меню-бара главного меню не было, и WKWebView их просто не получал:
    в поле диалога нельзя было вставить, из лога — скопировать. В режиме
    accessory меню не видно, но сочетания через него проходят.
    """
    main = NSApp.mainMenu()
    if main is not None and main.itemWithTitle_("Edit") is not None:
        return
    if main is None:
        main = NSMenu.alloc().init()
        # Первый пункт система считает меню приложения — Edit туда не кладём.
        main.addItem_(NSMenuItem.alloc().init())
    edit = NSMenu.alloc().initWithTitle_("Edit")
    for it in EDIT_ITEMS:
        if it is None:
            edit.addItem_(NSMenuItem.separatorItem())
        else:
            edit.addItemWithTitle_action_keyEquivalent_(*it)
    item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_("Edit", None, "")
    item.setSubmenu_(edit)
    main.addItem_(item)
    NSApp.setMainMenu_(main)


class Bridge(NSObject):
    """Приёмник сообщений от страницы: window.webkit.messageHandlers.py."""

    def initWithOwner_(self, owner):
        self = objc.super(Bridge, self).init()
        self.owner = owner
        return self

    def userContentController_didReceiveScriptMessage_(self, _controller, message):
        body = message.body()
        try:
            self.owner.handle(str(body["name"]),
                              body.get("arg") if body.get("arg") is not None else None)
        except Exception as e:
            self.owner.log(f"ошибка обработки {body}: {e}")


class Window:
    _ver_sent = None            # последний отправленный подвал: шлём, только если он сменился
    _ver = None                 # версии программы и sing-box: они не меняются, читаем раз
    data = None                 # каталог данных; задаётся в __init__
    ctrl = None                 # control.Controller; задаётся в __init__
    # Обновление: state — "" | available | working | error. Словарь каждый раз
    # заменяется целиком: его пишет фоновый поток, а читает главный.
    upd = NO_UPDATE
    _upd_info = None            # что ставить: ответ update.pick
    upd_timer = None            # плановая проверка; задаётся в start_update_checks
    _upd_checked = 0.0          # когда последний раз спрашивали GitHub

    def __init__(self, base, state, log, ctrl, data=None):
        self.base = base            # код: vpn, скрипты, sing-box
        self.data = data or base    # данные: conf/, lib/state
        self.state = state
        self.log = log
        # Включение, выключение и перезапуск — только через контроллер: он
        # один на меню и окно, операции идут по одной и доводятся до конца.
        self.ctrl = ctrl
        self.win = None
        self.view = None
        self.timer = None

    # ------------------------------------------------------------- создание

    def show(self):
        # Окно открывают, чтобы посмотреть, — тогда и спросить про новую
        # версию. Одной плановой проверки мало: релиз, вышедший через минуту
        # после старта, иначе ждал бы её шесть часов.
        if self.upd_timer is not None and time.time() - self._upd_checked > UPDATE_ON_SHOW:
            self.check_update()
        if self.win is not None:
            self.win.center()
            self.win.makeKeyAndOrderFront_(None)
            NSApp.activateIgnoringOtherApps_(True)
            return

        install_edit_menu()
        cfg = WKWebViewConfiguration.alloc().init()
        ucc = WKUserContentController.alloc().init()
        self.bridge = Bridge.alloc().initWithOwner_(self)
        ucc.addScriptMessageHandler_name_(self.bridge, "py")
        cfg.setUserContentController_(ucc)

        rect = NSMakeRect(0, 0, 940, 560)
        style = (NSTitledWindowMask | NSClosableWindowMask |
                 NSMiniaturizableWindowMask | NSResizableWindowMask)
        self.win = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            rect, style, NSBackingStoreBuffered, False)
        self.win.setTitle_("DualVPN")
        self.win.setReleasedWhenClosed_(False)   # окно переоткрывают, не пересоздают
        self.win.center()

        self.view = WKWebView.alloc().initWithFrame_configuration_(rect, cfg)
        self.view.setAutoresizingMask_(2 | 16)   # тянется по ширине и высоте
        self.win.contentView().addSubview_(self.view)

        # В бандле ресурсы лежат в Contents/Resources, а не рядом с модулем,
        # который py2app вообще упаковывает в zip.
        here = os.path.dirname(os.path.abspath(__file__))
        page = os.path.join(here, "ui", "index.html")
        if not os.path.exists(page):
            for up in (here, os.path.dirname(here), os.path.dirname(os.path.dirname(here))):
                cand = os.path.join(up, "ui", "index.html")
                if os.path.exists(cand):
                    page = cand
                    break
        url = NSURL.fileURLWithPath_(page)
        self.view.loadFileURL_allowingReadAccessToURL_(
            url, NSURL.fileURLWithPath_(os.path.dirname(page)))

        # В режиме проверки окно не показываем: тест гоняется при установке,
        # и выскакивающее посреди неё окно человек принимает за сбой. Оно всё
        # так же создаётся и грузит страницу — проверяется ровно то же самое.
        if os.environ.get("VPNLX_TEST_WINDOW"):
            self.win.setFrameOrigin_(NSMakePoint(-20000, -20000))
        else:
            self.win.makeKeyAndOrderFront_(None)
            NSApp.activateIgnoringOtherApps_(True)
        self.log("окно: создано")

        self.timer = NSTimer.scheduledTimerWithTimeInterval_repeats_block_(
            POLL, True, lambda _t: self.push())
        # Страница грузится асинхронно; первый кадр — когда она уже готова.
        NSTimer.scheduledTimerWithTimeInterval_repeats_block_(
            0.6, False, lambda _t: self.push())

    # ------------------------------------------------------------ отправка

    def visible(self):
        return self.win is not None and bool(self.win.isVisible())

    def eval(self, script):
        if self.view is not None:
            self.view.evaluateJavaScript_completionHandler_(script, None)

    def push(self):
        if self.win is None or not self.win.isVisible():
            return
        self.eval(f"call('render', {_js(self.status())})")
        self.eval(f"call('renderConfs', {_js(self.configs())})")
        self.eval(f"call('renderLogs', {_js(self.tail())})")
        self.eval(f"call('renderHowto', {_js(self.howto())})")
        v = self.version()
        if v != self._ver_sent:
            if self._ver_sent is None:
                self.log(f"окно: версия {v['app']} / sing-box {v['singbox'] or '—'}")
            self._ver_sent = v
            self.eval(f"call('renderVersion', {_js(v)})")

    def status(self):
        st = {}
        try:
            with open(os.path.join(self.state, "status.json"), encoding="utf-8") as fh:
                st = json.load(fh)
            # Пробер давно не писал — показаниям верить нельзя.
            if time.time() - st.get("updated", 0) > 15:
                st = {}
        except Exception:
            st = {}             # пробер ещё не написал первый статус
        st["up"] = bool(st.get("up"))
        st["err_count"] = self.err_count() if st else 0
        st["daemon"] = self.daemon_installed()

        # Операция и её исход. Раньше причину отказа угадывали по фразам в
        # логе, и половины фраз в списке не было — окно писало «выключено»,
        # когда служба падала на битом конфиге. Теперь служба пишет причину
        # сама (vpn: fail_start), а контроллер добавляет свои таймауты.
        op = (self.ctrl.snapshot() if self.ctrl is not None
              else {"phase": "idle", "step": "", "busy": False,
                    "error": "", "error_log": []})
        st["op"] = {"phase": op["phase"], "step": op["step"], "busy": op["busy"]}
        # Ошибку при поднятом туннеле не показываем: значит, его подняли
        # уже после неё, и она устарела.
        st["error"] = "" if st["up"] else op["error"]
        st["error_log"] = op["error_log"] if st["error"] else []
        return st

    def session(self):
        """Строки только последнего запуска службы."""
        return control.last_session(self.tail())

    def err_count(self):
        """Счётчик ошибок за текущий запуск.

        В приложении лог пишет демон, а не пробер, поэтому err_count из
        tui.py тут всегда нулевой — считаем сами по журналу.
        """
        return sum(1 for l in self.session()
                   if " ERROR " in l or l.startswith("ERROR"))

    # Те же правила, что в build-config.py: имя файла решает, чем он будет.
    CORP_PAT = (r"^corp\.conf$", r"^wg[-_0-9].*\.conf$", r"^wg\.conf$")
    PERSONAL_PAT = (r"^personal\.conf$", r"^(awg|amnezia).*\.conf$")

    def configs(self):
        """Два раздела: рабочий и личный.

        Личный выбирается — их может лежать сколько угодно. Рабочий не
        выбирается: build-config.py берёт единственный подходящий и ругается,
        если их несколько, поэтому здесь это показано как ошибка, а не выбор.
        """
        d = os.path.join(self.data, "conf")
        try:
            files = sorted(f for f in os.listdir(d) if f.lower().endswith(".conf"))
        except OSError:
            files = []

        corp = []
        for pat in self.CORP_PAT:
            m = [f for f in files if re.match(pat, f, re.I)]
            if m:
                corp = m
                break

        chosen = ""
        try:
            with open(os.path.join(self.state, "profile"), encoding="utf-8") as fh:
                chosen = fh.read().strip()
        except OSError:
            pass
        # Профиль мог указывать на удалённый файл — тогда он не в счёт.
        if chosen and chosen + ".conf" not in files:
            chosen = ""
        chosen_explicit = bool(chosen)

        personal = [f for f in files if f not in corp]
        if not chosen:
            for pat in self.PERSONAL_PAT:
                m = [f for f in personal if re.match(pat, f, re.I)]
                if m:
                    chosen = m[0][:-5]
                    break

        # Когда профиль не выбран, build-config.py тоже ищет по шаблонам и
        # падает, если подходящих несколько. Раньше окно в этом случае бодро
        # подсвечивало первый и молчало о том, что сборка не пройдёт.
        p_ambiguous = False
        if not chosen_explicit:
            for pat in self.PERSONAL_PAT:
                m = [f for f in personal if re.match(pat, f, re.I)]
                if m:
                    p_ambiguous = len(m) > 1
                    break

        return {
            "corp": [{"name": f[:-5], "active": True} for f in corp],
            # Несколько рабочих — не выбор, а поломка: сборка конфига упадёт.
            "corp_ambiguous": len(corp) > 1,
            "personal": [{"name": f[:-5], "active": f[:-5] == chosen}
                         for f in personal],
            "personal_ambiguous": p_ambiguous,
        }

    def tool(self, name):
        """Путь к файлу из состава программы: плоско в .app, в lib/* в проекте."""
        flat = os.path.join(self.base, name)
        if os.path.exists(flat):
            return flat
        for sub in ("lib/bin", "lib/scripts", "lib/launchd"):
            p = os.path.join(self.base, sub, name)
            if os.path.exists(p):
                return p
        return flat

    def version(self):
        """Подвал окна: версия программы и бинарника, состояние обновления."""
        if self._ver is None:
            self._ver = self.versions()
        return dict(self._ver, update=dict(self.upd))

    def versions(self):
        """Версия программы и бинарника.

        Версия лежит в файле VERSION в корне: её же читает сборка .app,
        чтобы номер в окне и в свойствах приложения не разъезжались.
        """
        try:
            with open(os.path.join(self.base, "VERSION"), encoding="utf-8") as fh:
                ver = fh.read().strip()
        except OSError:
            ver = "?"
        sb = ""
        try:
            out = subprocess.run([self.tool("sing-box"), "version"],
                                 capture_output=True, text=True, timeout=5)
            first = (out.stdout or "").splitlines()[0] if out.stdout else ""
            sb = first.replace("sing-box version", "").strip()
        except Exception:
            pass
        return {"app": ver, "singbox": sb}

    def howto(self):
        """Факты для раздела «как это работает» — из собранного конфига.

        Общие слова про VPN человек и так найдёт; ценно здесь то, что показаны
        его собственные подсети, его DNS и его эндпоинты.
        """
        out = {"corp_nets": [], "corp_dns": "", "corp_domains": [],
               "endpoints": [], "final": ""}
        try:
            with open(os.path.join(self.state, "config.json"), encoding="utf-8") as fh:
                cfg = json.load(fh)
        except Exception:
            return out

        for e in cfg.get("endpoints", []):
            peers = e.get("peers") or [{}]
            out["endpoints"].append({
                "tag": e.get("tag", ""),
                "address": f"{peers[0].get('address','')}:{peers[0].get('port','')}",
                "mtu": e.get("mtu", ""),
                "awg": bool(e.get("jc") or e.get("s1")),
            })

        for r in cfg.get("route", {}).get("rules", []):
            if r.get("outbound") == "wg-corp" and r.get("ip_cidr"):
                out["corp_nets"] = _list(r["ip_cidr"])
            if r.get("final"):
                out["final"] = r["final"]
        out["final"] = out["final"] or cfg.get("route", {}).get("final", "")

        for srv in cfg.get("dns", {}).get("servers", []):
            if srv.get("tag") == "dns-corp":
                out["corp_dns"] = srv.get("server", "")
        for r in cfg.get("dns", {}).get("rules", []):
            if r.get("server") == "dns-corp":
                out["corp_domains"] = _list(r.get("domain_suffix") or r.get("domain"))

        try:
            out["resolvers"] = sorted(os.listdir("/etc/resolver"))
        except OSError:
            out["resolvers"] = []
        return out

    def tail(self):
        return control.read_tail(os.path.join(self.state, "ui.log"), TAIL)

    # -------------------------------------------------------------- приём

    def handle(self, name, arg):
        if name == "site":
            self.eval(f"call('showSite', {_js(self.site())})")
        elif name == "load_site":
            self.load_site()
        elif name == "save_site":
            self.save_site(arg or {})
        elif name == "install_daemon":
            self.install_daemon()
        elif name == "update":
            self.start_update()
        elif name == "ready":
            self.log("окно: страница загрузилась")
        elif name == "jserror":
            self.log(f"окно: ОШИБКА JS — {arg}")
        elif name == "rendered":
            self.log(f"окно: отрисовано {arg}")
        elif name == "start":
            self.ctrl.start()
        elif name == "stop":
            self.ctrl.stop()
        elif name == "restart":
            self.ctrl.restart()
        elif name == "check":
            # Пробер живёт в этом же процессе (menubar.py), так что зовём его
            # напрямую. Идущую проверку он не дублирует.
            tui.probe_now(manual=True)
        elif name == "dismiss_error":
            self.ctrl.dismiss()
        elif name == "logs":
            self.eval(f"call('renderLogs', {_js(self.tail())})")
        elif name == "info":
            self.show_info(arg)
        elif name == "show_config":
            self.show_config(arg)
        elif name == "use_config":
            self.use_config(arg)
        elif name == "add_config":
            self.add_config(arg or "personal")
        elif name == "edit_config":
            self.edit_config(arg)
        elif name == "del_config":
            self.del_config(arg)
        else:
            self.log(f"неизвестное сообщение из окна: {name}")

    # Абзацами: страница сама переносит текст по ширине. Раньше здесь были
    # переносы строк, и в окне они сохранялись — абзац рвался посреди фразы.
    # Коротко и по убыванию важности. Прошлый текст был втрое длиннее и
    # ровный по тону — из него не было видно, что главное.
    INFO = {
        "corp": ("Рабочий туннель", [
            "Файл WireGuard от админа. Должен быть ровно один.",
            "Новый выдали — ＋ в заголовке раздела. Старый удалится, "
            "файл скопируется к себе, исходник больше не нужен.",
            "Имена: corp.conf, wg.conf, wg-*.conf, wg0-*.conf. "
            "Другое имя программа поправит сама.",
            "Куда идёт трафик, решает AllowedIPs внутри файла.",
        ]),
        "personal": ("Личный туннель", [
            "Всё, что не ушло в рабочий туннель, идёт сюда.",
            "Держи сколько угодно и переключайся кликом.",
            "Имена: personal.conf, awg-*.conf, amnezia-*.conf — "
            "или любой файл, выбранный в списке.",
            "AmneziaWG подхватывается сам: если в файле есть Jc, S1, H1 "
            "и подобные поля, маскировка уже работает.",
        ]),
    }

    def daemon_installed(self):
        return os.path.exists(PLIST)

    def install_daemon(self):
        """Ставит службу, спрашивая пароль администратора системным окном.

        Без службы приложение бесполезно: туннель правит таблицу маршрутов,
        а окно работает от обычного пользователя. Просить человека открыть
        терминал ради этого — значит потерять его на первом же шаге.
        """
        script = self.tool("install-daemon.sh")
        if not os.path.exists(script):
            self.eval(f"failed({_js('не нашёл установщик службы')})")
            return

        user = os.environ.get("USER") or ""
        # Кавычки внутри osascript двойные, поэтому пути не должны их содержать;
        # свои пути мы контролируем, но проверить дешевле, чем ловить потом.
        if '"' in script or '"' in user:
            self.eval(f"failed({_js('недопустимый путь установки')})")
            return
        # Внутри строки AppleScript кавычки экранируются: без \" osascript
        # падал с синтаксической ошибкой, и служба из DMG не ставилась.
        cmd = f'SUDO_USER={user} /bin/bash \\"{script}\\"'
        osa = (f'do shell script "{cmd}" with administrator privileges '
               f'with prompt "DualVPN устанавливает фоновую службу. '
               f'Она поднимает туннель, для этого нужны права администратора."')
        r = subprocess.run(["/usr/bin/osascript", "-e", osa],
                           capture_output=True, text=True)
        if r.returncode != 0:
            err = (r.stderr or "").strip()
            # -128 — человек нажал «Отмена», это не ошибка.
            msg = "" if "-128" in err else (err[:160] or "не удалось поставить службу")
            self.log(f"установка службы: {err[:200]}")
            if msg:
                self.eval(f"failed({_js(msg)})")
            return
        self.log("служба установлена")
        self.push()

    # ---------------------------------------------------------- обновление

    def updatable(self):
        """Обновлять есть что, только если работаем из установленного .app.

        Копия из репозитория (menubar.py под venv) версию берёт из VERSION
        рабочей копии, и сравнивать её с релизом бессмысленно.
        """
        return self.base == os.path.join(INSTALLED_APP, "Contents", "Resources")

    def start_update_checks(self):
        """Проверка при старте и раз в UPDATE_EVERY. Зовётся из главного потока."""
        if os.environ.get("VPNLX_TEST_WINDOW") or not self.updatable():
            return
        self.check_update()
        self.upd_timer = NSTimer.scheduledTimerWithTimeInterval_repeats_block_(
            UPDATE_EVERY, True, lambda _t: self.check_update())

    def check_update(self):
        if self.upd["state"] == "working":
            return
        self._upd_checked = time.time()
        threading.Thread(target=self._check_update, daemon=True).start()

    def _check_update(self):
        cur = self.version()["app"]
        try:
            info = update.check(cur)
        except update.UpdateError as e:
            # Фоновая проверка молчит: нет сети — не повод что-то показывать.
            self.log(f"обновление: проверка не удалась — {e}")
            return
        if self.upd["state"] == "working":
            return
        self._upd_info = info
        if info:
            self.log(f"обновление: есть {info['version']} (стоит {cur})")
            self.upd = dict(NO_UPDATE, state="available", version=info["version"])
        else:
            self.log(f"обновление: новее {cur} нет")
            self.upd = NO_UPDATE

    def start_update(self):
        info = self._upd_info
        if info is None or self.upd["state"] not in ("available", "error"):
            return
        self.upd = dict(NO_UPDATE, state="working", version=info["version"],
                        step="скачиваю")
        self.push()
        threading.Thread(target=self._update, args=(info,), daemon=True).start()

    def _update_step(self, step):
        self.upd = dict(self.upd, step=step)

    def _update(self, info):
        """Скачать, сверить, открыть образ и поставить. В фоновом потоке.

        Подвал перерисовывает таймер окна: из этого потока окно не трогаем.
        """
        tmp = tempfile.mkdtemp(prefix="dualvpn-update-")
        point = os.path.join(tmp, "mnt")
        mounted = False
        try:
            dmg = update.download(info, tmp)
            self._update_step("открываю образ")
            os.mkdir(point)
            app = update.mount(dmg, point)
            mounted = True
            self._update_step("жду пароль")
            err = self._apply(app, info["version"])
        except update.UpdateError as e:
            err = str(e)
        except OSError as e:
            err = f"обновление: {e}"
        finally:
            if mounted:
                update.unmount(point)
            shutil.rmtree(tmp, ignore_errors=True)

        if err is None:                 # «Отмена» в запросе пароля
            self.upd = dict(NO_UPDATE, state="available", version=info["version"])
        elif err:
            self.log(f"обновление: {err}")
            self.upd = dict(NO_UPDATE, state="error", version=info["version"],
                            error=err)
        else:
            self.log(f"обновление: поставлено {info['version']}, перезапускаюсь")
            self.relaunch()

    def _apply(self, app, version):
        """apply-update.sh под root. '' — успех, None — отмена, иначе ошибка.

        Скрипт — из установленного приложения, не из скачанного: под root
        идёт только код, которому уже доверились при установке.
        """
        script = self.tool("apply-update.sh")
        if not os.path.exists(script):
            return "не нашёл установщик обновления"
        user = os.environ.get("USER") or ""
        if '"' in script or '"' in app or '"' in user:
            return "недопустимый путь обновления"
        cmd = f'SUDO_USER={user} /bin/bash \\"{script}\\" \\"{app}\\"'
        osa = (f'do shell script "{cmd}" with administrator privileges '
               f'with prompt "DualVPN ставит версию {version}. '
               f'Чтобы заменить приложение в Программах, нужны права администратора."')
        r = subprocess.run(["/usr/bin/osascript", "-e", osa],
                           capture_output=True, text=True)
        for line in (r.stdout or "").strip().splitlines():
            self.log(f"apply-update: {line}")
        if r.returncode != 0:
            err = (r.stderr or "").strip()
            # -128 — человек нажал «Отмена», это не ошибка.
            return None if "-128" in err else (err[:160] or "не удалось поставить")
        return ""

    def relaunch(self):
        """Закрыться и открыть уже новую версию.

        open ждёт пару секунд: пока жив этот процесс, он лишь активировал бы
        его же. Туннель не трогаем — им владеет служба, а не приложение.
        """
        subprocess.Popen(["/bin/sh", "-c", f'sleep 2; /usr/bin/open "{INSTALLED_APP}"'],
                         start_new_session=True)
        AppHelper.callAfter(NSApp.terminate_, None)

    SITE_KEYS = ("CORP_DOMAINS", "CORP_PROBE", "CORP_HOSTS", "SB_CORP_EXCLUDE")

    def site_path(self):
        return os.path.join(self.data, "conf", "site.env")

    def site(self):
        """Текущие настройки рабочей сети.

        Раньше домен и адреса были зашиты в код. После выноса в site.env
        задать их стало нечем: файл руками создаёт не каждый, а без него
        рабочая сеть просто не резолвится.
        """
        out = {k: "" for k in self.SITE_KEYS}
        try:
            with open(self.site_path(), encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    if k in out:
                        out[k] = v.strip().strip('"').strip("'")
        except OSError:
            pass
        return out

    def load_site(self):
        """Читает готовый site.env и подставляет значения в форму.

        Не сохраняет сразу: человек должен увидеть, что именно подхватилось,
        прежде чем это уедет в файл.
        """
        panel = NSOpenPanel.openPanel()
        panel.setMessage_("Файл настроек рабочей сети (site.env)")
        panel.setAllowsOtherFileTypes_(True)
        if panel.runModal() != 1:
            return
        src = str(panel.URLs()[0].path())
        out = {k: "" for k in self.SITE_KEYS}
        try:
            with open(src, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    if k.startswith("export "):
                        k = k[len("export "):].strip()
                    if k in out:
                        out[k] = v.strip().strip('"').strip("'")
        except OSError as e:
            self.eval(f"failed({_js(str(e))})")
            return
        if not any(out.values()):
            self.eval(f"failed({_js('в файле нет знакомых настроек')})")
            return
        self.log(f"настройки подхвачены из {os.path.basename(src)}")
        self.eval(f"call('fillSite', {_js(out)})")

    def save_site(self, values):
        # Пробелы и переносы — в один пробел: список, вставленный столбиком,
        # тоже должен лечь строкой, а bash делит значение как раз по пробелам.
        vals = {k: " ".join(str(values.get(k, "") or "").split())
                for k in self.SITE_KEYS}
        # Кавычки в значении разорвали бы строку файла, который читает bash.
        for k, v in vals.items():
            if '"' in v:
                self.eval(f"failed({_js('кавычки в поле ' + k + ' недопустимы')})")
                return
        text = ("# Настройки рабочей сети. Файл читают vpn и скрипты диагностики.\n"
                "# Создан из окна программы.\n")
        for k in self.SITE_KEYS:
            text += f'{k}="{vals[k]}"\n'
        try:
            os.makedirs(os.path.dirname(self.site_path()), exist_ok=True)
            with open(self.site_path(), "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(self.site_path(), 0o600)
            self.log("настройки рабочей сети сохранены")
        except OSError as e:
            self.eval(f"failed({_js(str(e))})")
            return
        self.eval("closeSheet()")
        # Домены попадают в конфиг при сборке, то есть при старте туннеля.
        if self.status().get("up"):
            self.ctrl.restart()
        self.push()

    def show_info(self, key):
        title, paras = self.INFO.get(key, ("", []))
        if title:
            self.eval(f"showInfo({_js(title)}, {_js(paras)})")

    @staticmethod
    def _safe(name):
        """Имя приходит со страницы, а дальше идёт в open и unlink."""
        return bool(name) and not set(name) & set("/\\") and name not in (".", "..")

    def show_config(self, name):
        if not self._safe(name):
            return
        path = os.path.join(self.data, "conf", f"{name}.conf")
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            text = f"не читается: {e}"
        # Ключи прячет страница; сюда они всё же попадают, поэтому в лог ни строчки.
        self.eval(f"showConf({_js(name)}, {_js(text)})")

    def use_config(self, name):
        if not self._safe(name):
            return
        if any(c["name"] == name for c in self.configs()["corp"]):
            return                      # рабочий не выбирают, он один

        cur = [c for c in self.configs()["personal"] if c["active"]]
        if cur and cur[0]["name"] == name:
            return

        up = bool(self.status().get("up"))
        # Раньше здесь просто писался файл, а профиль читается при старте
        # туннеля: отметка переезжала, трафик шёл через прежний конфиг, и
        # понять это было невозможно. Теперь либо применяем, либо не трогаем.
        if up and not self.confirm(
                f"Переключиться на {name}?",
                "Туннель перезапустится, соединения оборвутся.",
                ok="Переключить"):
            return

        try:
            with open(os.path.join(self.state, "profile"), "w", encoding="utf-8") as fh:
                fh.write(name)
            self.log(f"профиль: {name}")
        except OSError as e:
            self.log(f"не смог сохранить профиль: {e}")
            self.eval(f"failed({_js(str(e))})")
            return

        if up:
            self.ctrl.restart()
        self.push()

    def add_config(self, kind):
        panel = NSOpenPanel.openPanel()
        panel.setAllowedFileTypes_(["conf"])
        panel.setMessage_("Рабочий конфиг WireGuard" if kind == "corp"
                          else "Личный конфиг WireGuard или AmneziaWG")
        if panel.runModal() != 1:
            return
        src = str(panel.URLs()[0].path())
        base = os.path.basename(src)

        # Тип определяется именем файла, поэтому имя приводим к нужному виду.
        # Иначе файл office.conf, выбранный как рабочий, молча стал бы личным.
        looks_corp = any(re.match(p, base, re.I) for p in self.CORP_PAT)
        if kind == "corp" and not looks_corp:
            base = "wg-" + base
        elif kind == "personal" and looks_corp:
            base = "awg-" + base

        conf_dir = os.path.join(self.data, "conf")
        dst = os.path.join(conf_dir, base)
        cur = self.configs()["corp"]
        replacing = [c["name"] + ".conf" for c in cur if c["name"] + ".conf" != base] \
            if kind == "corp" else []

        if replacing:
            if not self.confirm("Заменить рабочий конфиг?",
                                f"{', '.join(replacing)} будет удалён, "
                                f"вместо него — {base}.", ok="Заменить"):
                return
        if os.path.exists(dst) and not os.path.samefile(src, dst):
            if not self.confirm(f"Перезаписать {base}?",
                                "Файл с таким именем уже есть.", ok="Перезаписать"):
                return

        # Сначала копия во временный файл рядом, и только потом подмена. Иначе
        # неудачное копирование (нет места, источник пропал) оставляло бы
        # каталог вообще без рабочего конфига — сборка перестала бы проходить.
        tmp = dst + ".new"
        try:
            shutil.copy2(src, tmp)
            os.chmod(tmp, 0o600)            # внутри приватный ключ
            for old_name in replacing:      # их может быть несколько, если уже намусорено
                os.unlink(os.path.join(conf_dir, old_name))
            os.replace(tmp, dst)
            self.log(f"добавлен конфиг: {base}")
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            self.eval(f"failed({_js(str(e))})")
            return

        # Перезапуск нужен не только рабочему: если перезаписан файл активного
        # личного профиля, туннель тоже работает по старому содержимому.
        active = [c["name"] for c in self.configs()["personal"] if c["active"]]
        touches_active = kind == "corp" or base[:-5] in active
        if touches_active and self.status().get("up"):
            self.ctrl.restart()
        self.push()

    def edit_config(self, name):
        """Открывает файл в системном редакторе.

        Свой редактор в окне не делаю: там пришлось бы показать приватный ключ
        открытым текстом, ради чего маскировка в просмотре и заводилась.
        """
        if not self._safe(name):
            return
        path = os.path.join(self.data, "conf", f"{name}.conf")
        if os.path.exists(path):
            subprocess.run(["/usr/bin/open", "-t", path])

    def del_config(self, name):
        if not self._safe(name):
            return
        if not self.confirm(f"Удалить {name}.conf?",
                            "Файл будет удалён с диска, это не отменить."):
            return
        try:
            os.unlink(os.path.join(self.data, "conf", f"{name}.conf"))
            self.log(f"удалён конфиг: {name}")
            # Иначе демон при старте не найдёт профиль, выйдет с ошибкой,
            # launchd поднимет его снова — и так по кругу, без объяснений.
            prof = os.path.join(self.state, "profile")
            if os.path.exists(prof):
                with open(prof, encoding="utf-8") as fh:
                    if fh.read().strip() == name:
                        os.unlink(prof)
        except OSError as e:
            self.alert("Не удалось удалить", str(e))
        self.eval("closeSheet()")
        self.push()

    # ------------------------------------------------------------- диалоги

    def alert(self, text, info=""):
        a = NSAlert.alloc().init()
        a.setMessageText_(text)
        a.setInformativeText_(info)
        a.runModal()

    def confirm(self, text, info="", ok="Удалить"):
        a = NSAlert.alloc().init()
        a.setMessageText_(text)
        a.setInformativeText_(info)
        a.addButtonWithTitle_(ok)
        a.addButtonWithTitle_("Отмена")
        return a.runModal() == 1000        # 1000 = первая кнопка
