"""Окно приложения: та же вёрстка, что была на macOS, но на WebView2.

Вёрстка (ui/index.html) осталась прежней, поменялся только её мост: наружу
идёт `window.pywebview.api.send(name, arg)`, внутрь — `call(fn, arg)` и
`callN(fn, [args])`, которые дёргают `window[fn]`. Разметка, стили и вся
логика отрисовки — те же, что были на macOS.

Само окно систему не трогает: всё, что требует прав, уходит в службу через
именованный канал. Поэтому окно запускается от обычного пользователя, и UAC
на нём не появляется — кроме одного случая: запись конфигов (см. _admin_call).
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time

from . import instance, ipc, paths

POLL_EVERY = 2.0
# Сколько ждём отчёта страницы о готовности. Не дождались — WebView2 не
# поднялся, и окно так и висело бы серым: выходим с READY_LOST, трей
# перезапустит окно.
READY_WAIT = 20.0
READY_LOST = 3

# Фильтр для create_file_dialog. pywebview проверяет каждую строку регуляркой
# вида ^([\w ]+)\(\*\.\w+...\)$ : в описании допустимы только буквы и пробелы,
# без точек, а кириллица на части сборок под \w не подходит. Из-за «site.env
# (*.env)» и «Все файлы (*.*)» диалог падал с ValueError ещё до открытия —
# держим строки латиницей и без точек в описании.
_FILE_TYPES = ("Config files (*.conf;*.env)", "All files (*.*)")


def _is_admin():
    """Уже ли этот процесс с правами администратора.

    В портативной версии — да всегда, весь процесс поднят с правами при
    первом запуске. В установленной — нет: окно намеренно живёт от обычного
    пользователя, иначе UAC спрашивал бы себя на каждое открытие окна.
    """
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_elevated(exe, args, show=False):
    """Запускает exe с правами (UAC) и ждёт, пока он завершится.

    show — окно процесса видно: admin-op прячем, Блокнот с конфигом — нет.

    Раньше это делал powershell Start-Process -Verb RunAs: тот же
    ShellExecuteEx внутри, но сначала секунда-другая на запуск самого
    PowerShell — до появления окна UAC. Отказ в UAC приходит исключением;
    наружу он не выходит: вызывающий судит по файлу ответа.
    """
    import pywintypes
    import win32api
    import win32con
    import win32event
    from win32com.shell import shell, shellcon

    try:
        info = shell.ShellExecuteEx(
            fMask=shellcon.SEE_MASK_NOCLOSEPROCESS, lpVerb="runas",
            lpFile=exe, lpParameters=subprocess.list2cmdline(args),
            nShow=win32con.SW_SHOWNORMAL if show else win32con.SW_HIDE)
    except pywintypes.error:
        return
    proc = info.get("hProcess")
    if not proc:
        return
    try:
        win32event.WaitForSingleObject(proc, win32event.INFINITE)
    finally:
        win32api.CloseHandle(proc)


def _service_installed():
    """Стоит ли служба: канал молчит и у остановленной, а «Нужна установка»
    положено показывать только у непоставленной. None — узнать нечем.
    """
    try:
        import pywintypes
        import win32serviceutil
    except ImportError:
        return None
    try:
        win32serviceutil.QueryServiceStatus(paths.SERVICE_NAME)
        return True
    except pywintypes.error:
        return False


class Api:
    """То, что вёрстка зовёт через мост. Имена сообщений заданы в index.html."""

    def __init__(self, window_holder):
        self.holder = window_holder
        self.ready = threading.Event()
        # Прогретое окно, спрятанное до первого показа или крестиком.
        self.hidden = False

    # ------------------------------------------------------- приём из JS

    def send(self, name, arg=None):
        try:
            return self._dispatch(name, arg)
        except ipc.NotRunning as exc:
            self.js("failed", str(exc))
        except Exception as exc:                       # noqa: BLE001
            self.js("failed", f"{name}: {exc}")
        return None

    def _dispatch(self, name, arg):
        if name == "ready":
            self.ready.set()
            self.refresh(full=True)
            # Статус туннелей сразу при открытии: сама служба меряет сеть
            # только на подъёме туннеля, и прежний ответ мог устареть на часы.
            # Спрятанному окну проверка ни к чему — её сделает показ.
            if not self.hidden:
                threading.Thread(target=self._check, daemon=True).start()
        elif name == "check":
            threading.Thread(target=self._check, daemon=True).start()
        elif name == "start":
            self._guard(ipc.call("start", profile=""))
        elif name == "stop":
            self._guard(ipc.call("stop"))
        elif name == "restart":
            ipc.call("stop")
            self._guard(ipc.call("start", profile=""))
        elif name == "set_autostart":
            # Флажок лежит в каталоге службы — команда под администратором,
            # как и правка конфигов. Чем бы ни кончился UAC, флажок на
            # странице должен вернуться к настоящему состоянию.
            try:
                self._guard(self._admin_call("set-autostart", on=bool(arg)))
            finally:
                self.js("autostartDone")
                self.refresh()
        elif name == "use_config":
            self._guard(ipc.call("set-profile", profile=arg))
            self.refresh(full=True)
        elif name == "del_config":
            self._guard(self._admin_call("remove-config", name=arg["name"],
                                         kind=arg["kind"]))
            self.js("closeSheet")
            self.refresh(full=True)
        elif name == "add_config":
            self._add_config(arg)
        elif name == "show_config":
            self._show_conf(arg["name"], arg["kind"])
        elif name == "edit_config":
            # Блокнот держит поток, пока его не закроют, — мост не ждёт.
            threading.Thread(target=self._edit_conf,
                             args=(arg["name"], arg["kind"]), daemon=True).start()
        elif name == "info":
            # «i» у колонки показывает тот конфиг, что пойдёт в сборку.
            st = ipc.call("status").get("status", {})
            conf = self._confs(st).get(arg) or []
            chosen = [c for c in conf if c["active"]] or conf[:1]
            if chosen:
                self._show_conf(chosen[0]["name"], arg)
        elif name == "site":
            self.js("showSite", _parse_env(self._admin_call("get-site").get("text", "")))
        elif name == "load_site":
            self._load_site()
        elif name == "save_site":
            self._guard(self._admin_call("set-site", text=_format_env(arg or {})))
            self.js("closeSheet")
            self.js("restarting")
            ipc.call("stop")
            self._guard(ipc.call("start", profile=""))
        elif name == "logs":
            self._push_logs()
        elif name == "install_daemon":
            self._install_hint()
        elif name in ("rendered", "jserror"):
            # Диагностика страницы. jserror приходит, когда упала отрисовка, —
            # без него исключение внутри WebView2 не видно вообще нигде.
            if name == "jserror":
                self._log(f"js: {arg}")
        return None

    @staticmethod
    def _guard(reply):
        if not reply.get("ok"):
            raise RuntimeError(reply.get("error") or "служба отказала")

    # ------------------------------------------------------------- права

    def _admin_call(self, op, **payload):
        """Команда, которая пишет или читает conf\\ — там приватные ключи.

        Канал (ipc.Server) требует для таких команд администратора: обычный
        пользователь на многопользовательской машине не должен доставать чужие
        ключи через именованный канал, даже если сам он умеет к нему постучаться.

        Окно намеренно не элевировано целиком — иначе UAC спрашивал бы себя
        при каждом открытии окна, хотя конфиги правят редко. Поэтому права
        просим точечно, ровно на это одно действие: один короткий процесс,
        одно окно UAC, готовый результат — и он сразу же завершается.
        """
        if _is_admin():
            # Портативная версия элевирована с самого первого запуска —
            # выпрашивать права ещё раз значит просто мучить пользователя
            # лишним UAC-окном без всякой пользы.
            return ipc.call(op, **payload)

        with tempfile.TemporaryDirectory() as td:
            payload_file = os.path.join(td, "payload.json")
            result_file = os.path.join(td, "result.json")
            with open(payload_file, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)

            if getattr(sys, "frozen", False):
                exe, base_args = sys.executable, []
            else:
                exe, base_args = sys.executable, ["-m", "dualvpn.cli"]
            _run_elevated(exe, base_args + ["admin-op", op, payload_file, result_file])

            if os.path.isfile(result_file):
                with open(result_file, encoding="utf-8") as fh:
                    return json.load(fh)
            # UAC отменили или дочерний процесс не успел записать ответ —
            # оба исхода снаружи выглядят одинаково: действие не выполнено.
            return {"ok": False, "error": "запрос прав отменён или не выполнился"}

    # ------------------------------------------------------- вызовы в JS

    def js(self, fn, arg=None):
        w = self.holder.get("window")
        if w is None:
            return
        payload = json.dumps(arg, ensure_ascii=False, default=str)
        try:
            w.evaluate_js(f"call({json.dumps(fn)}, {payload})")
        except Exception:
            # Окно могли закрыть между проверкой и вызовом — это не ошибка.
            pass

    def jsn(self, fn, args):
        """Вызов функции страницы с несколькими аргументами."""
        w = self.holder.get("window")
        if w is None:
            return
        payload = json.dumps(list(args), ensure_ascii=False, default=str)
        try:
            w.evaluate_js(f"callN({json.dumps(fn)}, {payload})")
        except Exception:
            pass

    # ---------------------------------------------------------- обновление

    def refresh(self, full=False):
        """Гонит в страницу свежее состояние. Зовётся из потока опроса."""
        try:
            st = ipc.call("status").get("status", {})
        except ipc.NotRunning:
            self.js("render", {"up": False, "no_service": True,
                                "daemon": _service_installed()})
            return
        self.js("render", st)
        if full:
            self.js("renderVersion", {"app": st.get("version", paths.version()),
                                      "singbox": st.get("singbox", "")})
            self.js("renderConfs", self._confs(st))
            self.js("renderHowto", self._howto(st))
            self._push_logs()

    @staticmethod
    def _confs(st):
        """Раскладка конфигов по колонкам — ровно та, что ждёт renderConfs."""
        names = st.get("profiles") or []
        # Без выбранного профиля сборка берёт единственный личный — его и
        # подсвечиваем. Из нескольких без выбора не подсвечен ни один.
        active = st.get("profile") or (names[0] if len(names) == 1 else "")
        personal = [{"name": n, "active": n == active} for n in names]
        corp = [{"name": n, "active": False} for n in st.get("corp") or []]
        return {
            "corp": corp, "personal": personal,
            "corp_ambiguous": len(corp) > 1,
            "personal_ambiguous": len(names) > 1 and active not in names,
        }

    def _check(self):
        """Проверка туннелей службой сейчас; страница на это время пишет
        «проверяю…» — у каждого конфига, пока не проверен он сам."""
        self.js("checkStart")
        try:
            st = ipc.check_by_side(
                lambda st, pending: self.jsn("checkSides", (st, sorted(pending)))
            ).get("status")
            if st:
                self.js("render", st)
        except ipc.NotRunning:
            pass                       # опрос и так покажет «служба не отвечает»
        finally:
            self.js("checkDone")

    @staticmethod
    def _howto(st):
        site = paths.site_env()
        nets, endpoints = [], []
        # Туннели живут в своих процессах (corp.json, personal.json), основной
        # отдаёт корпу подсети правилом на socks-выход buildconfig.CORP_SOCKS_TAG.
        for cfg_path in (paths.CONFIG_JSON, paths.CORP_JSON, paths.PERSONAL_JSON):
            try:
                with open(cfg_path, encoding="utf-8") as fh:
                    cfg = json.load(fh)
            except (OSError, ValueError):
                continue
            for rule in cfg.get("route", {}).get("rules", []):
                if rule.get("outbound") == "corp-socks":
                    nets = rule.get("ip_cidr") or []
            for ep in cfg.get("endpoints", []):
                peers = ep.get("peers") or [{}]
                endpoints.append({
                    "tag": ep.get("tag", ""),
                    "address": ", ".join(ep.get("address") or []),
                    "mtu": ep.get("mtu"),
                    "awg": any(k in ep for k in ("jc", "s1", "h1")),
                    "peer": peers[0].get("address", ""),
                })
        return {
            "endpoints": endpoints,
            "corp_nets": nets,
            "corp_domains": (site.get("CORP_DOMAINS") or "").split(),
            "corp_dns": st.get("corp_dns", ""),
            "final": "личный туннель",
        }

    def _push_logs(self):
        self.js("renderLogs", ipc.call("log", lines=400).get("lines", []))

    # ------------------------------------------------------------ конфиги

    def _show_conf(self, name, kind):
        """Показывает содержимое конфига. Читает служба — каталог закрыт."""
        reply = self._admin_call("read-config", name=name, kind=kind)
        if reply.get("ok"):
            self.jsn("showConf", [name, kind, reply.get("text", "")])
        else:
            self.js("failed", reply.get("error") or "не прочитать конфиг")

    def _edit_conf(self, name, kind):
        """Открывает конфиг в Блокноте с правами: каталог conf\\ закрыт для
        пользователя. Свой редактор в окне не делаем, как и на macOS.

        Путь собирается только из имени, которое служба сама отдала в
        статусе: имя приходит со страницы, и «..\\» вывел бы Блокнот с правами
        за пределы conf\\.
        """
        try:
            st = ipc.call("status").get("status", {})
        except ipc.NotRunning as exc:
            self.js("failed", str(exc))
            return
        confs = self._confs(st).get(kind) if kind in ("corp", "personal") else []
        if name not in [c["name"] for c in confs]:
            self.js("failed", f"нет конфига «{name}»")
            return
        folder = paths.CONF_CORP if kind == "corp" else paths.CONF_PERSONAL
        # Полный путь: с правами запускается то, что найдётся по имени, а
        # PATH и текущий каталог пишет и обычный пользователь.
        notepad = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                               "System32", "notepad.exe")
        _run_elevated(notepad, [os.path.join(folder, f"{name}.conf")], show=True)
        self.refresh(full=True)

    def _add_config(self, kind):
        """Диалог выбора файла и передача его службе.

        Файл читаем здесь, от пользователя: у него есть доступ к своим папкам,
        а у службы под SYSTEM его может не быть — сетевой диск или профиль
        другого пользователя ей просто не видны.
        """
        import webview
        w = self.holder.get("window")
        picked = w.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=False, file_types=_FILE_TYPES)
        if not picked:
            return
        path = picked[0]
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        # Тип задаёт кнопка, имя чистит служба (buildconfig.safe_name):
        # там же удаляется прежний рабочий и выбирается новый личный.
        name = os.path.splitext(os.path.basename(path))[0]
        reply = self._admin_call("add-config", name=name, text=text, kind=kind)
        if not reply.get("ok"):
            self.js("failed", reply.get("error") or "не удалось добавить")
            return
        self.refresh(full=True)

    def _load_site(self):
        import webview
        w = self.holder.get("window")
        picked = w.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=False, file_types=_FILE_TYPES)
        if not picked:
            return
        with open(picked[0], encoding="utf-8", errors="replace") as fh:
            self.js("fillSite", _parse_env(fh.read()))

    def _install_hint(self):
        self.jsn("showInfo", [
            "Служба не установлена",
            ["Туннель держит служба Windows — без неё кнопки в окне ничего не "
             "включат: править таблицу маршрутов от обычного пользователя "
             "нельзя.",
             "Открой командную строку от имени администратора и выполни: "
             "dualvpn service install",
             "Установщик делает это сам; вручную нужно только при запуске из "
             "исходников."],
        ])

    def _log(self, line):
        try:
            paths.ensure_dirs()
            with open(os.path.join(paths.LOGS, "window.log"), "a",
                      encoding="utf-8") as fh:
                fh.write(f"{time.strftime('%H:%M:%S')} {line}\n")
        except OSError:
            pass


# ------------------------------------------------------------ site.env

def _parse_env(text):
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k.startswith("export "):
            k = k[len("export "):].strip()
        out[k] = v.strip().strip('"').strip("'")
    return out


def _format_env(values):
    """Собирает site.env обратно. Пустые поля не пишем — они значат «не задано»."""
    lines = ["# Настройки рабочей сети. Правится окном, но можно и руками.", ""]
    for key in ("CORP_DOMAINS", "CORP_PROBE", "CORP_HOSTS", "SB_CORP_EXCLUDE",
                "SB_LOG_LEVEL"):
        val = (values.get(key) or "").strip()
        if val:
            lines.append(f'{key}="{val}"')
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- запуск

def _dark_title(window):
    """Тёмный заголовок окна независимо от темы Windows.

    pywebview красит заголовок по AppsUseLightTheme, а страница всегда
    тёмная: в светлой теме над тёмным окном висела бы белая полоса.
    DWMWA_USE_IMMERSIVE_DARK_MODE = 20, с Windows 10 20H1. При смене темы
    Windows pywebview вернёт светлый — до следующего открытия окна.
    """
    try:
        import ctypes
        hwnd = window.native.Handle.ToInt32()
        on = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(on), ctypes.sizeof(on))
    except Exception:
        pass


def _source_icon():
    """Значок окна, запущенного из исходников. None — остаётся значок exe.

    pywebview берёт значок окна из sys.executable. В сборке это dualvpn.exe
    со своим ico, а из исходников — python.exe, и окно с кнопкой в панели
    задач показывали значок Python. Свой AppUserModelID нужен затем же: без
    него панель задач складывает окно в одну группу с python.exe и берёт
    значок оттуда. В сборке ID не задаём: ярлык из установщика его не знает,
    и закреплённый значок разошёлся бы с окном.
    """
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Enkeym.DualVPN")
    except Exception:
        pass
    try:
        from . import icon
        return icon.write_ico(os.path.join(tempfile.gettempdir(), "DualVPN-window.ico"))
    except Exception:
        return None


def _storage_path():
    """Своя папка данных WebView2, отдельная для прав администратора.

    По умолчанию pywebview кладёт её в общий %APPDATA%\\pywebview. Папку,
    которую уже занял браузер с другим уровнем прав или другими опциями,
    WebView2 открыть не может: инициализация кончается IsSuccess=False,
    pywebview это лишь пишет в лог, и окно остаётся серым и пустым.
    """
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "DualVPN",
                        "WebView2-" + ("admin" if _is_admin() else "user"))


def _hide_on_close(window, api):
    """Крестик прячет окно, а не закрывает процесс: следующий показ мгновенный.

    Только для закрытия пользователем: выход из системы и выключение
    отменять нельзя, иначе Windows покажет «приложение мешает завершению».
    Зовётся в потоке окна (before_show), туда же приходит FormClosing.
    """
    from System.Windows.Forms import CloseReason

    def closing(_sender, args):
        if args.CloseReason != CloseReason.UserClosing:
            return
        args.Cancel = True
        api.hidden = True
        window.native.Hide()

    window.native.FormClosing += closing


def _restore(window):
    """Свёрнутое — развернуть. SW_RESTORE, а не restore() pywebview: тот
    ставит Normal и уменьшил бы окно, развёрнутое до сворачивания на весь экран."""
    try:
        import win32con
        import win32gui
        hwnd = window.native.Handle.ToInt32()
        if win32gui.IsIconic(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
    except Exception:                                      # noqa: BLE001
        pass


def _show(window, api):
    """Показ прогретого окна по сигналу трея: свежий статус и проверка
    туннелей — как при первом открытии."""
    api.hidden = False
    window.show()
    _restore(window)
    # Страница ещё грузится — всё это сделает её ready.
    if api.ready.is_set():
        api.refresh(full=True)
        threading.Thread(target=api._check, daemon=True).start()


def open_window(resident=False, hidden=False):
    """Открывает окно; когда его закроют, завершает процесс — не возвращается.

    resident — окно трея: крестик прячет его, процесс живёт до выхода из трея,
    а показывает окно снова сигнал instance.WINDOW_SHOW. hidden — запуск
    спрятанным, прогрев: WebView2 и страница поднимаются заранее.
    """
    import webview

    holder = {}
    api = Api(holder)
    api.hidden = hidden
    # paths.UI_DIR, а не __file__: в собранном виде __file__ у модуля внутри
    # PyInstaller-архива не указывает на реальный файл на диске, и index.html
    # не находился — окно падало ещё до показа.
    index = os.path.join(paths.UI_DIR, "index.html")

    holder["window"] = webview.create_window(
        f"DualVPN {paths.version()}", index,
        js_api=api, width=1040, height=720, min_size=(880, 560), hidden=hidden,
        # Тот же фон, что --bg в index.html: иначе до загрузки страницы окно
        # белое и мигает на открытии.
        background_color="#101012")
    holder["window"].events.shown += lambda: _dark_title(holder.get("window"))
    if resident:
        holder["window"].events.before_show += lambda window: _hide_on_close(window, api)
        # Слушаем до webview.start: сигнал, пришедший, пока WebView2 ещё
        # стартует, дождётся окна в window.show().
        try:
            instance.listen(instance.WINDOW_SHOW,
                            lambda: _show(holder["window"], api))
        except OSError as exc:
            # Окно всё равно нужно; не показавшееся по сигналу трей заменит.
            api._log(f"сигнал показа недоступен: {exc}")
    icon = None if getattr(sys, "frozen", False) else _source_icon()

    def poll():
        # Ждём, пока страница отчитается о готовности: до этого window[fn]
        # ещё не определены, и любой вызов ушёл бы в пустоту.
        if not api.ready.wait(timeout=READY_WAIT):
            api._log(f"страница не ответила за {READY_WAIT:.0f} с — WebView2 "
                     "не поднялся, окно перезапускается")
            os._exit(READY_LOST)
        while holder.get("window") is not None:
            # Спрятанному окну опрос не нужен — свежее состояние даст показ.
            if not api.hidden:
                api.refresh()
            time.sleep(POLL_EVERY)

    threading.Thread(target=poll, daemon=True).start()
    # gui='edgechromium' — WebView2, он есть в Windows 10/11 из коробки.
    webview.start(gui="edgechromium", private_mode=False, icon=icon,
                  storage_path=_storage_path())
    holder["window"] = None
    # Окно закрыто — процесс тоже. WebView2 ходит через pythonnet, и потоки
    # .NET способны удержать dualvpn.exe после закрытия окна: тогда он висел
    # бы в диспетчере задач без окна. Ничего несохранённого здесь нет.
    os._exit(0)
