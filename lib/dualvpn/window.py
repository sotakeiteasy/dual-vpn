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

from . import instance, ipc, paths, tunnels

POLL_EVERY = 2.0
# Сколько ждём отчёта страницы о готовности. Не дождались — WebView2 не
# поднялся, и окно так и висело бы серым: выходим с READY_LOST, трей
# перезапустит окно.
READY_WAIT = 20.0
READY_LOST = 3
# Сколько холодное окно ждёт готовую страницу, прежде чем показаться как
# есть: дольше без окна кажется, что ярлык не сработал.
COLD_SHOW_WAIT = 4.0

# Фильтр для create_file_dialog. pywebview проверяет каждую строку регуляркой
# вида ^([\w ]+)\(\*\.\w+...\)$ : в описании допустимы только буквы и пробелы,
# без точек, а кириллица на части сборок под \w не подходит. Из-за «site.env
# (*.env)» и «Все файлы (*.*)» диалог падал с ValueError ещё до открытия —
# держим строки латиницей и без точек в описании.
_FILE_TYPES = ("Config files (*.conf)", "All files (*.*)")
# Списки правил туннеля: JSON экспорта или текст списка.
_RULES_TYPES = ("Rules (*.json;*.txt)", "All files (*.*)")


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
        # Холодное окно: создано спрятанным и покажется на ready, уже
        # отрисованным, — без него виден весь старт WebView2 с рывками.
        self.cold = False
        # Где окну встать при первом показе; до него оно за краем экрана.
        # С подчёркиванием: публичные атрибуты js_api pywebview обходит, и .NET
        # Point уводил его в рекурсию home.Empty.Empty… на каждой загрузке.
        self._home = None
        # Показ уже просили. Сигнал трея и запасной таймер бывают раньше
        # before_show: 9 октября двойной клик сразу после входа застал форму
        # несозданной, _unpark вернуть было нечего, а _park потом увёл окно за
        # край — открыто, в панели задач есть, на экране нет.
        self._show_wanted = False
        self._park_lock = threading.Lock()
        # Файл, про место которого служба спросила (ask): (имя, текст). Ответ
        # человека приходит через place_config — диалог выбора второй раз не нужен.
        self._asked = None

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
            self.reveal()
            # Статус туннелей сразу при открытии: сама служба меряет сеть
            # только на подъёме туннеля, и прежний ответ мог устареть на часы.
            # Спрятанному окну проверка ни к чему — её сделает показ.
            if not self.hidden:
                threading.Thread(target=self._check, daemon=True).start()
        elif name == "check":
            threading.Thread(target=self._check, daemon=True).start()
        elif name in ("start", "stop", "restart"):
            # Статус — сразу по ответу службы: без этого «работает» ждало
            # следующего опроса, и включение казалось дольше на POLL_EVERY.
            try:
                if name != "start":
                    reply = ipc.call("stop")
                if name != "stop":
                    reply = ipc.call("start", profile="")
                self._guard(reply)
            finally:
                self.refresh()
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
            # Выбор среди лежащих конфигов — без прав, как set-profile.
            self._guard(ipc.call("set-active", tunnel=arg["tunnel"], name=arg["name"]))
            self._apply()
        elif name == "del_config":
            self._guard(self._admin_call("remove-config", tunnel=arg["tunnel"],
                                         name=arg["name"],
                                         drop_tunnel=bool(arg.get("drop_tunnel"))))
            self.js("closeSheet")
            self._apply()
        elif name == "del_tunnel":
            self._guard(self._admin_call("remove-tunnel", tunnel=arg))
            self._apply()
        elif name == "add_config":
            self._add_config(arg or {})
        elif name == "place_config":
            self._place_config(arg or {})
        elif name == "show_config":
            self._show_conf(arg["tunnel"], arg["name"])
        elif name == "edit_config":
            # Блокнот держит поток, пока его не закроют, — мост не ждёт.
            threading.Thread(target=self._edit_conf,
                             args=(arg["tunnel"], arg["name"]), daemon=True).start()
        elif name == "move_config":
            self._guard(self._admin_call("move-config", tunnel=arg["tunnel"],
                                         name=arg["name"], to=arg["to"],
                                         drop_tunnel=bool(arg.get("drop_tunnel"))))
            self.js("closeSheet")
            self._apply()
        elif name == "set_mode":
            # «Всё остальное через этот туннель» (all) или напрямую (list у
            # основного): прежний основной служба сама переводит в list.
            self._guard(self._admin_call("set-tunnel", tunnel=arg["tunnel"],
                                         mode=arg["mode"]))
            self._apply()
        elif name == "tunnel_rules":
            self._tunnel_rules(arg)
        elif name == "save_rules":
            self._save_rules(arg)
        elif name == "load_rules":
            self._load_rules()
        elif name == "export_rules":
            self._export_rules(arg)
        elif name == "log_level":
            # Как флажок автозапуска: чем бы ни кончился UAC, галочка на
            # странице вернётся к настоящему уровню. Но только после _apply:
            # уровень держит основной процесс, и применение — полный перезапуск
            # VPN. Разблокированный раньше флажок давал второй клик посреди него,
            # и служба отвечала «уже идёт».
            try:
                self._guard(self._admin_call("set-log-level",
                                             level="debug" if arg else "info"))
                self._apply()
            finally:
                self.js("logLevelDone")
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

    def reveal(self):
        """Показывает холодное окно — один раз: зовут и ready, и запасной
        таймер open_window через COLD_SHOW_WAIT."""
        if not self.cold:
            return
        self.cold = False
        w = self.holder.get("window")
        if w is not None:
            _unpark(w, self)
            w.show()

    @staticmethod
    def _guard(reply):
        if not reply.get("ok"):
            raise RuntimeError(reply.get("error") or "служба отказала")

    def _apply(self):
        """Правка туннелей — на живой VPN через службу (решение #14): она
        перезапускает только процесс туннеля со сменившимся конфигом, а
        целиком — лишь когда сменилось то, что держит основной процесс.
        Выключенный не включает."""
        try:
            try:
                self._guard(ipc.call("apply"))
            except ipc.NotRunning:
                pass
        finally:
            self.refresh(full=True)

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
            self.js("renderHowto", self._howto(st))
            self._push_logs()

    def _check(self):
        """Проверка туннелей службой сейчас; страница на это время пишет
        «проверяю…» — у каждой плитки, пока не проверен её туннель."""
        self.js("checkStart")

        def on_side(st, pending):
            self.jsn("checkSides", (st, sorted(pending)))

        try:
            st = ipc.check_by_side(on_side).get("status")
            if st:
                self.js("render", st)
        except ipc.NotRunning:
            pass                       # опрос и так покажет «служба не отвечает»
        finally:
            self.js("checkDone")

    @staticmethod
    def _howto(st):
        """«Как подключиться» для renderHowto. Собранные конфиги в state\\run\\
        закрыты — читает служба; окну без прав она не отдаёт подсети и домены."""
        try:
            reply = ipc.call("howto")
        except ipc.NotRunning:
            reply = {}
        howto = reply.get("howto") or {"endpoints": [], "corp_nets": [],
                                        "corp_domains": []}
        return {**howto, "corp_dns": st.get("corp_dns", "")}

    def _push_logs(self):
        self.js("renderLogs", ipc.call("log", lines=400).get("lines", []))

    # ------------------------------------------------------------ конфиги

    def _show_conf(self, tunnel, name):
        """Показывает содержимое конфига. Читает служба — каталог закрыт."""
        reply = self._admin_call("read-config", tunnel=tunnel, name=name)
        if reply.get("ok"):
            self.jsn("showConf", [tunnel, name, reply.get("text", "")])
        else:
            self.js("failed", reply.get("error") or "не прочитать конфиг")

    def _edit_conf(self, tunnel, name):
        """Открывает конфиг в Блокноте с правами: каталог conf\\ закрыт для
        пользователя. Свой редактор в окне не делаем, как и на macOS.

        Путь собирается только из id и имени, которые служба сама отдала в
        статусе: они приходят со страницы, и «..\\» вывел бы Блокнот с правами
        за пределы conf\\.
        """
        try:
            st = ipc.call("status").get("status", {})
        except ipc.NotRunning as exc:
            self.js("failed", str(exc))
            return
        t = next((x for x in st.get("tunnels") or [] if x["id"] == tunnel), None)
        if t is None or name not in (t.get("confs") or []):
            self.js("failed", f"нет конфига «{name}»")
            return
        # Полный путь: с правами запускается то, что найдётся по имени, а
        # PATH и текущий каталог пишет и обычный пользователь.
        notepad = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                               "System32", "notepad.exe")
        _run_elevated(notepad, [tunnels.conf_path(t["id"], name)], show=True)
        # Был ли файл изменён, окну не узнать — каталог закрыт. Перезапуск
        # нужен только выбранному: запасной в сборку не идёт.
        try:
            if name == t.get("active"):
                self._apply()
            else:
                self.refresh(full=True)
        except Exception as exc:                       # noqa: BLE001
            self.js("failed", f"edit_config: {exc}")

    def _pick(self, file_types):
        """Путь из диалога открытия файла; None — передумали."""
        import webview
        picked = self.holder.get("window").create_file_dialog(
            webview.FileDialog.OPEN, allow_multiple=False, file_types=file_types)
        return picked[0] if picked else None

    def _add_config(self, arg):
        """Диалог выбора файла и передача его службе.

        arg пустой — место по AllowedIPs выбирает служба (_place); {tunnel} —
        в этот туннель; {tunnel, place: "replace"} — «Заменить файл…» у плитки.
        Файл читаем здесь, от пользователя: у него есть доступ к своим папкам,
        а у службы под SYSTEM его может не быть — сетевой диск или профиль
        другого пользователя ей просто не видны.
        """
        path = self._pick(_FILE_TYPES)
        if not path:
            return
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        # Имя чистит служба (tunnels.safe_name).
        name = os.path.splitext(os.path.basename(path))[0]
        self._send_config(name, text, arg.get("tunnel", ""), arg.get("place", ""))

    def _place_config(self, arg):
        """Ответ на вопрос службы о месте: place "replace" (с tunnel) или "new"."""
        asked, self._asked = self._asked, None
        if asked is None or arg.get("place") not in ("replace", "new"):
            return
        self._send_config(*asked, arg.get("tunnel", ""), arg["place"])

    def _send_config(self, name, text, tunnel, place):
        reply = self._admin_call("add-config", name=name, text=text,
                                 tunnel=tunnel, place=place)
        if reply.get("ask"):
            # Похоже на конфиг туннеля «по списку»: заменить его или отдельным
            # туннелем — решает человек; служба при ask ничего не записала.
            self._asked = (name, text)
            self.js("askPlace", {**reply["ask"], "file": name})
            return
        if not reply.get("ok"):
            self.js("failed", reply.get("error") or "не удалось добавить")
            return
        self._apply()

    # ------------------------------------------------------ туннелирование

    def _tunnel_rules(self, tunnel):
        """Лист «Туннелирование»: списки — только у администратора (get-tunnels),
        в них адреса и домены рабочей сети."""
        reply = self._admin_call("get-tunnels")
        self._guard(reply)
        t = next((x for x in reply.get("tunnels") or [] if x["id"] == tunnel), None)
        if t is None:
            raise RuntimeError(f"нет туннеля {tunnel}")
        self.js("showRules", {k: t[k] for k in ("id", "name", "mode", "active",
                                                "include", "exclude")})

    def _save_rules(self, arg):
        """Поля листа — текстом, как их ввёл человек: разбирает служба
        (routelist.parse), непонятое возвращается в rejected и стоит под полем."""
        lists = {k: arg[k] for k in ("include", "exclude") if k in arg}
        reply = self._admin_call("set-tunnel", tunnel=arg["tunnel"], **lists)
        if not reply.get("ok"):
            # Строка состояния — под листом: отказ («a.ru уже в «Работа»»)
            # стоит под полями, лист остаётся открытым с набранным.
            self.js("rulesFailed", reply.get("error") or "служба отказала")
            return
        self.js("rulesSaved", {"include": reply.get("include", []),
                               "exclude": reply.get("exclude", []),
                               "rejected": reply.get("rejected", {})})
        self._apply()

    def _load_rules(self):
        path = self._pick(_RULES_TYPES)
        if not path:
            return
        with open(path, encoding="utf-8", errors="replace") as fh:
            self.js("fillRules", _rules_from_file(fh.read()))

    def _export_rules(self, arg):
        """Сохранённые списки туннеля — в JSON, который «Загрузить из файла…»
        примет обратно, в том числе у другого туннеля."""
        import webview
        picked = self.holder.get("window").create_file_dialog(
            webview.FileDialog.SAVE, file_types=_RULES_TYPES,
            save_filename=f"{tunnels.safe_name(arg.get('name', ''))}.json")
        if not picked:
            return
        out = {k: [str(x) for x in arg.get(k) or []] for k in ("include", "exclude")}
        with open(picked[0], "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
            fh.write("\n")

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


def _rules_from_file(text):
    """Поля листа «Туннелирование» из файла: JSON экспорта {include, exclude}
    раскладывается по полям, любой другой текст — {text}: страница кладёт его
    в первое поле («пускать», у основного — «мимо VPN»)."""
    try:
        data = json.loads(text.lstrip("﻿"))
    except ValueError:
        data = None
    if not isinstance(data, dict) or not ({"include", "exclude"} & data.keys()):
        return {"text": text}
    out = {}
    for key in ("include", "exclude"):
        val = data.get(key)
        out[key] = ("\n".join(str(x) for x in val) if isinstance(val, list)
                    else val if isinstance(val, str) else "")
    return out


# ------------------------------------------------------------ site.env

def _parse_env(text):
    return paths.parse_env(text)


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


def _park(window, api):
    """Форма — за край экрана до первого настоящего показа.

    Спрятанное окно pywebview создаёт так: Opacity=0, Show, Hide. Невидимым
    оно не выходит: после UAC сначала мелькало белое пред-окно, потом само
    окно. За краем экрана этот показ никто не видит. Зовётся в before_show:
    оно идёт в потоке окна до этого Show. Место в центре рабочего стола
    запоминаем — его вернёт _unpark. Показ уже просили — не уводим: вернуть
    окно было бы некому.
    """
    with api._park_lock:
        if api._show_wanted:
            return
        try:
            from System.Drawing import Point
            from System.Windows.Forms import FormStartPosition, Screen
            form = window.native
            area = Screen.PrimaryScreen.WorkingArea
            api._home = Point(area.X + max(0, area.Width - form.Width) // 2,
                              area.Y + max(0, area.Height - form.Height) // 2)
            form.StartPosition = FormStartPosition.Manual
            form.Location = Point(-32000, -32000)
        except Exception:
            api._home = None


def _unpark(window, api):
    """Перед первым показом — на место из _park. Дальше окно стоит там,
    куда его передвинули. Замок — только на флаг и место: Invoke под ним
    ждал бы поток окна, а тот может ждать замок в _park."""
    with api._park_lock:
        api._show_wanted = True
        home, api._home = api._home, None
    if home is None:
        return
    try:
        from System import Action
        form = window.native
        form.Invoke(Action(lambda: setattr(form, "Location", home)))
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
    туннелей — как при первом открытии.

    Уже открытое (в том числе свёрнутое) только выходит вперёд: его статус
    держит опрос, а перерисовка с проверкой на повторный двойной клик по
    значку выглядела как открытие заново — кружки снова рыжие.
    """
    on_screen = not api.hidden and not api.cold
    api.hidden = False
    api.cold = False
    _unpark(window, api)
    window.show()
    _restore(window)
    # Страница ещё грузится — всё это сделает её ready.
    if not on_screen and api.ready.is_set():
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
    api.cold = not hidden
    # paths.UI_DIR, а не __file__: в собранном виде __file__ у модуля внутри
    # PyInstaller-архива не указывает на реальный файл на диске, и index.html
    # не находился — окно падало ещё до показа.
    index = os.path.join(paths.UI_DIR, "index.html")

    holder["window"] = webview.create_window(
        f"DualVPN {paths.version()}", index,
        # Спрятанным создаётся и видимое окно: покажет его Api.reveal.
        js_api=api, width=1040, height=720, min_size=(880, 560), hidden=True,
        # Тот же фон, что --bg в index.html: иначе до загрузки страницы окно
        # белое и мигает на открытии.
        background_color="#101012")
    holder["window"].events.shown += lambda: _dark_title(holder.get("window"))
    holder["window"].events.before_show += lambda window: _park(window, api)
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
    if api.cold:
        # Запасной показ: страница не ответила или refresh на ready ждёт службу
        # (ipc.call без таймаута). Невидимое окно было бы нечем закрыть.
        timer = threading.Timer(COLD_SHOW_WAIT, api.reveal)
        timer.daemon = True
        timer.start()
    # gui='edgechromium' — WebView2, он есть в Windows 10/11 из коробки.
    webview.start(gui="edgechromium", private_mode=False, icon=icon,
                  storage_path=_storage_path())
    holder["window"] = None
    # Окно закрыто — процесс тоже. WebView2 ходит через pythonnet, и потоки
    # .NET способны удержать dualvpn.exe после закрытия окна: тогда он висел
    # бы в диспетчере задач без окна. Ничего несохранённого здесь нет.
    os._exit(0)
