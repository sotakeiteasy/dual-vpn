"""Окно приложения: та же вёрстка, что была на macOS, но на WebView2.

Вёрстка (ui/index.html) осталась прежней, поменялся только её мост: наружу
идёт `window.pywebview.api.send(name, arg)`, внутрь — `call(fn, arg)` и
`callN(fn, [args])`, которые дёргают `window[fn]`. Разметка, стили и вся
логика отрисовки — те же, что были на macOS.

Само окно систему не трогает: всё, что требует прав, уходит в службу через
именованный канал. Поэтому окно запускается от обычного пользователя, и UAC
на нём не появляется.
"""

import json
import os
import threading
import time

from . import ipc, paths

POLL_EVERY = 2.0


class Api:
    """То, что вёрстка зовёт через мост. Имена сообщений заданы в index.html."""

    def __init__(self, window_holder):
        self.holder = window_holder
        self.ready = threading.Event()

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
        elif name == "start":
            self._guard(ipc.call("start", profile=""))
        elif name == "stop":
            self._guard(ipc.call("stop"))
        elif name == "restart":
            ipc.call("stop")
            self._guard(ipc.call("start", profile=""))
        elif name == "use_config":
            self._guard(ipc.call("set-profile", profile=arg))
            self.refresh(full=True)
        elif name == "del_config":
            self._guard(ipc.call("remove-config", name=arg))
            self.js("closeSheet")
            self.refresh(full=True)
        elif name == "add_config":
            self._add_config(arg)
        elif name == "info":
            self._show_conf(arg)
        elif name == "site":
            self.js("showSite", _parse_env(ipc.call("get-site").get("text", "")))
        elif name == "load_site":
            self._load_site()
        elif name == "save_site":
            self._guard(ipc.call("set-site", text=_format_env(arg or {})))
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
            self.js("render", {"up": False, "no_service": True})
            return
        self.js("render", st)
        if full:
            self.js("renderVersion", {"app": st.get("version", paths.version()),
                                      "singbox": st.get("singbox", "")})
            self.js("renderConfs", self._confs(st))
            self.js("renderHowto", self._howto(st))
            self._push_logs()

    def _confs(self, st):
        """Раскладка конфигов по колонкам — ровно та, что ждёт renderConfs."""
        names = st.get("profiles") or []
        active = st.get("profile") or "personal"
        corp, personal = [], []
        for n in names:
            low = n.lower()
            is_corp = (low in ("corp", "wg")
                       or low.startswith("wg-") or low.startswith("wg0-")
                       or (low.startswith("wg") and low[2:3].isdigit()))
            (corp if is_corp else personal).append(
                {"name": n, "active": (not is_corp and n == active)})
        # Если активный профиль не выбран явно, подсвечиваем personal.
        if personal and not any(c["active"] for c in personal):
            for c in personal:
                if c["name"] == "personal":
                    c["active"] = True
        return {
            "corp": corp, "personal": personal,
            "corp_ambiguous": len(corp) > 1,
            "personal_ambiguous": False,
        }

    @staticmethod
    def _howto(st):
        site = paths.site_env()
        nets, endpoints = [], []
        try:
            with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
                cfg = json.load(fh)
            for rule in cfg.get("route", {}).get("rules", []):
                if rule.get("outbound") == "wg-corp":
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
        except (OSError, ValueError):
            pass
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

    def _show_conf(self, name):
        """Показывает содержимое конфига. Читает служба — каталог закрыт."""
        reply = ipc.call("read-config", name=name)
        if reply.get("ok"):
            self.jsn("showConf", [name, reply.get("text", "")])
        else:
            self.js("failed", reply.get("error") or "не прочитать конфиг")

    def _add_config(self, kind):
        """Диалог выбора файла и передача его службе.

        Файл читаем здесь, от пользователя: у него есть доступ к своим папкам,
        а у службы под SYSTEM его может не быть — сетевой диск или профиль
        другого пользователя ей просто не видны.
        """
        import webview
        w = self.holder.get("window")
        picked = w.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=False,
            file_types=("Конфиги WireGuard (*.conf)", "Все файлы (*.*)"))
        if not picked:
            return
        path = picked[0]
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        name = os.path.splitext(os.path.basename(path))[0]
        if kind == "corp" and not _looks_corp(name):
            # Имя решает, каким туннелем станет файл, поэтому подгоняем его,
            # а не полагаемся на то, что человек назвал файл правильно.
            name = "corp"
        reply = ipc.call("add-config", name=name, text=text)
        if not reply.get("ok"):
            self.js("failed", reply.get("error") or "не удалось добавить")
            return
        self.refresh(full=True)

    def _load_site(self):
        import webview
        w = self.holder.get("window")
        picked = w.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=False,
            file_types=("site.env (*.env)", "Все файлы (*.*)"))
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
    for key in ("CORP_DOMAINS", "CORP_PROBE", "CORP_HOSTS", "SB_CORP_EXCLUDE"):
        val = (values.get(key) or "").strip()
        if val:
            lines.append(f'{key}="{val}"')
    return "\n".join(lines) + "\n"


def _looks_corp(name):
    low = name.lower()
    return (low in ("corp", "wg") or low.startswith("wg-")
            or low.startswith("wg0-"))


# ---------------------------------------------------------------- запуск

def open_window():
    """Открывает окно и не возвращается, пока его не закроют."""
    import webview

    holder = {}
    api = Api(holder)
    index = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "ui", "index.html")

    holder["window"] = webview.create_window(
        f"DualVPN {paths.version()}", index,
        js_api=api, width=1040, height=720, min_size=(880, 560))

    def poll():
        # Ждём, пока страница отчитается о готовности: до этого window[fn]
        # ещё не определены, и любой вызов ушёл бы в пустоту.
        api.ready.wait(timeout=15)
        while holder.get("window") is not None:
            api.refresh()
            time.sleep(POLL_EVERY)

    threading.Thread(target=poll, daemon=True).start()
    # gui='edgechromium' — WebView2, он есть в Windows 10/11 из коробки.
    webview.start(gui="edgechromium", private_mode=False)
    holder["window"] = None
