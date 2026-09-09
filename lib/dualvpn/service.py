"""Служба Windows: владеет туннелем, отвечает трею, пишет состояние.

Работает под LocalSystem, потому что правка таблицы маршрутов и создание
сетевого адаптера требуют прав, которых у обычного пользователя нет. Всё
остальное приложение — трей и окно — обычные пользовательские процессы,
и общаются они со службой через именованный канал (см. ipc.py).

Служба ставится один раз установщиком и запускается вручную или при входе в
систему; сама она туннель не поднимает, пока не попросят. Автоподключение —
это отдельный флажок в state\\autostart, который читается при старте службы.
"""

import datetime
import os
import subprocess
import sys
import threading

from . import ipc, paths, probe, tunnel, winnet

AUTOSTART_FILE = os.path.join(paths.STATE, "autostart")
SERVICE_LOG = os.path.join(paths.LOGS, "service.log")


class Core:
    """Логика службы, отделённая от обвязки Windows.

    Отдельным классом — чтобы её можно было запустить и в консоли
    (`dualvpn.exe run-service`) при отладке, не устанавливая службу.
    """

    def __init__(self):
        self.lock = threading.Lock()      # один start/stop одновременно
        self.tunnel = tunnel.Tunnel(self.log)
        self.prober = probe.Prober()
        self.server = ipc.Server(self.handle, self.log)
        self.last_error = ""
        self.busy = ""

    # ---------------------------------------------------------------- лог

    def log(self, line):
        paths.ensure_dirs()
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        try:
            with open(SERVICE_LOG, "a", encoding="utf-8") as fh:
                fh.write(f"{stamp} {line}\n")
        except OSError:
            pass

    # -------------------------------------------------------------- жизнь

    def start(self):
        paths.ensure_dirs()
        self.log(f"=== служба запущена, версия {paths.version()} ===")
        threading.Thread(target=self.prober.run, daemon=True).start()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        if self.autostart_enabled():
            self.log("→ автоподключение включено")
            threading.Thread(target=self._do_start, daemon=True).start()

    def shutdown(self):
        """Остановка службы. Туннель снимаем обязательно.

        Оставить его поднятым нельзя: без службы никто не уберёт маршруты, и
        после перезагрузки половина интернета смотрела бы в мёртвый адаптер.
        """
        self.log("=== служба останавливается ===")
        self.prober.stop_event.set()
        self.server.stop_event.set()
        with self.lock:
            self.tunnel.stop()
        winnet.PS.close()

    # ----------------------------------------------------------- автозапуск

    @staticmethod
    def autostart_enabled():
        return os.path.exists(AUTOSTART_FILE)

    @staticmethod
    def set_autostart(on):
        paths.ensure_dirs()
        if on:
            with open(AUTOSTART_FILE, "w", encoding="utf-8") as fh:
                fh.write("1\n")
        else:
            try:
                os.remove(AUTOSTART_FILE)
            except OSError:
                pass

    # -------------------------------------------------------------- команды

    def handle(self, op, payload, is_admin):
        """Обработчик команд из канала. Права уже проверены в ipc.Server."""
        if op == "status":
            return {"ok": True, "status": self._status()}
        if op == "start":
            return self._do_start(payload.get("profile", ""))
        if op == "stop":
            return self._do_stop()
        if op == "set-profile":
            return self._set_profile(payload.get("profile", ""))
        if op == "list-profiles":
            return {"ok": True, "profiles": self._profiles()}
        if op == "set-autostart":
            self.set_autostart(bool(payload.get("on")))
            return {"ok": True, "autostart": self.autostart_enabled()}
        if op == "add-config":
            return self._add_config(payload.get("name", ""),
                                    payload.get("text", ""))
        if op == "remove-config":
            return self._remove_config(payload.get("name", ""))
        if op == "read-config":
            return self._read_config(payload.get("name", ""))
        if op == "set-site":
            return self._set_site(payload.get("text", ""))
        if op == "get-site":
            return {"ok": True, "text": self._read_site()}
        if op == "log":
            return {"ok": True, "lines": self._tail_log(int(payload.get("lines", 200)))}
        return {"ok": False, "error": f"неизвестная команда: {op}"}

    def _status(self):
        st = self.prober.snapshot()
        st["up"] = bool(st.get("tun")) and bool(st.get("r_low"))
        st["busy"] = self.busy
        st["last_error"] = self.last_error
        st["autostart"] = self.autostart_enabled()
        st["version"] = paths.version()
        st["singbox"] = self._singbox_version()
        st["profiles"] = self._profiles()
        return st

    _singbox_cached = None

    @classmethod
    def _singbox_version(cls):
        """Версия sing-box. Спрашиваем один раз: бинарник между запусками
        службы не меняется, а запуск процесса на каждый опрос статуса —
        это раз в две секунды на пустом месте."""
        if cls._singbox_cached is not None:
            return cls._singbox_cached
        cls._singbox_cached = ""
        try:
            out = subprocess.run(
                [paths.SINGBOX, "version"], capture_output=True, text=True,
                timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            first = (out.stdout or "").strip().splitlines()
            if first:
                # «sing-box version 1.14.0-lx.35» → «1.14.0-lx.35»
                parts = first[0].split()
                cls._singbox_cached = parts[-1] if parts else ""
        except Exception:
            pass
        return cls._singbox_cached

    def _do_start(self, profile=""):
        if not self.lock.acquire(blocking=False):
            return {"ok": False, "error": f"уже идёт: {self.busy or 'операция'}"}
        try:
            self.busy = "включаю"
            if not profile:
                profile = probe.Prober.current_profile()
            err = self.tunnel.start(profile)
            self.last_error = err
            if err:
                self.log(f"!! {err}")
                # Наполовину поднятое состояние опаснее выключенного: маршруты
                # уже могли встать. Убираем за собой сразу, а не ждём человека.
                self.tunnel.stop()
                return {"ok": False, "error": err}
            return {"ok": True}
        finally:
            self.busy = ""
            self.lock.release()

    def _do_stop(self):
        if not self.lock.acquire(blocking=False):
            return {"ok": False, "error": f"уже идёт: {self.busy or 'операция'}"}
        try:
            self.busy = "выключаю"
            self.tunnel.stop()
            self.last_error = ""
            return {"ok": True}
        finally:
            self.busy = ""
            self.lock.release()

    # -------------------------------------------------------------- конфиги

    @staticmethod
    def _profiles():
        try:
            return sorted(f[:-5] for f in os.listdir(paths.CONF)
                          if f.lower().endswith(".conf"))
        except OSError:
            return []

    @staticmethod
    def _safe_name(name):
        """Имя конфига — это имя файла, и ничего кроме.

        Через канал сюда приходит текст от пользователя, а пишем мы в каталог,
        доступный только SYSTEM. Без этой проверки «..\\..\\Windows\\System32»
        был бы обычной записью файла с правами системы.
        """
        name = (name or "").strip()
        if name.lower().endswith(".conf"):
            name = name[:-5]
        if not name or os.path.sep in name or "/" in name or name in (".", ".."):
            raise ValueError(f"недопустимое имя конфига: {name!r}")
        if any(c in name for c in '<>:"|?*\\'):
            raise ValueError(f"недопустимое имя конфига: {name!r}")
        return name

    def _add_config(self, name, text):
        name = self._safe_name(name)
        paths.ensure_dirs()
        path = os.path.join(paths.CONF, f"{name}.conf")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        self.log(f"→ добавлен конфиг {name}.conf")
        return {"ok": True, "profiles": self._profiles()}

    def _read_config(self, name):
        """Отдаёт конфиг целиком, вместе с ключами.

        Каталог conf\\ закрыт от обычного пользователя, поэтому прочитать файл
        может только служба. Права проверяет ipc.Server: команды нет ни в
        READ_OPS, ни в USER_OPS, значит нужен администратор.
        """
        name = self._safe_name(name)
        try:
            with open(os.path.join(paths.CONF, f"{name}.conf"),
                      encoding="utf-8", errors="replace") as fh:
                return {"ok": True, "text": fh.read()}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    def _remove_config(self, name):
        name = self._safe_name(name)
        try:
            os.remove(os.path.join(paths.CONF, f"{name}.conf"))
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        self.log(f"→ удалён конфиг {name}.conf")
        return {"ok": True, "profiles": self._profiles()}

    def _set_profile(self, name):
        if name:
            name = self._safe_name(name)
            if not os.path.isfile(os.path.join(paths.CONF, f"{name}.conf")):
                return {"ok": False, "error": f"нет конфига {name}.conf"}
        paths.ensure_dirs()
        with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
            fh.write(name)
        return {"ok": True, "profile": name}

    @staticmethod
    def _read_site():
        try:
            with open(os.path.join(paths.CONF, "site.env"), encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    def _set_site(self, text):
        paths.ensure_dirs()
        with open(os.path.join(paths.CONF, "site.env"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        self.log("→ обновлены настройки рабочей сети")
        return {"ok": True}

    @staticmethod
    def _tail_log(lines):
        """Последние строки журнала sing-box — их показывает окно."""
        try:
            files = sorted(f for f in os.listdir(paths.LOGS)
                           if f.startswith("vpn-") and f.endswith(".log"))
            if not files:
                return []
            with open(os.path.join(paths.LOGS, files[-1]),
                      encoding="utf-8", errors="replace") as fh:
                return fh.read().splitlines()[-lines:]
        except OSError:
            return []


# ------------------------------------------------------- обвязка Windows

def _service_class():
    """Класс службы собираем лениво: pywin32 нужен только здесь."""
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class DualVPNService(win32serviceutil.ServiceFramework):
        _svc_name_ = paths.SERVICE_NAME
        _svc_display_name_ = paths.SERVICE_DISPLAY
        _svc_description_ = ("Два туннеля WireGuard одновременно: рабочий и "
                             "личный. Держит маршруты и убирает их за собой.")

        # В собранном виде службу запускает не python.exe со скриптом, а наш
        # собственный exe. Диспетчеру служб нужно сказать об этом явно, иначе
        # он пропишет в реестр путь к несуществующему pythonservice.exe и
        # служба не стартует вовсе — с невнятной ошибкой 1053.
        if getattr(sys, "frozen", False):
            _exe_name_ = sys.executable
            _exe_args_ = "service run"

        def __init__(self, args):
            super().__init__(args)
            self.wait_stop = win32event.CreateEvent(None, 0, 0, None)
            self.core = Core()

        def SvcStop(self):
            # Останов может занять секунды: уборка маршрутов ходит в
            # PowerShell. Предупреждаем диспетчер, иначе он решит, что служба
            # зависла, и убьёт её посреди уборки.
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING,
                                     waitHint=60000)
            try:
                self.core.shutdown()
            finally:
                win32event.SetEvent(self.wait_stop)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""))
            self.core.start()
            win32event.WaitForSingleObject(self.wait_stop, win32event.INFINITE)

    return DualVPNService


def run_in_console():
    """Тот же Core, но в консоли — для отладки без установки службы."""
    import time
    core = Core()
    core.start()
    print(f"DualVPN {paths.version()}: служба работает в консоли, Ctrl+C — выход")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        core.shutdown()


def run_dispatcher():
    """Точка входа, которую зовёт диспетчер служб у собранного exe.

    Из исходников этот путь не используется: там службу запускает
    pythonservice.exe, и win32serviceutil разбирается сам.
    """
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_service_class())
    servicemanager.StartServiceCtrlDispatcher()


def handle_command_line():
    """install / remove / start / stop / restart через win32serviceutil."""
    import win32serviceutil
    win32serviceutil.HandleCommandLine(_service_class())
