"""Значок в трее: включить, выключить, добавить конфиг, открыть окно.

Остальное — выбор личного профиля, автозапуск, рабочая сеть — только в окне:
меню трея держим коротким, а настройки — в одном месте.

Туннелем владеет служба, трей шлёт ей команды через именованный канал.
Установленный трей запускается от администратора (манифест, см. dualvpn.spec):
конфиги с ключами служба принимает только от администратора, и так UAC
спрашивается один раз при запуске, а не на каждое добавление конфига.

Значок рисуется кодом, а не берётся из файла: он маленький, состояний у него
четыре, и держать четыре .ico в сборке ради этого незачем. Заодно он сам
подстраивается под тёмную и светлую тему панели задач.
"""

import os
import sys
import threading
import time

from . import ipc, paths

POLL_EVERY = 3.0
# Сколько выход ждёт, пока служба закончит начатый start и примет stop.
QUIT_WAIT = 40.0
# Сколько даём окну показаться, прежде чем считать его процесс зависшим.
WINDOW_START_WAIT = 15.0

# Пределы полей NOTIFYICONDATA с завершающим нулём. pystray их не обрезает:
# строка длиннее — ValueError, и падает тот поток, который менял подпись.
# Раньше это был поток опроса: длинная ошибка в статусе (путь к логу)
# убивала его, и значок навсегда застывал в последнем цвете.
TIP_MAX = 127
INFO_MAX = 255

# Цвета состояний. Взяты такими, чтобы отличаться и на светлой, и на тёмной
# панели: серый заметно темнее любой из них, зелёный и красный — насыщенные.
COLORS = {
    "off": (128, 128, 128, 255),
    "up": (46, 160, 67, 255),
    "busy": (210, 153, 34, 255),
    "error": (218, 54, 51, 255),
}


def _icon_image(state):
    """Кружок нужного цвета. Pillow приходит вместе с pystray."""
    from PIL import Image, ImageDraw

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((6, 6, size - 6, size - 6), fill=COLORS.get(state, COLORS["off"]))
    if state == "up":
        # Вторая, меньшая точка: два туннеля — два кружка. На беглый взгляд
        # видно не только «включено», но и что поднято именно наше двойное.
        d.ellipse((size // 2 - 4, size // 2 - 4, size // 2 + 4, size // 2 + 4),
                  fill=(255, 255, 255, 255))
    return img


class Tray:
    def __init__(self):
        self.icon = None
        self.state = "off"
        self.status = {}
        self._last_menu_sig = None
        self._window_proc = None
        self._window_started = 0.0
        self.stop_event = threading.Event()

    # ------------------------------------------------------------- статус

    def poll(self):
        while not self.stop_event.is_set():
            try:
                self._poll_once()
            except Exception:                              # noqa: BLE001
                # Поток опроса один, и умереть ему нельзя: без него значок
                # перестаёт отражать состояние, а меню — включать и выключать.
                pass
            self.stop_event.wait(POLL_EVERY)

    def _poll_once(self):
        try:
            self.status = ipc.call("status").get("status", {})
            if self.status.get("busy"):
                new = "busy"
            elif self.status.get("up"):
                new = "up"
            elif self.status.get("last_error"):
                new = "error"
            else:
                new = "off"
        except ipc.NotRunning:
            self.status = {}
            new = "error"
        if new != self.state:
            self.state = new
            self._refresh_icon()
        else:
            # Подпись меняется и без смены цвета: профиль, адрес выхода.
            self._refresh_title()
        # pystray на Windows собирает меню один раз, в update_menu(), и потом
        # показывает готовое. Перестраивать только при смене цвета мало: меню
        # строилось до первого ответа службы, первый опрос давал тот же цвет
        # «выключен», и пункты, зависящие от статуса, так и оставались серыми.
        sig = self._menu_sig()
        if sig != self._last_menu_sig:
            self._last_menu_sig = sig
            if self.icon is not None:
                self.icon.update_menu()

    def _menu_sig(self):
        """То, от чего зависят подписи, галочки и доступность пунктов меню."""
        st = self.status
        return (bool(st), bool(st.get("up")), bool(st.get("busy")))

    def _refresh_icon(self):
        if self.icon is None:
            return
        self.icon.icon = _icon_image(self.state)
        self._refresh_title()
        # Меню перестраивает _poll_once по _menu_sig — здесь не нужно.

    def _refresh_title(self):
        if self.icon is None:
            return
        self.icon.title = _clip(self._title(), TIP_MAX)

    def _title(self):
        st = self.status
        if not st:
            return "DualVPN — служба не отвечает"
        if st.get("busy"):
            return f"DualVPN — {st['busy']}…"
        if not st.get("up"):
            err = st.get("last_error")
            return "DualVPN — выключен" + (f" ({err})" if err else "")
        who = st.get("profile") or "personal"
        exit_ip = st.get("exit_ip") or "—"
        if st.get("exit_state") == "leak":
            return f"DualVPN — УТЕЧКА, виден адрес провайдера ({exit_ip})"
        return f"DualVPN — работает · {who} · выход {exit_ip}"

    # -------------------------------------------------------------- меню

    def _menu(self):
        """Меню строится один раз, а меняется через функции в полях.

        Это не стилистика: pystray перечитывает text/enabled/checked при каждом
        показе меню, только если там callable. Со статичными строками
        update_menu() не поменял бы ни подписи, ни галочки — пункт так и остался
        бы «Включить» на поднятом туннеле.
        """
        import pystray

        return pystray.Menu(
            pystray.MenuItem(
                lambda _i: "Выключить" if self.status.get("up") else "Включить",
                self.on_toggle,
                enabled=lambda _i: bool(self.status) and not self.status.get("busy"),
                default=True),
            pystray.MenuItem(
                "Перезапустить", self.on_restart,
                enabled=lambda _i: bool(self.status.get("up"))
                and not self.status.get("busy")),
            pystray.Menu.SEPARATOR,
            # Как и в окне, при поднятом туннеле конфиги не меняем: новый файл
            # подействовал бы только после перезапуска, а до того работал бы
            # старый — «поменял, а ничего не изменилось».
            pystray.MenuItem(
                "Добавить рабочий конфиг…", lambda: self.on_add_config("corp"),
                enabled=self._can_edit),
            pystray.MenuItem(
                "Добавить личный конфиг…", lambda: self.on_add_config("personal"),
                enabled=self._can_edit),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Открыть панель управления…", self.on_window),
            pystray.MenuItem("Закрыть", self.on_quit),
        )

    # -------------------------------------------------------------- команды

    def _do(self, op, **payload):
        """Команда в службу в отдельном потоке.

        start честно работает до тридцати секунд, а обработчик меню в pystray
        выполняется в потоке значка: подождать прямо здесь значит подвесить
        сам значок вместе со всем меню.
        """
        def work():
            try:
                reply = ipc.call(op, **payload)
                if not reply.get("ok"):
                    self._notify(reply.get("error") or "не вышло")
            except ipc.NotRunning as exc:
                self._notify(str(exc))
        threading.Thread(target=work, daemon=True).start()

    def on_toggle(self):
        if self.status.get("up"):
            self._do("stop")
        else:
            self._do("start", profile="")

    def on_restart(self):
        def work():
            try:
                ipc.call("stop")
                reply = ipc.call("start", profile="")
                if not reply.get("ok"):
                    self._notify(reply.get("error") or "не вышло")
            except ipc.NotRunning as exc:
                self._notify(str(exc))
        threading.Thread(target=work, daemon=True).start()

    # ---------------------------------------------------------------- конфиги

    def _can_edit(self, _item=None):
        return (bool(self.status) and not self.status.get("up")
                and not self.status.get("busy"))

    def on_add_config(self, kind):
        """Файл .conf в службу. Имя под тип туннеля подгоняет служба: рабочий
        ложится как corp.conf и заменяет прежние, личный становится активным."""
        def work():
            picked = _pick_file(
                "Рабочий конфиг WireGuard" if kind == "corp"
                else "Личный конфиг WireGuard / AmneziaWG",
                "Конфиги WireGuard (*.conf)\0*.conf\0Все файлы\0*.*\0")
            if not picked:
                return
            path, text = picked
            name = os.path.splitext(os.path.basename(path))[0]
            reply = self._call("add-config", name=name, text=text, kind=kind)
            if reply is not None:
                what = "рабочий" if kind == "corp" else "личный"
                self._notify(f"{what} конфиг добавлен: {reply.get('name')}.conf")
        threading.Thread(target=work, daemon=True).start()

    def _call(self, op, **payload):
        """Команда в службу с уведомлением об ошибке. None — не вышло."""
        try:
            reply = ipc.call(op, **payload)
        except ipc.NotRunning as exc:
            self._notify(str(exc))
            return None
        if not reply.get("ok"):
            self._notify(reply.get("error") or "не вышло")
            return None
        self._poll_once()
        return reply

    def on_window(self):
        """Окно — в отдельном процессе.

        И pywebview, и pystray хотят собственный цикл сообщений в главном
        потоке; в одном процессе они друг друга блокируют. Отдельный процесс
        обходится дешевле, чем попытка их подружить.

        Окно одно: если прошлое ещё живо, поднимаем его. Раньше каждый
        клик запускал новое, а запоминалось только последнее — «Закрыть» снимал
        его, а первое оставалось висеть.
        """
        import subprocess
        import sys

        proc = self._window_proc
        if proc is not None and proc.poll() is None:
            if _raise_window(f"DualVPN {paths.version()}"):
                return
            # Окно ещё может не показаться (WebView2 стартует секунду-две) —
            # оно само встанет на передний план. Но процесс без окна дольше
            # WINDOW_START_WAIT завис: без замены панель больше не открылась бы.
            if time.monotonic() - self._window_started < WINDOW_START_WAIT:
                return
            proc.terminate()

        if getattr(sys, "frozen", False):
            # sys.executable здесь — сам трей (DualVPN-Tray.exe). У портативной
            # версии это же имя exe одно на всё, и у него есть ветка "window" —
            # ею и пользуемся. У установленной версии трей и окно — разные
            # exe, и окно живёт в соседнем dualvpn.exe.
            name = os.path.basename(sys.executable).lower()
            if name == "dualvpn-portable.exe":
                cmd = [sys.executable, "window"]
            else:
                sibling = os.path.join(os.path.dirname(sys.executable), "dualvpn.exe")
                if not os.path.isfile(sibling):
                    # Раньше здесь тихо запускали сам трей ещё раз — снаружи
                    # это выглядело как «нажал Окно, а появился второй значок».
                    # Явное сообщение лучше молчаливого дубля: причина обычно —
                    # антивирус, унёсший dualvpn.exe в карантин при установке.
                    self._notify("не найден dualvpn.exe рядом с программой — "
                                 "переустанови приложение или проверь карантин "
                                 "антивируса")
                    return
                cmd = [sibling, "window"]
        else:
            cmd = [sys.executable, "-m", "dualvpn.cli", "window"]

        # Раньше вывод окна уходил в никуда: при падении (например, из-за
        # неверного пути к index.html) причину нельзя было увидеть нигде.
        try:
            paths.ensure_dirs()
            log = open(os.path.join(paths.LOGS, "window-launch.log"),
                      "a", encoding="utf-8", errors="replace")
        except OSError:
            log = subprocess.DEVNULL
        self._window_proc = subprocess.Popen(
            cmd, stdout=log, stderr=log,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self._window_started = time.monotonic()

    def on_quit(self):
        """Выключает VPN и закрывает значок — в обеих версиях.

        Раньше в установленной версии туннель после «Выход» оставался поднятым:
        им владеет служба. Снаружи это выглядело как «закрыл программу, а она
        работает», и выключить VPN без значка было нечем, кроме диспетчера
        задач. Теперь выход значит выход.

        stop шлём и при «выключен»: туннель мог подниматься (busy) или остаться
        полуживым после ошибки, а stop на чистой системе безвреден. Значок
        прячем сразу — уборка маршрутов идёт секунды, и всё это время меню
        было бы живым, но бесполезным.
        """
        self.stop_event.set()
        if self.icon is not None:
            self.icon.visible = False
        # Ожидание — в рабочем потоке: обработчик меню идёт в потоке
        # сообщений значка, и до QUIT_WAIT секунд процесс висел бы с мёртвым
        # циклом сообщений. icon.stop() — по концу уборки: после него run()
        # завершает процесс через os._exit, и недоделанный stop оборвался бы.
        threading.Thread(target=self._quit_work, daemon=True).start()

    def _quit_work(self):
        # Пока идёт start (до тридцати секунд), служба на stop отвечает «уже
        # идёт» — ждём конца операции и повторяем, иначе выход оставил бы
        # туннель поднятым ровно в тот момент, когда его включали.
        # Любой другой отказ повтором не лечится — выходим сразу.
        deadline = time.monotonic() + QUIT_WAIT
        try:
            while (not ipc.call("stop").get("ok")
                   and ipc.call("status").get("status", {}).get("busy")
                   and time.monotonic() < deadline):
                time.sleep(1)
        except ipc.NotRunning:
            # Службы нет — опускать нечего. В портативной версии уборку
            # всё равно доделает portable.run() через core.shutdown().
            pass
        finally:
            # Окно — отдельный процесс; без трея ему некому быть, и оно
            # висело бы в диспетчере задач после «Закрыть». В finally: сбой
            # вызова не должен оставить процесс без значка и без выхода.
            proc = self._window_proc
            if proc is not None and proc.poll() is None:
                proc.terminate()
            if self.icon is not None:
                self.icon.stop()

    def _notify(self, text):
        if self.icon is None:
            return
        try:
            self.icon.notify(_clip(text, INFO_MAX), "DualVPN")
        except Exception:
            # Уведомления есть не во всех сборках Windows; молчать тут можно —
            # ошибка всё равно видна в подписи значка и в окне.
            pass

    # -------------------------------------------------------------- запуск

    def run(self):
        import pystray

        _dark_menus()
        self.icon = pystray.Icon(
            "dualvpn", _icon_image("off"), f"DualVPN {paths.version()}",
            menu=self._menu())
        threading.Thread(target=self.poll, daemon=True).start()
        self.icon.run()


def _clip(text, limit):
    text = str(text or "")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _dark_menus():
    """Тёмное меню значка: окно тёмное всегда, светлое меню рядом выбивается.

    Нативное меню Win32 тёмным делает только недокументированный
    SetPreferredAppMode (uxtheme, ordinal 135) с ForceDark = 2, а
    FlushMenuThemes (ordinal 136) сбрасывает уже закэшированную тему меню.
    Есть с Windows 10 1903, сборка 18362. Установщик пускает и с 17763, а там
    под ordinal 135 другая функция, поэтому на старых сборках не зовём ничего.
    Зовётся до создания значка; на любой ошибке меню просто остаётся светлым.
    """
    try:
        import ctypes
        if sys.getwindowsversion().build < 18362:
            return
        uxtheme = ctypes.windll.uxtheme
        uxtheme[135](2)
        uxtheme[136]()
    except Exception:
        pass


def _raise_window(title):
    """Выводит уже открытое окно на передний план. False — окна не нашлось.

    SW_RESTORE только для свёрнутого: развёрнутое на весь экран он бы
    уменьшил. Трей и окно оба от администратора, так что UIPI
    SetForegroundWindow не режет.
    """
    import pywintypes
    import win32con
    import win32gui

    try:
        hwnd = win32gui.FindWindow(None, title)
    except pywintypes.error:
        return False
    if not hwnd:
        return False
    # Окно есть — значит, True, даже если Windows не отдала ему фокус:
    # иначе трей счёл бы живое окно зависшим и перезапустил бы его.
    try:
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE
                            if win32gui.IsIconic(hwnd) else win32con.SW_SHOW)
        win32gui.SetForegroundWindow(hwnd)
    except pywintypes.error:
        pass
    return True


def _pick_file(title, filters):
    """Стандартный диалог «Открыть». (путь, текст) или None, если отменили.

    Зовётся из рабочего потока, а не из потока значка: диалог модальный, и
    меню на всё время выбора иначе застыло бы. COM диалогу нужен свой на поток.
    utf-8-sig: Блокнот сохраняет с BOM, и без этого «[Interface]» в первой
    строке не узнавался бы.
    """
    import pythoncom
    import pywintypes
    import win32con
    import win32gui

    pythoncom.CoInitialize()
    try:
        path, _filter, _flags = win32gui.GetOpenFileNameW(
            Title=title, Filter=filters,
            Flags=win32con.OFN_EXPLORER | win32con.OFN_FILEMUSTEXIST
            | win32con.OFN_HIDEREADONLY)
    except pywintypes.error:
        return None                     # отмена — это тоже error, с кодом 0
    finally:
        pythoncom.CoUninitialize()
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        return path, fh.read()


def run():
    Tray().run()
    # Значок закрыт — процесс обязан закончиться. Обычный выход ждёт все
    # недемонические потоки, а их может оставить COM диалога выбора файла или
    # pywin32; тогда DualVPN-Tray.exe остался бы висеть без значка, и снять
    # его можно было бы только из диспетчера задач. Уборка уже сделана в on_quit.
    os._exit(0)
