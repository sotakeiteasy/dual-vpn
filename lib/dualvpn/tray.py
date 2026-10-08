"""Значок в трее: включить, выключить, конфиги с кружком статуса, открыть окно.

Остальное — выбор личного профиля, автозапуск, рабочая сеть — только в окне:
меню трея держим коротким, а настройки — в одном месте.

Туннелем владеет служба, трей шлёт ей команды через именованный канал.
Установленный трей работает от администратора: конфиги с ключами служба
принимает только от администратора, и так UAC спрашивается один раз при
запуске, а не на каждое добавление конфига. Права он поднимает сам (run), а не
манифестом: ярлык к уже работающему трею открывает окно без UAC.

Значок рисуется кодом, а не берётся из файла: он маленький, состояний у него
четыре, и держать четыре .ico в сборке ради этого незачем. Заодно он сам
подстраивается под тёмную и светлую тему панели задач.
"""

import functools
import os
import sys
import threading
import time

from . import instance, ipc, paths, window

# Включение у службы идёт ~1,2 с: при опросе раз в три секунды жёлтый
# «включаю» почти не попадал в опрос, если включали из окна.
POLL_EVERY = 1.0
# Сколько выход ждёт, пока служба закончит начатый start и примет stop.
QUIT_WAIT = 40.0
# Сколько живое окно имеет на то, чтобы принять сигнал и стать видимым.
# Не стало — процесс завис, его снимаем и запускаем новое окно.
WINDOW_SHOW_WAIT = 5.0
# Через сколько после старта трей прогревает спрятанное окно: сразу после
# входа в систему машине и так есть чем заняться.
WARM_AFTER = 10.0
# Сколько второй запуск ждёт, пока первый трей начнёт слушать «покажи окно».
OPEN_SIGNAL_WAIT = 2.0

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

# Длиннее имя конфига в меню обрезаем: меню растягивается по самому длинному
# пункту, и имя файла в сотню знаков сделало бы его шириной в пол-экрана.
NAME_MAX = 28

# Свои сообщения окну значка pystray. Всё, что трогает HMENU, идёт через них
# в поток значка: там же открывается меню, и перестройка не может попасть
# между открытием и закрытием — update_menu() удалил бы показанное меню.
WM_APP = 0x8000
WM_SYNC_MENU = WM_APP + 1
WM_CHECKED = WM_APP + 2


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
        # Открытие окна зовут меню, второй запуск ярлыка и прогрев —
        # каждый из своего потока; без замка два разом запустили бы два окна.
        self._window_lock = threading.Lock()
        # Команды трея, на которые служба ещё не ответила. Пока они есть,
        # значок жёлтый сразу, а не с первым опросом, заставшим службу занятой.
        self._pending = 0
        self._state_lock = threading.Lock()
        # Меню и кружки — только в потоке значка (см. WM_SYNC_MENU).
        self._menu_open = False
        # Конфиги, чей ответ на проверку при открытии меню ещё не пришёл.
        self._checking = frozenset()
        self._check_gen = 0
        # Задан ли хост проверки рабочей сети. Знает только ответ check;
        # до первой проверки считаем, что задан.
        self.corp_probe = True
        self._corp_item = None
        self._personal_item = None
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
        # Опрос идёт и из своего потока, и из потоков команд по их окончании.
        with self._state_lock:
            self._poll_locked()

    def _poll_locked(self):
        try:
            self.status = ipc.call("status").get("status", {})
            if self._pending or self.status.get("busy"):
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
        if self._menu_sig() != self._last_menu_sig:
            self._post(WM_SYNC_MENU)

    def _menu_sig(self):
        """То, от чего зависят подписи, галочки и доступность пунктов меню."""
        st = self.status
        return (bool(st), bool(st.get("up")), bool(st.get("busy")),
                _conf_labels(st))

    def _post(self, msg, wparam=0, lparam=0):
        """Сообщение окну значка. Окна ещё нет — опрос повторит."""
        hwnd = getattr(self.icon, "_hwnd", None)
        if not hwnd:
            return
        import win32gui
        try:
            win32gui.PostMessage(hwnd, msg, wparam, lparam)
        except Exception:                                  # noqa: BLE001
            pass                                           # окно уже закрыто

    def _sync_menu(self, _wparam=0, _lparam=0):
        """Перестройка меню по статусу. Только в потоке значка и не при
        открытом меню: закрытие меню само позовёт её ещё раз."""
        if self._menu_open or self.icon is None:
            return
        sig = self._menu_sig()
        if sig != self._last_menu_sig:
            self._last_menu_sig = sig
            self.icon.update_menu()

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
        if st.get("out") == "direct":
            return "DualVPN — запасной выход напрямую: личный не работает"
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
                # Без default=True: левый клик по значку не должен включать и
                # выключать VPN — промахнуться слишком легко. Только из меню.
                enabled=lambda _i: bool(self.status) and not self.status.get("busy")),
            pystray.MenuItem(
                "Перезапустить", self.on_restart,
                enabled=lambda _i: bool(self.status.get("up"))
                and not self.status.get("busy")),
            pystray.Menu.SEPARATOR,
            *self._conf_items(pystray),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Открыть панель управления…", self.on_window),
            pystray.MenuItem("Закрыть", self.on_quit),
        )

    def _conf_items(self, pystray):
        """Пункты конфигов: имя и кружок статуса слева, клик — другой файл.

        Кружок ставит _paint_dots, а не pystray: картинок у пунктов pystray
        не умеет. Ссылки на пункты нужны, чтобы найти их место в HMENU.
        """
        self._corp_item = pystray.MenuItem(
            lambda _i: _conf_labels(self.status)[0],
            lambda: self.on_add_config("corp"), enabled=self._can_edit)
        self._personal_item = pystray.MenuItem(
            lambda _i: _conf_labels(self.status)[1],
            lambda: self.on_add_config("personal"), enabled=self._can_edit)
        return self._corp_item, self._personal_item

    # ------------------------------------------------------ кружки в меню

    def _hook_menu(self):
        """Проверка туннелей при каждом открытии меню.

        pystray открывает меню в обработчике WM_NOTIFY на правый клик, и
        TrackPopupMenuEx не возвращается, пока меню открыто. Оборачиваем этот
        обработчик: до показа — свежие подписи и рыжие кружки, проверка в
        отдельном потоке; её ответ приходит сообщением WM_CHECKED, которое
        модальный цикл меню доставляет, пока меню на экране.
        """
        from pystray._util import win32

        handlers = self.icon._message_handlers
        orig = handlers[win32.WM_NOTIFY]

        def on_notify(wparam, lparam):
            if lparam != win32.WM_RBUTTONUP:
                return orig(wparam, lparam)
            self._check_gen += 1
            self._checking = (frozenset(ipc.CHECK_SIDES)
                              if self.status.get("up") else frozenset())
            try:
                self._sync_menu()
                self._paint_dots()
            except Exception:                              # noqa: BLE001
                pass                       # без кружков, но меню откроется
            threading.Thread(target=self._check_work, args=(self._check_gen,),
                             daemon=True).start()
            self._menu_open = True
            try:
                return orig(wparam, lparam)
            finally:
                self._menu_open = False
                self._sync_menu()

        handlers[win32.WM_NOTIFY] = on_notify
        handlers[WM_SYNC_MENU] = self._sync_menu
        handlers[WM_CHECKED] = self._on_checked

    def _check_work(self, gen):
        """Проверка при открытии меню. Кружок конфига перекрашивается, как
        только проверен он сам: молчащий рабочий не держит рыжим личный."""
        def on_side(st, pending):
            with self._state_lock:
                self.status = st
            self._post(WM_CHECKED, gen, _side_bits(pending))

        try:
            reply = ipc.check_by_side(on_side)
        except Exception:                                  # noqa: BLE001
            reply = {}             # рыжий всё равно надо погасить — ниже
        if reply.get("status"):
            with self._state_lock:
                self.status = reply["status"]
        if "corp_probe" in reply:
            self.corp_probe = bool(reply["corp_probe"])
        self._post(WM_CHECKED, gen, 0)

    def _on_checked(self, wparam, lparam):
        # Ответ прошлого открытия меню не гасит рыжий у текущего.
        if wparam != self._check_gen:
            return
        # Только убавляем: поздний ответ стороны не вернёт рыжий готовой.
        self._checking &= _sides_of(lparam)
        if self._menu_open:
            self._paint_dots()
            _redraw_menus(self.icon._hwnd)

    def _paint_dots(self):
        """Кружки в пунктах конфигов текущего HMENU. Поток значка."""
        handle = self.icon._menu_handle
        if not handle:
            return
        items = list(self.icon.menu)
        names = _conf_names(self.status)
        colors = _conf_colors(self.status, self.corp_probe, self._checking)
        for item, name, color in zip((self._corp_item, self._personal_item),
                                     names, colors):
            if item in items:
                _set_item_bitmap(handle[0], items.index(item),
                                 _dot_bitmap(color) if name else None)

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
        self._busy_while(work)

    def _busy_while(self, work):
        """work в отдельном потоке, значок жёлтый, пока она идёт.

        По окончании опрашиваем службу сразу: зелёный или красный должен
        появиться, как только служба ответила, а не через период опроса.
        """
        with self._state_lock:
            self._pending += 1
            self.state = "busy"
            self._refresh_icon()

        def run():
            try:
                work()
            finally:
                with self._state_lock:
                    self._pending -= 1
                try:
                    self._poll_once()
                except Exception:                          # noqa: BLE001
                    pass                                   # догонит поток опроса
        threading.Thread(target=run, daemon=True).start()

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
        self._busy_while(work)

    # ---------------------------------------------------------------- конфиги

    def _can_edit(self, _item=None):
        # При поднятом туннеле тоже можно: on_add_config сам перезапустит VPN,
        # чтобы новый файл подействовал сразу, а не после ручного перезапуска.
        return bool(self.status) and not self.status.get("busy")

    def on_add_config(self, kind):
        """Файл .conf в службу. Тип задаёт пункт меню, имя чистит служба:
        рабочий заменяет прежний, личный становится активным. Был поднят
        туннель — перезапускаем его с новым конфигом."""
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
            if reply is None:
                return
            what = "рабочий" if kind == "corp" else "личный"
            if self.status.get("up"):
                self._notify(f"{what} конфиг заменён: {reply.get('name')}.conf,"
                             " перезапускаю VPN")
                self.on_restart()
            else:
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

        Окно одно: живое (в том числе прогретое и спрятанное) получает сигнал
        «покажись», новое запускается, только если прежнего нет или оно не
        показалось за WINDOW_SHOW_WAIT. Раньше каждый клик запускал новое, а
        запоминалось только последнее — «Закрыть» снимал его, а первое
        оставалось висеть. Ожидание — в своём потоке: зовут нас и из
        обработчика меню, а он идёт в потоке значка.
        """
        threading.Thread(target=self._open_window, daemon=True).start()

    def _open_window(self):
        with self._window_lock:
            if self.stop_event.is_set():
                return
            proc = self._window_proc
            if proc is not None and proc.poll() is None:
                # Фокус есть у трея (по нему щёлкнули), а окно — другой процесс.
                # Любому, а не proc.pid: у портативной (onefile) окно в дочернем.
                instance.allow_foreground()
                if (instance.signal(instance.WINDOW_SHOW, wait=WINDOW_SHOW_WAIT)
                        and _wait_visible(proc.pid, WINDOW_SHOW_WAIT)):
                    return
                # Живой процесс, не показавший окна, завис: без замены панель
                # больше не открылась бы.
                proc.terminate()
            # Новое окно показывается не сразу, а на готовности страницы
            # (window.Api.reveal) — право на передний план нужно и ему.
            instance.allow_foreground()
            self._launch_window(hidden=False)

    def _warm(self):
        """Прогрев: спрятанное окно заранее, чтобы первый показ был мгновенным."""
        with self._window_lock:
            proc = self._window_proc
            if self.stop_event.is_set() or (proc is not None and proc.poll() is None):
                return
            self._launch_window(hidden=True)

    def _launch_window(self, hidden, retry=True):
        """Новый процесс окна. Только под _window_lock."""
        import subprocess
        import sys

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
        cmd += ["--resident"] + (["--hidden"] if hidden else [])

        # Раньше вывод окна уходил в никуда: при падении (например, из-за
        # неверного пути к index.html) причину нельзя было увидеть нигде.
        try:
            paths.ensure_dirs()
            log = open(os.path.join(paths.LOGS, "window-launch.log"),
                      "a", encoding="utf-8", errors="replace")
        except OSError:
            log = subprocess.DEVNULL
        proc = subprocess.Popen(
            cmd, stdout=log, stderr=log,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self._window_proc = proc
        threading.Thread(target=self._watch_window, args=(proc, hidden, retry),
                         daemon=True).start()

    def _watch_window(self, proc, hidden, retry):
        """Окно, чей WebView2 не поднялся, выходит с window.READY_LOST.

        Показываемое запускаем ещё раз — один раз: сбой бывает разовым, а
        повторяющийся перезапуском не лечится. Прогретое не трогаем: новое
        окно запустит первый же показ.
        """
        if proc.wait() != window.READY_LOST or hidden or not retry:
            return
        with self._window_lock:
            if self._window_proc is proc and not self.stop_event.is_set():
                self._launch_window(hidden=False, retry=False)

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
            # Под замком: окно, запущенное минуту назад из другого потока,
            # тоже должно закрыться, а новое после stop_event не запустится.
            with self._window_lock:
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

    def run(self, background=False):
        import pystray

        _dark_menus()
        self.icon = pystray.Icon(
            "dualvpn", _icon_image("off"), f"DualVPN {paths.version()}",
            menu=self._menu())
        self._hook_menu()
        self._start_window(background)
        self.icon.run(setup=self._setup)

    def _start_window(self, background):
        """Ярлык — окно сразу; вход в систему (--background) — только значок,
        а окно прогревается спрятанным. Повторный запуск ярлыка приходит
        сигналом TRAY_OPEN (см. already_running)."""
        try:
            # Сигналит ярлык, запущенный без прав, — событие открыто и ему.
            instance.listen(instance.TRAY_OPEN, self.on_window,
                            sddl=instance.USER_SIGNAL_SDDL)
        except OSError:
            pass                   # окно откроется из меню, не с ярлыка
        if background:
            timer = threading.Timer(WARM_AFTER, self._warm)
            timer.daemon = True
            timer.start()
        else:
            self.on_window()

    def _setup(self, icon):
        """Опрос — только после показа значка. pystray ставит видимость не
        разом: собирает картинку, показывает, и лишь потом visible=True.
        Опрос, сменивший цвет в этом окне, терял картинку: значок оставался
        серым при работающем VPN, а следующие опросы цвет уже не меняли."""
        icon.visible = True
        threading.Thread(target=self.poll, daemon=True).start()


def _clip(text, limit):
    text = str(text or "")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _conf_names(st):
    """(рабочий, личный): имена конфигов для меню, None — показывать нечего.

    Личный — выбранный, а без выбора единственный, как берёт его сборка.
    Из нескольких без выбора не показываем ни один: выбирают их в окне.
    """
    corp = st.get("corp") or []
    names = st.get("profiles") or []
    active = st.get("profile") or (names[0] if len(names) == 1 else "")
    return (corp[0] if corp else None, active if active in names else None)


def _conf_labels(st):
    """Подписи пунктов конфигов: имя файла или приглашение добавить."""
    corp, personal = _conf_names(st)
    return (_clip(corp, NAME_MAX) if corp else "Добавить рабочий конфиг…",
            _clip(personal, NAME_MAX) if personal else "Добавить личный конфиг…")


def _side_bits(sides):
    """Набор сторон — в число для lParam сообщения окну значка."""
    return sum(1 << i for i, s in enumerate(ipc.CHECK_SIDES) if s in sides)


def _sides_of(bits):
    return frozenset(s for i, s in enumerate(ipc.CHECK_SIDES) if bits >> i & 1)


def _conf_colors(st, corp_probe, checking):
    """(рабочий, личный): ключи COLORS для кружков.

    VPN выключен — итог прошлой проверки этих же файлов (st["last"]), а если
    его нет — серые. checking — конфиги, чей ответ трей ещё ждёт: они
    рыжие, как и те, что служба проверяет сама. Каждый по себе: молчащий
    рабочий не красит рыжим работающий личный. Личный работает, если
    выход виден и он не мимо туннеля. Рабочий — если хост проверки ответил
    по DNS или HTTP; без CORP_PROBE ответить нечему, и серый честнее красного.
    """
    if not st.get("up"):
        last = st.get("last") or {}
        return last.get("corp") or "off", last.get("personal") or "off"
    if st.get("busy"):
        return "busy", "busy"
    personal = ("up" if st.get("exit_ip") and st.get("out") != "direct"
                and st.get("exit_state") not in ("leak", "direct") else "error")
    if st.get("corp_ip") or st.get("corp_http"):
        corp = "up"
    else:
        corp = "error" if corp_probe else "off"
    busy = {s for s in ipc.CHECK_SIDES
            if s in checking or st.get(f"checking_{s}")}
    return ("busy" if "corp" in busy else corp,
            "busy" if "personal" in busy else personal)


@functools.lru_cache(maxsize=None)
def _win_api():
    """Свои прототипы user32/gdi32: у pystray они общие, их не трогаем."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32")
    gdi32 = ctypes.WinDLL("gdi32")
    set_info = user32.SetMenuItemInfoW
    set_info.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.BOOL,
                         ctypes.c_void_p]
    set_info.restype = wintypes.BOOL
    create_dib = gdi32.CreateDIBSection
    create_dib.argtypes = [wintypes.HDC, ctypes.c_void_p, wintypes.UINT,
                           ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE,
                           wintypes.DWORD]
    create_dib.restype = wintypes.HBITMAP
    return set_info, create_dib


@functools.lru_cache(maxsize=None)
def _dot_bitmap(state):
    """HBITMAP кружка для пункта меню; кэш по цвету, удалять незачем.

    32 бита с альфой, premultiplied, строки сверху вниз — только такую
    картинку меню Windows рисует с прозрачным краем. Рисуем вчетверо крупнее
    и уменьшаем: кружок в 16 точек без сглаживания выходит рваным.
    """
    import ctypes
    from ctypes import wintypes

    import win32api
    from PIL import Image, ImageDraw

    size = win32api.GetSystemMetrics(71)            # SM_CXMENUCHECK
    big = size * 4
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    pad = big // 5
    ImageDraw.Draw(img).ellipse((pad, pad, big - pad, big - pad),
                                fill=COLORS[state])
    rgba = img.resize((size, size), Image.LANCZOS).tobytes()
    bgra = bytearray(len(rgba))
    for i in range(0, len(rgba), 4):
        r, g, b, a = rgba[i:i + 4]
        bgra[i:i + 4] = (b * a // 255, g * a // 255, r * a // 255, a)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                    ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD),
                    ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD),
                    ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG),
                    ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD)]

    hdr = BITMAPINFOHEADER(biSize=ctypes.sizeof(BITMAPINFOHEADER),
                           biWidth=size, biHeight=-size, biPlanes=1,
                           biBitCount=32, biCompression=0)   # BI_RGB
    bits = ctypes.c_void_p()
    hbmp = _win_api()[1](None, ctypes.byref(hdr), 0,       # DIB_RGB_COLORS
                         ctypes.byref(bits), None, 0)
    if not hbmp:
        return None
    ctypes.memmove(bits, bytes(bgra), len(bgra))
    return hbmp


def _set_item_bitmap(hmenu, pos, hbmp):
    """Картинка пункта слева от текста; None — убрать."""
    import ctypes
    from pystray._util import win32

    info = win32.MENUITEMINFO(cbSize=ctypes.sizeof(win32.MENUITEMINFO),
                              fMask=win32.MIIM_BITMAP, hbmpItem=hbmp)
    _win_api()[0](hmenu, pos, True, ctypes.byref(info))


def _redraw_menus(hwnd):
    """Перерисовать открытые меню потока значка: Windows сама не узнаёт,
    что картинка пункта сменилась. Окно меню — класс #32768."""
    import win32gui
    import win32process

    tid, _pid = win32process.GetWindowThreadProcessId(hwnd)

    def each(child, _extra):
        if win32gui.GetClassName(child) == "#32768":
            win32gui.InvalidateRect(child, None, True)
        return True

    try:
        win32gui.EnumThreadWindows(tid, each, None)
    except Exception:                                      # noqa: BLE001
        pass                                               # меню уже закрыли


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


def _child_pids(pid):
    """pid и его прямые дети. Окно бывает не в запущенном процессе:
    портативный onefile-exe — загрузчик, Python идёт его ребёнком; то же
    у python.exe из venv при запуске из исходников."""
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260)]

    k = ctypes.WinDLL("kernel32")
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    pids = {pid}
    snap = k.CreateToolhelp32Snapshot(0x2, 0)              # TH32CS_SNAPPROCESS
    if not snap or snap == wintypes.HANDLE(-1).value:
        return pids
    try:
        entry = PROCESSENTRY32W(dwSize=ctypes.sizeof(PROCESSENTRY32W))
        ok = k.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.th32ParentProcessID == pid:
                pids.add(entry.th32ProcessID)
            ok = k.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k.CloseHandle(snap)
    return pids


def _wait_visible(pid, timeout):
    """Ждёт видимое окно верхнего уровня у процесса pid (или его ребёнка).
    False — не дождались.

    По pid, а не по заголовку: окно с тем же именем могло остаться от процесса,
    запущенного из командной строки, а спрятанное прогретое окно FindWindow находил
    бы и невидимым.
    """
    import win32gui
    import win32process

    def visible():
        pids = _child_pids(pid)
        found = []

        def each(hwnd, _extra):
            if (win32gui.IsWindowVisible(hwnd)
                    and win32process.GetWindowThreadProcessId(hwnd)[1] in pids):
                found.append(hwnd)
            return True

        win32gui.EnumWindows(each, None)
        return bool(found)

    deadline = time.monotonic() + timeout
    while True:
        if visible():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


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


def already_running(background=False):
    """True — трей этого сеанса уже есть; ему передано «покажи окно».

    Задача при входе (background) окно не открывает: трей уже запустили
    руками, и незапрошенная панель поверх всего только мешала бы.
    Мьютекс не создался по другой причине — считаем себя первым: лишний
    значок лучше, чем ни одного.

    Процесс без прав мьютекс не занимает, а только проверяет: он сейчас
    перезапустится с правами (run), и занятое им имя заставило бы трей с
    правами считать себя вторым.
    """
    try:
        if window._is_admin():
            if instance.claim():
                return False
        elif not instance.exists():
            return False
    except OSError:
        return False
    if not background:
        # Фокус сейчас у нас (щёлкнули ярлык), а окно покажет другой процесс.
        instance.allow_foreground()
        instance.signal(instance.TRAY_OPEN, wait=OPEN_SIGNAL_WAIT)
    return True


def _relaunch_elevated():
    """Тот же запуск с правами администратора (UAC), без ожидания.

    Отказ в UAC — просто выход: трея не было и нет, как если бы ярлык не нажали.
    """
    import ctypes
    import subprocess

    args = sys.argv[1:] if getattr(sys, "frozen", False) else [
        os.path.abspath(sys.argv[0])] + sys.argv[1:]
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, subprocess.list2cmdline(args), None, 1)


def run(background=False):
    if already_running(background):
        return
    # Ярлык запускает трей без прав (в манифесте их нет — иначе UAC спрашивал
    # бы и тогда, когда трей уже есть и нужно только показать окно). Трея нет —
    # теперь права нужны.
    if not window._is_admin():
        _relaunch_elevated()
        return
    Tray().run(background)
    # Значок закрыт — процесс обязан закончиться. Обычный выход ждёт все
    # недемонические потоки, а их может оставить COM диалога выбора файла или
    # pywin32; тогда DualVPN-Tray.exe остался бы висеть без значка, и снять
    # его можно было бы только из диспетчера задач. Уборка уже сделана в on_quit.
    os._exit(0)
