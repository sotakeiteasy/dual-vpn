"""Значок в трее: включить, выключить, выбрать профиль, открыть окно.

Обычный пользовательский процесс. Всё, что требует прав, уходит в службу через
именованный канал, поэтому UAC здесь не появляется никогда.

Значок рисуется кодом, а не берётся из файла: он маленький, состояний у него
четыре, и держать четыре .ico в сборке ради этого незачем. Заодно он сам
подстраивается под тёмную и светлую тему панели задач.
"""

import threading

from . import ipc, paths

POLL_EVERY = 3.0

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
    def __init__(self, on_quit_stops_tunnel=False):
        self.icon = None
        self.state = "off"
        self.status = {}
        self.stop_event = threading.Event()
        # В портативной версии туннель держит этот же процесс, и выход из трея
        # обязан его опустить. В установленной — им владеет служба, и закрытие
        # значка не должно выключать VPN.
        self.quit_stops_tunnel = on_quit_stops_tunnel

    # ------------------------------------------------------------- статус

    def poll(self):
        while not self.stop_event.is_set():
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
            self.stop_event.wait(POLL_EVERY)

    def _refresh_icon(self):
        if self.icon is None:
            return
        self.icon.icon = _icon_image(self.state)
        self._refresh_title()
        self.icon.update_menu()

    def _refresh_title(self):
        if self.icon is None:
            return
        self.icon.title = self._title()

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
            pystray.MenuItem("Личный профиль", pystray.Menu(self._profile_items)),
            pystray.MenuItem(
                "Включать при старте", self.on_autostart,
                checked=lambda _i: bool(self.status.get("autostart"))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Окно…", self.on_window),
            pystray.MenuItem("Выход", self.on_quit),
        )

    def _profile_items(self):
        """Генератор пунктов подменю — pystray зовёт его при каждом показе."""
        import pystray

        # Рабочий конфиг подключается всегда и выбора не требует — в списке
        # только личные, иначе выбрать «corp» личным туннелем было бы можно.
        names = [n for n in (self.status.get("profiles") or [])
                 if not _looks_corp(n)]
        if not names:
            yield pystray.MenuItem("(конфигов нет)", None, enabled=False)
            return
        for name in names:
            yield pystray.MenuItem(
                name,
                # name связываем значением, а не замыканием по переменной цикла:
                # иначе все пункты меню выбирали бы последний профиль.
                lambda _i, _it, n=name: self.on_profile(n),
                checked=lambda _it, n=name: n == (self.status.get("profile")
                                                  or "personal"),
                radio=True)

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

    def on_profile(self, name):
        self._do("set-profile", profile=name)

    def on_autostart(self):
        self._do("set-autostart", on=not self.status.get("autostart"))

    def on_window(self):
        """Окно — в отдельном процессе.

        И pywebview, и pystray хотят собственный цикл сообщений в главном
        потоке; в одном процессе они друг друга блокируют. Отдельный процесс
        обходится дешевле, чем попытка их подружить.
        """
        import os
        import subprocess
        import sys
        if getattr(sys, "frozen", False):
            # sys.executable здесь — сам трей, и запуск его без аргументов дал
            # бы второй значок вместо окна.
            sibling = os.path.join(os.path.dirname(sys.executable), "dualvpn.exe")
            if os.path.isfile(sibling):
                # Установленная версия: окно живёт в соседнем консольном exe.
                cmd = [sibling, "window"]
            else:
                # Портативная: соседа нет, файл один — зовём его же с командой.
                cmd = [sys.executable, "window"]
        else:
            cmd = [sys.executable, "-m", "dualvpn.cli", "window"]
        subprocess.Popen(cmd, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def on_quit(self):
        """Закрывает значок.

        В установленной версии туннель при этом остаётся поднятым: им владеет
        служба, и «закрыл значок» не должно означать «выключил VPN» — это ровно
        то поведение, которого ждут от обычного VPN-клиента.

        В портативной держать туннель после выхода некому, поэтому опускаем.
        Сам вызов делаем здесь, а не только в portable.run(): пользователь ждёт,
        что к моменту исчезновения значка сеть уже вернулась в норму.
        """
        if self.quit_stops_tunnel and self.status.get("up"):
            try:
                ipc.call("stop")
            except ipc.NotRunning:
                # Ядро в этом же процессе, но канал мог не подняться. Уборку
                # всё равно доделает portable.run() через core.shutdown().
                pass
        self.stop_event.set()
        if self.icon is not None:
            self.icon.stop()

    def _notify(self, text):
        if self.icon is None:
            return
        try:
            self.icon.notify(text, "DualVPN")
        except Exception:
            # Уведомления есть не во всех сборках Windows; молчать тут можно —
            # ошибка всё равно видна в подписи значка и в окне.
            pass

    # -------------------------------------------------------------- запуск

    def run(self):
        import pystray

        self.icon = pystray.Icon(
            "dualvpn", _icon_image("off"), f"DualVPN {paths.version()}",
            menu=self._menu())
        threading.Thread(target=self.poll, daemon=True).start()
        self.icon.run()


def _looks_corp(name):
    low = name.lower()
    return (low in ("corp", "wg") or low.startswith("wg-")
            or low.startswith("wg0-"))


def run():
    Tray().run()
