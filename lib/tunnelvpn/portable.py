"""Портативный режим: приложение целиком в одном exe, без установки.

Служба в обычной версии нужна ровно за одним: держать права постоянно, чтобы
трей мог править маршруты, не вызывая UAC на каждое включение. Портативная
версия решает ту же задачу иначе — просит права один раз, при запуске (это
делает манифест exe, см. installer/tunnelvpn.spec), и дальше держит туннель
прямо в себе.

Кода это почти не добавляет: логика службы и так вынесена в service.Core,
а трей и окно общаются с ней через именованный канал. Канал остаётся и здесь,
просто оба его конца оказываются в одном процессе — зато трей, окно и CLI
работают одинаково в обеих версиях, без единой развилки.

Выход из трея опускает туннель в обеих версиях (см. Tray.on_quit). Здесь это
ещё и подстраховано core.shutdown(): держать туннель после выхода некому —
маршруты и правило брандмауэра остались бы висеть, а сеть смотрела бы в
исчезнувший адаптер.
"""

import os
import sys

# Каталоги данных до переименования в TunnelVPN: встретив их, забираем целиком.
DATA_NAME, LEGACY_DATA_NAME = "TunnelVPN-Data", "DualVPN-Data"
LOCAL_NAME, LEGACY_LOCAL_NAME = "TunnelVPN", "DualVPN"
# Имя exe портативной сборки (installer/tunnelvpn.spec), в нижнем регистре.
EXE_NAME = "tunnelvpn-portable.exe"


def is_portable():
    """Процесс — портативная сборка: службы нет, ядро живёт в процессе трея,
    окно — тот же exe с командой window."""
    return os.path.basename(sys.executable).lower() == EXE_NAME


def _adopt(legacy, path):
    """Каталог старого имени → новое имя, если нового ещё нет: конфиги и ключи
    переезжают с прошлой версии. Не вышло (занят, нет прав) — новый каталог
    заведётся пустым, старый останется нетронутым."""
    if os.path.isdir(legacy) and not os.path.exists(path):
        try:
            os.rename(legacy, path)
        except OSError:
            pass
    return path


def data_dir():
    """Куда портативная версия кладёт конфиги и состояние.

    Рядом с exe, а не в ProgramData: смысл портативной версии в том, что папку
    можно унести целиком. Если рядом с exe писать нельзя (запустили с флешки
    только на чтение или из Program Files), откатываемся в профиль
    пользователя — иначе приложение не стартует вовсе.
    """
    here = os.path.dirname(os.path.abspath(sys.executable
                                           if getattr(sys, "frozen", False)
                                           else sys.argv[0]))
    candidate = _adopt(os.path.join(here, LEGACY_DATA_NAME),
                       os.path.join(here, DATA_NAME))
    try:
        os.makedirs(candidate, exist_ok=True)
        probe = os.path.join(candidate, ".writable")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("")
        os.remove(probe)
        return candidate
    except OSError:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return _adopt(os.path.join(base, LEGACY_LOCAL_NAME),
                      os.path.join(base, LOCAL_NAME))


def run(background=False):
    """Поднимает ядро в фоне и отдаёт главный поток трею.

    Второй запуск в том же сеансе только просит первый показать окно: второе
    ядро подняло бы второй туннель поверх первого. Поэтому проверка — до
    core.start().

    Главный поток обязан достаться трею: pystray держит в нём цикл сообщений
    Windows, и из любого другого потока значок просто не появится.
    """
    # Импорт после того, как выставлен TUNNELVPN_DATA: paths читает его при
    # импорте, и раскладка определяется один раз на весь процесс.
    from . import service, tray

    if tray.already_running(background):
        return

    core = service.Core()
    core.log("=== портативный запуск ===")
    core.start()

    t = tray.Tray()

    try:
        t.run(background)
    finally:
        # Сюда приходим и по «Выход», и по любому исключению в трее.
        # Туннель снимаем в обоих случаях: висящие маршруты хуже, чем
        # закрывшееся приложение.
        core.shutdown()
    # Как и у установленного трея (tray.run): процесс без значка жить не
    # должен, даже если какой-то поток не дал бы обычному выходу завершиться.
    os._exit(0)
