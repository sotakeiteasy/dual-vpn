"""Один трей на сеанс и сигналы между процессами DualVPN.

Ярлык в меню «Пуск» запускает DualVPN-Tray.exe каждый раз заново. Раньше
каждый такой запуск ставил ещё один значок; теперь второй запуск находит
первый по именованному мьютексу, просит его показать окно и выходит.

Имена — в пространстве Local\\: у каждого сеанса Windows свой трей, и
второй пользователь на той же машине не должен «находить» чужой.

ctypes, а не win32event: признак «уже есть» приходит через GetLastError, и
между вызовом и проверкой его не должен перетереть никакой другой вызов.
"""

import ctypes
import threading
import time

TRAY_MUTEX = "Local\\DualVPN-Tray"
# Трею: «покажи окно» — так второй запуск ярлыка открывает панель.
TRAY_OPEN = "Local\\DualVPN-Tray-Open"
# Прогретому окну: «покажись».
WINDOW_SHOW = "Local\\DualVPN-Window-Show"

ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5
EVENT_MODIFY_STATE = 0x0002
INFINITE = 0xFFFFFFFF
ASFW_ANY = 0xFFFFFFFF

# Дескрипторы держим до конца процесса: закрытый мьютекс отпустил бы имя,
# и следующий запуск ярлыка счёл бы себя первым.
_held = []


def _kernel32():
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    k.CreateMutexW.restype = wintypes.HANDLE
    k.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL,
                               wintypes.LPCWSTR]
    k.CreateEventW.restype = wintypes.HANDLE
    k.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k.OpenEventW.restype = wintypes.HANDLE
    k.SetEvent.argtypes = [wintypes.HANDLE]
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.WaitForSingleObject.restype = wintypes.DWORD
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


def claim(name=TRAY_MUTEX):
    """True — этот процесс первый с таким именем и держит его до выхода.

    Отказ в доступе к мьютексу — тоже «уже запущен»: его создал процесс с
    другими правами, а не никто.
    """
    k = _kernel32()
    handle = k.CreateMutexW(None, False, name)
    err = ctypes.get_last_error()
    if not handle:
        if err == ERROR_ACCESS_DENIED:
            return False
        raise ctypes.WinError(err)
    if err == ERROR_ALREADY_EXISTS:
        k.CloseHandle(handle)
        return False
    _held.append(handle)
    return True


def listen(name, callback):
    """Зовёт callback в своём потоке на каждый signal(name). Событие
    создаётся сразу, до возврата: сигнал сразу после listen не потеряется."""
    k = _kernel32()
    # Автосброс: одно ожидание — один сигнал, без ручного ResetEvent.
    handle = k.CreateEventW(None, False, False, name)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    _held.append(handle)

    def loop():
        while k.WaitForSingleObject(handle, INFINITE) == 0:
            try:
                callback()
            except Exception:                              # noqa: BLE001
                # Один неудачный показ не должен глушить все следующие.
                pass

    threading.Thread(target=loop, daemon=True).start()


def signal(name, wait=0.0):
    """Взводит событие name. False — его никто не слушает.

    wait — сколько ждать, пока слушатель появится: трей, запущенный
    мгновением раньше, мог ещё не дойти до listen.
    """
    k = _kernel32()
    deadline = time.monotonic() + wait
    while True:
        handle = k.OpenEventW(EVENT_MODIFY_STATE, False, name)
        if handle:
            try:
                return bool(k.SetEvent(handle))
            finally:
                k.CloseHandle(handle)
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def allow_foreground(pid=ASFW_ANY):
    """Разрешает процессу pid (по умолчанию любому) вывести окно вперёд.

    Окно поднимает не тот процесс, по которому щёлкнули, а другой; без этого
    Windows не даёт ему фокус и лишь мигает кнопкой в панели задач.
    """
    try:
        ctypes.windll.user32.AllowSetForegroundWindow(ctypes.c_uint32(pid))
    except Exception:                                      # noqa: BLE001
        pass
