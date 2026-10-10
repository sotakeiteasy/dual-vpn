"""Один трей на сеанс и сигналы между процессами TunnelVPN.

Ярлык в меню «Пуск» запускает TunnelVPN-Tray.exe каждый раз заново. Раньше
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

TRAY_MUTEX = "Local\\TunnelVPN-Tray"
# Трею: «покажи окно» — так второй запуск ярлыка открывает панель.
TRAY_OPEN = "Local\\TunnelVPN-Tray-Open"
# Прогретому окну: «покажись».
WINDOW_SHOW = "Local\\TunnelVPN-Window-Show"

ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5
ERROR_FILE_NOT_FOUND = 2
EVENT_MODIFY_STATE = 0x0002
SYNCHRONIZE = 0x00100000
SDDL_REVISION_1 = 1
# Событие трея: трей работает от администратора, а ярлык запускает TunnelVPN-Tray.exe
# от обычного пользователя. Без этого дескриптора событие получает DACL
# администратора и высокую метку целостности, и обычный процесс его не откроет.
# Сигналить (EVENT_MODIFY_STATE) — интерактивному пользователю, метка — средняя.
USER_SIGNAL_SDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100002;;;IU)S:(ML;;NW;;;ME)"
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
    k.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k.OpenMutexW.restype = wintypes.HANDLE
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


def exists(name=TRAY_MUTEX):
    """Есть ли мьютекс name, без захвата. Для процесса без прав: claim у него
    занял бы имя, и трей, перезапущенный с правами, счёл бы себя вторым.
    Отказ в доступе — тоже «есть»: мьютекс трея с правами администратора.
    """
    k = _kernel32()
    handle = k.OpenMutexW(SYNCHRONIZE, False, name)
    err = ctypes.get_last_error()
    if handle:
        k.CloseHandle(handle)
        return True
    if err == ERROR_ACCESS_DENIED:
        return True
    if err == ERROR_FILE_NOT_FOUND:
        return False
    raise ctypes.WinError(err)


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", ctypes.c_uint32),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", ctypes.c_int)]


def _create_event(k, name, sddl):
    """CreateEventW с дескриптором из sddl; None — права по умолчанию."""
    # Автосброс: одно ожидание — один сигнал, без ручного ResetEvent.
    if sddl is None:
        return k.CreateEventW(None, False, False, name)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    sd = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            ctypes.c_wchar_p(sddl), SDDL_REVISION_1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), sd, False)
        return k.CreateEventW(ctypes.addressof(sa), False, False, name)
    finally:
        ctypes.windll.kernel32.LocalFree(sd)


def listen(name, callback, sddl=None):
    """Зовёт callback в своём потоке на каждый signal(name). Событие
    создаётся сразу, до возврата: сигнал сразу после listen не потеряется.
    sddl — права на событие (USER_SIGNAL_SDDL: сигналит и процесс без прав)."""
    k = _kernel32()
    handle = _create_event(k, name, sddl)
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
