"""Именованный канал между треем и службой.

Туннель правит таблицу маршрутов, поэтому им владеет служба под LocalSystem, а
трей работает от обычного пользователя и шлёт ей команды. Так UAC спрашивают
один раз при установке, а не при каждом включении.

Канал, а не порт на localhost: порт видно из любого процесса и его пришлось бы
защищать самодельным токеном, а у канала есть родной ACL.

Права разделены. Включить и выключить может любой, кто вошёл в систему, —
это не повышение привилегий, а ровно то, что делает кнопка в трее. Всё, что
пишет конфиги, требует администратора: конфиг исполняется службой от SYSTEM и
содержит приватные ключи, поэтому подсунуть его обычный пользователь не должен.

Формат простой: одна строка JSON туда, одна обратно, соединение закрывается.
Обе стороны говорят через pywin32 (win32file/win32pipe). У встроенного open()
на именованном канале Windows есть известная червоточина: на части сочетаний
Windows/Python комбинация «чтение и запись сразу» валится с
OSError: [Errno 22] Invalid argument, хотя сам канал исправен. Через pywin32
работает то же самое, что уже годами работает на стороне сервера — не
изобретаем второй протокол, идём тем же путём.
"""

import json
import threading

from . import paths

# Команды, которые только читают. Остальные требуют администратора, кроме
# явно перечисленных в USER_OPS.
READ_OPS = frozenset({"status", "list-profiles", "log"})
# Команды управления туннелем: их разрешаем любому вошедшему пользователю.
USER_OPS = frozenset({"start", "stop", "set-profile"})


def requires_admin(op):
    """Нужны ли для команды права администратора.

    Отдельной функцией, а не условием внутри обработчика соединения: это
    граница доступа к приватным ключам, и она должна быть проверяема, не
    поднимая канал. Всё, что не перечислено явно, требует прав — новая
    команда по умолчанию закрыта, а не открыта.
    """
    return op not in READ_OPS and op not in USER_OPS

_BUF = 65536


class Server:
    """Слушает канал и раздаёт команды обработчику.

    handler(op, payload, is_admin) -> dict. Исключения обработчика не валят
    службу: клиент получает {"ok": false, "error": ...}.
    """

    def __init__(self, handler, log):
        self.handler = handler
        self.log = log
        self.stop_event = threading.Event()

    def serve_forever(self):
        import pywintypes
        import win32file
        import win32pipe

        sa = self._security()
        while not self.stop_event.is_set():
            pipe = None
            try:
                pipe = win32pipe.CreateNamedPipe(
                    paths.PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE
                    | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    _BUF, _BUF, 0, sa,
                )
                win32pipe.ConnectNamedPipe(pipe, None)
            except pywintypes.error as exc:
                if not self.stop_event.is_set():
                    self.log(f"канал: {exc}")
                if pipe is not None:
                    try:
                        win32file.CloseHandle(pipe)
                    except Exception:
                        pass
                continue
            # Каждое соединение — в своём потоке, и сразу открываем следующий
            # экземпляр канала. Иначе `start`, честно работающий до тридцати
            # секунд, всё это время не давал бы трею даже спросить статус.
            threading.Thread(target=self._serve_one, args=(pipe,),
                             daemon=True).start()

    def _serve_one(self, pipe):
        try:
            self._exchange(pipe)
        except Exception as exc:
            if not self.stop_event.is_set():
                self.log(f"канал: {exc}")
        finally:
            import win32file
            import win32pipe
            try:
                win32pipe.DisconnectNamedPipe(pipe)
                win32file.CloseHandle(pipe)
            except Exception:
                pass

    def _exchange(self, pipe):
        import win32file
        import win32pipe

        _, data = win32file.ReadFile(pipe, _BUF)
        try:
            req = json.loads(data.decode("utf-8"))
            op = str(req.get("op", ""))
            payload = req.get("payload") or {}
        except (ValueError, AttributeError):
            self._reply(pipe, {"ok": False, "error": "не разобрал запрос"})
            return

        # Кто спрашивает, выясняем строго на этом соединении: олицетворяем
        # клиента и смотрим его токен. Судить по чему-то, что прислал он сам,
        # нельзя — это он и подделает.
        is_admin = False
        try:
            win32pipe.ImpersonateNamedPipeClient(pipe)
            is_admin = _client_is_admin()
        except Exception:
            is_admin = False
        finally:
            try:
                import win32security
                win32security.RevertToSelf()
            except Exception:
                pass

        if requires_admin(op) and not is_admin:
            self._reply(pipe, {"ok": False,
                               "error": "нужны права администратора"})
            return

        try:
            result = self.handler(op, payload, is_admin)
        except Exception as exc:
            result = {"ok": False, "error": str(exc)}
        self._reply(pipe, result)

    @staticmethod
    def _reply(pipe, obj):
        import win32file
        win32file.WriteFile(
            pipe, json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n")

    @staticmethod
    def _security():
        """ACL канала: SYSTEM и администраторы полностью, вошедшие — читать/писать.

        Без явного дескриптора канал, созданный службой под LocalSystem,
        обычному пользователю недоступен вовсе, и трей не смог бы даже
        спросить статус.
        """
        import ntsecuritycon as con
        import win32security

        users = win32security.ConvertStringSidToSid("S-1-5-11")     # Authenticated Users
        admins = win32security.ConvertStringSidToSid("S-1-5-32-544")
        system = win32security.ConvertStringSidToSid("S-1-5-18")

        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                 con.FILE_ALL_ACCESS, system)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                 con.FILE_ALL_ACCESS, admins)
        # Прошедшие проверку подлинности — только обмен сообщениями, без права
        # менять сам канал. Everyone (куда входят анонимные) не даём ничего.
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE, users)

        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)

        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        sa.bInheritHandle = 0
        return sa


def _client_is_admin():
    """Состоит ли олицетворяемый сейчас клиент в администраторах."""
    import win32api
    import win32security

    admins = win32security.ConvertStringSidToSid("S-1-5-32-544")
    token = win32security.OpenThreadToken(
        win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True)
    for sid, attrs in win32security.GetTokenInformation(
            token, win32security.TokenGroups):
        if sid == admins and attrs & win32security.SE_GROUP_ENABLED:
            return True
    return False


# ---------------------------------------------------------------- клиент

class NotRunning(RuntimeError):
    """Службы нет или она не отвечает."""


def call(op, **payload):
    """Шлёт команду службе и возвращает её ответ.

    Вызов блокирующий и таймаута не имеет — это осознанно: `start` честно
    работает до тридцати секунд, и обрывать его по таймеру значило бы бросить
    туннель на полпути, с уже расставленными маршрутами.
    """
    import pywintypes
    import win32file
    import win32pipe

    req = json.dumps({"op": op, "payload": payload},
                     ensure_ascii=False).encode("utf-8")
    handle = None
    try:
        # Все экземпляры канала заняты другими клиентами — редко, но бывает,
        # если трей опрашивает статус ровно в момент, когда открылось окно.
        # WaitNamedPipe ждёт освобождения; на 20 попыток по 200мс — секунды
        # четыре суммарно, дальше уже не «занято», а действительно не отвечает.
        for _ in range(20):
            try:
                handle = win32file.CreateFile(
                    paths.PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING, 0, None)
                break
            except pywintypes.error as exc:
                if exc.winerror != 231:          # не ERROR_PIPE_BUSY — сразу наружу
                    raise
                win32pipe.WaitNamedPipe(paths.PIPE_NAME, 200)
        if handle is None:
            raise NotRunning(
                f"служба {paths.SERVICE_NAME} не отвечает: канал занят")

        win32file.WriteFile(handle, req)
        _, data = win32file.ReadFile(handle, _BUF)
    except pywintypes.error as exc:
        raise NotRunning(
            f"служба {paths.SERVICE_NAME} не отвечает: {exc.strerror}") from exc
    finally:
        if handle is not None:
            win32file.CloseHandle(handle)

    try:
        return json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise NotRunning("служба ответила неразборчиво") from exc
