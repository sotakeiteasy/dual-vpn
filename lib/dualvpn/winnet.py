"""Сеть Windows: маршруты, интерфейсы, IPv6, кеш DNS.

Чтение состояния идёт через WMI (root/StandardCimv2: MSFT_NetRoute,
MSFT_NetIPAddress, ...) — это ровно те классы, поверх которых построены
командлеты Get-NetRoute и компания. Вывод структурирован и от языка системы не
зависит, как и у командлетов (`route print` на русской Windows печатает
«Сетевой адрес» и разбирается только угадыванием колонок), а запрос стоит
10–20 мс.

Раньше каждое чтение запускало отдельный powershell.exe — 2–4 секунды на
вызов. Пробер делал их по шесть за цикл, включение — несколько десятков:
«Включить» шло полторы минуты, статус отставал на десятки секунд, а машина
постоянно молотила PowerShell в фоне.

Изменения идут тем же путём: маршруты — методами MSFT_NetRoute, правило
NRPT — методами PS_DnsClientNrptRule, правило брандмауэра — через COM.
PowerShell не запускается вовсе: не ответил WMI — пустой ответ и причина
в last_error, а следующий вызов подключается заново.
"""

import ctypes
import os
import random
import re
import socket
import struct
import threading

# Последняя причина, по которой запрос не удался. Наружу ошибки не летят:
# уборка обязана доходить до конца даже тогда, когда всё вокруг уже сломано,
# но для диагностики причину знать надо.
last_error = ""

# Куда сообщать об отказах WMI и COM: служба подставляет свой журнал.
# Запасного пути нет, и по журналу должно быть видно, бывают ли отказы вообще.
on_error = None
_reported = ""


def _fail(msg):
    """Запоминает причину сбоя и сообщает о ней; подряд одну и ту же — один раз:
    проверки идут каждым кругом пробера, и журнал иначе забился бы повтором."""
    global last_error, _reported
    last_error = msg
    if on_error is None or msg == _reported:
        return
    _reported = msg
    try:
        on_error(msg)
    except Exception:                                      # noqa: BLE001
        pass


# ------------------------------------------------------------------- WMI

_tls = threading.local()


def _wmi():
    """Подключение к root/StandardCimv2, своё на каждый поток.

    COM требует инициализации в каждом потоке, а у службы их много: пробер,
    поток на каждое соединение канала, медленные проверки.
    """
    svc = getattr(_tls, "wmi", None)
    if svc is None:
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        # Прямой слэш вместо обратных: моникер одинаково понимает оба, а
        # прямой не зависит от того, как по дороге экранировали строку.
        svc = win32com.client.GetObject("winmgmts:root/StandardCimv2")
        _tls.wmi = svc
    return svc


def _instances(wql):
    """Объекты WQL-запроса списком, или None, если WMI не ответил."""
    try:
        return list(_wmi().ExecQuery(wql))
    except Exception as exc:                               # noqa: BLE001
        _fail(f"WMI: {exc}")
        _tls.wmi = None
        return None


def _query(wql, props):
    """Строки WQL-запроса как список словарей, или None, если WMI не ответил.

    None, а не пустой список: «ничего не нашлось» и «спросить не удалось» —
    разные ответы, и _create_route на втором не верит таблице.
    """
    rows = _instances(wql)
    if rows is None:
        return None
    try:
        return [{p: getattr(r, p) for p in props} for r in rows]
    except Exception:                                      # noqa: BLE001
        return None


def _q(value):
    """Строка для WQL в одинарных кавычках. Наши значения — адреса и имена
    без кавычек, но экранируем на всякий случай."""
    return "'" + str(value).replace("'", "") + "'"


def _is_tun_hop(next_hop):
    """Шлюз нашего же tun (172.19.0.2 из 172.19.0.1/30). sing-box ставит
    через него свой маршрут по умолчанию, и аплинком он быть не может."""
    return str(next_hop or "").startswith("172.19.0.")


# ------------------------------------------------------------- маршруты

def default_route():
    """(индекс интерфейса, шлюз) активного аплинка, или (None, '').

    Берём маршрут по умолчанию с настоящим следующим узлом: у туннелей
    NextHop нулевой или это шлюз нашего tun, и без этого условия после
    подъёма туннеля «аплинком» оказывался бы сам туннель. Из нескольких
    аплинков (Wi-Fi и кабель) — тот, у кого меньше сумма метрик маршрута и
    интерфейса: так выбирает и сама Windows.

    Только подключённые интерфейсы: у выдернутого кабеля или отвалившегося
    Wi-Fi маршрут по умолчанию остаётся в таблице, и кабель с метрикой
    поменьше выигрывал у живого Wi-Fi — сторож не видел смены сети.
    """
    rows = _query("SELECT InterfaceIndex,NextHop,RouteMetric FROM MSFT_NetRoute"
                  " WHERE DestinationPrefix='0.0.0.0/0'",
                  ("InterfaceIndex", "NextHop", "RouteMetric")) or []
    rows = [r for r in rows
            if r.get("NextHop") not in (None, "", "0.0.0.0")
            and not _is_tun_hop(r.get("NextHop"))]
    metrics = _interface_metrics()
    if metrics is not None:
        rows = [r for r in rows if r.get("InterfaceIndex") in metrics]
    if not rows:
        return None, ""
    metrics = metrics or {}
    best = min(rows, key=lambda r: (r.get("RouteMetric") or 0)
               + metrics.get(r.get("InterfaceIndex"), 0))
    return best.get("InterfaceIndex"), best.get("NextHop", "")


def _interface_metrics():
    """{индекс: метрика} подключённых IPv4-интерфейсов, или None, если WMI
    не ответил: тогда аплинк выбираем, как прежде, среди всех."""
    rows = _query("SELECT InterfaceIndex,InterfaceMetric FROM MSFT_NetIPInterface"
                  " WHERE AddressFamily=2 AND ConnectionState=1",
                  ("InterfaceIndex", "InterfaceMetric"))
    if rows is None:
        return None
    return {r["InterfaceIndex"]: r.get("InterfaceMetric") or 0 for r in rows}


def tun_index(tun_ip):
    """Индекс нашего tun по его адресу, или None.

    Опознаём именно по адресу, а не по имени адаптера: имя wintun-адаптера
    задаёт sing-box, оно повторяется у других клиентов на том же движке, и
    уборка по имени попадала бы по чужому туннелю.
    """
    rows = _query("SELECT InterfaceIndex FROM MSFT_NetIPAddress"
                  f" WHERE IPAddress={_q(tun_ip)}", ("InterfaceIndex",))
    return rows[0].get("InterfaceIndex") if rows else None


def interface_exists(if_index):
    """Жив ли ещё интерфейс с таким индексом."""
    rows = _query("SELECT InterfaceIndex FROM MSFT_NetIPInterface"
                  f" WHERE InterfaceIndex={int(if_index)} AND AddressFamily=2",
                  ("InterfaceIndex",))
    return bool(rows)


def routes_for(prefix):
    """Все строки таблицы на этот destination: [{InterfaceIndex, NextHop}].

    Их бывает несколько — по одной на интерфейс, и как раз этим отличается
    «наш маршрут» от «такой же маршрут соседнего VPN-клиента».
    """
    rows = _query("SELECT InterfaceIndex,NextHop,RouteMetric FROM MSFT_NetRoute"
                  f" WHERE DestinationPrefix={_q(prefix)}",
                  ("InterfaceIndex", "NextHop", "RouteMetric"))
    return rows or []


def add_route(prefix, if_index, next_hop="0.0.0.0", metric=1):
    add_routes([(prefix, if_index, next_hop, metric)])


def add_routes(routes):
    """Ставит маршруты: routes — [(prefix, if_index, next_hop, metric)].

    Через MSFT_NetRoute.Create — это и есть New-NetRoute, только без запуска
    PowerShell: тот вместе с загрузкой модуля NetTCPIP стоил 2–9 секунд на
    каждый вызов, а включение делает два (видно по service.log). Что WMI
    поставить не смог, пробуем ещё раз через новое подключение; не встало и
    тогда — в last_error, а пропавший маршрут к пиру сторож поставит заново.
    """
    global last_error
    for _ in range(2):
        if not routes:
            return
        try:
            cls = _wmi().Get("MSFT_NetRoute")
        except Exception as exc:                           # noqa: BLE001
            last_error = f"WMI: {exc}"
            _tls.wmi = None
            continue
        routes = [r for r in routes if not _create_route(cls, *r)]
        if routes:
            _tls.wmi = None                 # второй заход — с новым подключением
    if routes:
        _fail(f"WMI: не встали маршруты {', '.join(r[0] for r in routes)}: "
              f"{last_error}")


def _create_route(cls, prefix, if_index, next_hop, metric):
    """Один маршрут через WMI. True — маршрут на этом интерфейсе стоит.

    «Такой уже есть» WMI отдаёт ошибкой, а для нас это успех: поэтому после
    сбоя смотрим в таблицу, а не ставим маршрут ещё раз зря.
    """
    global last_error
    try:
        params = cls.Methods_("Create").InParameters.SpawnInstance_()
        params.Properties_("DestinationPrefix").Value = prefix
        params.Properties_("InterfaceIndex").Value = int(if_index)
        params.Properties_("NextHop").Value = next_hop
        params.Properties_("RouteMetric").Value = int(metric)
        params.Properties_("PolicyStore").Value = "ActiveStore"
        # Этот провайдер при успехе отдаёт ReturnValue None, а сбой — исключением
        # (проверено на Windows 11); 0 — на случай провайдера по канону WMI.
        if cls.ExecMethod_("Create", params).ReturnValue in (0, None):
            return True
        last_error = f"WMI: маршрут {prefix} не создан"
    except Exception as exc:                               # noqa: BLE001
        last_error = f"WMI: {exc}"
    return any(r.get("InterfaceIndex") == int(if_index)
               for r in routes_for(prefix) or [])


def del_route(prefix, if_index=None):
    """Снимает маршрут. С указанным интерфейсом — только его строку.

    Без if_index удаление снимает все строки на этот destination, включая
    чужие. Вызывающий обязан сначала убедиться, что чужих там нет — этим
    занимается tunnel.py, здесь только механика.

    Удаляем экземпляр MSFT_NetRoute напрямую — это и есть Remove-NetRoute,
    только без запуска PowerShell. Успех вызывающий проверяет по таблице.
    """
    wql = f"SELECT * FROM MSFT_NetRoute WHERE DestinationPrefix={_q(prefix)}"
    if if_index is not None:
        wql += f" AND InterfaceIndex={int(if_index)}"
    try:
        for r in _instances(wql) or []:
            r.Delete_()
    except Exception as exc:                               # noqa: BLE001
        _fail(f"WMI: маршрут {prefix} не снят: {exc}")
        _tls.wmi = None


def routes_on_interface(if_index):
    """Все IPv4-маршруты, висящие на интерфейсе. Для финальной уборки."""
    rows = _query("SELECT DestinationPrefix FROM MSFT_NetRoute"
                  f" WHERE InterfaceIndex={int(if_index)} AND AddressFamily=2",
                  ("DestinationPrefix",)) or []
    return [r.get("DestinationPrefix", "") for r in rows if r.get("DestinationPrefix")]


# ------------------------------------------------------------------ DNS

def resolve4(name):
    """A-запись имени, или ''. Резолвим до подъёма туннеля, пока DNS ещё свой."""
    try:
        return socket.getaddrinfo(name, None, socket.AF_INET)[0][4][0]
    except (OSError, IndexError):
        return ""


def resolve4_via(name, server, timeout=4.0):
    """То же, но у конкретного DNS-сервера, в обход системного.

    Свой минимальный DNS-запрос по UDP вместо Resolve-DnsName -Server: тот
    стоил запуска PowerShell, а пробер спрашивает корп-DNS постоянно.
    """
    qid = random.randint(0, 0xFFFF)
    try:
        labels = [p.encode("idna") for p in name.strip(".").split(".")]
    except UnicodeError:
        return ""
    qname = b"".join(bytes([len(p)]) + p for p in labels) + bytes([0])
    packet = (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname
              + struct.pack(">HH", 1, 1))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
    except OSError:
        return ""
    return _first_a(data, qid)


def _first_a(data, qid):
    """Первая A-запись из DNS-ответа, или ''."""
    try:
        rid, flags, qd, an = struct.unpack(">HHHH", data[:8])
        if rid != qid or flags & 0x000F:
            return ""
        pos = 12
        for _ in range(qd):
            pos = _skip_name(data, pos) + 4
        for _ in range(an):
            pos = _skip_name(data, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                return socket.inet_ntoa(data[pos:pos + 4])
            pos += rdlen
    except (struct.error, IndexError, OSError):
        pass
    return ""


def _skip_name(data, pos):
    while True:
        n = data[pos]
        if n == 0:
            return pos + 1
        if n & 0xC0 == 0xC0:          # ссылка на имя выше — два байта
            return pos + 2
        pos += n + 1


def flush_dns():
    """Кеш резолвера: в нём оседают ответы корп-DNS, недоступного без туннеля."""
    try:
        if not ctypes.windll.dnsapi.DnsFlushResolverCache():
            _fail("DnsFlushResolverCache не сбросил кеш")
    except Exception as exc:                               # noqa: BLE001
        _fail(f"dnsapi: {exc}")


# ------------------------------------------------------------- DNS: NRPT
#
# Windows опрашивает DNS всех адаптеров сразу. Положительный ответ принимает
# первый же, а на NXDOMAIN от туннеля ждёт остальные: DNS роутера на Wi-Fi
# молчит, и несуществующее корп-имя отвечало ровно через 12 с таймаута.
# Правило NRPT говорит: имена этих доменов спрашивать только у DNS туннеля —
# тогда NXDOMAIN окончателен сразу. Правило касается лишь корп-доменов,
# остальные имена идут как раньше.

NRPT_COMMENT = "DualVPN"

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


def nrpt_namespaces(domains):
    """Домены из конфига → суффиксы NRPT вида '.corp.example'.

    Имя уходит в системное правило DNS, поэтому всё, что не похоже на
    домен, отбрасываем: домены приходят из site.env, который правит
    пользователь, и мусор из него не должен дойти до резолвера.
    """
    out = []
    for d in domains:
        d = str(d).strip().strip(".").lower()
        if d and _DOMAIN_RE.match(d) and f".{d}" not in out:
            out.append(f".{d}")
    return out


def _wmi_dns():
    """Подключение к root/Microsoft/Windows/DNS, своё на каждый поток.

    Там живут классы командлетов DnsClient: Add-DnsClientNrptRule — обёртка
    над PS_DnsClientNrptRule.Add, только с запуском PowerShell и загрузкой
    модуля, а это ~1.7 с на вызов против десятков мс напрямую.
    """
    svc = getattr(_tls, "wmi_dns", None)
    if svc is None:
        _wmi()                      # CoInitialize в этом потоке
        import win32com.client
        svc = win32com.client.GetObject("winmgmts:root/Microsoft/Windows/DNS")
        _tls.wmi_dns = svc
    return svc


def _nrpt_call(method, **args):
    """Статический метод PS_DnsClientNrptRule: Get, Add или Remove.

    Для Get — список правил (у каждого .Name и .Comment), для остальных —
    пустой список. None — WMI не ответил или метод вернул ошибку.
    Правила только через Get: перечисление класса запросом их не видит.
    """
    try:
        cls = _wmi_dns().Get("PS_DnsClientNrptRule")
        params = cls.Methods_(method).InParameters.SpawnInstance_()
        for name, value in args.items():
            params.Properties_.Item(name).Value = value
        out = cls.ExecMethod_(method, params)
        # Add и Remove без PassThru выходных параметров не отдают вовсе:
        # None здесь — успех, сбой метода приходит исключением COM. Пустой
        # выход Get по той же причине значит «правил нет».
        if out is not None and out.ReturnValue:
            _fail(f"WMI: PS_DnsClientNrptRule.{method} вернул {out.ReturnValue}")
            return None
        if method != "Get" or out is None:
            return []
        return list(out.Properties_.Item("cmdletOutput").Value or ())
    except Exception as exc:                               # noqa: BLE001
        _fail(f"WMI: PS_DnsClientNrptRule.{method}: {exc}")
        _tls.wmi_dns = None
        return None


def nrpt_set(domains, server):
    """Ставит правило «домены → DNS туннеля». Идемпотентно, True — если встало."""
    names = nrpt_namespaces(domains)
    if not nrpt_clear() or not names or not re.match(r"^[\d.]+$", str(server)):
        return False
    return _nrpt_call("Add", Namespace=names, NameServers=[server],
                      Comment=NRPT_COMMENT) is not None


def nrpt_clear():
    """Снимает наши правила — по комментарию, чужие NRPT не трогаем.

    False — WMI не справился: правило могло остаться.
    """
    rules = _nrpt_call("Get")
    if rules is None:
        return False
    ours = [r.Name for r in rules if r.Comment == NRPT_COMMENT]
    return all([_nrpt_call("Remove", Name=name, Force=True) is not None
                for name in ours])


# ----------------------------------------------------------------- IPv6
#
# Если личный сервер v6 не выдаёт, нести его в туннель нечем, а оставить как
# есть — значит гнать v6-трафик мимо туннеля, с настоящего адреса.
#
# На macOS для этого выключали IPv6 на сетевом сервисе. На Windows тот же приём
# (Disable-NetAdapterBinding ms_tcpip6) передёргивает адаптер, рвёт все
# соединения и на некоторых драйверах не возвращается без перезагрузки.
# Правило брандмауэра делает то же самое обратимо и мгновенно, а снятие
# правила возвращает всё как было.

V6_RULE = "DualVPN-block-IPv6"

# Весь глобальный IPv6. Не '::/0': брандмауэр такую запись не принимает
# («префиксы адресов недопустимы»), правило не создавалось вовсе, а ошибку
# молча глотал запуск PowerShell — IPv6 всё это время шёл мимо туннеля.
V6_GLOBAL = "2000::/3"


def _firewall():
    """Политика брандмауэра через COM (HNetCfg.FwPolicy2).

    Правило ищется по имени за миллисекунды. WMI (MSFT_NetFirewallRule)
    перебирает все правила системы даже при поиске по ключу — около секунды,
    а проверка идёт в каждом цикле пробера.
    """
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()
    return win32com.client.Dispatch("HNetCfg.FwPolicy2")


def _interface_alias(if_index):
    rows = _query("SELECT InterfaceAlias FROM MSFT_NetIPInterface"
                  f" WHERE InterfaceIndex={int(if_index)}", ("InterfaceAlias",))
    return rows[0].get("InterfaceAlias", "") if rows else ""


def v6_block(uplink_index):
    """Блокирует исходящий IPv6 через физический аплинк. Идемпотентно.

    Только на аплинке, а не на всех интерфейсах: если личный сервер выдал
    v6-адрес, IPv6 законно идёт через tun, и общий запрет сломал бы его.
    Возвращает, стоит ли правило после вызова.
    """
    global last_error
    last_error = ""
    if v6_blocked():
        return True
    alias = _interface_alias(uplink_index)
    try:
        import win32com.client
        fw = _firewall()
        rule = win32com.client.Dispatch("HNetCfg.FWRule")
        rule.Name = V6_RULE
        rule.Description = "Пока поднят туннель DualVPN. Снимается при выключении."
        rule.Direction = 2                    # исходящие
        rule.Action = 0                       # запретить
        rule.RemoteAddresses = V6_GLOBAL
        if alias:
            rule.Interfaces = [alias]
        rule.Profiles = 0x7FFFFFFF            # все профили сети
        rule.Enabled = True
        fw.Rules.Add(rule)
    except Exception as exc:                               # noqa: BLE001
        last_error = f"брандмауэр: {exc}"
    if v6_blocked():
        return True
    last_error = last_error or "брандмауэр не создал правило"
    return False


def v6_unblock():
    try:
        fw = _firewall()
        # Remove снимает одно правило с этим именем; дублей могло накопиться
        # несколько, поэтому — пока находится.
        for _ in range(20):
            if not _has_rule(fw):
                return
            fw.Rules.Remove(V6_RULE)
    except Exception as exc:                               # noqa: BLE001
        _fail(f"брандмауэр: правило IPv6 не снято: {exc}")


def _has_rule(fw):
    try:
        fw.Rules.Item(V6_RULE)
        return True
    except Exception:                                      # noqa: BLE001
        return False


def v6_blocked():
    try:
        return _has_rule(_firewall())
    except Exception as exc:                               # noqa: BLE001
        _fail(f"брандмауэр не ответил: {exc}")
        return False


# -------------------------------------------------------------- процесс

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

_k32 = None


def _kernel32():
    """Свой экземпляр kernel32 с прописанными типами: по умолчанию ctypes
    считает результат int, и 64-битный дескриптор процесса мог бы обрезаться.

    Загружается при первом вызове, а не при импорте: тесты гоняются на Linux,
    где ctypes.WinDLL нет, и модуль должен импортироваться и там.
    """
    global _k32
    if _k32 is None:
        k32 = ctypes.WinDLL("kernel32")
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
        k32.QueryFullProcessImageNameW.argtypes = (
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong))
        k32.CloseHandle.argtypes = (ctypes.c_void_p,)
        _k32 = k32
    return _k32


def pids_of(exe_path):
    """PID'ы процессов, запущенных ровно из этого файла.

    Сравниваем полный путь, а не имя: у пользователя может быть свой sing-box
    из другого клиента, и снимать его мы не имеем права.

    Через WinAPI (EnumProcesses + QueryFullProcessImageName): миллисекунды
    вместо запуска PowerShell, а вызов идёт в каждом цикле пробера.
    """
    target = os.path.normcase(os.path.abspath(exe_path))
    try:
        import win32process
        pids = win32process.EnumProcesses()
        k32 = _kernel32()
    except Exception as exc:                               # noqa: BLE001
        _fail(f"WinAPI: список процессов недоступен: {exc}")
        return []
    out = []
    for pid in pids:
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            continue
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_ulong(len(buf))
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                if os.path.normcase(buf.value) == target:
                    out.append(int(pid))
        finally:
            k32.CloseHandle(h)
    return out
