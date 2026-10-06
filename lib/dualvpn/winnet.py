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
брандмауэра — через COM. PowerShell остался только запасным путём, если WMI
или COM вдруг не ответят.
"""

import ctypes
import json
import os
import random
import re
import socket
import struct
import subprocess
import threading

_PS_ARGS = [
    "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
    "-ExecutionPolicy", "Bypass", "-Command",
]

# CREATE_NO_WINDOW: под службой окна и так нет, но при запуске из трея
# без этого флага на каждый вызов моргала бы консоль.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Последняя причина, по которой запрос не удался. Наружу ошибки не летят
# (см. PowerShell.run), но для диагностики знать её надо.
last_error = ""


class PowerShell:
    """Запускает PowerShell — по процессу на запрос.

    Потокобезопасен без замков: у каждого вызова свой процесс, общего
    состояния между вызовами нет.

    Долгоживущий хост (`powershell.exe -Command -`, команды в stdin) здесь
    пробовали: в этом режиме PowerShell читает stdin до конца потока и только
    потом что-то выполняет, так что ответа не было вовсе.
    """

    def run(self, script, timeout=30):
        """Выполняет script, возвращает stdout. Наружу ошибок не отдаёт.

        Почти все вызовы здесь — «сними маршрут, если он есть», и отсутствие
        объекта это норма, а не сбой. Пустая строка значит и «ничего не
        нашлось», и «спросить не удалось»; кто хочет знать наверняка, смотрит
        на состояние системы после.

        Исключений отсюда не бывает намеренно: уборка маршрутов обязана
        доходить до конца даже тогда, когда всё вокруг уже сломано, — а
        именно в таком состоянии её обычно и зовут.
        """
        global last_error
        # Первая же ошибка не должна прекращать скрипт: «нет такого маршрута»
        # здесь ожидаемый ответ, а не повод бросать остальное.
        #
        # OutputEncoding: читаем вывод как UTF-8, а PowerShell в канал пишет
        # в кодировке консоли — на русской Windows это cp866, и кириллица
        # (имена адаптеров вроде «Беспроводная сеть») приходила кашей.
        # catch пишет причину в stderr: без этого сбой (как с правилом IPv6)
        # не оставлял следа нигде, и last_error оставался пустым.
        wrapped = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8\n"
                   "$ErrorActionPreference='SilentlyContinue'\n"
                   "try {\n" + script + "\n} catch { [Console]::Error.WriteLine($_) }\n")
        try:
            r = subprocess.run(
                _PS_ARGS + [wrapped],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout, creationflags=_NO_WINDOW,
            )
        except subprocess.TimeoutExpired:
            last_error = f"powershell не ответил за {timeout}с"
            return ""
        except OSError as exc:
            last_error = f"powershell не запустился: {exc}"
            return ""
        out = (r.stdout or "").strip()
        if (r.stderr or "").strip():
            last_error = r.stderr.strip()[:200]
        elif not out and r.returncode != 0:
            last_error = f"код возврата {r.returncode}"
        return out

    def json(self, script, timeout=30, default=None):
        """То же, но результат заворачивается в JSON и разбирается.

        @(...) вокруг выражения обязателен: ConvertTo-Json от одного объекта
        отдаёт объект, а от списка — массив, и без принудительного массива
        разбор ломался бы ровно на «нашёлся ровно один маршрут».
        """
        raw = self.run(
            "@(" + script + ") | ConvertTo-Json -Compress -Depth 4",
            timeout,
        )
        if not raw:
            return [] if default is None else default
        try:
            data = json.loads(raw)
        except ValueError:
            return [] if default is None else default
        return data if isinstance(data, list) else [data]

    def close(self):
        """Ничего не держим — оставлено, чтобы не трогать места вызова."""


PS = PowerShell()


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
    global last_error
    try:
        return list(_wmi().ExecQuery(wql))
    except Exception as exc:                               # noqa: BLE001
        last_error = f"WMI: {exc}"
        _tls.wmi = None
        return None


def _query(wql, props):
    """Строки WQL-запроса как список словарей, или None, если WMI не ответил.

    None, а не пустой список: «ничего не нашлось» и «спросить не удалось» —
    разные ответы, и на втором вызывающий уходит в PowerShell.
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
    """
    rows = _query("SELECT InterfaceIndex,NextHop,RouteMetric FROM MSFT_NetRoute"
                  " WHERE DestinationPrefix='0.0.0.0/0'",
                  ("InterfaceIndex", "NextHop", "RouteMetric"))
    if rows is None:
        rows = PS.json(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
            " Select-Object InterfaceIndex,NextHop,RouteMetric")
    rows = [r for r in rows
            if r.get("NextHop") not in (None, "", "0.0.0.0")
            and not _is_tun_hop(r.get("NextHop"))]
    if not rows:
        return None, ""
    metrics = _interface_metrics()
    best = min(rows, key=lambda r: (r.get("RouteMetric") or 0)
               + metrics.get(r.get("InterfaceIndex"), 0))
    return best.get("InterfaceIndex"), best.get("NextHop", "")


def _interface_metrics():
    rows = _query("SELECT InterfaceIndex,InterfaceMetric FROM MSFT_NetIPInterface"
                  " WHERE AddressFamily=2", ("InterfaceIndex", "InterfaceMetric"))
    return {r["InterfaceIndex"]: r.get("InterfaceMetric") or 0 for r in rows or []}


def tun_index(tun_ip):
    """Индекс нашего tun по его адресу, или None.

    Опознаём именно по адресу, а не по имени адаптера: имя wintun-адаптера
    задаёт sing-box, оно повторяется у других клиентов на том же движке, и
    уборка по имени попадала бы по чужому туннелю.
    """
    rows = _query("SELECT InterfaceIndex FROM MSFT_NetIPAddress"
                  f" WHERE IPAddress={_q(tun_ip)}", ("InterfaceIndex",))
    if rows is None:
        rows = PS.json(
            "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |"
            f" Where-Object {{ $_.IPAddress -eq '{tun_ip}' }} |"
            " Select-Object -First 1 InterfaceIndex")
    return rows[0].get("InterfaceIndex") if rows else None


def interface_exists(if_index):
    """Жив ли ещё интерфейс с таким индексом."""
    rows = _query("SELECT InterfaceIndex FROM MSFT_NetIPInterface"
                  f" WHERE InterfaceIndex={int(if_index)} AND AddressFamily=2",
                  ("InterfaceIndex",))
    if rows is None:
        rows = PS.json(
            f"Get-NetIPInterface -InterfaceIndex {if_index} -AddressFamily IPv4"
            " -ErrorAction SilentlyContinue | Select-Object InterfaceIndex")
    return bool(rows)


def routes_for(prefix):
    """Все строки таблицы на этот destination: [{InterfaceIndex, NextHop}].

    Их бывает несколько — по одной на интерфейс, и как раз этим отличается
    «наш маршрут» от «такой же маршрут соседнего VPN-клиента».
    """
    rows = _query("SELECT InterfaceIndex,NextHop,RouteMetric FROM MSFT_NetRoute"
                  f" WHERE DestinationPrefix={_q(prefix)}",
                  ("InterfaceIndex", "NextHop", "RouteMetric"))
    if rows is None:
        rows = PS.json(
            f"Get-NetRoute -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue |"
            " Select-Object InterfaceIndex,NextHop,RouteMetric")
    return rows


def add_route(prefix, if_index, next_hop="0.0.0.0", metric=1):
    add_routes([(prefix, if_index, next_hop, metric)])


def add_routes(routes):
    """Ставит маршруты: routes — [(prefix, if_index, next_hop, metric)].

    Через MSFT_NetRoute.Create — это и есть New-NetRoute, только без запуска
    PowerShell: тот вместе с загрузкой модуля NetTCPIP стоил 2–9 секунд на
    каждый вызов, а включение делает два (видно по service.log). Что WMI
    поставить не смог, уходит одной пачкой в командлет, как раньше.
    """
    global last_error
    if not routes:
        return
    try:
        cls = _wmi().Get("MSFT_NetRoute")
    except Exception as exc:                               # noqa: BLE001
        last_error = f"WMI: {exc}"
        _tls.wmi = None
        cls = None
    if cls is not None:
        routes = [r for r in routes if not _create_route(cls, *r)]
    if not routes:
        return
    PS.run("\n".join(
        f"New-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {int(idx)}"
        f" -NextHop '{hop}' -RouteMetric {int(metric)}"
        " -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue"
        " | Out-Null"
        for prefix, idx, hop, metric in routes))


def _create_route(cls, prefix, if_index, next_hop, metric):
    """Один маршрут через WMI. True — маршрут на этом интерфейсе стоит.

    «Такой уже есть» WMI отдаёт ошибкой, а New-NetRoute с SilentlyContinue её
    глотал: для нас это успех, поэтому после сбоя смотрим в таблицу, а не
    отправляем маршрут в PowerShell зря.
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
    только без запуска PowerShell. Не вышло — тем же командлетом.
    """
    wql = f"SELECT * FROM MSFT_NetRoute WHERE DestinationPrefix={_q(prefix)}"
    if if_index is not None:
        wql += f" AND InterfaceIndex={int(if_index)}"
    rows = _instances(wql)
    if rows is not None:
        try:
            for r in rows:
                r.Delete_()
            return
        except Exception as exc:                           # noqa: BLE001
            global last_error
            last_error = f"WMI: {exc}"
    scope = f" -InterfaceIndex {if_index}" if if_index is not None else ""
    PS.run(
        f"Remove-NetRoute -DestinationPrefix '{prefix}'{scope}"
        " -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue"
    )


def routes_on_interface(if_index):
    """Все IPv4-маршруты, висящие на интерфейсе. Для финальной уборки."""
    rows = _query("SELECT DestinationPrefix FROM MSFT_NetRoute"
                  f" WHERE InterfaceIndex={int(if_index)} AND AddressFamily=2",
                  ("DestinationPrefix",))
    if rows is None:
        rows = PS.json(
            f"Get-NetRoute -InterfaceIndex {if_index} -AddressFamily IPv4"
            " -ErrorAction SilentlyContinue | Select-Object DestinationPrefix")
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
        if ctypes.windll.dnsapi.DnsFlushResolverCache():
            return
    except Exception:                                      # noqa: BLE001
        pass
    PS.run("Clear-DnsClientCache -ErrorAction SilentlyContinue")


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

    Имя уходит в командную строку PowerShell, поэтому всё, что не похоже
    на домен, отбрасываем: домены приходят из site.env, который правит
    пользователь, и кавычка в нём не должна дойти до интерпретатора.
    """
    out = []
    for d in domains:
        d = str(d).strip().strip(".").lower()
        if d and _DOMAIN_RE.match(d) and f".{d}" not in out:
            out.append(f".{d}")
    return out


def nrpt_set(domains, server):
    """Ставит правило «домены → DNS туннеля». Идемпотентно, True — если встало."""
    nrpt_clear()
    names = nrpt_namespaces(domains)
    if not names or not re.match(r"^[\d.]+$", str(server)):
        return False
    quoted = ",".join(f"'{n}'" for n in names)
    out = PS.run(
        "$ErrorActionPreference='Stop'\n"
        f"Add-DnsClientNrptRule -Namespace {quoted} -NameServers '{server}'"
        f" -Comment '{NRPT_COMMENT}' | Out-Null\n"
        "'ok'"
    )
    return out.endswith("ok")


def nrpt_clear():
    """Снимает наши правила — по комментарию, чужие NRPT не трогаем."""
    PS.run(
        "Get-DnsClientNrptRule -ErrorAction SilentlyContinue"
        f" | Where-Object {{ $_.Comment -eq '{NRPT_COMMENT}' }}"
        " | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue"
    )


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
# глотал PS.run — IPv6 всё это время шёл мимо туннеля.
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
    # Запасной путь — тем же правилом через командлет.
    out = PS.run(
        "$ErrorActionPreference='Stop'\n"
        f"New-NetFirewallRule -DisplayName '{V6_RULE}'"
        f" -Direction Outbound -Action Block -RemoteAddress '{V6_GLOBAL}'"
        + (f" -InterfaceAlias '{alias}'" if alias else "") +
        " -Profile Any | Out-Null\n"
        "'ok'"
    )
    if out.endswith("ok"):
        return True
    last_error = last_error or "New-NetFirewallRule не создал правило"
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
    except Exception:                                      # noqa: BLE001
        pass
    PS.run(
        f"Remove-NetFirewallRule -DisplayName '{V6_RULE}'"
        " -ErrorAction SilentlyContinue"
    )


def _has_rule(fw):
    try:
        fw.Rules.Item(V6_RULE)
        return True
    except Exception:                                      # noqa: BLE001
        return False


def v6_blocked():
    try:
        return _has_rule(_firewall())
    except Exception:                                      # noqa: BLE001
        return bool(PS.json(
            f"Get-NetFirewallRule -DisplayName '{V6_RULE}' -ErrorAction SilentlyContinue"
            " | Select-Object DisplayName"))


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
    except Exception:                                      # noqa: BLE001
        return _pids_of_ps(target)
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


def _pids_of_ps(target):
    rows = PS.json(
        "Get-Process -Name sing-box -ErrorAction SilentlyContinue |"
        " Select-Object Id,Path"
    )
    out = []
    for r in rows:
        p = r.get("Path") or ""
        if p and os.path.normcase(os.path.abspath(p)) == target:
            out.append(int(r["Id"]))
    return out
