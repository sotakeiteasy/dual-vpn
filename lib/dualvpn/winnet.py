"""Сеть Windows: маршруты, интерфейсы, IPv6, кеш DNS.

Всё идёт через командлеты NetTCPIP (`Get-NetRoute`, `New-NetRoute`, ...), а не
через `route.exe` и `netsh`. Причина одна: вывод командлетов структурирован и
не зависит от языка системы, а `route print` на русской Windows печатает
«Сетевой адрес» и разбирается только угадыванием колонок.

Платить за это запуском PowerShell на каждый вызов нельзя: пробер опрашивает
состояние раз в две секунды, а холодный старт powershell.exe — почти секунда.
Поэтому процесс поднимается один раз и живёт, пока живёт служба, а команды
отправляются ему в stdin и разделяются маркером.
"""

import json
import os
import subprocess
import threading
import uuid

# Маркер конца ответа. Случайный на каждый запуск, чтобы его нельзя было
# подделать выводом самой команды.
_MARK = f"<<<dualvpn-{uuid.uuid4().hex}>>>"

_PS_ARGS = [
    "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
    "-ExecutionPolicy", "Bypass", "-Command", "-",
]

# CREATE_NO_WINDOW: под службой окна и так нет, но при запуске из трея
# без этого флага на каждый вызов моргала бы консоль.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class PowerShellError(RuntimeError):
    pass


class PowerShell:
    """Долгоживущий powershell, которому команды шлют по одной.

    Не потокобезопасен сам по себе — доступ сериализуется замком: пробер и
    обработчик команд службы ходят сюда из разных потоков.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None

    def _spawn(self):
        self._proc = subprocess.Popen(
            _PS_ARGS,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            bufsize=1, creationflags=_NO_WINDOW,
        )

    def _alive(self):
        return self._proc is not None and self._proc.poll() is None

    def run(self, script, timeout=20):
        """Выполняет script, возвращает его вывод одной строкой.

        Ошибки PowerShell не всплывают исключением: почти все вызовы здесь —
        «сними маршрут, если он есть», и отсутствие объекта это норма, а не
        сбой. Кто хочет знать результат, проверяет таблицу маршрутов после.
        """
        with self._lock:
            if not self._alive():
                self._spawn()
            try:
                return self._exchange(script, timeout)
            except (OSError, PowerShellError):
                # Процесс мог умереть между проверкой и записью — например,
                # система убила его при выходе из сеанса. Один раз поднимаем
                # заново: если и вторая попытка не прошла, это уже не икота.
                self._kill()
                self._spawn()
                return self._exchange(script, timeout)

    def _exchange(self, script, timeout):
        # $ErrorActionPreference='Continue' — иначе первая же ошибка в скрипте
        # уронила бы весь хост, и следующая команда ушла бы в мёртвый stdin.
        wrapped = (
            "$ErrorActionPreference='Continue'\n"
            "try {\n" + script + "\n} catch { }\n"
            f"Write-Output '{_MARK}'\n"
        )
        self._proc.stdin.write(wrapped)
        self._proc.stdin.flush()

        out = []
        done = threading.Event()

        def read():
            try:
                for line in self._proc.stdout:
                    if line.rstrip("\r\n") == _MARK:
                        break
                    out.append(line.rstrip("\r\n"))
            finally:
                done.set()

        t = threading.Thread(target=read, daemon=True)
        t.start()
        if not done.wait(timeout):
            # Читающий поток остался висеть на stdout — процесс уже не наш,
            # доверять его буферу нельзя. Убиваем, следующий вызов поднимет.
            self._kill()
            raise PowerShellError(f"powershell не ответил за {timeout}с")
        return "\n".join(out).strip()

    def json(self, script, timeout=20, default=None):
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

    def _kill(self):
        if self._proc is not None:
            try:
                self._proc.kill()
            except OSError:
                pass
            self._proc = None

    def close(self):
        with self._lock:
            self._kill()


# Один хост на процесс. Служба и трей — разные процессы, у каждого свой.
PS = PowerShell()


# ------------------------------------------------------------- маршруты

def default_route():
    """(индекс интерфейса, шлюз) активного аплинка, или (None, '').

    Берём маршрут по умолчанию с настоящим следующим узлом: у tun-интерфейса
    NextHop нулевой, и без этого условия после подъёма туннеля «аплинком»
    оказывался бы сам туннель.
    """
    rows = PS.json(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
        " Where-Object { $_.NextHop -ne '0.0.0.0' } |"
        " Sort-Object RouteMetric |"
        " Select-Object -First 1 InterfaceIndex,NextHop"
    )
    if not rows:
        return None, ""
    return rows[0].get("InterfaceIndex"), rows[0].get("NextHop", "")


def tun_index(tun_ip):
    """Индекс нашего tun по его адресу, или None.

    Опознаём именно по адресу, а не по имени адаптера: имя wintun-адаптера
    задаёт sing-box, оно повторяется у других клиентов на том же движке, и
    уборка по имени попадала бы по чужому туннелю.
    """
    rows = PS.json(
        "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |"
        f" Where-Object {{ $_.IPAddress -eq '{tun_ip}' }} |"
        " Select-Object -First 1 InterfaceIndex"
    )
    return rows[0].get("InterfaceIndex") if rows else None


def interface_exists(if_index):
    """Жив ли ещё интерфейс с таким индексом."""
    return bool(PS.json(
        f"Get-NetIPInterface -InterfaceIndex {if_index} -AddressFamily IPv4"
        " -ErrorAction SilentlyContinue | Select-Object InterfaceIndex"
    ))


def routes_for(prefix):
    """Все строки таблицы на этот destination: [{InterfaceIndex, NextHop}].

    Их бывает несколько — по одной на интерфейс, и как раз этим отличается
    «наш маршрут» от «такой же маршрут соседнего VPN-клиента».
    """
    return PS.json(
        f"Get-NetRoute -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue |"
        " Select-Object InterfaceIndex,NextHop,RouteMetric"
    )


def add_route(prefix, if_index, next_hop="0.0.0.0", metric=1):
    PS.run(
        f"New-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {if_index}"
        f" -NextHop '{next_hop}' -RouteMetric {metric}"
        " -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue"
        " | Out-Null"
    )


def del_route(prefix, if_index=None):
    """Снимает маршрут. С указанным интерфейсом — только его строку.

    Без if_index удаление снимает все строки на этот destination, включая
    чужие. Вызывающий обязан сначала убедиться, что чужих там нет — этим
    занимается tunnel.py, здесь только механика.
    """
    scope = f" -InterfaceIndex {if_index}" if if_index is not None else ""
    PS.run(
        f"Remove-NetRoute -DestinationPrefix '{prefix}'{scope}"
        " -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue"
    )


def routes_on_interface(if_index):
    """Все IPv4-маршруты, висящие на интерфейсе. Для финальной уборки."""
    rows = PS.json(
        f"Get-NetRoute -InterfaceIndex {if_index} -AddressFamily IPv4"
        " -ErrorAction SilentlyContinue | Select-Object DestinationPrefix"
    )
    return [r.get("DestinationPrefix", "") for r in rows if r.get("DestinationPrefix")]


def resolve4(name):
    """A-запись имени, или ''. Резолвим до подъёма туннеля, пока DNS ещё свой."""
    rows = PS.json(
        f"Resolve-DnsName -Name '{name}' -Type A -ErrorAction SilentlyContinue |"
        " Where-Object { $_.IPAddress } | Select-Object -First 1 IPAddress"
    )
    return rows[0].get("IPAddress", "") if rows else ""


def resolve4_via(name, server):
    """То же, но у конкретного DNS-сервера, в обход системного."""
    rows = PS.json(
        f"Resolve-DnsName -Name '{name}' -Type A -Server '{server}'"
        " -DnsOnly -ErrorAction SilentlyContinue |"
        " Where-Object { $_.IPAddress } | Select-Object -First 1 IPAddress"
    )
    return rows[0].get("IPAddress", "") if rows else ""


# ----------------------------------------------------------------- IPv6
#
# Личный сервер v6-адрес не выдаёт, нести v6 в туннель нечем. Оставить как
# есть — значит гнать v6-трафик мимо туннеля, с настоящего адреса.
#
# На macOS для этого выключали IPv6 на сетевом сервисе. На Windows тот же приём
# (Disable-NetAdapterBinding ms_tcpip6) передёргивает адаптер, рвёт все
# соединения и на некоторых драйверах не возвращается без перезагрузки.
# Правило брандмауэра делает то же самое обратимо и мгновенно: исходящий v6
# блокируется целиком, а снятие правила возвращает всё как было.

V6_RULE = "DualVPN-block-IPv6"


def v6_block():
    """Блокирует исходящий IPv6. Идемпотентно."""
    PS.run(
        f"if (-not (Get-NetFirewallRule -DisplayName '{V6_RULE}'"
        " -ErrorAction SilentlyContinue)) {"
        f" New-NetFirewallRule -DisplayName '{V6_RULE}' -Direction Outbound"
        " -Action Block -RemoteAddress '::/0' -Profile Any"
        " -Description 'Пока поднят туннель DualVPN. Снимается при выключении.'"
        " | Out-Null }"
    )


def v6_unblock():
    PS.run(
        f"Remove-NetFirewallRule -DisplayName '{V6_RULE}'"
        " -ErrorAction SilentlyContinue"
    )


def v6_blocked():
    return bool(PS.json(
        f"Get-NetFirewallRule -DisplayName '{V6_RULE}' -ErrorAction SilentlyContinue"
        " | Select-Object DisplayName"
    ))


# ------------------------------------------------------------------ DNS

def flush_dns():
    """Кеш резолвера: в нём оседают ответы корп-DNS, недоступного без туннеля."""
    PS.run("Clear-DnsClientCache -ErrorAction SilentlyContinue")


# -------------------------------------------------------------- процесс

def pids_of(exe_path):
    """PID'ы процессов, запущенных ровно из этого файла.

    Сравниваем полный путь, а не имя: у пользователя может быть свой sing-box
    из другого клиента, и снимать его мы не имеем права.
    """
    target = os.path.normcase(os.path.abspath(exe_path))
    rows = PS.json(
        "Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\""
        " -ErrorAction SilentlyContinue | Select-Object ProcessId,ExecutablePath"
    )
    out = []
    for r in rows:
        p = r.get("ExecutablePath") or ""
        if p and os.path.normcase(os.path.abspath(p)) == target:
            out.append(int(r["ProcessId"]))
    return out
