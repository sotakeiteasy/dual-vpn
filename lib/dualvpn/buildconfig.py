#!/usr/bin/env python3
"""
Собирает config.json для sing-box-lx из обычных WireGuard/AmneziaWG .conf файлов.

    conf/personal/<имя>.conf   личный AmneziaWG  -> весь остальной трафик
    conf/corp/<имя>.conf       корпоративный WG  -> подсети из его AllowedIPs

Рабочий ровно один. Личных сколько угодно, нужный выбирает профиль:
    set SB_PERSONAL=nl-1 && python -m dualvpn.buildconfig
    python -m dualvpn.buildconfig --personal nl-1
Без профиля берётся единственный личный.

Корп-маршруты берутся ИЗ AllowedIPs корп-конфига, поэтому при ротации
достаточно положить новый файл — правки скрипта не нужны.

Зовётся службой при каждом включении, отдельно запускать не нужно.
"""

import ipaddress
import json
import socket
import os
import re
import sys

# Раскладку знает paths.py — здесь только имена.
from . import paths, winnet

BASE = paths.BASE
CONF = paths.CONF
CONF_CORP = paths.CONF_CORP
CONF_PERSONAL = paths.CONF_PERSONAL
STATE = paths.STATE
KINDS = ("corp", "personal")

# Поля [Interface], которые sing-box ждёт как AWG-параметры (в нижнем регистре).
AWG_INT = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")
AWG_HDR = ("h1", "h2", "h3", "h4")
AWG_CPS = ("i1", "i2", "i3", "i4", "i5")
# AWG 3.x: ключ шифрования заголовков, паддинг и тайминги-диапазоны "min-max".
# В .conf — CamelCase без разделителей, в sing-box — snake_case.
AWG3_STR = {"headerprotectionkey": "header_protection_key"}
AWG3_RANGE = {
    "contentpaddingaddition": "content_padding_addition",
    "rekeyaftertime": "rekey_after_time",
    "rekeytimeout": "rekey_timeout",
    "rejectaftertime": "reject_after_time",
    "keepalivetimeout": "keepalive_timeout",
    "maxhandshakeattempts": "max_handshake_attempts",
}
AWG3_BOOL = {"randomtrailers": "random_trailers",
             "disablecookies": "disable_cookies"}

# Потолок MTU для AWG с junk-параметрами: S1–S4 удлиняют пакеты, и с MTU
# из файла (часто 1420) они не пролезают в мобильных сетях и вложенных
# туннелях. Файл пользователя не меняем — режем только при сборке.
AWG_JUNK = ("jc", "s1", "s2", "s3", "s4")
AWG_MTU_MAX = 1280


# Раньше тип туннеля решало имя файла в плоском conf\. Эти шаблоны остались
# только для переезда старых установок в conf\corp и conf\personal.
_LEGACY_CORP_PAT = (r"^corp\.conf$", r"^wg[-_0-9].*\.conf$", r"^wg\.conf$")
_LEGACY_PERSONAL_PAT = (r"^personal\.conf$", r"^(awg|amnezia).*\.conf$")

# Имя конфига — это имя файла. В Windows в нём запрещены эти знаки и
# управляющие символы, а CON, NUL, COM1… — имена устройств: файл nul.conf
# не создать вовсе. Длину режем, чтобы путь в ProgramData не упёрся в MAX_PATH.
_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL",
             *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
NAME_MAX = 80


def conf_dir(kind):
    if kind not in KINDS:
        raise ValueError(f"неизвестный тип конфига: {kind!r}")
    return CONF_CORP if kind == "corp" else CONF_PERSONAL


def safe_name(name):
    """Имя, под которым конфиг ляжет в conf\\<тип>\\, из имени файла человека.

    Не отказывает никогда: недопустимые знаки становятся «_», пустое имя —
    «config». Так добавление не ломается из-за имени, как у wg-quick, где
    неподходящее имя файла — это ошибка.
    """
    stem = (name or "").strip()
    if stem.lower().endswith(".conf"):
        stem = stem[:-5]
    stem = _BAD_CHARS.sub("_", stem)
    # Точка и пробел в конце Windows молча отрезает: «nl.» и «nl» стали бы
    # одним файлом, а ссылка в профиле — на несуществующий.
    stem = stem[:NAME_MAX].strip(" .")
    if stem.split(".")[0].upper() in _RESERVED:
        stem = f"_{stem}"
    return stem or "config"


def check_name(name):
    """Имя, пришедшее через канал, должно быть уже безопасным — то, что мы
    сами отдали в списке. Иначе «..\\..\\Windows» стал бы записью с правами
    системы."""
    if not name or safe_name(name) != name:
        raise ValueError(f"недопустимое имя конфига: {name!r}")
    return name


def list_confs(kind):
    """Имена конфигов этого типа, без .conf."""
    try:
        return sorted(f[:-5] for f in os.listdir(conf_dir(kind))
                      if f.lower().endswith(".conf"))
    except OSError:
        return []


def conf_path(kind, name):
    return os.path.join(conf_dir(kind), f"{check_name(name)}.conf")


def migrate_flat():
    """Переносит конфиги из плоского conf\\ (до 0.3) по папкам типов.

    Тип берём по старым правилам имени — ровно так, как их понимала прежняя
    сборка, — поэтому после обновления включается то же, что и до него.
    Возвращает [(имя, тип)] перенесённых.
    """
    moved = []
    try:
        files = sorted(os.listdir(CONF))
    except OSError:
        return moved
    for f in files:
        src = os.path.join(CONF, f)
        if not f.lower().endswith(".conf") or not os.path.isfile(src):
            continue
        kind = ("corp" if any(re.match(p, f, re.IGNORECASE)
                              for p in _LEGACY_CORP_PAT) else "personal")
        name = safe_name(f)
        os.makedirs(conf_dir(kind), exist_ok=True)
        os.replace(src, os.path.join(conf_dir(kind), f"{name}.conf"))
        moved.append((name, kind))
    return moved


def legacy_default_personal(names):
    """Какой личный сборка брала без профиля до 0.3: personal.conf, потом awg*."""
    for pat in _LEGACY_PERSONAL_PAT:
        found = [n for n in names if re.match(pat, f"{n}.conf", re.IGNORECASE)]
        if found:
            return found[0]
    return ""


def check_conf_text(text):
    """Похож ли текст на конфиг WireGuard. None — да, иначе причина отказа.

    Ловит случайно выбранный не тот файл (site.env, пустой) до того, как он
    ляжет в conf\\ вместо ключей.
    """
    sections = {line.strip().lower() for line in (text or "").splitlines()}
    if "[interface]" not in sections or "[peer]" not in sections:
        return "это не конфиг WireGuard: нет секции [Interface] или [Peer]"
    return None


def pick_corp():
    """Единственный рабочий конфиг."""
    have = list_confs("corp")
    if not have:
        sys.exit("рабочий конфиг не добавлен")
    if len(have) > 1:
        sys.exit(f"рабочих конфигов несколько: {', '.join(have)}\n"
                 f"оставь в {CONF_CORP} только один")
    return conf_path("corp", have[0])


def pick_personal():
    """Личный по профилю (SB_PERSONAL=nl-1 или --personal nl-1), а без
    профиля — единственный."""
    name = os.environ.get("SB_PERSONAL", "")
    if "--personal" in sys.argv:
        name = sys.argv[sys.argv.index("--personal") + 1]
    name = name.strip()
    have = list_confs("personal")
    if name:
        if name not in have:
            sys.exit(f"нет личного конфига «{name}»\n"
                     f"есть: {', '.join(have) if have else '(пусто)'}")
        return conf_path("personal", name)
    if not have:
        sys.exit("личный конфиг не добавлен")
    if len(have) > 1:
        sys.exit(f"личных конфигов несколько: {', '.join(have)} — выбери один")
    return conf_path("personal", have[0])


def parse_conf(path):
    """Разбирает wg-quick/awg-quick файл в {'interface': {...}, 'peer': {...}}."""
    out = {"interface": {}, "peer": {}}
    section = None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("["):
                section = line.strip("[]").strip().lower()
                continue
            if "=" not in line or section not in ("interface", "peer"):
                continue
            key, val = line.split("=", 1)
            out[section][key.strip().lower()] = val.strip()
    if not out["interface"] or not out["peer"]:
        sys.exit(f"{path}: не хватает секции [Interface] или [Peer]")
    return out


def _is_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def split_list(value):
    return [x.strip() for x in value.split(",") if x.strip()]


def endpoint(conf, tag, default_mtu):
    """Строит sing-box endpoint из разобранного .conf."""
    iface, peer = conf["interface"], conf["peer"]

    for required, where in (("privatekey", iface), ("publickey", peer),
                            ("endpoint", peer), ("allowedips", peer)):
        if required not in where:
            sys.exit(f"[{tag}] в конфиге нет обязательного поля {required}")

    host, _, port = peer["endpoint"].rpartition(":")
    if not port.isdigit():
        sys.exit(f"[{tag}] Endpoint должен быть host:port, получено {peer['endpoint']!r}")

    # Имя резолвим ЗДЕСЬ, пока системный DNS ещё обычный. Иначе sing-box при
    # старте попробует резолвить его через свой же туннель, который в этот
    # момент не поднят, и упадёт с "context deadline exceeded".
    if not re.match(r"^[\d.]+$", host) and ":" not in host:
        name = host
        try:
            host = socket.getaddrinfo(name, None, socket.AF_INET)[0][4][0]
        except OSError as exc:
            sys.exit(f"[{tag}] не удалось резолвить {name}: {exc}")

        # НЕ подменять частный адрес публичным. Корп-сервер доступен по
        # внутреннему адресу (имя из конфига -> адрес внутри сети), и именно на
        # него отвечает; публичный 178.209.105.2 из этой сети молчит.
        # Такая подмена ломала корп-туннель: пакеты уходили, ответов не было.
        # Принудительно взять публичный адрес: SB_ENDPOINT_PUBLIC=1
        if (ipaddress.ip_address(host).is_private
                and os.environ.get("SB_ENDPOINT_PUBLIC") == "1"):
            # Спрашиваем публичный DNS в обход системного: системный в корп-сети
            # как раз и отдаёт внутренний адрес, ради обхода которого сюда и
            # зашли. dig на Windows нет, поэтому Resolve-DnsName с -Server.
            pub = winnet.resolve4_via(name, "8.8.8.8") or \
                  winnet.resolve4_via(name, "1.1.1.1")
            if pub:
                print(f"  [{tag}] {name}: {host} -> публичный {pub}")
                host = pub

    ep = {
        "type": "wireguard",
        "tag": tag,
        "mtu": as_int(iface.get("mtu", default_mtu), tag, "MTU"),
        "address": split_list(iface.get("address", "")),
        "private_key": iface["privatekey"],
        "peers": [{
            "address": host,
            "port": int(port),
            "public_key": peer["publickey"],
            "allowed_ips": split_list(peer["allowedips"]),
        }],
    }
    if "presharedkey" in peer:
        ep["peers"][0]["pre_shared_key"] = peer["presharedkey"]
    if "persistentkeepalive" in peer:
        ep["peers"][0]["persistent_keepalive_interval"] = num_or_range(
            peer["persistentkeepalive"], tag, "PersistentKeepalive")

    # AWG-обфускация: числа как числа, magic-заголовки-диапазоны как строки.
    for k in AWG_INT:
        if k in iface:
            ep[k] = as_int(iface[k], tag, k.capitalize())
    for k in AWG_HDR:
        if k in iface:
            ep[k] = num_or_range(iface[k], tag, k.upper())
    for k in AWG_CPS:
        if k in iface:
            ep[k] = iface[k]
    for k, key in AWG3_STR.items():
        if k in iface:
            ep[key] = iface[k]
    for k, key in AWG3_RANGE.items():
        if k in iface:
            ep[key] = num_or_range(iface[k], tag, key)
    for k, key in AWG3_BOOL.items():
        if k in iface:
            ep[key] = iface[k].lower() in ("1", "true", "yes", "on")

    if any(ep.get(k) for k in AWG_JUNK) and ep["mtu"] > AWG_MTU_MAX:
        print(f"  [{tag}] MTU {ep['mtu']} -> {AWG_MTU_MAX}: AWG с junk-параметрами")
        ep["mtu"] = AWG_MTU_MAX
    return ep


def as_int(value, tag, field):
    """Число из .conf. Опечатка — внятная ошибка с именем поля, а не трейсбек:
    последняя строка вывода уходит в окно как причина отказа."""
    try:
        return int(str(value).strip())
    except ValueError:
        sys.exit(f"[{tag}] {field} = {value!r}: ожидаю целое число")


def num_or_range(value, tag, field):
    """Число или диапазон "min-max": "25" -> 25, "25-35" -> "25-35".

    Диапазоны пришли с AmneziaWG 2.0 (H1–H4) и 3.x (тайминги, keepalive).
    sing-box-lx принимает их строкой, а число — числом.
    """
    v = str(value).strip()
    lo, sep, hi = v.partition("-")
    if not sep:
        return as_int(v, tag, field)
    as_int(lo, tag, field)
    as_int(hi, tag, field)
    return f"{lo.strip()}-{hi.strip()}"


def corp_routes(conf):
    """Подсети корпа из AllowedIPs, без 0.0.0.0/0 и IPv6."""
    nets = []
    for cidr in split_list(conf["peer"]["allowedips"]):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.prefixlen == 0:
            continue
        nets.append(str(net))
    if not nets:
        sys.exit("[corp] в AllowedIPs нет ни одной IPv4-подсети")
    return nets


def dns_domains(conf):
    """Домены для корп-DNS: из имени корп-endpoint + известные внутренние."""
    domains = set()
    host = conf["peer"]["endpoint"].rpartition(":")[0]
    if not re.match(r"^[\d.]+$", host):
        parts = host.split(".")
        if len(parts) >= 2:
            domains.add(".".join(parts[-2:]))
    return domains


def dns_section(corp_dns, domains):
    """Серверы и правила DNS: корп-домены — в корп-DNS, остальное — 8.8.8.8.

    Корп-DNS спрашиваем по TCP. По UDP sing-box держит к нему один сокет
    через wg-corp; ответы на нём терялись (больше половины запросов шли
    3–10 с), и новый сокет sing-box открывал только по таймауту — клиент
    Windows к этому времени уже отвечал «хост не найден». У TCP потеря
    пакета — повтор через доли секунды, а не таймаут всего запроса.
    """
    servers = [{
        "type": "udp", "tag": "dns-personal",
        "server": "8.8.8.8", "detour": "awg-personal",
    }]
    rules = []
    if corp_dns:
        servers.insert(0, {
            "type": "tcp", "tag": "dns-corp",
            "server": corp_dns[0], "detour": "wg-corp",
        })
        rules.append({"domain_suffix": domains, "server": "dns-corp"})
    return servers, rules


# Частные диапазоны: всё, что не отдано корпу, ходит напрямую.
LOCAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "169.254.0.0/16", "224.0.0.0/4"]


def running_pid():
    """PID работающего sing-box из нашей папки, иначе ''."""
    try:
        pids = winnet.pids_of(paths.SINGBOX)
        return str(pids[0]) if pids else ""
    except Exception:
        return ""


# Уровни журнала sing-box. Чужое слово в site.env не должно ронять запуск:
# sing-box check отверг бы весь конфиг из-за опечатки в диагностическом ключе.
LOG_LEVELS = ("trace", "debug", "info", "warn", "error", "fatal", "panic")


def log_level():
    """SB_LOG_LEVEL из site.env: debug — когда ищем причину сбоя, иначе info.
    Статистика адресов и сторож службы читают строки info и error — выше
    warn их не будет."""
    level = os.environ.get("SB_LOG_LEVEL", "").strip().lower()
    if level and level not in LOG_LEVELS:
        print(f"SB_LOG_LEVEL={level}: такого уровня нет, беру info",
              file=sys.stderr)
    return level if level in LOG_LEVELS else "info"


def main():
    os.makedirs(STATE, exist_ok=True)
    out_path = os.path.join(STATE, "config.json")

    # Перезаписывать конфиг под работающим процессом нельзя: адрес пира может
    # смениться, и sing-box падает на «sendmsg: socket is already connected»,
    # а корп-туннель молча перестаёт подниматься. `vpn start` зовёт сборку до
    # запуска, поэтому его это не касается; запрет — на ручные пересборки.
    pid = running_pid()
    if pid and "--force" not in sys.argv and "--out" not in sys.argv:
        sys.exit(f"sing-box уже работает (pid {pid}) — конфиг не трогаю.\n"
                 f"Останови его (`vpn stop`) или пересобери в другой файл:\n"
                 f"  python3 {os.path.relpath(__file__, BASE)} --out /tmp/test.json")
    if "--out" in sys.argv:
        out_path = sys.argv[sys.argv.index("--out") + 1]

    p_path = pick_personal()
    c_path = pick_corp()

    personal = parse_conf(p_path)
    corp = parse_conf(c_path)

    # Значение по умолчанию — только когда в конфиге нет строки MTU.
    #
    # 1280, а не 1420: клиент WireGuard на macOS в этом случае берёт именно
    # 1280, и конфиги от провайдеров рассчитаны на это. С 1420 у сервера
    # nl-1 рукопожатие проходило, а данные не пролезали — туннель выглядел
    # поднятым, но интернета не было. Конфиги со своим MTU (personal.conf)
    # это не затрагивает: там значение берётся из файла.
    ep_personal = endpoint(personal, "awg-personal", 1280)
    ep_corp = endpoint(corp, "wg-corp", 1280)

    # Переключатели для диагностики, без правки файлов:
    #   SB_STACK=system|gvisor|mixed   сетевой стек tun
    #   SB_CORP_MTU=1380               MTU корп-туннеля
    #   SB_TUN_MTU=1380                MTU самого tun
    stack = os.environ.get("SB_STACK", "gvisor")

    # SB_CORP_SYSTEM=1 — поднимать корп-туннель системным интерфейсом.
    # Оставлено запасным выходом от macOS-версии. Там для эндпоинта с одним
    # пиром sing-box открывал connected UDP-сокет, отправка с явным адресом
    # получателя давала EISCONN, ломалась переустановка ключей раз в ~2 минуты
    # и туннель тихо умирал. На Windows этот путь другой, и дефект не
    # воспроизводится — но если туннель начнёт отваливаться по тому же
    # расписанию, проверять стоит отсюда.
    if os.environ.get("SB_CORP_SYSTEM") == "1":
        ep_corp["system"] = True

    # SB_CORP_AWG=1 — пустить корп через AWG-код форка с нейтральными
    # параметрами. При Jc=0, S1=S2=0 и H1..H4 = 1,2,3,4 пакеты AmneziaWG
    # побайтово совпадают с ванильным WireGuard (это штатные номера типов
    # сообщений), поэтому обычный сервер принимает их как есть.
    # Смысл: личный туннель на этом же коде работает без ошибок, а обычный
    # WireGuard-путь форка отбивался EISCONN при рукопожатии (см. выше).
    if os.environ.get("SB_CORP_AWG") == "1":
        ep_corp.update({"jc": 0, "jmin": 0, "jmax": 0, "s1": 0, "s2": 0,
                        "h1": 1, "h2": 2, "h3": 3, "h4": 4})

    # SB_CORP_2PEERS=1 — добавить корпу фиктивного второго пира.
    # sing-box открывает connected UDP-сокет ТОЛЬКО когда пир один; при двух и
    # более он использует ListenPacket, где отправка с явным адресом легальна
    # и EISCONN не возникает. Пир-пустышка ведёт в TEST-NET-1 (RFC 5737),
    # трафика туда нет, на маршрутизацию он не влияет.
    if os.environ.get("SB_CORP_2PEERS") == "1":
        ep_corp["peers"].append({
            "address": "192.0.2.1",
            "port": 51820,
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "allowed_ips": ["192.0.2.2/32"],
        })
    if os.environ.get("SB_CORP_MTU"):
        ep_corp["mtu"] = int(os.environ["SB_CORP_MTU"])

    routes = corp_routes(corp)

    # SB_CORP_EXCLUDE="198.51.100.7/32 ..." — не гнать эти адреса в корп-туннель.
    # Нужно, когда какой-то адрес из AllowedIPs недоступен со стороны корп-сети:
    # без исключения соединение с ним висит 15с и тормозит браузер.
    excl = os.environ.get("SB_CORP_EXCLUDE", "").replace(",", " ").split()
    if excl:
        drop = [ipaddress.ip_network(x, strict=False) for x in excl if _is_cidr(x)]
        routes = [r for r in routes
                  if not any(ipaddress.ip_network(r, strict=False).subnet_of(d)
                             for d in drop)]
        for ep in (ep_corp,):
            ep["peers"][0]["allowed_ips"] = [
                c for c in ep["peers"][0]["allowed_ips"]
                if not (_is_cidr(c) and any(
                    ipaddress.ip_network(c, strict=False).subnet_of(d) for d in drop))
            ]
        print(f"  исключено из корпа: {' '.join(excl)}")

    # IPv6 включаем ТОЛЬКО если сервер выдал нам v6-адрес в [Interface] Address.
    # Наличия ::/0 в AllowedIPs недостаточно: конфиги его пишут по привычке.
    #
    # Почему это важно. Если дать tun v6-адрес, не имея v6 на самом туннеле,
    # приложения видят «IPv6 есть» и по Happy Eyeballs идут сначала по нему.
    # Трафик заходит в туннель и умирает там с
    #     "missing IPv6 local address",
    # причём не молча — соединение получает отказ, и браузер рвёт страницу
    # (это и был ERR_CONNECTION_CLOSED). Без v6-адреса на tun приложения
    # просто не пытаются использовать v6 и сразу работают по IPv4.
    personal_v6 = any(
        ipaddress.ip_network(a, strict=False).version == 6
        for a in split_list(personal["interface"].get("address", ""))
        if _is_cidr(a)
    )
    tun_address = ["172.19.0.1/30"]
    if personal_v6:
        tun_address.append("fdfe:dcba:9876::1/126")
    else:
        # Раз v6 наружу нести нечем — не заявляем, что умеем его маршрутизировать.
        for ep in (ep_personal, ep_corp):
            allowed = ep["peers"][0]["allowed_ips"]
            ep["peers"][0]["allowed_ips"] = [
                c for c in allowed
                if not (_is_cidr(c)
                        and ipaddress.ip_network(c, strict=False).version == 6)
            ]

    # Корп-DNS: из [Interface] DNS корп-конфига, иначе не поднимаем.
    corp_dns = split_list(corp["interface"].get("dns", ""))
    corp_dns = [d for d in corp_dns if re.match(r"^[\d.]+$", d)]

    # Домены, которые резолвятся через корп-DNS. На Windows это и есть весь
    # split-DNS: запросы идут через tun, и правила sing-box до них доходят —
    # отдельных системных правил (NRPT) не нужно.
    # Домены рабочей сети берём из настроек: у каждого они свои.
    extra = {d for d in os.environ.get("CORP_DOMAINS", "").split() if d}

    # ВАЖНО: домен корп-endpoint сюда попадать не должен. Иначе имя сервера
    # придётся резолвить через корп-DNS, который доступен только когда
    # туннель уже поднят — замкнутый круг. Его резолвим публично.
    endpoint_host = corp["peer"]["endpoint"].rpartition(":")[0].lower()
    domains = sorted(
        d for d in (dns_domains(corp) | extra)
        if not endpoint_host.endswith(d.lower())
    )

    dns_servers, dns_rules = dns_section(corp_dns, domains)

    config = {
        "log": {"level": log_level(), "timestamp": True},
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": "dns-personal",
            "strategy": "ipv4_only",
        },
        "endpoints": [ep_personal, ep_corp],
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            "mtu": int(os.environ.get("SB_TUN_MTU", ep_personal["mtu"])),
            "address": tun_address,
            "auto_route": True,
            # Windows шлёт DNS-запрос во все адаптеры сразу и берёт первый
            # ответ — обычно от DNS провайдера, и корп-домены резолвились
            # мимо корп-DNS. strict_route закрывает DNS на остальных
            # адаптерах правилами брандмауэра. Выключить: SB_STRICT_ROUTE=0.
            "strict_route": os.environ.get("SB_STRICT_ROUTE") != "0",
            "stack": stack,
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_cidr": routes, "outbound": "wg-corp"},
                # Локальная сеть — напрямую, не в туннель. Без этого запросы
                # к соседним устройствам (NAS, принтер, роутер) уходили в
                # личный туннель и висли там по 15 секунд.
                # Правило стоит ПОСЛЕ корпоративного: порядок решает, и корп
                # свои подсети из этих же диапазонов уже забрал выше.
                {"ip_cidr": LOCAL_NETS, "outbound": "direct"},
            ],
            "final": "awg-personal",
            # SB_NO_AUTODETECT=1 — не перепривязывать сокеты к интерфейсу.
            # Наш скрипт меняет маршруты сразу после старта, и при включённом
            # автоопределении sing-box может перепривязать UDP-сокет туннеля
            # к tun: пакеты тогда уходят через en0, а ответы на en0 до сокета
            # не доходят.
            "auto_detect_interface":
                os.environ.get("SB_NO_AUTODETECT") != "1",
            "default_domain_resolver": "dns-personal",
        },
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    # На Windows chmod почти ничего не значит — приватные ключи в config.json
    # закрывает не он, а ACL каталога данных, который выставляет установщик.
    # Строку оставляем ради запусков из исходников под WSL и ради явности.
    os.chmod(out_path, 0o600)

    print(f"собрано: {out_path}")
    print(f"  из     : {os.path.basename(p_path)} + {os.path.basename(c_path)}")
    print(f"  личный : {ep_personal['peers'][0]['address']}:"
          f"{ep_personal['peers'][0]['port']}  mtu {ep_personal['mtu']}"
          f"  awg={'да' if any(k in ep_personal for k in AWG_INT) else 'нет'}")
    print(f"  корп   : {ep_corp['peers'][0]['address']}:"
          f"{ep_corp['peers'][0]['port']}  mtu {ep_corp['mtu']}")
    print(f"  в корп : {', '.join(routes)}")
    print(f"  корп-DNS: {corp_dns[0] if corp_dns else 'нет'}"
          f"  для {', '.join(domains)}")


if __name__ == "__main__":
    main()
