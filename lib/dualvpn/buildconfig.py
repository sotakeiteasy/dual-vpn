#!/usr/bin/env python3
"""
Собирает конфиги sing-box-lx из обычных WireGuard/AmneziaWG .conf файлов.

Туннели и их правила — conf/tunnels.json (tunnels.py), у каждого активный
.conf в conf/tunnels/<id>/. Режим list — в туннель идут подсети из его
AllowedIPs и записи «пускать»; all — весь остальной трафик.

Процессов 1 + N: state/run/config.json — tun, маршрутизация и DNS;
state/run/tunnel-<id>.json — по процессу на туннель, каждый за своим socks
на loopback. Сбой туннеля чинится перезапуском одного его процесса: tun не
падает, а трафик упавшего основного до его возвращения идёт напрямую.

Подсети туннеля берутся ИЗ AllowedIPs его конфига, поэтому при ротации
достаточно положить новый файл — правки скрипта не нужны.

Зовётся службой при каждом включении, отдельно запускать не нужно.
"""

import ipaddress
import json
import socket
import os
import re
import secrets
import sys
import threading

# Раскладку знает paths.py — здесь только имена.
from . import paths, tunnels, winnet
from .tunnels import NAME_MAX, check_name, safe_name  # их зовут и через buildconfig

BASE = paths.BASE
CONF = paths.CONF

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
# только для переезда старых установок: сначала в conf\corp и conf\personal,
# оттуда tunnels.migrate переносит их в туннели.
_LEGACY_CORP_PAT = (r"^corp\.conf$", r"^wg[-_0-9].*\.conf$", r"^wg\.conf$")
_LEGACY_PERSONAL_PAT = (r"^personal\.conf$", r"^(awg|amnezia).*\.conf$")


def migrate_flat():
    """Переносит конфиги из плоского conf\\ (до 0.3) по папкам типов.

    Тип берём по старым правилам имени — ровно так, как их понимала прежняя
    сборка, — поэтому после обновления включается то же, что и до него.
    Профиль, если он не указывал на перенесённый личный, — тот, что сборка
    брала сама. Возвращает [(имя, тип)] перенесённых.
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
        folder = os.path.join(CONF, kind)
        os.makedirs(folder, exist_ok=True)
        os.replace(src, os.path.join(folder, f"{name}.conf"))
        moved.append((name, kind))
    personal = [n for n, kind in moved if kind == "personal"]
    if personal and _legacy_profile() not in personal:
        with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
            fh.write(legacy_default_personal(personal))
    return moved


def _legacy_profile():
    try:
        with open(paths.PROFILE_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def legacy_default_personal(names):
    """Какой личный сборка брала без профиля до 0.3: personal.conf, потом awg*."""
    for pat in _LEGACY_PERSONAL_PAT:
        found = [n for n in sorted(names)
                 if re.match(pat, f"{n}.conf", re.IGNORECASE)]
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


def parse_text(text, where="конфиг"):
    """Разбирает текст wg-quick/awg-quick в {'interface': {...}, 'peer': {...}}.

    Без секции — ValueError: служба разбирает так и добавляемый конфиг, а
    ей падать нельзя. where — что назвать в причине.
    """
    out = {"interface": {}, "peer": {}}
    section = None
    for raw in (text or "").splitlines():
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
        raise ValueError(f"{where}: не хватает секции [Interface] или [Peer]")
    return out


def parse_conf(path):
    """Разбирает .conf с диска; без секции — выход сборки с причиной."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        return parse_text(text, path)
    except ValueError as exc:
        sys.exit(str(exc))


def conf_dns(conf):
    """IPv4-адреса из [Interface] DNS; имена и IPv6 sing-box туннеля не нужны."""
    return [d for d in split_list(conf["interface"].get("dns", ""))
            if re.match(r"^[\d.]+$", d)]


def is_full(conf):
    """Есть ли в AllowedIPs 0.0.0.0/0: такой сервер принимает любой трафик."""
    for cidr in split_list(conf["peer"].get("allowedips", "")):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.prefixlen == 0:
            return True
    return False


def _is_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def split_list(value):
    return [x.strip() for x in value.split(",") if x.strip()]


# Сколько ждём DNS за адресом пира. Без потолка getaddrinfo висел
# 12 с, когда DNS роутера не отвечал, — и столько же стояло переподключение.
SYSTEM_DNS_WAIT = 4.0
# Запасные DNS: спрашиваем разом с системным, но их ответ берём, только
# если системный не ответил. Только запасные: в корп-сети
# системный отдаёт внутренний адрес пира, а публичный оттуда молчит.
PUBLIC_DNS = ("8.8.8.8", "1.1.1.1")


def _ask_dns(name, wait):
    """Спрашивает системный и запасные DNS разом, ждёт не дольше wait.

    Возвращает (системный, {сервер: IPv4}); системный — адрес, исключение
    или None, если промолчал. Ответ системного главный, поэтому запасных
    ждём, только пока он не ответил сам. Спрашивать по очереди стоило до
    трёх потолков подряд. getaddrinfo не прервать, поэтому каждый запрос
    идёт в фоновом потоке: зависший доживёт своё сам.
    """
    answers = {}
    ready = threading.Condition()

    def system():
        try:
            return socket.getaddrinfo(name, None, socket.AF_INET)[0][4][0]
        except (OSError, IndexError) as exc:
            return OSError(str(exc))

    def run(source, ask):
        answer = ask()
        with ready:
            answers[source] = answer
            ready.notify_all()

    asks = {None: system}
    for server in PUBLIC_DNS:
        asks[server] = lambda server=server: winnet.resolve4_via(
            name, server, timeout=wait)
    for source, ask in asks.items():
        threading.Thread(target=run, args=(source, ask), daemon=True).start()

    def settled():
        sys_answer = answers.get(None)
        if isinstance(sys_answer, str):
            return True
        publics = [answers.get(s) for s in PUBLIC_DNS]
        return sys_answer is not None and (any(publics)
                                           or len(answers) == len(asks))

    with ready:
        ready.wait_for(settled, wait)
        found = dict(answers)
    return found.pop(None, None), {s: ip for s, ip in found.items() if ip}


def _known_peer_ips():
    """Последние удачные адреса пиров: {имя: IPv4}."""
    try:
        with open(paths.PEER_IPS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    out = {}
    for name, ip in data.items():
        try:
            if isinstance(ip, str) and ipaddress.ip_address(ip).version == 4:
                out[name] = ip
        except ValueError:
            pass
    return out


def _remember_peer_ip(name, ip):
    """Запоминает удачный адрес. Не вышло записать — не беда, сборка важнее."""
    known = _known_peer_ips()
    if known.get(name) == ip:
        return
    known[name] = ip
    tmp = paths.PEER_IPS_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(known, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, paths.PEER_IPS_FILE)
    except OSError:
        pass


def resolve_peer(name, tag, log=print):
    """Адрес пира: системный DNS, затем публичный, затем прошлый удачный.

    Без запасных путей переподключение зависело от DNS роутера: тот молчал,
    и туннель не поднимался, хотя адрес сервера не менялся месяцами.
    """
    known = _known_peer_ips().get(name)
    ip, publics = _ask_dns(name, SYSTEM_DNS_WAIT)
    if not isinstance(ip, str):
        exc = ip or TimeoutError(f"системный DNS молчит {SYSTEM_DNS_WAIT:g} с")
        for server in PUBLIC_DNS:
            ip = publics.get(server)
            if ip:
                log(f"  [{tag}] {name}: системный DNS не ответил ({exc}), "
                    f"{ip} через {server}")
                break
        else:
            ip = known
            if not ip:
                sys.exit(f"[{tag}] не удалось резолвить {name}: {exc}; "
                         f"публичный DNS не ответил, прошлого адреса нет")
            log(f"  [{tag}] {name}: ни один DNS не ответил ({exc}), "
                f"беру прошлый адрес {ip}")
            return ip
    _remember_peer_ip(name, ip)
    return ip


def peer_host(host, tag, log=print):
    """Адрес пира для конфига: IP как есть, имя — резолвим."""
    if not re.match(r"^[\d.]+$", host) and ":" not in host:
        name = host
        host = resolve_peer(name, tag, log)

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
                log(f"  [{tag}] {name}: {host} -> публичный {pub}")
                host = pub
    return host


def endpoint(conf, tag, default_mtu, log=print, resolve=True):
    """Строит sing-box endpoint из разобранного .conf. resolve=False — имя
    пира остаётся именем: основному конфигу адрес пира не нужен."""
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
    if resolve:
        host = peer_host(host, tag, log)

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


def allowed_nets(conf, v6=False):
    """Подсети из AllowedIPs, без маршрута по умолчанию; IPv6 — только с v6 на tun."""
    nets = []
    for cidr in split_list(conf["peer"].get("allowedips", "")):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen == 0 or (net.version == 6 and not v6):
            continue
        nets.append(str(net))
    return nets


def split_entries(entries, v6=False):
    """Записи списка туннеля (routelist) → (ip_cidr, domain_suffix) sing-box.

    «x.su» — сам домен и поддомены, «*.x.su» → «.x.su» — только поддомены.
    IPv6 без v6 на tun отбрасываем, как и AllowedIPs: соединение по нему всё
    равно умерло бы в туннеле.
    """
    nets, domains = [], []
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            domains.append(entry[1:] if entry.startswith("*.") else entry)
            continue
        if net.version == 4 or v6:
            nets.append(str(net))
    return nets, domains


def _match(nets, domains):
    """Условие правила sing-box. Пустых полей не пишем: правило без условий
    совпадает со всем."""
    match = {}
    if nets:
        match["ip_cidr"] = nets
    if domains:
        match["domain_suffix"] = domains
    return match


def tunnel_rule(nets, domains, ex_nets, ex_domains, outbound):
    """Правило основного процесса для туннеля «по списку»; None — пускать нечего.

    ip_cidr и domain_suffix в одном правиле sing-box объединяет через «или».
    Исключение — отрицание внутри «и»: соединение не вырезается из подсети, а
    идёт дальше по правилам — к локальной сети, «мимо VPN» или в выход. Так
    /32 внутри подсети из AllowedIPs тоже исключается.
    """
    match = _match(nets, domains)
    if not match:
        return None
    exclude = _match(ex_nets, ex_domains)
    if not exclude:
        return {**match, "outbound": outbound}
    return {"type": "logical", "mode": "and",
            "rules": [match, {**exclude, "invert": True}],
            "outbound": outbound}


def off_endpoint(domains, host):
    """Домены для DNS туннеля без того, под которым живёт его сервер.

    Иначе имя сервера пришлось бы резолвить через DNS туннеля, который
    доступен только когда туннель уже поднят, — замкнутый круг.
    """
    host = host.lower()

    def covers(d):
        if d.startswith("."):
            return host.endswith(d)
        return host == d or host.endswith(f".{d}")
    return [d for d in domains if not covers(d)]


def corp_diagnostics(ep):
    """SB_CORP_* — диагностика туннелей «по списку», без правки файлов."""
    # SB_CORP_SYSTEM=1 — поднимать туннель системным интерфейсом.
    # Оставлено запасным выходом от macOS-версии. Там для эндпоинта с одним
    # пиром sing-box открывал connected UDP-сокет, отправка с явным адресом
    # получателя давала EISCONN, ломалась переустановка ключей раз в ~2 минуты
    # и туннель тихо умирал. На Windows этот путь другой, и дефект не
    # воспроизводится — но если туннель начнёт отваливаться по тому же
    # расписанию, проверять стоит отсюда.
    if os.environ.get("SB_CORP_SYSTEM") == "1":
        ep["system"] = True

    # SB_CORP_AWG=1 — пустить туннель через AWG-код форка с нейтральными
    # параметрами. При Jc=0, S1=S2=0 и H1..H4 = 1,2,3,4 пакеты AmneziaWG
    # побайтово совпадают с ванильным WireGuard (это штатные номера типов
    # сообщений), поэтому обычный сервер принимает их как есть.
    # Смысл: личный туннель на этом же коде работает без ошибок, а обычный
    # WireGuard-путь форка отбивался EISCONN при рукопожатии (см. выше).
    if os.environ.get("SB_CORP_AWG") == "1":
        ep.update({"jc": 0, "jmin": 0, "jmax": 0, "s1": 0, "s2": 0,
                   "h1": 1, "h2": 2, "h3": 3, "h4": 4})

    # SB_CORP_2PEERS=1 — добавить фиктивного второго пира.
    # sing-box открывает connected UDP-сокет ТОЛЬКО когда пир один; при двух и
    # более он использует ListenPacket, где отправка с явным адресом легальна
    # и EISCONN не возникает. Пир-пустышка ведёт в TEST-NET-1 (RFC 5737),
    # трафика туда нет, на маршрутизацию он не влияет.
    if os.environ.get("SB_CORP_2PEERS") == "1":
        ep["peers"].append({
            "address": "192.0.2.1",
            "port": 51820,
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "allowed_ips": ["192.0.2.2/32"],
        })
    # SB_CORP_MTU=1380 — MTU туннелей «по списку».
    if os.environ.get("SB_CORP_MTU"):
        ep["mtu"] = as_int(os.environ["SB_CORP_MTU"], ep["tag"], "SB_CORP_MTU")


def dns_section(by_tunnel, public_detour):
    """Серверы и правила DNS: домены туннеля — в его DNS, остальное — 8.8.8.8.

    by_tunnel — [(id, адрес DNS, домены)] туннелей «по списку» с DNS в .conf.
    DNS туннеля спрашиваем по TCP. По UDP sing-box держит к нему один сокет
    через туннель; ответы на нём терялись (больше половины запросов шли
    3–10 с), и новый сокет sing-box открывал только по таймауту — клиент
    Windows к этому времени уже отвечал «хост не найден». У TCP потеря
    пакета — повтор через доли секунды, а не таймаут всего запроса.
    """
    servers, rules = [], []
    for tid, server, domains in by_tunnel:
        servers.append({"type": "tcp", "tag": dns_tag(tid),
                        "server": server, "detour": socks_tag(tid)})
        # Пустой domain_suffix sing-box считает совпадением со всем: без
        # доменов любое имя уходило бы в DNS туннеля.
        if domains:
            rules.append({"domain_suffix": domains, "server": dns_tag(tid)})
    # Публичный DNS идёт тем же выходом, что и трафик: упал основной туннель —
    # переключатель OUT_TAG уводит в direct и его. Иначе без основного не
    # резолвилось бы ни одно имя, и запасной выход был бы бесполезен. Без
    # основного туннеля — напрямую: detour на пустой direct sing-box отвергает.
    public = {"type": "udp", "tag": PUBLIC_DNS_TAG, "server": "8.8.8.8"}
    if public_detour:
        public["detour"] = public_detour
    servers.append(public)
    return servers, rules


# Частные диапазоны: всё, что не отдано туннелям «по списку», ходит напрямую.
LOCAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "169.254.0.0/16", "224.0.0.0/4"]

# Каждый туннель живёт в своём процессе sing-box (боковой: state/run/tunnel-<id>.json):
# сторож перезапускает упавший один, не трогая tun, маршруты и другие туннели.
# Основной процесс ходит в каждый через свой socks на loopback.
#
# Теги туннеля строятся из его id. id — только [a-z0-9-] (tunnels.check_id),
# поэтому тег туннеля не совпадёт с постоянными: у тех нет префикса с дефисом.
def ep_tag(tid):
    return f"wg-{tid}"


def socks_tag(tid):
    return f"socks-{tid}"


def dns_tag(tid):
    return f"dns-{tid}"


# Выход для всего, что не забрали туннели «по списку» и не локальная сеть:
# основной туннель, а пока он мёртв — напрямую. Переключает служба через
# clash_api, без перезапуска.
OUT_TAG = "out"
DIRECT_TAG = "direct"
PUBLIC_DNS_TAG = "dns"


def _free_port():
    """Свободный порт на loopback. Его могут занять между проверкой и
    стартом sing-box — тогда старт упадёт с понятной ошибкой в журнале."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def new_link():
    """Порт, логин и пароль socks между процессами — новые на каждую сборку.

    Порт на loopback открыт любому локальному процессу; без пароля чужая
    программа ходила бы в рабочую сеть нашим туннелем.
    """
    return {"port": _free_port(),
            "username": secrets.token_hex(8),
            "password": secrets.token_urlsafe(24)}


def new_api():
    """Адрес и секрет clash_api основного процесса."""
    return {"port": _free_port(), "secret": secrets.token_urlsafe(24)}


def write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)
    # На Windows chmod почти ничего не значит — приватные ключи закрывает не
    # он, а ACL каталога данных, который выставляет установщик. Строку
    # оставляем ради запусков из исходников под WSL и ради явности.
    os.chmod(path, 0o600)


def read_json(path):
    """Собранный конфиг как словарь; нет или битый — пустой."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def side_json(tid):
    """Путь к конфигу бокового процесса туннеля. С префиксом: id «config»
    иначе затёр бы config.json рядом."""
    return os.path.join(paths.RUN, f"tunnel-{tid}.json")


def side_config(ep, link, level="info"):
    """Конфиг бокового процесса: socks-вход на loopback и один endpoint."""
    return {
        "log": {"level": level, "timestamp": True},
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": link["port"],
            "users": [{"username": link["username"],
                       "password": link["password"]}],
        }],
        "endpoints": [ep],
        "route": {
            "final": ep["tag"],
            # Без автоопределения: оно привязало бы сокет к интерфейсу по
            # умолчанию, а это tun основного процесса — пакеты к пиру ушли
            # бы обратно в tun. К пиру их ведёт host-маршрут через аплинк.
            "auto_detect_interface": False,
        },
    }


def side_link(main_cfg, tid):
    """Порт и логин socks бокового процесса из основного конфига, иначе None."""
    for ob in main_cfg.get("outbounds", []):
        if ob.get("tag") == socks_tag(tid):
            return {"port": ob.get("server_port"),
                    "username": ob.get("username"),
                    "password": ob.get("password")}
    return None


def side_ids(main_cfg):
    """id туннелей, чьи боковые процессы ждёт основной конфиг, по порядку."""
    prefix = socks_tag("")
    return [ob["tag"][len(prefix):] for ob in main_cfg.get("outbounds", [])
            if ob.get("type") == "socks"
            and ob.get("tag", "").startswith(prefix)]


def main_id(main_cfg):
    """id основного туннеля — того, что за selector out, — иначе None."""
    prefix = socks_tag("")
    for ob in main_cfg.get("outbounds", []):
        if ob.get("tag") == OUT_TAG:
            tag = ob.get("default") or ""
            return tag[len(prefix):] if tag.startswith(prefix) else None
    return None


def ep_of_socks(tag):
    """Тег endpoint туннеля по тегу его socks-выхода; чужой тег — как есть."""
    prefix = socks_tag("")
    if tag.startswith(prefix) and len(tag) > len(prefix):
        return ep_tag(tag[len(prefix):])
    return tag


def tunnel_dns(main_cfg):
    """{id: адрес DNS туннеля} из основного конфига, по порядку туннелей."""
    prefix = dns_tag("")
    return {s["tag"][len(prefix):]: s.get("server", "")
            for s in main_cfg.get("dns", {}).get("servers", [])
            if s.get("tag", "").startswith(prefix)}


def tunnel_domains(main_cfg):
    """Домены, которые основной конфиг отдаёт DNS туннелей, — для NRPT."""
    prefix = dns_tag("")
    names = []
    for rule in main_cfg.get("dns", {}).get("rules", []):
        if rule.get("server", "").startswith(prefix):
            names += rule.get("domain_suffix", [])
    return names


def tunnel_nets(main_cfg, tid):
    """Подсети, которые основной конфиг пускает в туннель (без исключений)."""
    for rule in main_cfg.get("route", {}).get("rules", []):
        if rule.get("outbound") == socks_tag(tid):
            match = rule["rules"][0] if rule.get("type") == "logical" else rule
            return match.get("ip_cidr", [])
    return []


def api_of(main_cfg):
    """(адрес, секрет) clash_api из основного конфига, иначе None."""
    api = main_cfg.get("experimental", {}).get("clash_api") or {}
    if not api.get("external_controller"):
        return None
    return api["external_controller"], api.get("secret", "")


def running_pid():
    """PID работающего sing-box из нашей папки, иначе ''."""
    try:
        pids = winnet.pids_of(paths.SINGBOX)
        return str(pids[0]) if pids else ""
    except Exception:
        return ""


def sources():
    """(туннели, {id: путь к активному .conf}) для сборки из tunnels.json.
    Испорченный файл или неоднозначный активный конфиг — sys.exit с причиной."""
    try:
        data = tunnels.load()
        return data, {t["id"]: tunnels.active_conf(t) for t in data["tunnels"]}
    except ValueError as exc:
        sys.exit(str(exc))


def _unique(items):
    return list(dict.fromkeys(items))


def _summary(t, ep, nets, domains, dns):
    peer = ep["peers"][0]
    awg = "да" if any(k in ep for k in AWG_INT) else "нет"
    lines = [f"  [{t['id']}] {t['name']}: "
             f"{'весь остальной трафик' if t['mode'] == 'all' else 'по списку'}, "
             f"{peer['address']}:{peer['port']}  mtu {ep['mtu']}  awg={awg}"]
    if nets or domains:
        lines.append(f"      пускаю: {', '.join(nets + domains)}")
    if t["exclude"]:
        lines.append(f"      мимо  : {', '.join(t['exclude'])}")
    if dns:
        lines.append(f"      DNS   : {dns[1]} для {', '.join(dns[2]) or '(доменов нет)'}")
    return lines


def build(data, confs, out_path, side_path=None, log=print):
    """Основной конфиг и по боковому на туннель. Возвращает [(id, имя)]
    собранных по порядку файла.

    data — tunnels.validate(); confs — {id: путь к активному .conf}. Туннель
    без конфига пропускается: пустой слот не держит остальные.
    """
    side_path = side_path or side_json
    config, sides, built, report = assemble(data, confs, log)
    write_json(out_path, config)
    for tid, side in sides.items():
        write_json(side_path(tid), side)

    print(f"собрано: {out_path}")
    for line in report:
        print(line)
    return built


def assemble(data, confs, log=print, links=None, api=None, resolve=True):
    """(основной конфиг, {id: боковой конфиг}, [(id, имя)], строки сводки) без
    записи на диск.

    links — {id: связь socks} и api — clash_api работающего запуска: с ними
    основной конфиг выходит тем же, если туннели не менялись. resolve=False —
    имена пиров в боковых не резолвятся.
    """
    links, level = links or {}, data["log_level"]
    built = []                       # (туннель, разобранный .conf, endpoint)
    for t in data["tunnels"]:
        path = confs.get(t["id"])
        if not path:
            log(f"  [{t['id']}] «{t['name']}»: конфига нет, туннель пропускаю")
            continue
        conf = parse_conf(path)
        # Значение по умолчанию — только когда в конфиге нет строки MTU.
        #
        # 1280, а не 1420: клиент WireGuard на macOS в этом случае берёт именно
        # 1280, и конфиги от провайдеров рассчитаны на это. С 1420 у сервера
        # nl-1 рукопожатие проходило, а данные не пролезали — туннель выглядел
        # поднятым, но интернета не было. Конфиги со своим MTU это не
        # затрагивает: там значение берётся из файла.
        built.append((t, conf, endpoint(conf, ep_tag(t["id"]), 1280, log,
                                        resolve)))
    if not built:
        sys.exit("ни у одного туннеля нет конфига — добавь .conf")
    main = next((b for b in built if b[0]["mode"] == "all"), None)

    # IPv6 включаем ТОЛЬКО если сервер основного туннеля выдал нам v6-адрес в
    # [Interface] Address. Наличия ::/0 в AllowedIPs недостаточно: конфиги
    # его пишут по привычке.
    #
    # Почему это важно. Если дать tun v6-адрес, не имея v6 на самом туннеле,
    # приложения видят «IPv6 есть» и по Happy Eyeballs идут сначала по нему.
    # Трафик заходит в туннель и умирает там с
    #     "missing IPv6 local address",
    # причём не молча — соединение получает отказ, и браузер рвёт страницу
    # (это и был ERR_CONNECTION_CLOSED). Без v6-адреса на tun приложения
    # просто не пытаются использовать v6 и сразу работают по IPv4.
    v6 = main is not None and any(
        ipaddress.ip_network(a, strict=False).version == 6
        for a in split_list(main[1]["interface"].get("address", ""))
        if _is_cidr(a))
    tun_address = ["172.19.0.1/30"]
    if v6:
        tun_address.append("fdfe:dcba:9876::1/126")

    # Переключатели для диагностики, без правки файлов:
    #   SB_STACK=system|gvisor|mixed   сетевой стек tun
    #   SB_TUN_MTU=1380                MTU самого tun
    #   SB_CORP_*                      туннелям «по списку», см. corp_diagnostics
    stack = os.environ.get("SB_STACK", "gvisor")

    rules, dns_tunnels, report = [], [], []
    for t, conf, ep in built:
        # Какой трафик пустить в туннель, решает основной процесс. С AllowedIPs
        # из файла endpoint отбрасывал бы домены и адреса из «пускать»,
        # которых в AllowedIPs нет.
        ep["peers"][0]["allowed_ips"] = ["0.0.0.0/0"] + (["::/0"] if v6 else [])
        nets, domains, dns = [], [], None
        if t["mode"] == "list":
            corp_diagnostics(ep)
            inc_nets, domains = split_entries(t["include"], v6)
            nets = _unique(allowed_nets(conf, v6) + inc_nets)
            ex_nets, ex_domains = split_entries(t["exclude"], v6)
            rule = tunnel_rule(nets, domains, ex_nets, ex_domains,
                               socks_tag(t["id"]))
            if rule:
                rules.append(rule)
            else:
                log(f"  [{t['id']}] «{t['name']}»: пускать нечего — ни подсетей "
                    f"в AllowedIPs, ни записей в списке")
            # DNS туннеля: из [Interface] DNS его .conf, иначе не поднимаем.
            servers = conf_dns(conf)
            if servers:
                host = conf["peer"]["endpoint"].rpartition(":")[0]
                dns = (t["id"], servers[0], off_endpoint(domains, host))
                dns_tunnels.append(dns)
        report += _summary(t, ep, nets, domains, dns)

    # Локальная сеть — напрямую, не в туннель. Без этого запросы к соседним
    # устройствам (NAS, принтер, роутер) уходили в личный туннель и висли там
    # по 15 секунд. Правило стоит ПОСЛЕ туннелей «по списку»: порядок решает,
    # и свои подсети из этих же диапазонов они уже забрали выше.
    rules.append({"ip_cidr": LOCAL_NETS, "outbound": DIRECT_TAG})
    if main:
        bypass = _match(*split_entries(main[0]["exclude"], v6))
        if bypass:
            rules.append({**bypass, "outbound": DIRECT_TAG})

    links = {t["id"]: links.get(t["id"]) or new_link() for t, _, _ in built}
    api = api or new_api()
    outbounds = [{"type": "direct", "tag": DIRECT_TAG}]
    outbounds += [{"type": "socks", "tag": socks_tag(tid), "version": "5",
                   "server": "127.0.0.1", "server_port": link["port"],
                   "username": link["username"], "password": link["password"]}
                  for tid, link in links.items()]
    if main:
        # Рвать соединения при смене выхода: открытые через мёртвый основной
        # туннель иначе висят до своих таймаутов.
        outbounds.append({"type": "selector", "tag": OUT_TAG,
                          "outbounds": [socks_tag(main[0]["id"]), DIRECT_TAG],
                          "default": socks_tag(main[0]["id"]),
                          "interrupt_exist_connections": True})
    dns_servers, dns_rules = dns_section(dns_tunnels, OUT_TAG if main else None)
    mtu = main[2]["mtu"] if main else min(ep["mtu"] for _, _, ep in built)

    config = {
        "log": {"level": level, "timestamp": True},
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": PUBLIC_DNS_TAG,
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            "mtu": int(os.environ.get("SB_TUN_MTU", mtu)),
            "address": tun_address,
            "auto_route": True,
            # Windows шлёт DNS-запрос во все адаптеры сразу и берёт первый
            # ответ — обычно от DNS провайдера, и корп-домены резолвились
            # мимо корп-DNS. strict_route закрывает DNS на остальных
            # адаптерах правилами брандмауэра. Выключить: SB_STRICT_ROUTE=0.
            "strict_route": os.environ.get("SB_STRICT_ROUTE") != "0",
            "stack": stack,
        }],
        "outbounds": outbounds,
        "experimental": {"clash_api": {
            "external_controller": f"127.0.0.1:{api['port']}",
            "secret": api["secret"],
        }},
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                *rules,
            ],
            # Нет туннеля на «весь остальной трафик» — остальное напрямую.
            "final": OUT_TAG if main else DIRECT_TAG,
            # SB_NO_AUTODETECT=1 — не перепривязывать сокеты к интерфейсу.
            # Наш скрипт меняет маршруты сразу после старта, и при включённом
            # автоопределении sing-box может перепривязать UDP-сокет туннеля
            # к tun: пакеты тогда уходят через en0, а ответы на en0 до сокета
            # не доходят.
            "auto_detect_interface":
                os.environ.get("SB_NO_AUTODETECT") != "1",
            "default_domain_resolver": PUBLIC_DNS_TAG,
        },
    }

    sides = {t["id"]: side_config(ep, links[t["id"]], level) for t, _, ep in built}
    return config, sides, [(t["id"], t["name"]) for t, _, _ in built], report


def _drop_stale_sides(keep):
    """Боковые конфиги туннелей, которых больше нет, — с диска: в них
    приватные ключи."""
    try:
        names = os.listdir(paths.RUN)
    except OSError:
        return
    for f in names:
        if (f.startswith("tunnel-") and f.endswith(".json")
                and f[len("tunnel-"):-len(".json")] not in keep):
            _remove(os.path.join(paths.RUN, f))


def drop_legacy():
    """Собранные конфиги из state\\ — с диска: до state\\run\\ они лежали
    там, где их читает любой пользователь, а в них приватные ключи.
    corp.json и personal.json — имена боковых до 0.4."""
    try:
        names = os.listdir(paths.STATE)
    except OSError:
        return
    for f in names:
        if f in ("config.json", "corp.json", "personal.json") or (
                f.startswith("tunnel-") and f.endswith(".json")):
            _remove(os.path.join(paths.STATE, f))


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def main(log=print):
    """Собирает state\\run\\config.json и боковые. [(id, имя)] собранных туннелей."""
    os.makedirs(paths.RUN, exist_ok=True)
    out_path = paths.CONFIG_JSON

    # Перезаписывать конфиг под работающим процессом нельзя: адрес пира может
    # смениться, и sing-box падает на «sendmsg: socket is already connected»,
    # а корп-туннель молча перестаёт подниматься. `vpn start` зовёт сборку до
    # запуска, поэтому его это не касается; запрет — на ручные пересборки.
    pid = running_pid()
    if pid and "--force" not in sys.argv and "--out" not in sys.argv:
        sys.exit(f"sing-box уже работает (pid {pid}) — конфиг не трогаю.\n"
                 f"Останови его (`vpn stop`) или пересобери в другой файл:\n"
                 f"  python3 {os.path.relpath(__file__, BASE)} --out /tmp/test.json")
    side_path = None
    if "--out" in sys.argv:
        out_path = sys.argv[sys.argv.index("--out") + 1]
        stem = os.path.splitext(out_path)[0]
        side_path = lambda tid: f"{stem}.{tid}.json"

    data, confs = sources()
    built = build(data, confs, out_path, side_path, log)
    if side_path is None:
        _drop_stale_sides([tid for tid, _ in built])
        drop_legacy()
    return built


if __name__ == "__main__":
    main()
