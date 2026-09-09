#!/usr/bin/env python3
"""
Собирает config.json для sing-box-lx из обычных WireGuard/AmneziaWG .conf файлов.

    conf/personal.conf   личный AmneziaWG  -> весь остальной трафик
    conf/corp.conf       корпоративный WG  -> подсети из его AllowedIPs

Вместо personal.conf можно взять любой другой файл из conf\\ — профиль:
    set SB_PERSONAL=nl-1 && python -m dualvpn.buildconfig
    python -m dualvpn.buildconfig --personal nl-1

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
STATE = paths.STATE

# Поля [Interface], которые sing-box ждёт как AWG-параметры (в нижнем регистре).
AWG_INT = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")
AWG_HDR = ("h1", "h2", "h3", "h4")
AWG_CPS = ("i1", "i2", "i3", "i4", "i5")


# Как называются конфиги в conf/. Регистр не важен.
# Корп-файл обычно приходит от админов как wg0-<фамилия>.conf — берём и такой.
PERSONAL_PAT = (r"^personal\.conf$", r"^(awg|amnezia).*\.conf$")
CORP_PAT = (r"^corp\.conf$", r"^wg[-_0-9].*\.conf$", r"^wg\.conf$")


def personal_patterns():
    """Шаблоны для личного конфига.

    По умолчанию — personal.conf / awg*.conf. Если задан профиль
    (SB_PERSONAL=nl-1 или --personal nl-1), берём ровно этот файл: так рядом
    с personal.conf можно держать сколько угодно других серверов и
    переключаться между ними без переименований.
    """
    name = os.environ.get("SB_PERSONAL", "")
    if "--personal" in sys.argv:
        name = sys.argv[sys.argv.index("--personal") + 1]
    name = name.strip()
    if not name:
        return PERSONAL_PAT
    if os.sep in name:
        sys.exit(f"профиль — это имя файла в conf/, без путей: получено {name!r}")
    stem = re.escape(name[:-5] if name.lower().endswith(".conf") else name)
    return (rf"^{stem}\.conf$",)


def list_profiles():
    """Имена всех .conf в conf/ — для подсказки в сообщениях об ошибке."""
    try:
        return sorted(f[:-5] for f in os.listdir(CONF)
                      if f.lower().endswith(".conf"))
    except OSError:
        return []


def pick_conf(what, patterns, exclude=None):
    """Ищет в conf/ файл по шаблонам: сперва точное имя, потом общее."""
    try:
        files = sorted(os.listdir(CONF))
    except OSError:
        sys.exit(f"нет каталога {CONF}\nсоздай его и положи туда .conf")

    for pat in patterns:
        found = [
            os.path.join(CONF, f) for f in files
            if re.match(pat, f, re.IGNORECASE)
            and os.path.join(CONF, f) != exclude
        ]
        if len(found) > 1:
            names = ", ".join(os.path.basename(f) for f in found)
            sys.exit(f"{what} конфиг неоднозначен: подходят {names}\n"
                     f"оставь в {CONF} только один")
        if found:
            return found[0]

    have = list_profiles()
    sys.exit(f"в {CONF} не найден {what} конфиг\n"
             f"ожидаю имя вида: {', '.join(p.strip('^$') for p in patterns)}\n"
             f"есть: {', '.join(have) if have else '(пусто)'}")


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
        "mtu": int(iface.get("mtu", default_mtu)),
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
        ep["peers"][0]["persistent_keepalive_interval"] = int(peer["persistentkeepalive"])

    # AWG-обфускация: числа как числа, magic-заголовки-диапазоны как строки.
    for k in AWG_INT:
        if k in iface:
            ep[k] = int(iface[k])
    for k in AWG_HDR:
        if k in iface:
            v = iface[k]
            ep[k] = v if "-" in v else int(v)
    for k in AWG_CPS:
        if k in iface:
            ep[k] = iface[k]
    return ep


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

    p_path = pick_conf("личный", personal_patterns())
    c_path = pick_conf("корпоративный", CORP_PAT, exclude=p_path)

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

    dns_servers = [{
        "type": "udp", "tag": "dns-personal",
        "server": "8.8.8.8", "detour": "awg-personal",
    }]
    dns_rules = []
    if corp_dns:
        dns_servers.insert(0, {
            "type": "udp", "tag": "dns-corp",
            "server": corp_dns[0], "detour": "wg-corp",
        })
        dns_rules.append({"domain_suffix": domains, "server": "dns-corp"})

    config = {
        "log": {"level": "info", "timestamp": True},
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
