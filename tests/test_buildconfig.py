"""Разбор .conf и сборка config.json для sing-box.

Сюда попадают чужие файлы: конфиг рабочей сети выдаёт админ, личный — сервер
или панель провайдера. Формат у всех немного свой, и ошибка разбора обычно
не падает, а тихо собирает туннель не туда.
"""

import json
import socket
import threading
import time

import pytest

from dualvpn import buildconfig, paths, tunnels


CORP = """
[Interface]
PrivateKey = cHJpdmF0ZS1jb3JwLWtleQ==
Address = 10.1.2.3/32
DNS = 10.0.0.53

[Peer]
PublicKey = cHVibGljLWNvcnAta2V5
Endpoint = 198.51.100.10:51820
AllowedIPs = 10.10.0.0/16, 192.168.77.0/24
"""

PERSONAL_AWG = """
[Interface]
PrivateKey = cHJpdmF0ZS1wZXJzb25hbA==
Address = 10.9.0.2/32
MTU = 1420
Jc = 4
S1 = 30
H1 = 1234567
H2 = 100-200

[Peer]
PublicKey = cHVibGljLXBlcnNvbmFs
Endpoint = 203.0.113.5:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# --------------------------------------------------------------- разбор

def test_секции_разбираются_с_приведением_регистра(tmp_path):
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", CORP))
    assert conf["interface"]["privatekey"] == "cHJpdmF0ZS1jb3JwLWtleQ=="
    assert conf["peer"]["endpoint"] == "198.51.100.10:51820"


def test_комментарии_не_попадают_в_значения(tmp_path):
    text = "[Interface]\nPrivateKey = key  # это ключ\n\n[Peer]\nPublicKey = pub\n"
    conf = buildconfig.parse_conf(_write(tmp_path, "x.conf", text))
    assert conf["interface"]["privatekey"] == "key"


def test_без_секции_peer_это_ошибка(tmp_path):
    text = "[Interface]\nPrivateKey = key\n"
    with pytest.raises(SystemExit):
        buildconfig.parse_conf(_write(tmp_path, "x.conf", text))


# ------------------------------------------------------------- маршруты

def test_подсети_туннеля_берутся_из_allowedips(tmp_path):
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", CORP))
    assert buildconfig.allowed_nets(conf) == ["10.10.0.0/16", "192.168.77.0/24"]


def test_ноль_маршрут_и_ipv6_без_v6_на_tun_отбрасываются(tmp_path):
    """AllowedIPs = 0.0.0.0/0 у туннеля «по списку» забрал бы весь трафик."""
    text = CORP.replace("10.10.0.0/16, 192.168.77.0/24",
                        "0.0.0.0/0, 10.10.0.0/16, ::/0, fd00::/64")
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", text))

    assert buildconfig.allowed_nets(conf) == ["10.10.0.0/16"]
    assert buildconfig.allowed_nets(conf, v6=True) == ["10.10.0.0/16", "fd00::/64"]


def test_записи_списка_делятся_на_подсети_и_домены():
    """*.x — только поддомены (.x), x — сам домен с поддоменами."""
    nets, domains = buildconfig.split_entries(
        ["corp.example", "*.intra.example", "198.51.100.7/32", "10.0.0.0/8",
         "2001:db8::/32"])

    assert nets == ["198.51.100.7/32", "10.0.0.0/8"]
    assert domains == ["corp.example", ".intra.example"]


def test_ipv6_из_списка_остаётся_при_v6_на_tun():
    assert buildconfig.split_entries(["2001:db8::/32"], v6=True) == (
        ["2001:db8::/32"], [])


def test_правило_без_исключений_одно_условие_или():
    rule = buildconfig.tunnel_rule(["10.0.0.0/8"], ["corp.example"], [], [],
                                   "socks-work")
    assert rule == {"ip_cidr": ["10.0.0.0/8"], "domain_suffix": ["corp.example"],
                    "outbound": "socks-work"}


def test_исключение_это_отрицание_внутри_и():
    """/32 внутри /16 из AllowedIPs раньше не исключался: SB_CORP_EXCLUDE
    выкидывал только подсети, целиком лежащие в исключении."""
    rule = buildconfig.tunnel_rule(["10.10.0.0/16"], [], ["10.10.5.9/32"],
                                   ["git.corp.example"], "socks-work")

    assert rule == {"type": "logical", "mode": "and", "rules": [
        {"ip_cidr": ["10.10.0.0/16"]},
        {"ip_cidr": ["10.10.5.9/32"], "domain_suffix": ["git.corp.example"],
         "invert": True}],
        "outbound": "socks-work"}


def test_пускать_нечего_правила_нет():
    """Правило без условий sing-box считает совпадением со всем."""
    assert buildconfig.tunnel_rule([], [], ["10.0.0.1/32"], [], "socks-x") is None


@pytest.mark.parametrize("host, kept", [
    ("vpn.corp.example", [".other.example", "intra.example"]),
    ("corp.example", [".corp.example", ".other.example", "intra.example"]),
    ("198.51.100.10", ["corp.example", ".corp.example", ".other.example",
                       "intra.example"]),
])
def test_домен_сервера_не_уходит_в_dns_туннеля(host, kept):
    """Имя сервера пришлось бы резолвить через DNS, доступный только когда
    туннель уже поднят, — замкнутый круг."""
    domains = ["corp.example", ".corp.example", ".other.example", "intra.example"]
    assert buildconfig.off_endpoint(domains, host) == kept

# ------------------------------------------------------------- endpoint

def test_endpoint_собирается_из_конфига(tmp_path):
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", CORP))
    ep = buildconfig.endpoint(conf, "wg-corp", 1280)

    assert ep["type"] == "wireguard"
    assert ep["tag"] == "wg-corp"
    assert ep["mtu"] == 1280                       # в конфиге строки MTU нет
    assert ep["address"] == ["10.1.2.3/32"]
    assert ep["peers"][0]["address"] == "198.51.100.10"
    assert ep["peers"][0]["port"] == 51820


def test_mtu_из_конфига_важнее_умолчания(tmp_path):
    text = CORP.replace("DNS = 10.0.0.53", "DNS = 10.0.0.53\nMTU = 1420")
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", text))
    assert buildconfig.endpoint(conf, "wg-corp", 1280)["mtu"] == 1420


def test_awg_с_junk_режет_mtu_до_1280(tmp_path, capsys):
    """S1–S4 удлиняют пакеты: с 1420 из файла они не пролезают в мобильной сети."""
    path = _write(tmp_path, "p.conf", PERSONAL_AWG)
    conf = buildconfig.parse_conf(path)

    assert buildconfig.endpoint(conf, "awg-personal", 1280)["mtu"] == 1280
    assert "MTU 1420 -> 1280" in capsys.readouterr().out
    assert "MTU = 1420" in (tmp_path / "p.conf").read_text(encoding="utf-8")


def test_awg_с_нулевым_junk_mtu_не_трогает(tmp_path):
    """Jc = 0, S1 = 0 — пакеты как у обычного WireGuard, удлинения нет."""
    text = PERSONAL_AWG.replace("Jc = 4", "Jc = 0").replace("S1 = 30", "S1 = 0")
    conf = buildconfig.parse_conf(_write(tmp_path, "p.conf", text))
    assert buildconfig.endpoint(conf, "awg-personal", 1280)["mtu"] == 1420


def test_awg_с_малым_mtu_не_поднимается(tmp_path):
    text = PERSONAL_AWG.replace("MTU = 1420", "MTU = 1200")
    conf = buildconfig.parse_conf(_write(tmp_path, "p.conf", text))
    assert buildconfig.endpoint(conf, "awg-personal", 1280)["mtu"] == 1200


def test_awg_поля_числа_числами_диапазоны_строками(tmp_path):
    """H1..H4 бывают и числом, и диапазоном вида 100-200 — их не сломать."""
    conf = buildconfig.parse_conf(_write(tmp_path, "p.conf", PERSONAL_AWG))
    ep = buildconfig.endpoint(conf, "awg-personal", 1280)

    assert ep["jc"] == 4
    assert ep["s1"] == 30
    assert ep["h1"] == 1234567
    assert ep["h2"] == "100-200"


def test_keepalive_переносится(tmp_path):
    conf = buildconfig.parse_conf(_write(tmp_path, "p.conf", PERSONAL_AWG))
    ep = buildconfig.endpoint(conf, "awg-personal", 1280)
    assert ep["peers"][0]["persistent_keepalive_interval"] == 25


def test_обычный_wireguard_без_awg_полей(tmp_path):
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", CORP))
    ep = buildconfig.endpoint(conf, "wg-corp", 1280)
    assert not any(k in ep for k in ("jc", "s1", "h1"))


@pytest.mark.parametrize("missing", ["PrivateKey", "PublicKey", "Endpoint", "AllowedIPs"])
def test_без_обязательного_поля_сборка_прекращается(tmp_path, missing):
    text = "\n".join(l for l in CORP.splitlines()
                     if not l.strip().startswith(missing))
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", text))
    with pytest.raises(SystemExit):
        buildconfig.endpoint(conf, "wg-corp", 1280)


def test_порт_обязан_быть_числом(tmp_path):
    text = CORP.replace("198.51.100.10:51820", "198.51.100.10:не-порт")
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", text))
    with pytest.raises(SystemExit):
        buildconfig.endpoint(conf, "wg-corp", 1280)


# ------------------------------------------------------ резолв адреса пира

@pytest.fixture
def peer(tmp_path, monkeypatch):
    """Конфиг с именем сервера, файл прошлых адресов во временной папке."""
    monkeypatch.setattr(paths, "PEER_IPS_FILE", str(tmp_path / "peer-ips.json"))
    monkeypatch.setattr(buildconfig, "SYSTEM_DNS_WAIT", 0.2)
    asked = []

    def via(name, server, timeout=4.0):
        asked.append(server)
        return ""
    monkeypatch.setattr(buildconfig.winnet, "resolve4_via", via)
    text = CORP.replace("198.51.100.10:51820", "vpn.example.com:51820")
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", text))
    return conf, asked


def _system_dns(monkeypatch, answer):
    def getaddrinfo(name, *a, **kw):
        if isinstance(answer, Exception):
            raise answer
        return [(None, None, None, "", (answer, 0))]
    monkeypatch.setattr(buildconfig.socket, "getaddrinfo", getaddrinfo)


def _known(tmp_path):
    return json.loads((tmp_path / "peer-ips.json").read_text(encoding="utf-8"))


def test_системный_dns_главный_и_адрес_запоминается(peer, monkeypatch, tmp_path):
    """В корп-сети системный DNS отдаёт внутренний адрес, а публичный оттуда
    молчит — ответ публичного DNS его не перебивает."""
    conf, asked = peer
    _system_dns(monkeypatch, "10.20.0.1")
    monkeypatch.setattr(buildconfig.winnet, "resolve4_via",
                        lambda name, server, timeout=4.0: "203.0.113.9")

    ep = buildconfig.endpoint(conf, "wg-corp", 1280)

    assert ep["peers"][0]["address"] == "10.20.0.1"
    assert _known(tmp_path) == {"vpn.example.com": "10.20.0.1"}


def test_без_системного_dns_адрес_через_публичный(peer, monkeypatch, tmp_path):
    conf, asked = peer
    _system_dns(monkeypatch, socket.gaierror(11001, "getaddrinfo failed"))
    monkeypatch.setattr(buildconfig.winnet, "resolve4_via",
                        lambda name, server, timeout=4.0:
                        asked.append(server) or ("" if server == "8.8.8.8" else "203.0.113.9"))
    lines = []

    ep = buildconfig.endpoint(conf, "wg-corp", 1280, lines.append)

    assert ep["peers"][0]["address"] == "203.0.113.9"
    assert sorted(asked) == ["1.1.1.1", "8.8.8.8"]
    assert "203.0.113.9 через 1.1.1.1" in lines[0]
    assert _known(tmp_path) == {"vpn.example.com": "203.0.113.9"}


def test_зависший_системный_dns_не_держит_дольше_потолка(peer, monkeypatch):
    """getaddrinfo висел 12 с, пока DNS роутера молчал, — столько стоило переподключение."""
    conf, asked = peer
    release = threading.Event()
    monkeypatch.setattr(buildconfig.socket, "getaddrinfo",
                        lambda *a, **kw: release.wait(5) and [])
    monkeypatch.setattr(buildconfig.winnet, "resolve4_via",
                        lambda name, server, timeout=4.0: "203.0.113.9")
    started = time.monotonic()

    try:
        ep = buildconfig.endpoint(conf, "wg-corp", 1280, lambda line: None)
    finally:
        release.set()

    assert time.monotonic() - started < 2
    assert ep["peers"][0]["address"] == "203.0.113.9"


def _silent_dns(monkeypatch, release):
    """Все DNS молчат: системный висит, публичные дожидаются своего таймаута."""
    monkeypatch.setattr(buildconfig.socket, "getaddrinfo",
                        lambda *a, **kw: release.wait(5) and [])
    monkeypatch.setattr(buildconfig.winnet, "resolve4_via",
                        lambda name, server, timeout=4.0:
                        release.wait(min(timeout, 0.5)) and "")


def test_все_dns_спрашиваются_разом(peer, monkeypatch, tmp_path):
    """По очереди молчащие системный, 8.8.8.8 и 1.1.1.1 стоили 12 с — три потолка."""
    conf, _ = peer
    (tmp_path / "peer-ips.json").write_text(
        json.dumps({"vpn.example.com": "10.20.0.1"}), encoding="utf-8")
    monkeypatch.setattr(buildconfig, "SYSTEM_DNS_WAIT", 0.5)
    release = threading.Event()
    _silent_dns(monkeypatch, release)
    started = time.monotonic()

    try:
        ep = buildconfig.endpoint(conf, "wg-corp", 1280, lambda line: None)
    finally:
        release.set()

    assert time.monotonic() - started < 1.0
    assert ep["peers"][0]["address"] == "10.20.0.1"


def test_без_всякого_dns_берётся_прошлый_адрес(peer, monkeypatch, tmp_path):
    conf, asked = peer
    (tmp_path / "peer-ips.json").write_text(
        json.dumps({"vpn.example.com": "10.20.0.1"}), encoding="utf-8")
    _system_dns(monkeypatch, socket.gaierror(11001, "getaddrinfo failed"))
    lines = []

    ep = buildconfig.endpoint(conf, "wg-corp", 1280, lines.append)

    assert ep["peers"][0]["address"] == "10.20.0.1"
    assert sorted(asked) == ["1.1.1.1", "8.8.8.8"]
    assert "прошлый адрес 10.20.0.1" in lines[0]


@pytest.mark.parametrize("saved", [None, "{битый", '{"vpn.example.com": "не-адрес"}'])
def test_без_dns_и_прошлого_адреса_сборка_прекращается(peer, monkeypatch, tmp_path, saved):
    conf, _ = peer
    if saved is not None:
        (tmp_path / "peer-ips.json").write_text(saved, encoding="utf-8")
    _system_dns(monkeypatch, socket.gaierror(11001, "getaddrinfo failed"))

    with pytest.raises(SystemExit, match="vpn.example.com"):
        buildconfig.endpoint(conf, "wg-corp", 1280)


# ---------------------------------------------------------------- DNS

def test_dns_туннеля_по_tcp_через_его_socks():
    """По UDP ответы корп-DNS терялись, и запрос висел до таймаута sing-box."""
    servers, rules = buildconfig.dns_section(
        [("work", "10.0.0.53", ["corp.example"])], "out")

    assert servers[0] == {"type": "tcp", "tag": "dns-work",
                          "server": "10.0.0.53", "detour": "socks-work"}
    assert servers[1] == {"type": "udp", "tag": "dns", "server": "8.8.8.8",
                          "detour": "out"}
    assert rules == [{"domain_suffix": ["corp.example"], "server": "dns-work"}]


def test_без_доменов_правила_dns_нет():
    """Пустой domain_suffix sing-box считает совпадением со всем: любое имя
    уходило в корп-DNS — проверено живьём на 1.14.2-lx.11."""
    servers, rules = buildconfig.dns_section([("work", "10.0.0.53", [])], "out")
    assert servers[0]["tag"] == "dns-work"
    assert rules == []


def test_без_основного_туннеля_публичный_dns_напрямую():
    """detour на пустой direct sing-box отвергает."""
    servers, _ = buildconfig.dns_section([], None)
    assert servers == [{"type": "udp", "tag": "dns", "server": "8.8.8.8"}]


# ----------------------------------------------------- сборка целиком

LAB = (CORP.replace("DNS = 10.0.0.53\n", "")
       .replace("198.51.100.10", "198.51.100.20")
       .replace("10.10.0.0/16, 192.168.77.0/24", "172.20.0.0/16"))
CONFS = {"work": CORP, "lab": LAB, "home": PERSONAL_AWG}


def _tunnel(tid, mode, include=(), exclude=()):
    return {"id": tid, "name": tid.title(), "mode": mode,
            "include": list(include), "exclude": list(exclude)}


THREE = [
    _tunnel("work", "list", ["corp.example", "*.intra.example"],
            ["10.10.5.9", "git.corp.example"]),
    _tunnel("lab", "list", ["203.0.113.9"]),
    _tunnel("home", "all", exclude=["198.51.100.7"]),
]


@pytest.fixture
def build(tmp_path, monkeypatch):
    """Собирает туннели во временную state\\: (основной, {id: боковой})."""
    monkeypatch.setattr(paths, "STATE", str(tmp_path))

    def run(items, level="info", texts=CONFS):
        data = tunnels.validate({"log_level": level, "tunnels": items})
        confs = {t["id"]: _write(tmp_path, f"{t['id']}.conf", texts[t["id"]])
                 for t in data["tunnels"]}
        ids = buildconfig.build(data, confs, str(tmp_path / "config.json"),
                                log=lambda line: None)
        main = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
        return main, {tid: json.loads(open(buildconfig.side_json(tid),
                                           encoding="utf-8").read())
                      for tid in ids}
    return run


def _by_tag(items, tag):
    return next(i for i in items if i.get("tag") == tag)


def test_каждый_туннель_живёт_в_своём_конфиге(build):
    """Сторож перезапускает туннель один, не трогая tun и другие туннели."""
    main, sides = build(THREE)

    assert "endpoints" not in main
    assert list(sides) == ["work", "lab", "home"]
    for tid, cfg in sides.items():
        assert [e["tag"] for e in cfg["endpoints"]] == [f"wg-{tid}"]
        assert cfg["route"]["final"] == f"wg-{tid}"
        # Автоопределение привязало бы сокет к tun основного процесса.
        assert cfg["route"]["auto_detect_interface"] is False


def test_endpoint_пускает_всё_что_отдал_основной(build):
    """С AllowedIPs из файла домены и адреса из «пускать» отбрасывались бы
    внутри endpoint."""
    _, sides = build(THREE)
    for cfg in sides.values():
        assert cfg["endpoints"][0]["peers"][0]["allowed_ips"] == ["0.0.0.0/0"]


def test_у_каждого_туннеля_свой_socks_с_паролем(build):
    main, sides = build(THREE)

    passwords = set()
    for tid, cfg in sides.items():
        socks = _by_tag(main["outbounds"], f"socks-{tid}")
        inbound = _by_tag(cfg["inbounds"], "socks-in")
        assert inbound["listen"] == socks["server"] == "127.0.0.1"
        assert socks["server_port"] == inbound["listen_port"]
        assert inbound["users"] == [{"username": socks["username"],
                                     "password": socks["password"]}]
        assert len(socks["password"]) >= 24
        passwords.add(socks["password"])
    assert len(passwords) == 3


def test_пароль_socks_новый_на_каждую_сборку(build):
    first, _ = build(THREE)
    second, _ = build(THREE)
    assert (_by_tag(first["outbounds"], "socks-work")["password"]
            != _by_tag(second["outbounds"], "socks-work")["password"])


def test_порядок_правил_списки_локальная_сеть_мимо_vpn(build):
    main, _ = build(THREE)

    assert main["route"]["rules"] == [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"type": "logical", "mode": "and", "rules": [
            {"ip_cidr": ["10.10.0.0/16", "192.168.77.0/24"],
             "domain_suffix": ["corp.example", ".intra.example"]},
            {"ip_cidr": ["10.10.5.9/32"], "domain_suffix": ["git.corp.example"],
             "invert": True}],
         "outbound": "socks-work"},
        {"ip_cidr": ["172.20.0.0/16", "203.0.113.9/32"], "outbound": "socks-lab"},
        {"ip_cidr": buildconfig.LOCAL_NETS, "outbound": "direct"},
        {"ip_cidr": ["198.51.100.7/32"], "outbound": "direct"},
    ]


def test_остальное_через_основной_с_запасным_direct(build):
    main, sides = build(THREE)

    assert main["route"]["final"] == "out"
    out = _by_tag(main["outbounds"], "out")
    assert out["type"] == "selector"
    assert out["outbounds"] == ["socks-home", "direct"]
    assert out["default"] == "socks-home"
    assert main["inbounds"][0]["mtu"] == sides["home"]["endpoints"][0]["mtu"]
    assert buildconfig.api_of(main)[0].startswith("127.0.0.1:")
    assert buildconfig.api_of(main)[1]


def test_dns_только_у_туннелей_по_списку_с_dns_в_conf(build):
    main, _ = build(THREE)

    assert main["dns"]["servers"] == [
        {"type": "tcp", "tag": "dns-work", "server": "10.0.0.53",
         "detour": "socks-work"},
        {"type": "udp", "tag": "dns", "server": "8.8.8.8", "detour": "out"},
    ]
    assert main["dns"]["rules"] == [
        {"domain_suffix": ["corp.example", ".intra.example"], "server": "dns-work"}]
    assert main["dns"]["final"] == "dns"
    assert main["route"]["default_domain_resolver"] == "dns"


def test_без_основного_туннеля_остальное_напрямую(build):
    main, sides = build(THREE[:2])

    assert list(sides) == ["work", "lab"]
    assert main["route"]["final"] == "direct"
    assert not any(o["tag"] == "out" for o in main["outbounds"])
    assert "detour" not in _by_tag(main["dns"]["servers"], "dns")
    assert main["inbounds"][0]["mtu"] == 1280


def test_уровень_журнала_во_всех_конфигах(build):
    main, sides = build(THREE, level="debug")
    assert {main["log"]["level"]} | {s["log"]["level"] for s in sides.values()} == {"debug"}


def test_v6_только_когда_он_есть_у_основного(build):
    texts = dict(CONFS, home=PERSONAL_AWG.replace(
        "Address = 10.9.0.2/32", "Address = 10.9.0.2/32, fd00::2/128"))

    main, sides = build(THREE, texts=texts)
    assert "fdfe:dcba:9876::1/126" in main["inbounds"][0]["address"]
    assert sides["work"]["endpoints"][0]["peers"][0]["allowed_ips"] == [
        "0.0.0.0/0", "::/0"]

    main, _ = build(THREE)
    assert main["inbounds"][0]["address"] == ["172.19.0.1/30"]


def test_туннель_без_конфига_пропускается(build, tmp_path):
    """Пустой слот (рабочий после переезда без рабочего .conf) не держит остальные."""
    data = tunnels.validate({"tunnels": THREE})
    confs = {"home": _write(tmp_path, "home.conf", PERSONAL_AWG)}
    lines = []

    assert buildconfig.build(data, confs, str(tmp_path / "c.json"),
                             log=lines.append) == ["home"]
    assert any("«Work»: конфига нет" in line for line in lines)


def test_ни_одного_конфига_это_ошибка(tmp_path):
    data = tunnels.validate({"tunnels": THREE})
    with pytest.raises(SystemExit, match="ни у одного туннеля нет конфига"):
        buildconfig.build(data, {}, str(tmp_path / "c.json"))


def test_помощники_читают_собранный_конфиг(build):
    """Служба, пробер и окно находят туннели по этим функциям, а не по строкам."""
    main, _ = build(THREE)

    assert buildconfig.side_ids(main) == ["work", "lab", "home"]
    assert buildconfig.side_link(main, "lab")["port"] == _by_tag(
        main["outbounds"], "socks-lab")["server_port"]
    assert buildconfig.side_link(main, "нет") is None
    assert buildconfig.tunnel_dns(main) == {"work": "10.0.0.53"}
    assert buildconfig.tunnel_domains(main) == ["corp.example", ".intra.example"]
    assert buildconfig.tunnel_nets(main, "work") == ["10.10.0.0/16", "192.168.77.0/24"]
    assert buildconfig.tunnel_nets(main, "lab") == ["172.20.0.0/16", "203.0.113.9/32"]


@pytest.mark.parametrize("tag, ep", [
    ("socks-work", "wg-work"), ("socks-", "socks-"), ("direct", "direct"),
])
def test_socks_выход_в_статистике_под_тегом_туннеля(tag, ep):
    assert buildconfig.ep_of_socks(tag) == ep


# ----------------------------------------------- main: откуда туннели

@pytest.fixture
def state(tmp_path, monkeypatch):
    """conf\\ и state\\ во временной папке, sing-box не запущен."""
    state = tmp_path / "state"
    for kind, text in (("corp", CORP), ("personal", PERSONAL_AWG)):
        d = tmp_path / "conf" / kind
        d.mkdir(parents=True)
        (d / f"{kind}.conf").write_text(text, encoding="utf-8")
    monkeypatch.setattr(buildconfig, "CONF_CORP", str(tmp_path / "conf" / "corp"))
    monkeypatch.setattr(buildconfig, "CONF_PERSONAL",
                        str(tmp_path / "conf" / "personal"))
    monkeypatch.setattr(paths, "STATE", str(state))
    monkeypatch.setattr(paths, "CONFIG_JSON", str(state / "config.json"))
    monkeypatch.setattr(paths, "TUNNELS_JSON", str(tmp_path / "conf" / "tunnels.json"))
    monkeypatch.setattr(paths, "CONF_TUNNELS", str(tmp_path / "conf" / "tunnels"))
    monkeypatch.setattr(buildconfig, "running_pid", lambda: "")
    monkeypatch.setattr(buildconfig.sys, "argv", ["buildconfig"])
    for key in ("SB_PERSONAL", "SB_CORP_EXCLUDE", "CORP_DOMAINS", "SB_LOG_LEVEL"):
        monkeypatch.delenv(key, raising=False)
    return state


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_без_tunnels_json_собирает_рабочий_и_личный_из_site_env(state, monkeypatch):
    """До переезда правила из site.env дают ту же сборку, что дал бы migrate."""
    monkeypatch.setenv("CORP_DOMAINS", "corp.example")
    monkeypatch.setenv("SB_CORP_EXCLUDE", "10.10.5.9")

    buildconfig.main(log=lambda line: None)

    main = _load(state / "config.json")
    assert buildconfig.side_ids(main) == ["work", "home"]
    assert (state / "tunnel-work.json").exists()
    assert (state / "tunnel-home.json").exists()
    rule = next(r for r in main["route"]["rules"] if r.get("outbound") == "socks-work")
    assert rule["rules"][0]["domain_suffix"] == ["corp.example"]
    assert rule["rules"][1] == {"ip_cidr": ["10.10.5.9/32"], "invert": True}
    assert _by_tag(main["outbounds"], "out")["default"] == buildconfig.PERSONAL_SOCKS_TAG


def test_без_рабочего_конфига_старая_сборка_отказывает(state, tmp_path):
    """Окно до переезда тоже не даёт включить без рабочего конфига."""
    (tmp_path / "conf" / "corp" / "corp.conf").unlink()
    with pytest.raises(SystemExit, match="рабочий конфиг не добавлен"):
        buildconfig.main(log=lambda line: None)


def test_с_tunnels_json_собирает_из_него(state, tmp_path):
    d = tmp_path / "conf" / "tunnels" / "lab"
    d.mkdir(parents=True)
    (d / "lab-1.conf").write_text(LAB, encoding="utf-8")
    tunnels.save({"tunnels": [_tunnel("lab", "list")]})

    buildconfig.main(log=lambda line: None)

    assert buildconfig.side_ids(_load(state / "config.json")) == ["lab"]


def test_испорченный_tunnels_json_это_внятная_ошибка(state, tmp_path):
    (tmp_path / "conf" / "tunnels.json").write_text("{", encoding="utf-8")
    with pytest.raises(SystemExit, match="tunnels.json не читается"):
        buildconfig.main(log=lambda line: None)


def test_старые_и_лишние_боковые_конфиги_удаляются(state):
    """В них приватные ключи туннелей, которых больше нет."""
    state.mkdir()
    for name in ("corp.json", "personal.json", "tunnel-old.json", "status.json"):
        (state / name).write_text("{}", encoding="utf-8")

    buildconfig.main(log=lambda line: None)

    assert sorted(p.name for p in state.iterdir()) == [
        "config.json", "status.json", "tunnel-home.json", "tunnel-work.json"]
# -------------------------------------------------------------- мелочи

@pytest.mark.parametrize("value, level", [
    (None, "info"), ("", "info"), ("debug", "debug"), (" DEBUG ", "debug"),
    ("verbose", "info"),
])
def test_уровень_журнала_из_site_env(monkeypatch, value, level):
    if value is None:
        monkeypatch.delenv("SB_LOG_LEVEL", raising=False)
    else:
        monkeypatch.setenv("SB_LOG_LEVEL", value)

    assert buildconfig.log_level() == level


def test_split_list_режет_по_запятой_и_чистит_пробелы():
    assert buildconfig.split_list(" a , b ,, c ") == ["a", "b", "c"]


@pytest.mark.parametrize("value,ok", [
    ("10.0.0.0/8", True),
    ("192.168.1.1/32", True),
    ("::/0", True),
    ("не-адрес", False),
    ("", False),
])
def test_распознавание_cidr(value, ok):
    assert buildconfig._is_cidr(value) is ok
