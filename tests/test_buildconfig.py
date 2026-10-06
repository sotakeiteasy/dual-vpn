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

from dualvpn import buildconfig, paths


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

def test_корп_маршруты_берутся_из_allowedips(tmp_path):
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", CORP))
    assert buildconfig.corp_routes(conf) == ["10.10.0.0/16", "192.168.77.0/24"]


def test_ноль_маршрут_в_корпе_отбрасывается(tmp_path):
    """AllowedIPs = 0.0.0.0/0 у рабочего конфига забрал бы весь трафик."""
    text = CORP.replace("10.10.0.0/16, 192.168.77.0/24",
                        "0.0.0.0/0, 10.10.0.0/16")
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", text))
    assert buildconfig.corp_routes(conf) == ["10.10.0.0/16"]


def test_корп_без_единой_подсети_это_ошибка(tmp_path):
    text = CORP.replace("10.10.0.0/16, 192.168.77.0/24", "0.0.0.0/0")
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", text))
    with pytest.raises(SystemExit):
        buildconfig.corp_routes(conf)


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


def test_системный_dns_первым_и_адрес_запоминается(peer, monkeypatch, tmp_path):
    """В корп-сети системный DNS отдаёт внутренний адрес — публичный не спрашиваем."""
    conf, asked = peer
    _system_dns(monkeypatch, "10.20.0.1")

    ep = buildconfig.endpoint(conf, "wg-corp", 1280)

    assert ep["peers"][0]["address"] == "10.20.0.1"
    assert asked == []
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
    assert asked == ["8.8.8.8", "1.1.1.1"]
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


def test_без_всякого_dns_берётся_прошлый_адрес(peer, monkeypatch, tmp_path):
    conf, asked = peer
    (tmp_path / "peer-ips.json").write_text(
        json.dumps({"vpn.example.com": "10.20.0.1"}), encoding="utf-8")
    _system_dns(monkeypatch, socket.gaierror(11001, "getaddrinfo failed"))
    lines = []

    ep = buildconfig.endpoint(conf, "wg-corp", 1280, lines.append)

    assert ep["peers"][0]["address"] == "10.20.0.1"
    assert asked == ["8.8.8.8", "1.1.1.1"]
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

def test_корп_dns_по_tcp_через_корп_туннель():
    """По UDP ответы корп-DNS терялись, и запрос висел до таймаута sing-box."""
    servers, rules = buildconfig.dns_section(["10.0.0.53"], ["corp.example"])

    assert servers[0] == {"type": "tcp", "tag": "dns-corp",
                          "server": "10.0.0.53", "detour": "corp-socks"}
    assert servers[1]["tag"] == "dns-personal"
    assert rules == [{"domain_suffix": ["corp.example"], "server": "dns-corp"}]


def test_без_корп_доменов_правила_dns_нет():
    """Пустой domain_suffix sing-box считает совпадением со всем: любое имя
    уходило в корп-DNS — проверено живьём на 1.14.2-lx.11."""
    servers, rules = buildconfig.dns_section(["10.0.0.53"], [])
    assert servers[0]["tag"] == "dns-corp"
    assert rules == []


def test_публичный_dns_идёт_выходом_с_запасным_direct():
    """Через awg-personal напрямую при мёртвом личном не резолвилось бы
    ничего — и запасной direct был бы бесполезен."""
    servers, _ = buildconfig.dns_section([], [])
    assert servers[0]["detour"] == "out"


# ----------------------------------------------------- сборка целиком

@pytest.fixture
def built(tmp_path, monkeypatch):
    """Собирает оба конфига из CORP и PERSONAL_AWG во временную папку."""
    state = tmp_path / "state"
    for kind, text in (("corp", CORP), ("personal", PERSONAL_AWG)):
        d = tmp_path / "conf" / kind
        d.mkdir(parents=True)
        (d / f"{kind}.conf").write_text(text, encoding="utf-8")
    monkeypatch.setattr(buildconfig, "CONF_CORP", str(tmp_path / "conf" / "corp"))
    monkeypatch.setattr(buildconfig, "CONF_PERSONAL",
                        str(tmp_path / "conf" / "personal"))
    monkeypatch.setattr(buildconfig, "STATE", str(state))
    monkeypatch.setattr(paths, "CORP_JSON", str(state / "corp.json"))
    monkeypatch.setattr(buildconfig, "running_pid", lambda: "")
    monkeypatch.setattr(buildconfig.sys, "argv", ["buildconfig"])
    for key in ("SB_PERSONAL", "SB_CORP_EXCLUDE", "CORP_DOMAINS"):
        monkeypatch.delenv(key, raising=False)

    def load():
        buildconfig.main(log=lambda line: None)
        return (json.loads((state / "config.json").read_text(encoding="utf-8")),
                json.loads((state / "corp.json").read_text(encoding="utf-8")))
    return load


def _by_tag(items, tag):
    return next(i for i in items if i.get("tag") == tag)


def test_корп_живёт_в_своём_конфиге(built):
    """Сторож перезапускает корп один, не трогая tun и личный туннель."""
    main, corp = built()

    assert [e["tag"] for e in main["endpoints"]] == ["awg-personal"]
    assert [e["tag"] for e in corp["endpoints"]] == ["wg-corp"]
    assert corp["route"]["final"] == "wg-corp"
    # Автоопределение привязало бы сокет к tun основного процесса.
    assert corp["route"]["auto_detect_interface"] is False


def test_корп_подсети_и_корп_dns_идут_в_socks_с_паролем(built):
    main, corp = built()

    rule = next(r for r in main["route"]["rules"] if "ip_cidr" in r
                and r["outbound"] != "direct")
    assert rule == {"ip_cidr": ["10.10.0.0/16", "192.168.77.0/24"],
                    "outbound": "corp-socks"}
    assert _by_tag(main["dns"]["servers"], "dns-corp")["detour"] == "corp-socks"

    socks = _by_tag(main["outbounds"], "corp-socks")
    inbound = _by_tag(corp["inbounds"], "socks-in")
    assert inbound["listen"] == "127.0.0.1"
    assert socks["server"] == "127.0.0.1"
    assert socks["server_port"] == inbound["listen_port"]
    assert inbound["users"] == [{"username": socks["username"],
                                 "password": socks["password"]}]
    assert len(socks["password"]) >= 24


def test_пароль_socks_новый_на_каждую_сборку(built):
    first, _ = built()
    second, _ = built()
    assert (_by_tag(first["outbounds"], "corp-socks")["password"]
            != _by_tag(second["outbounds"], "corp-socks")["password"])


def test_остальное_через_личный_с_запасным_direct(built):
    main, _ = built()

    assert main["route"]["final"] == "out"
    out = _by_tag(main["outbounds"], "out")
    assert out["type"] == "selector"
    assert out["outbounds"] == ["awg-personal", "direct"]
    assert out["default"] == "awg-personal"
    assert buildconfig.api_of(main)[0].startswith("127.0.0.1:")
    assert buildconfig.api_of(main)[1]


def test_перезапуск_корпа_меняет_только_адрес_пира(built, monkeypatch):
    """Основной процесс работает и знает порт и пароль socks — они остаются."""
    main, before = built()
    monkeypatch.setattr(buildconfig, "peer_host", lambda host, tag, log: "198.51.100.99")

    assert buildconfig.refresh_corp_peer(log=lambda line: None) == "198.51.100.99"

    after = json.loads(open(paths.CORP_JSON, encoding="utf-8").read())
    assert after["endpoints"][0]["peers"][0]["address"] == "198.51.100.99"
    after["endpoints"][0]["peers"][0]["address"] = "198.51.100.10"
    assert after == before
    assert buildconfig.corp_link(main)["port"] == before["inbounds"][0]["listen_port"]


def test_без_корп_dns_только_личный():
    servers, rules = buildconfig.dns_section([], ["corp.example"])
    assert [s["tag"] for s in servers] == ["dns-personal"]
    assert rules == []


def test_числовой_endpoint_не_даёт_доменов(tmp_path):
    """Иначе домен сервера пошёл бы резолвиться через корп-DNS, который
    доступен только когда туннель уже поднят — замкнутый круг."""
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", CORP))
    assert buildconfig.dns_domains(conf) == set()


def test_имя_сервера_даёт_домен_второго_уровня(tmp_path):
    text = CORP.replace("198.51.100.10:51820", "vpn.example.com:51820")
    conf = buildconfig.parse_conf(_write(tmp_path, "corp.conf", text))
    assert buildconfig.dns_domains(conf) == {"example.com"}


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
