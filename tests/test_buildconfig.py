"""Разбор .conf и сборка config.json для sing-box.

Сюда попадают чужие файлы: конфиг рабочей сети выдаёт админ, личный — сервер
или панель провайдера. Формат у всех немного свой, и ошибка разбора обычно
не падает, а тихо собирает туннель не туда.
"""

import pytest

from dualvpn import buildconfig


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
    conf = buildconfig.parse_conf(_write(tmp_path, "p.conf", PERSONAL_AWG))
    assert buildconfig.endpoint(conf, "awg-personal", 1280)["mtu"] == 1420


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


# ---------------------------------------------------------------- DNS

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
