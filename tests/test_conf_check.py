"""Проверка конфига отдельно от VPN (test-config): сервер отвечает или нет —
и при выключенном VPN, и у запасного, не роняя живой туннель."""

import contextlib
import os
import socket
import struct
import threading
import types

import pytest

from dualvpn import buildconfig, paths, probe, service, tunnel, tunnels

CONF = """[Interface]
PrivateKey = cHJpdmF0ZS1rZXktcHJpdmF0ZS1rZXktcHJpdmF0ZS0=
Address = 10.8.0.2/32
DNS = 10.8.0.1
[Peer]
PublicKey = cHVibGljLWtleS1wdWJsaWMta2V5LXB1YmxpYy1rZXk=
Endpoint = 198.51.100.7:51820
AllowedIPs = 10.8.0.0/24
"""


# ------------------------------------------------------------- DNS по TCP

def _reply(qid, name, ip=None, rcode=0):
    """Ответ DNS на _dns_query: вопрос и, с ip, A-запись с указателем сжатия."""
    query = probe._dns_query(name, qid)
    an = 1 if ip else 0
    head = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, an, 0, 0)
    body = query[12:]
    if ip:
        body += struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
    return head + body


def test_адрес_из_ответа_dns():
    assert probe._dns_addr(_reply(7, "corp.example", "10.1.2.3"), 7) == "10.1.2.3"


def test_nxdomain_это_ответ_без_адреса():
    assert probe._dns_addr(_reply(7, "corp.example", rcode=3), 7) == ""


def test_чужой_номер_запроса_не_ответ():
    assert probe._dns_addr(_reply(8, "corp.example", "10.1.2.3"), 7) is None


def test_кириллический_домен_уходит_в_idna():
    assert b"xn--" in probe._dns_query("сайт.рф", 1)


# ------------------------------------------------------------ trial_check

LINK = {"port": 1, "username": "u", "password": "p"}


def test_полный_работает_по_204(monkeypatch):
    monkeypatch.setattr(probe.Prober, "_http_code", staticmethod(lambda url, proxy="": "204"))
    assert probe.trial_check(LINK, True, "", "") == ("up", "HTTP 204")


def test_полный_молчит(monkeypatch):
    monkeypatch.setattr(probe.Prober, "_http_code", staticmethod(lambda url, proxy="": ""))
    assert probe.trial_check(LINK, True, "", "") == ("error", "сервер не отвечает")


def test_по_списку_ответ_dns_без_адреса_сети(monkeypatch):
    """Итог читает любой: адрес домена из рабочей сети в ответ не идёт."""
    monkeypatch.setattr(probe, "_dns_via_proxy", lambda link, server, name: "10.1.2.3")
    assert probe.trial_check(LINK, False, "corp.example", "10.8.0.1") == ("up", probe.BY_DNS)


def test_по_списку_dns_не_знает_домен_это_правила(monkeypatch):
    monkeypatch.setattr(probe, "_dns_via_proxy", lambda *a: probe.DNS_NO_ADDR)
    assert probe.trial_check(LINK, False, "corp.example", "10.8.0.1") == ("rules", "corp.example")


def test_по_списку_без_домена_спрашивает_служебное_имя(monkeypatch):
    asked = []
    monkeypatch.setattr(probe, "_dns_via_proxy",
                        lambda link, server, name: asked.append(name) or probe.DNS_NO_ADDR)
    assert probe.trial_check(LINK, False, "", "10.8.0.1") == ("up", probe.BY_DNS)
    assert asked == [probe.DNS_ASK_NAME]


def test_по_списку_без_dns_по_https(monkeypatch):
    seen = []
    monkeypatch.setattr(probe.Prober, "_http_code",
                        staticmethod(lambda url, proxy="": seen.append((url, proxy)) or "403"))
    assert probe.trial_check(LINK, False, "corp.example", "") == ("up", "HTTP 403")
    assert seen == [("https://corp.example", probe._proxy_url(LINK))]


# -------------------------------------------------------------- check_one

def _plan(monkeypatch, **p):
    item = {"id": "t1", "name": "t", "mode": "list", "host": "", "dns": "",
            "running": True, **p}
    monkeypatch.setattr(probe.Prober, "check_plan", staticmethod(lambda: [item]))


def test_живой_основной_проверяется_задержкой_через_его_socks(monkeypatch):
    _plan(monkeypatch, mode="all")
    tags = []
    assert probe.Prober().check_one("t1", lambda tag: tags.append(tag) or 42) == ("up", "42 мс")
    assert tags == [buildconfig.socks_tag("t1")]


def test_живой_по_списку_dns_ответил(monkeypatch):
    _plan(monkeypatch, dns="10.8.0.1", host="corp.example")
    monkeypatch.setattr(probe.Prober, "_dns_ask", staticmethod(lambda server, name: "10.1.2.3"))
    assert probe.Prober().check_one("t1", None) == ("up", probe.BY_DNS)


# ------------------------------------------------------------ Core._test_conf

class _Tunnel:
    """Туннель без системы: twin — id живого процесса с тем же ключом."""

    def __init__(self, twin=None, err=""):
        self.twin, self.err, self.trials = twin, err, []

    def side_with_key(self, key):
        return self.twin

    def delay(self, tag):
        return 10

    @contextlib.contextmanager
    def trial(self, tid, conf):
        self.trials.append(tid)
        yield (None, self.err) if self.err else (LINK, "")


@pytest.fixture
def core(monkeypatch):
    core = service.Core.__new__(service.Core)
    core._tests_lock, core._trial_lock = threading.Lock(), threading.Lock()
    core.log = lambda line: None
    core.tunnel = _Tunnel()
    core.prober = probe.Prober()
    return core


def _tunnel(monkeypatch, mode="list", include=(), text=CONF):
    data = tunnels.validate({"tunnels": [{"id": "t1", "name": "Работа", "mode": mode,
                                          "include": list(include)}]})
    monkeypatch.setattr(service.Core, "_tunnels", staticmethod(lambda: data))
    os.makedirs(tunnels.conf_dir("t1"), exist_ok=True)
    with open(tunnels.conf_path("t1", "w1"), "w", encoding="utf-8") as fh:
        fh.write(text)
    return data["tunnels"][0]


def test_нет_такого_конфига_отказ(core, monkeypatch):
    _tunnel(monkeypatch)
    reply = core._test_conf("t1", "..\\..\\x")
    assert not reply["ok"] and "нет конфига" in reply["error"]


def test_проверка_вне_vpn_через_временный_процесс(core, monkeypatch):
    _tunnel(monkeypatch, include=["corp.example"])
    seen = []
    monkeypatch.setattr(probe, "trial_check",
                        lambda link, full, host, dns: seen.append((full, host, dns)) or ("up", "по DNS"))

    reply = core._test_conf("t1", "w1")

    assert reply["ok"] and reply["test"]["result"] == "up"
    assert core.tunnel.trials == ["t1"] and seen == [(False, "corp.example", "10.8.0.1")]
    tests = core._tests_of("t1", ["w1"])
    assert tests["w1"]["result"] == "up" and tests["w1"]["checking"] is False


def test_тот_же_ключ_в_живом_процессе_проверяет_пробер(core, monkeypatch):
    """Второй процесс с тем же ключом увёл бы сервер у живого туннеля."""
    _tunnel(monkeypatch)
    core.tunnel = _Tunnel(twin="t1")
    monkeypatch.setattr(core.prober, "check_one", lambda tid, delay: ("up", "по DNS"))

    assert core._test_conf("t1", "w1")["test"]["result"] == "up"
    assert core.tunnel.trials == []


def test_нечем_проверить_без_запуска(core, monkeypatch):
    _tunnel(monkeypatch, text=CONF.replace("DNS = 10.8.0.1\n", ""))
    assert core._test_conf("t1", "w1")["test"]["result"] == "none"
    assert core.tunnel.trials == []


def test_процесс_не_поднялся_итог_ошибка(core, monkeypatch):
    _tunnel(monkeypatch)
    core.tunnel = _Tunnel(err="sing-box не запустился")
    test = core._test_conf("t1", "w1")["test"]
    assert (test["result"], test["answer"]) == ("error", "sing-box не запустился")


def test_заменённый_файл_прежний_итог_не_показывает(core, monkeypatch):
    _tunnel(monkeypatch)
    monkeypatch.setattr(probe, "trial_check", lambda *a: ("up", "по DNS"))
    core._test_conf("t1", "w1")
    path = tunnels.conf_path("t1", "w1")
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    assert core._tests_of("t1", ["w1"]) == {}


# -------------------------------------------------------------- Tunnel.trial

class _Proc:
    def poll(self):
        return None

    def terminate(self):
        self.ended = True

    def wait(self, timeout=None):
        return 0


@pytest.fixture
def routes(monkeypatch):
    """Таблица маршрутов: {префикс: [строки]}; added — что ставили."""
    table, added = {}, []
    monkeypatch.setattr(tunnel.winnet, "routes_for", lambda p: table.get(p, []))
    monkeypatch.setattr(tunnel.winnet, "add_routes", lambda rows: added.extend(rows) or [
        table.setdefault(p, []).append({"NextHop": gw, "InterfaceIndex": idx})
        for p, idx, gw, _ in rows])
    monkeypatch.setattr(tunnel.winnet, "del_route",
                        lambda p, idx: table.pop(p, None))
    monkeypatch.setattr(tunnel.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(tunnel, "_port_open", lambda port: True)
    monkeypatch.setattr(os.path, "isfile", lambda p: True)
    return types.SimpleNamespace(table=table, added=added)


def test_при_живом_vpn_временный_маршрут_к_пиру_снимается(routes):
    t = tunnel.Tunnel(lambda line: None)
    t.uplink = (5, "192.168.1.1")
    conf = buildconfig.parse_text(CONF)
    with t.trial("t1", conf) as (link, err):
        assert not err and link["port"]
        assert routes.added == [("198.51.100.7/32", 5, "192.168.1.1", 1)]
        cfg = buildconfig.read_json(os.path.join(paths.RUN, "trial-t1.json"))
        assert cfg["inbounds"][0]["type"] == "http"
        assert cfg["endpoints"][0]["peers"][0]["allowed_ips"] == ["0.0.0.0/0"]
    assert "198.51.100.7/32" not in routes.table
    assert not os.path.exists(os.path.join(paths.RUN, "trial-t1.json"))


def test_чужой_маршрут_к_пиру_не_трогает(routes):
    t = tunnel.Tunnel(lambda line: None)
    t.uplink = (5, "192.168.1.1")
    routes.table["198.51.100.7/32"] = [{"NextHop": "192.168.1.1", "InterfaceIndex": 5}]
    with t.trial("t1", buildconfig.parse_text(CONF)):
        pass
    assert routes.added == [] and routes.table["198.51.100.7/32"]


def test_без_vpn_маршрут_не_нужен(routes):
    t = tunnel.Tunnel(lambda line: None)
    with t.trial("t1", buildconfig.parse_text(CONF)) as (link, err):
        assert not err
    assert routes.added == []
