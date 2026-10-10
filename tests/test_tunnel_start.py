"""Включение: реальный адрес, два процесса sing-box и их раздельная судьба.

Реальный адрес спрашиваем в фоне, но до старта sing-box. На плохой сети
запрос к ifconfig.me висел до 15 с и держал всё включение. Ждать его после
старта sing-box нельзя: запрос ушёл бы в туннель, адрес выхода записался бы
как «реальный», и пробер показывал бы утечку в рабочем туннеле.

Корп и основной — разные процессы: корп перезапускается один, его
падение не срывает включение, а выход наружу переключается через clash_api.

Систему подменяем целиком: winnet, sing-box и сеть — границы. clash_api
изображает настоящий HTTP-сервер на loopback.
"""

import http.server
import json
import threading
import time
import urllib.request

import pytest

from tunnelvpn import buildconfig, paths, tunnel, tunnels, winnet


class FakeNet:
    last_error = ""

    def __init__(self):
        self.singbox_running = False
        self.added = []
        self.gone = set()       # маршруты, которые система потеряла

    def tun_index(self, _ip):
        return 45 if self.singbox_running else None

    def pids_of(self, _exe):
        return []

    def v6_blocked(self):
        return False

    def default_route(self):
        return 18, "192.168.0.1"

    def v6_block(self, _idx):
        return True

    def add_routes(self, routes):
        self.added += routes

    def routes_for(self, prefix):
        if prefix in self.gone:
            return []
        return [{"InterfaceIndex": idx, "NextHop": hop}
                for p, idx, hop, _m in self.added if p == prefix]


class FakeProc:
    def __init__(self, cfg):
        self.cfg = cfg
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 1

    def kill(self):
        self.returncode = 1

    def wait(self, timeout=None):
        return self.returncode


class FakeBuild:
    """Сборка без conf\\: остальное — настоящий buildconfig."""

    def __init__(self):
        self.on_main = lambda: None

    def main(self, log=print):
        self.on_main()
        return BUILT

    def __getattr__(self, name):
        return getattr(buildconfig, name)


class FakeIfconfig:
    """ifconfig.me: отвечает, когда отпустят, или по таймауту падает."""

    def __init__(self, ip):
        self.ip = ip
        self.called = threading.Event()
        self.release = threading.Event()

    def __call__(self, _url, timeout=None):
        self.called.set()
        if not self.release.wait(2):
            raise OSError("timed out")
        return self

    def read(self):
        return self.ip.encode()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


HOME_SOCKS = buildconfig.socks_tag("home")
BUILT = [("work", "Работа"), ("home", "Личный")]


def _side(tun, tid):
    return next(s for s in tun.sides if s.tid == tid)


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name in ("SINGBOX", "WINTUN"):
        f = tmp_path / name
        f.write_text("")
        monkeypatch.setattr(paths, name, str(f))
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "outbounds": [{"type": "selector", "tag": buildconfig.OUT_TAG,
                       "outbounds": [HOME_SOCKS, buildconfig.DIRECT_TAG],
                       "default": HOME_SOCKS},
                      {"type": "socks", "tag": "socks-work", "server_port": 1080},
                      {"type": "socks", "tag": HOME_SOCKS, "server_port": 1081}],
    }))
    monkeypatch.setattr(paths, "CONFIG_JSON", str(cfg))
    monkeypatch.setattr(paths, "STATE", str(tmp_path))
    monkeypatch.setattr(paths, "RUN", str(tmp_path))
    for tid, ip in (("work", "203.0.113.20"), ("home", "203.0.113.10")):
        with open(buildconfig.side_json(tid), "w", encoding="utf-8") as fh:
            json.dump({"endpoints": [{"peers": [{"address": ip}]}]}, fh)
    monkeypatch.setattr(paths, "OWNED_FILE", str(tmp_path / "owned"))
    monkeypatch.setattr(paths, "REAL_IP_FILE", str(tmp_path / "real-ip"))
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setattr(paths, "LOGS", str(logs))
    # Туннели: рабочий «по списку» и личный основной с двумя конфигами.
    monkeypatch.setattr(paths, "CONF", str(tmp_path / "conf"))
    monkeypatch.setattr(paths, "TUNNELS_JSON", str(tmp_path / "conf" / "tunnels.json"))
    monkeypatch.setattr(paths, "CONF_TUNNELS", str(tmp_path / "conf" / "tunnels"))
    for tid, names in (("work", ["corp"]), ("home", ["nl-1", "nl-2"])):
        d = tmp_path / "conf" / "tunnels" / tid
        d.mkdir(parents=True)
        for name in names:
            (d / f"{name}.conf").write_text("[Interface]\n", encoding="utf-8")
    tunnels.save({"tunnels": [
        {"id": "work", "name": "Работа", "mode": "list", "active": "corp"},
        {"id": "home", "name": "Личный", "mode": "all", "active": "nl-1"}]})

    net = FakeNet()
    monkeypatch.setattr(tunnel, "winnet", net)
    build = FakeBuild()
    monkeypatch.setattr(tunnel, "buildconfig", build)
    seen = {"checked": [], "started": [], "dies": set(), "socks": [],
            "socks_open": True}

    def run(cmd, **_k):
        if "check" in cmd:
            seen["checked"].append(cmd[-1])
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr(tunnel.subprocess, "run", run)
    monkeypatch.setattr(tunnel, "REAL_IP_WAIT", 0.3)
    monkeypatch.setattr(tunnel, "SIDE_WAIT", 0.5)

    # Что лежит в real-ip в момент старта sing-box — это и увидит пробер.
    def popen(cmd, **_k):
        cfg_path = cmd[cmd.index("-c") + 1]
        seen["started"].append(cfg_path)
        proc = FakeProc(cfg_path)
        if cfg_path == paths.CONFIG_JSON:
            with open(paths.REAL_IP_FILE, encoding="utf-8") as fh:
                seen["real_ip"] = fh.read()
            net.singbox_running = True
        elif any(buildconfig.side_json(tid) == cfg_path for tid in seen["dies"]):
            proc.returncode = 1
        return proc

    def port_open(port):
        seen["socks"].append(port)
        return seen["socks_open"]

    monkeypatch.setattr(tunnel.subprocess, "Popen", popen)
    monkeypatch.setattr(tunnel, "_port_open", port_open)

    lines = []
    tun = tunnel.Tunnel(log=lines.append)
    seen["log"] = lines
    seen["net"] = net
    monkeypatch.setattr(tun, "_keep_awake", lambda _on: None)
    yield tun, build, seen
    for fh in (tun.logfile, *(side.logfile for side in tun.sides)):
        if fh is not None:
            fh.close()


def test_адрес_спрашивается_пока_собирается_конфиг(env, monkeypatch):
    tun, build, seen = env
    ifconfig = FakeIfconfig("198.51.100.7")
    monkeypatch.setattr(urllib.request, "urlopen", ifconfig)
    asked = []

    def build_main():
        asked.append(ifconfig.called.wait(1))
        ifconfig.release.set()

    build.on_main = build_main

    assert tun.start() == ""

    assert asked == [True]
    assert seen["real_ip"] == "198.51.100.7"


def test_медленная_сеть_не_держит_включение(env, monkeypatch):
    tun, _build, seen = env
    ifconfig = FakeIfconfig("198.51.100.7")
    monkeypatch.setattr(urllib.request, "urlopen", ifconfig)

    began = time.time()
    assert tun.start() == ""

    assert time.time() - began < 1.5
    assert seen["real_ip"] == ""


def test_опоздавший_ответ_не_записывается(env, monkeypatch):
    """Ответ после старта sing-box мог прийти через туннель — это не реальный адрес."""
    tun, _build, _seen = env
    ifconfig = FakeIfconfig("198.51.100.7")
    monkeypatch.setattr(urllib.request, "urlopen", ifconfig)
    assert tun.start() == ""

    ifconfig.release.set()
    time.sleep(0.2)

    with open(paths.REAL_IP_FILE, encoding="utf-8") as fh:
        assert fh.read() == ""


def test_при_чужом_vpn_реальный_адрес_не_записывается(env, monkeypatch):
    """Половинки Amnezia стоят до наших: ifconfig.me ответил её выходом."""
    tun, _build, seen = env
    ifconfig = FakeIfconfig("198.51.100.99")
    ifconfig.release.set()
    monkeypatch.setattr(urllib.request, "urlopen", ifconfig)
    seen["net"].added.append(("0.0.0.0/1", 31, "0.0.0.0", 0))

    assert tun.start() == ""

    assert seen["real_ip"] == ""
    assert any("поднят другой VPN (интерфейс 31)" in line for line in seen["log"])


# ---------------------------------------------------------- три процесса


def test_проверяются_все_конфиги_и_туннели_стартуют_первыми(env):
    """Основной сразу отдаёт трафик в socks — туннели должны уже слушать."""
    tun, _build, seen = env

    assert tun.start() == ""

    sides = [buildconfig.side_json("work"), buildconfig.side_json("home")]
    assert sorted(seen["checked"]) == sorted([paths.CONFIG_JSON, *sides])
    # Туннели стартуют вместе, порядок между ними не задан; основной — после.
    assert sorted(seen["started"][:2]) == sorted(sides)
    assert seen["started"][2:] == [paths.CONFIG_JSON]
    assert sorted(seen["socks"]) == [1080, 1081]
    for side in tun.sides:
        assert side.log_start[0].startswith(paths.LOGS)
        assert f"tunnel-{side.tid}-" in side.log_start[0]
    assert "vpn-" in tun.log_start[0]


def _no_net(_url, timeout=None):
    raise OSError("нет сети")


def test_туннели_ждут_свой_socks_одновременно(env, monkeypatch):
    """По очереди ожидания складывались: ~0.8 с включения на каждый процесс."""
    tun, _build, seen = env
    seen["socks_open"] = False
    monkeypatch.setattr(tunnel, "SIDE_WAIT", 1.0)
    monkeypatch.setattr(tun, "set_out", lambda _tag: True)
    monkeypatch.setattr(urllib.request, "urlopen", _no_net)

    began = time.time()
    assert tun.start() == ""

    # Порознь — два SIDE_WAIT (2 с), вместе — один.
    assert time.time() - began < 1.7


def test_порт_открыт_только_когда_его_слушают():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        assert tunnel._port_open(port)
    assert not tunnel._port_open(port)


def test_пиры_берутся_из_конфигов_туннелей(env):
    tun, _build, seen = env

    assert tun.start() == ""

    hosts = {r[0] for r in seen["net"].added}
    assert {"203.0.113.10/32", "203.0.113.20/32"} <= hosts


def test_маршруты_к_пирам_на_месте_журнал_молчит(env):
    tun, _build, seen = env

    assert tun.start() == ""

    assert not any("пропал" in l for l in seen["log"])
    assert tun.mend_peer_routes() == []


def test_пропавший_на_старте_маршрут_к_пиру_ставится_заново(env):
    """Без host-маршрута WireGuard уходит в tun петлёй — ни одного рукопожатия."""
    tun, _build, seen = env
    seen["net"].gone = {"203.0.113.10/32"}

    assert tun.start() == ""

    route = ("203.0.113.10/32", 18, "192.168.0.1", 1)
    assert seen["net"].added.count(route) == 2
    assert "!! маршрут к пиру 203.0.113.10 пропал — ставлю заново" in seen["log"]
    assert not any("203.0.113.20 пропал" in l for l in seen["log"])


def test_маршрут_к_пиру_пропал_в_работе_ставится_заново(env):
    tun, _build, seen = env
    assert tun.start() == ""
    assert tun.restart_side(_side(tun, "work")) == ""
    net = seen["net"]
    net.gone = {"203.0.113.10/32", "203.0.113.20/32"}
    before = len(net.added)

    assert tun.mend_peer_routes() == ["203.0.113.10", "203.0.113.20"]
    assert net.added[before:] == [("203.0.113.10/32", 18, "192.168.0.1", 1),
                                  ("203.0.113.20/32", 18, "192.168.0.1", 1)]


def test_сверка_маршрутов_без_туннеля_ничего_не_делает(env):
    tun, _build, seen = env

    assert tun.mend_peer_routes() == []
    assert seen["net"].added == []


def test_упавший_корп_не_срывает_включение(env):
    """Интернету корп не нужен: без него включение идёт дальше."""
    tun, _build, seen = env
    seen["dies"] = {"work"}

    assert tun.start() == ""

    assert tun.proc is not None
    assert any("процесс «Работа» упал" in l and "туннель «Работа» недоступен" in l
               for l in seen["log"])


def test_упавший_личный_включает_выход_напрямую(env, monkeypatch):
    """Интернет работает и без личного: socks без процесса отказывал бы всем."""
    tun, _build, seen = env
    seen["dies"] = {"home"}
    outs = []
    monkeypatch.setattr(tun, "set_out", outs.append)

    assert tun.start() == ""

    assert tun.proc is not None
    assert outs == [buildconfig.DIRECT_TAG]
    assert any("процесс «Личный» упал" in l and "выход напрямую" in l
               for l in seen["log"])


def test_туннель_не_открыл_socks_гасим_его(env, monkeypatch):
    tun, _build, seen = env
    seen["socks_open"] = False
    monkeypatch.setattr(tun, "set_out", lambda _tag: True)

    assert tun.start() == ""

    assert _side(tun, "work").proc is None and tun.main.proc is None
    assert any("не открыл socks" in l for l in seen["log"])


def test_повторное_включение_поднимает_мёртвый_корп(env):
    tun, _build, seen = env
    assert tun.start() == ""
    _side(tun, "work").proc.returncode = 1
    main = tun.proc

    assert tun.start() == ""

    assert tun.proc is main
    assert seen["started"][-1] == buildconfig.side_json("work")
    assert _side(tun, "work").alive()


def test_повторное_включение_возвращает_выход_на_личный(env, monkeypatch):
    tun, _build, seen = env
    assert tun.start() == ""
    tun.main.proc.returncode = 1
    outs = []
    monkeypatch.setattr(tun, "set_out", outs.append)

    assert tun.start() == ""

    assert seen["started"][-1] == buildconfig.side_json("home")
    assert tun.main.alive() and _side(tun, "work").alive()
    assert outs == [HOME_SOCKS]


@pytest.mark.parametrize("which, rest", [("work", "home"), ("home", "work")])
def test_перезапуск_туннеля_не_трогает_остальные(env, monkeypatch, which, rest):
    tun, _build, seen = env
    assert tun.start() == ""
    side, other = _side(tun, which), _side(tun, rest)
    main, old, other_proc = tun.proc, side.proc, other.proc
    # DNS изнутри туннеля отдал бы другой адрес: 7 октября в офисе корп-имя
    # так стало внешним адресом, и корп час перезапускался впустую.
    for name in ("refresh_peer", "resolve_peer", "peer_host"):
        monkeypatch.setattr(buildconfig, name, lambda *a, **kw: "203.0.113.99",
                            raising=False)
    monkeypatch.setattr(winnet, "resolve4", lambda name: "203.0.113.99")

    assert tun.restart_side(side) == ""

    assert old.terminated
    assert not main.terminated and not other_proc.terminated
    assert tun.proc is main and other.proc is other_proc
    assert side.proc is not old and side.alive()
    assert not any(r[0] == "203.0.113.99/32" for r in seen["net"].added)
    assert not any("203.0.113.99" in parts for parts in tun.owned_lines())


def test_перезапуск_туннеля_без_туннеля_отказ(env):
    tun, _build, seen = env

    assert tun.restart_side(tunnel.Side("work", "Работа")) == "туннель не поднят"
    assert seen["started"] == []


def test_стоп_гасит_все_процессы(env, monkeypatch):
    tun, _build, _seen = env
    assert tun.start() == ""
    procs = [tun.proc] + [side.proc for side in tun.sides]
    for name in ("routes_on_interface", "v6_unblock", "nrpt_clear",
                 "flush_dns", "del_route"):
        monkeypatch.setattr(tunnel.winnet, name, lambda *_a: [], raising=False)
    monkeypatch.setattr(tunnel.winnet, "interface_exists", lambda _i: False,
                        raising=False)

    tun.stop()

    assert all(p.terminated for p in procs)
    for side in tun.sides:
        assert side.proc is None and side.logfile is None
        assert side.log_start is None
    assert tun.log_start is None


# ------------------------------------------------------------ профиль


def _active(tid):
    return tunnels.find(tunnels.load(), tid)["active"]


def test_профиль_становится_активным_конфигом_основного(env):
    tun, _build, seen = env

    assert tun.start("nl-2") == ""

    assert _active("home") == "nl-2" and _active("work") == "corp"
    assert tun.profile == "nl-2"
    assert "→ профиль «Личный»: nl-2" in seen["log"]


def test_без_профиля_берётся_выбранный_в_tunnels_json(env):
    tun, _build, _seen = env

    assert tun.start() == ""

    assert tun.profile == "nl-1" and _active("home") == "nl-1"
    assert tun.main_id == "home"
    assert [s.tid for s in tun.sides] == ["work", "home"]


def test_чужой_профиль_отказ_до_остановки(env):
    tun, _build, seen = env
    assert tun.start() == ""
    main, started = tun.proc, list(seen["started"])

    err = tun.start("..\\nl-1")

    assert "нет профиля" in err
    assert tun.proc is main and not main.terminated
    assert seen["started"] == started
    assert _active("home") == "nl-1"


def test_профиль_без_основного_туннеля_отказ(env):
    tun, _build, _seen = env
    tunnels.save({"tunnels": [{"id": "work", "name": "Работа", "mode": "list"}]})

    assert "нет туннеля для всего остального трафика" in tun.start("nl-1")


def test_испорченный_tunnels_json_отказ_с_причиной(env):
    tun, _build, seen = env
    with open(paths.TUNNELS_JSON, "w", encoding="utf-8") as fh:
        fh.write("{")

    assert "tunnels.json не читается" in tun.start()
    assert seen["started"] == []


def test_тот_же_профиль_второй_раз_уже_работает(env):
    tun, _build, seen = env
    assert tun.start("nl-2") == ""
    main = tun.proc

    assert tun.start("nl-2") == ""
    assert tun.start() == ""

    assert tun.proc is main
    assert seen["log"].count("→ уже работает") == 2


def test_без_основного_упавший_туннель_выход_не_трогает(env, monkeypatch):
    tun, build, seen = env
    monkeypatch.setattr(build, "main", lambda log=print: [("work", "Работа")])
    with open(paths.CONFIG_JSON, "w", encoding="utf-8") as fh:
        json.dump({"outbounds": [
            {"type": "socks", "tag": "socks-work", "server_port": 1080}]}, fh)
    seen["dies"] = {"work"}
    outs = []
    monkeypatch.setattr(tun, "set_out", outs.append)

    assert tun.start() == ""

    assert tun.main is None and [s.tid for s in tun.sides] == ["work"]
    assert outs == []


def test_пиры_после_перезапуска_службы_берутся_из_собранного_конфига(env):
    """Новый Tunnel не знает туннелей, а stop без журнала чистит по пирам."""
    tun, _build, _seen = env

    assert tun.sides == []
    assert sorted(tun._peer_ips()) == ["203.0.113.10", "203.0.113.20"]


# ------------------------------------------------- смена конфига на ходу


def _use(tid, name):
    data = tunnels.load()
    tunnels.find(data, tid)["active"] = name
    tunnels.save(data)


@pytest.fixture
def live(env, monkeypatch):
    """Поднятый VPN; сборка отдаёт основной конфиг как у работающего (или
    seen["main_cfg"]) и боковые с пиром по имени, пир резолвится в seen["peer"]."""
    tun, build, seen = env
    assert tun.start() == ""
    running = buildconfig.read_json(paths.CONFIG_JSON)
    seen.update(asked=[], main_cfg=running, peer="203.0.113.30")

    def assemble(data, confs, log, links, api, resolve):
        seen["asked"].append({"links": links, "resolve": resolve})
        sides = {tid: {"endpoints": [{"peers": [{"address": f"{tid}.example"}]}]}
                 for tid in confs}
        return seen["main_cfg"], sides, [], []

    def peer_host(host, _tag, _log):
        if not seen["peer"]:
            raise SystemExit(f"не удалось разрешить {host}")
        return seen["peer"]

    build.assemble, build.peer_host = assemble, peer_host
    seen["outs"] = []
    monkeypatch.setattr(tun, "set_out", seen["outs"].append)
    return tun, seen


def _peer(tid):
    return buildconfig.read_json(buildconfig.side_json(tid))["endpoints"][0]["peers"][0]


def test_смена_конфига_основного_перезапускает_только_его_процесс(live):
    tun, seen = live
    main, work, home = tun.proc, _side(tun, "work").proc, tun.main.proc
    _use("home", "nl-2")

    done = tun.reload_sides()

    assert [(side.tid, err) for side, err in done] == [("home", "")]
    assert home.terminated and tun.main.alive() and tun.main.proc is not home
    assert not main.terminated and not work.terminated and tun.proc is main
    # Пока процесс основного лежит — выход напрямую, потом обратно.
    assert seen["outs"] == [buildconfig.DIRECT_TAG, HOME_SOCKS]
    assert _peer("home")["address"] == "203.0.113.30"
    assert ("203.0.113.30/32", 18, "192.168.0.1", 1) in seen["net"].added
    assert any(parts[:2] == ["host", "203.0.113.30"] for parts in tun.owned_lines())
    assert tun.profile == "nl-2"


def test_сборка_берёт_связи_работающего_запуска_без_резолва(live):
    tun, seen = live
    _use("home", "nl-2")

    tun.reload_sides()

    [asked] = seen["asked"]
    assert asked["resolve"] is False
    assert {tid: link["port"] for tid, link in asked["links"].items()} == {
        "work": 1080, "home": 1081}


def test_переписанный_файл_того_же_конфига_тоже_смена(live):
    tun, seen = live
    work = _side(tun, "work").proc
    with open(tunnels.active_conf(tunnels.find(tunnels.load(), "work")), "a",
              encoding="utf-8") as fh:
        fh.write("MTU = 1380\n")

    done = tun.reload_sides()

    assert [side.tid for side, _ in done] == ["work"]
    assert work.terminated
    # Не основной: выход не трогаем.
    assert seen["outs"] == []


def test_без_смены_конфигов_никого_не_перезапускает(live):
    tun, seen = live
    _use("home", "nl-2")
    tun.reload_sides()
    started = list(seen["started"])

    assert tun.reload_sides() == []
    assert seen["started"] == started


def test_сменился_основной_конфиг_нужен_полный_перезапуск(live):
    """Подсети или DNS туннеля «по списку» держит основной процесс: он конфиг не перечитывает."""
    tun, seen = live
    seen["main_cfg"] = {**seen["main_cfg"], "route": {"final": "direct"}}
    home = tun.main.proc
    _use("home", "nl-2")

    assert tun.reload_sides() is None

    assert not home.terminated
    assert _peer("home")["address"] == "203.0.113.10"


def test_смена_уровня_журнала_без_полного_перезапуска(live):
    """Основной возьмёт уровень на следующем включении: ради журнала tun не роняем."""
    tun, seen = live
    inner = tunnel.buildconfig.assemble
    level = {"level": "debug", "timestamp": True}

    def assemble(*args, **kw):
        main, sides, built, report = inner(*args, **kw)
        return ({**main, "log": level},
                {tid: {**side, "log": level} for tid, side in sides.items()}, built, report)

    tunnel.buildconfig.assemble = assemble
    main, work, home = tun.proc, _side(tun, "work").proc, tun.main.proc

    done = tun.reload_sides()

    assert sorted((side.tid, err) for side, err in done) == [("home", ""), ("work", "")]
    assert work.terminated and home.terminated
    assert not main.terminated and tun.proc is main
    assert seen["outs"] == [buildconfig.DIRECT_TAG, HOME_SOCKS]
    # Работающий конфиг, сменён только журнал: пир заново не резолвился.
    assert _peer("work")["address"] == "203.0.113.20" and _peer("home")["address"] == "203.0.113.10"
    assert all(buildconfig.read_json(buildconfig.side_json(tid))["log"] == level
               for tid in ("work", "home"))
    assert tun.reload_sides() == []


def test_испорченный_tunnels_json_нужен_полный_перезапуск(live):
    tun, _seen = live
    with open(paths.TUNNELS_JSON, "w", encoding="utf-8") as fh:
        fh.write("{")

    assert tun.reload_sides() is None


def test_без_поднятого_vpn_нужен_полный(env):
    tun, _build, seen = env

    assert tun.reload_sides() is None
    assert seen["started"] == []


def test_пир_не_резолвится_прежний_процесс_работает(live):
    tun, seen = live
    seen["peer"] = ""
    home = tun.main.proc
    _use("home", "nl-2")

    [(side, err)] = tun.reload_sides()

    assert side is tun.main and "не удалось разрешить home.example" in err
    assert not home.terminated and tun.main.proc is home
    assert seen["outs"] == []
    assert _peer("home")["address"] == "203.0.113.10"
    # Метка старая: следующая правка попробует снова.
    seen["peer"] = "203.0.113.30"
    assert [s.tid for s, _ in tun.reload_sides()] == ["home"]


def test_не_поднявшийся_на_новом_конфиге_следующая_правка_не_трогает(live):
    """Его конфиг уже на диске: поднимать будет сторож, лишний перезапуск не нужен."""
    tun, seen = live
    seen["dies"] = {"work"}
    with open(tunnels.active_conf(tunnels.find(tunnels.load(), "work")), "a",
              encoding="utf-8") as fh:
        fh.write("MTU = 1380\n")

    [(side, err)] = tun.reload_sides()

    assert side.tid == "work" and "упал" in err
    assert tun.reload_sides() == []


def test_пир_с_маршрутом_второй_раз_не_ставится(live):
    """Новый конфиг на тот же сервер, что у соседа: маршрут к нему уже наш."""
    tun, seen = live
    seen["peer"] = "203.0.113.20"
    before = list(seen["net"].added)
    _use("home", "nl-2")

    tun.reload_sides()

    assert seen["net"].added == before


# ------------------------------------------------------------ выход наружу


class FakeClash(http.server.BaseHTTPRequestHandler):
    """clash_api основного процесса: selector out и замер задержки."""

    secret = "s3cret"
    now = HOME_SOCKS
    delays = {HOME_SOCKS: 0, buildconfig.DIRECT_TAG: 42}
    paths_seen = []

    def _auth(self):
        if self.headers.get("Authorization") != f"Bearer {self.secret}":
            self._send(401, {"message": "Unauthorized"})
            return False
        return True

    def _send(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        FakeClash.paths_seen.append(self.path)
        if not self._auth():
            return
        if self.path == f"/proxies/{buildconfig.OUT_TAG}":
            self._send(200, {"name": "out", "now": FakeClash.now})
            return
        tag = self.path.split("/")[2]
        ms = self.delays.get(tag)
        if ms:
            self._send(200, {"delay": ms})
        else:
            self._send(504, {"message": "Timeout"})

    def do_PUT(self):
        if not self._auth():
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeClash.now = body["name"]
        self._send(204)

    def log_message(self, *_a):
        pass


@pytest.fixture
def clash(env):
    tun, _build, seen = env
    server = http.server.HTTPServer(("127.0.0.1", 0), FakeClash)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    FakeClash.now = HOME_SOCKS
    FakeClash.paths_seen = []
    with open(paths.CONFIG_JSON, encoding="utf-8") as fh:
        cfg = json.load(fh)
    cfg["experimental"] = {"clash_api": {
        "external_controller": f"127.0.0.1:{server.server_port}",
        "secret": FakeClash.secret}}
    with open(paths.CONFIG_JSON, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    yield tun, seen
    server.shutdown()
    server.server_close()


def test_переключение_выхода_на_direct_и_обратно(clash):
    tun, _seen = clash

    assert tun.out_now() == HOME_SOCKS
    assert tun.set_out(buildconfig.DIRECT_TAG)
    assert tun.out_now() == buildconfig.DIRECT_TAG
    assert tun.set_out(HOME_SOCKS)
    assert tun.out_now() == HOME_SOCKS


def test_задержка_живого_и_мёртвого_выхода(clash):
    tun, _seen = clash

    assert tun.delay(buildconfig.DIRECT_TAG) == 42
    assert tun.delay(HOME_SOCKS) is None
    # Мерить по имени: голый адрес sing-box через selector не меряет.
    assert "cp.cloudflare.com" in FakeClash.paths_seen[-1]


def test_чужой_секрет_это_отказ_а_не_исключение(clash, monkeypatch):
    tun, seen = clash
    monkeypatch.setattr(FakeClash, "secret", "другой")

    assert tun.set_out(buildconfig.DIRECT_TAG) is False
    assert tun.out_now() == ""
    assert tun.delay(buildconfig.DIRECT_TAG) is None
    assert any("не переключить" in l for l in seen["log"])


def test_системный_прокси_не_перехватывает_clash_api(clash, monkeypatch):
    tun, _seen = clash
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")

    assert tun.out_now() == HOME_SOCKS


def test_без_clash_api_выход_не_переключается(env):
    tun, _build, _seen = env

    assert tun.set_out(buildconfig.DIRECT_TAG) is False
    assert tun.out_now() == ""
