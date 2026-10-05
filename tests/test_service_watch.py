"""Сторож сети: смена аплинка и упавший sing-box поднимают туннель заново,
мигание сети и команда человека — нет, повторы конечны.

Core без службы: туннель — заглушка, аплинк кладём в снимок пробера руками,
круги сторожа гоняем вызовом _watch_once без ожиданий."""

import json
import threading

import pytest

from dualvpn import probe, service

OFFICE = (12, "192.168.19.1")
HOME = (7, "192.168.0.1")


@pytest.fixture(autouse=True)
def _paths_file(monkeypatch, tmp_path):
    """Статистика адресов — во временную папку, не в настоящий state."""
    path = tmp_path / "paths.json"
    monkeypatch.setattr(service, "PATHS_FILE", str(path))
    return path


def _timeout(addr, tag="awg-personal"):
    return (f"+0300 2026-10-05 09:59:57 ERROR [2478390845 15.1s] connection: open "
            f"connection to {addr} using outbound/wireguard[{tag}]: "
            f"context deadline exceeded\n")


class _Proc:
    returncode = 1

    def poll(self):
        return self.returncode


class _Tunnel:
    def __init__(self, prober):
        self.prober = prober
        self.uplink = OFFICE
        self.proc = None
        self.log_start = None
        self.fail = False
        self.starts = 0

    def start(self, _profile):
        self.starts += 1
        if self.fail:
            return "не поднялся"
        s = self.prober.snapshot()
        self.uplink = (s["iface"], s["gw"])
        return ""

    def stop(self):
        self.uplink = None


def _core(monkeypatch):
    core = service.Core.__new__(service.Core)
    core.lock = threading.Lock()
    core.busy = ""
    core.last_error = ""
    core.log_lock = threading.Lock()
    core._paths, core._ip_names = {}, {}
    core.prober = probe.Prober()
    core.tunnel = _Tunnel(core.prober)
    core.logged = []
    monkeypatch.setattr(core, "log", core.logged.append)
    monkeypatch.setattr(core.prober, "probe_fast", lambda: None)
    monkeypatch.setattr(probe.Prober, "current_profile", staticmethod(lambda: "p"))
    monkeypatch.setattr(service, "RECONNECT_GAP", 0.0)
    _net(core, OFFICE)
    return core


def _sing_log(core, tmp_path, old=""):
    """Журнал sing-box: old — строки прошлого запуска до начала текущего."""
    path = tmp_path / "vpn.log"
    path.write_bytes(old.encode())
    core.tunnel.log_start = (str(path), len(old.encode()))
    return path


def _append(path, *lines):
    with open(path, "a", encoding="utf-8") as fh:
        fh.writelines(lines)


def _net(core, uplink):
    core.prober.set(iface=uplink[0], gw=uplink[1])


def _rounds(core, n, state=(None, 0, 0.0)):
    for _ in range(n):
        state = core._watch_once(*state)
    return state


def test_новая_сеть_после_устойчивых_кругов_переподключает(monkeypatch):
    core = _core(monkeypatch)
    _net(core, HOME)

    state = _rounds(core, service.UPLINK_SETTLE - 1)
    assert core.tunnel.starts == 0

    _rounds(core, 1, state)
    assert core.tunnel.starts == 1
    assert core.tunnel.uplink == HOME
    assert core.busy == ""
    # Ответы корпа и адрес выхода мерили старую сеть — нужна новая проверка.
    assert core.prober._remeasure.is_set()


def test_неудачное_переподключение_проверку_не_просит(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.fail = True
    core.tunnel.proc = _Proc()

    _rounds(core, 1)

    assert not core.prober._remeasure.is_set()


def test_мигание_сети_не_переподключает(monkeypatch):
    core = _core(monkeypatch)

    state = (None, 0, 0.0)
    for _ in range(5):
        _net(core, HOME)
        state = _rounds(core, service.UPLINK_SETTLE - 1, state)
        _net(core, OFFICE)
        state = _rounds(core, 1, state)

    assert core.tunnel.starts == 0


def test_пропавший_шлюз_не_переподключает(monkeypatch):
    core = _core(monkeypatch)
    core.prober.set(iface=None, gw="")

    _rounds(core, service.UPLINK_SETTLE * 3)

    assert core.tunnel.starts == 0


def test_сам_упавший_sing_box_поднимается_заново(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.proc = _Proc()

    _rounds(core, 1)

    assert core.tunnel.starts == 1


def test_выключенный_туннель_не_трогаем(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.uplink = None
    core.tunnel.proc = _Proc()
    _net(core, HOME)

    _rounds(core, service.UPLINK_SETTLE * 3)

    assert core.tunnel.starts == 0


def test_повторы_после_неудачи_конечны(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.fail = True
    _net(core, HOME)

    _rounds(core, service.UPLINK_SETTLE + service.RECONNECT_TRIES * 3)

    assert core.tunnel.starts == 1 + service.RECONNECT_TRIES
    assert core._retry_left == 0


def test_поднялся_на_повторе_повторы_прекращаются(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.fail = True
    _net(core, HOME)
    state = _rounds(core, service.UPLINK_SETTLE)
    assert core.tunnel.starts == 1

    core.tunnel.fail = False
    _rounds(core, service.RECONNECT_TRIES * 3, state)

    assert core.tunnel.starts == 2
    assert core.tunnel.uplink == HOME
    assert core._retry_left == 0


def test_выключение_человеком_отменяет_повторы(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.fail = True
    _net(core, HOME)
    state = _rounds(core, service.UPLINK_SETTLE)
    assert core._retry_left == service.RECONNECT_TRIES

    assert core._do_stop() == {"ok": True}
    _rounds(core, service.RECONNECT_TRIES * 3, state)

    assert core.tunnel.starts == 1


def test_после_остановки_службы_туннель_не_поднимается(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.proc = _Proc()
    core.prober.stop_event.set()

    _rounds(core, 1)

    assert core.tunnel.starts == 0


def test_занятая_служба_сторожа_не_пускает(monkeypatch):
    core = _core(monkeypatch)
    core.busy = "включаю"
    _net(core, HOME)

    _rounds(core, service.UPLINK_SETTLE * 3)

    assert core.tunnel.starts == 0


# ------------------------------------------------------- мёртвый туннель

def test_таймауты_к_разным_адресам_переподключают(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log, _timeout("34.117.59.81:443"), _timeout("172.217.23.238:443"))
    state = _rounds(core, 1)
    assert core.tunnel.starts == 0

    _append(log, _timeout("160.79.104.10:443"))
    _rounds(core, 1, state)

    assert core.tunnel.starts == 1
    assert any("awg-personal" in line for line in core.logged)


def test_таймауты_к_одному_адресу_не_переподключают(monkeypatch, tmp_path):
    """Лежит один сайт, а не туннель."""
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log, *[_timeout("160.79.104.10:443")] * 5)

    _rounds(core, 3)

    assert core.tunnel.starts == 0


def test_таймауты_разных_туннелей_не_складываются(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log, _timeout("10.10.0.5:443", "wg-corp"),
            _timeout("34.117.59.81:443"), _timeout("172.217.23.238:443"))

    _rounds(core, 1)

    assert core.tunnel.starts == 0


def test_повтор_раньше_паузы_не_переподключает(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log, _timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"),
            _timeout("9.9.9.9:443"))
    state = _rounds(core, 1)
    assert core.tunnel.starts == 1

    _append(log, _timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"),
            _timeout("9.9.9.9:443"))
    _rounds(core, 3, state)

    assert core.tunnel.starts == 1


def test_ошибки_прошлого_запуска_не_в_счёт(monkeypatch, tmp_path):
    """open_log продолжает свежий файл: строки до заголовка — чужой сеанс."""
    core = _core(monkeypatch)
    _sing_log(core, tmp_path, old=_timeout("1.1.1.1:443") +
              _timeout("8.8.8.8:443") + _timeout("9.9.9.9:443"))

    _rounds(core, 3)

    assert core.tunnel.starts == 0


def test_недописанная_строка_дочитывается_на_следующем_круге(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    line = _timeout("9.9.9.9:443")
    _append(log, _timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"), line[:40])
    state = _rounds(core, 1)
    assert core.tunnel.starts == 0

    _append(log, line[40:])
    _rounds(core, 1, state)

    assert core.tunnel.starts == 1


# ------------------------------------------------------------ журнал сторожа

def _said(core, text):
    return [line for line in core.logged if text in line]


def _three_dead():
    return (_timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"), _timeout("9.9.9.9:443"))


def test_мёртвый_туннель_в_журнале_с_тегом_числом_и_адресами(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log, _timeout("34.117.59.81:443"), _timeout("172.217.23.238:443"),
            _timeout("34.117.59.81:443"))

    _rounds(core, 1)

    [line] = _said(core, "переподключаю")
    assert "awg-personal" in line
    assert "таймаутов 3" in line
    assert "172.217.23.238, 34.117.59.81" in line


def test_мёртвый_в_паузе_пишется_один_раз(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log, *_three_dead())
    state = _rounds(core, 1)

    for _ in range(3):
        _append(log, *_three_dead())
        state = _rounds(core, 1, state)

    assert len(_said(core, "жду")) == 1


def test_в_паузе_мёртвого_смена_сети_переподключает(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log, *_three_dead())
    state = _rounds(core, 1)
    assert core.tunnel.starts == 1

    _net(core, HOME)
    for _ in range(service.UPLINK_SETTLE):
        _append(log, *_three_dead())
        state = _rounds(core, 1, state)

    assert core.tunnel.starts == 2


def test_без_шлюза_мёртвый_не_переподключает(monkeypatch, tmp_path):
    """Wi-Fi отвалился или компьютер проснулся: таймауты от сети, а не от
    туннеля, и без сети переподключение только снимет туннель."""
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _net(core, (None, ""))
    _append(log, *_three_dead())

    _rounds(core, 3)

    assert core.tunnel.starts == 0
    assert not _said(core, "переподключаю")
    assert not _said(core, "жду")


def test_таймауты_без_шлюза_не_копятся(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _net(core, (None, ""))
    _append(log, _timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"))
    state = _rounds(core, 1)

    _net(core, OFFICE)
    _append(log, _timeout("9.9.9.9:443"))
    _rounds(core, 1, state)

    assert core.tunnel.starts == 0


def test_повторы_пишутся_с_номером(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.fail = True
    _net(core, HOME)

    _rounds(core, service.UPLINK_SETTLE + service.RECONNECT_TRIES * 3)

    n = service.RECONNECT_TRIES
    assert _said(core, f"повтор 1 из {n}")
    assert _said(core, f"повтор {n} из {n}")


def test_время_подъёма_туннеля_в_журнале(monkeypatch):
    core = _core(monkeypatch)

    assert core._do_start("p") == {"ok": True}
    core.tunnel.fail = True
    core._do_start("p")

    assert _said(core, "туннель поднят за")
    assert _said(core, "не поднялся (за")


def test_мигание_сети_в_журнале(monkeypatch):
    core = _core(monkeypatch)
    _net(core, HOME)
    state = _rounds(core, service.UPLINK_SETTLE - 1)
    _net(core, OFFICE)

    _rounds(core, 1, state)

    assert len(_said(core, "вижу новую сеть")) == 1
    [line] = _said(core, "сеть моргнула")
    assert f"шлюз {HOME[1]}" in line


def test_сон_между_кругами_в_журнале(monkeypatch):
    core = _core(monkeypatch)

    core._note_sleep(1000.0, 1000.0 + 25 * 60)

    [line] = _said(core, "компьютер спал")
    assert "25.0 мин" in line


def test_обычный_круг_сном_не_считается(monkeypatch):
    core = _core(monkeypatch)

    core._note_sleep(1000.0, 1000.0 + service.SLEEP_GAP)

    assert not _said(core, "спал")


# ------------------------------------------------------- куда что ходит

_PFX = "+0300 2026-10-05 22:45:33 INFO "


def _dns(qid, name, kind, value):
    return f"{_PFX}[{qid} 8ms] dns: exchanged {kind} {name}. 10 IN {kind} {value}\n"


def _conn(addr, tag="awg-personal", packet=""):
    return (f"{_PFX}[2734387054 1ms] endpoint/wireguard[{tag}]: "
            f"outbound {packet}connection to {addr}\n")


def _prematch(ip, tag="awg-personal"):
    return (f"{_PFX}[639815585 1ms] router: pre-match: forward udp connection "
            f"from 172.19.0.1 to {ip} via outbound/wireguard[{tag}]\n")


def _saved(path):
    return json.loads(path.read_text(encoding="utf-8"))["tags"]


def test_адреса_по_тегу_с_доменом_из_dns(monkeypatch, tmp_path, _paths_file):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log,
            _dns(1, "watson.events.data.microsoft.com", "CNAME",
                 "blobcollectorcommon.trafficmanager.net."),
            _dns(1, "blobcollectorcommon.trafficmanager.net", "A", "20.42.65.92"),
            _dns(2, "git.corp.example", "A", "10.20.0.4"),
            _conn("20.42.65.92:443"), _conn("20.42.65.92:443"),
            _conn("10.20.0.4:443", "wg-corp"),
            _conn("140.82.121.6:443"),
            _conn("172.15.0.110:53", "wg-corp", packet="packet "),
            _prematch("91.189.91.157"))

    assert core._do_stop() == {"ok": True}

    assert _saved(_paths_file) == {
        "awg-personal": {"watson.events.data.microsoft.com": 2,
                         "140.82.121.6": 1, "91.189.91.157": 1},
        "wg-corp": {"git.corp.example": 1},
    }


def test_статистика_пишется_раз_в_период(monkeypatch, tmp_path, _paths_file):
    core = _core(monkeypatch)
    log = _sing_log(core, tmp_path)
    _append(log, _conn("1.1.1.1:443"))
    state = _rounds(core, 1)
    assert _saved(_paths_file) == {"awg-personal": {"1.1.1.1": 1}}

    _append(log, _conn("1.1.1.1:443"))
    state = _rounds(core, 1, state)
    assert _saved(_paths_file) == {"awg-personal": {"1.1.1.1": 1}}

    core._paths_at = 0.0
    _rounds(core, 1, state)
    assert _saved(_paths_file) == {"awg-personal": {"1.1.1.1": 2}}


def test_статистика_копится_между_запусками_и_режется(monkeypatch, tmp_path,
                                                     _paths_file):
    monkeypatch.setattr(service, "PATHS_KEEP", 2)
    first = _core(monkeypatch)
    _append(_sing_log(first, tmp_path), _conn("1.1.1.1:443"), _conn("2.2.2.2:443"))
    first._do_stop()

    second = _core(monkeypatch)
    _append(_sing_log(second, tmp_path), _conn("2.2.2.2:443"), _conn("3.3.3.3:443"))
    second._do_stop()

    assert _saved(_paths_file) == {"awg-personal": {"2.2.2.2": 2, "1.1.1.1": 1}}


def test_испорченная_статистика_не_мешает_выключить(monkeypatch, tmp_path, _paths_file):
    _paths_file.write_text('{"tags": {"awg-personal": {"1.1.1.1": "x"}}}',
                           encoding="utf-8")
    core = _core(monkeypatch)
    _append(_sing_log(core, tmp_path), _conn("2.2.2.2:443"))

    assert core._do_stop() == {"ok": True}

    assert core.tunnel.uplink is None
    assert _saved(_paths_file) == {"awg-personal": {"2.2.2.2": 1}}
