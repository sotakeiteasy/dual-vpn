"""Сторож сети: смена аплинка и упавший sing-box поднимают туннель заново,
мигание сети и команда человека — нет, повторы конечны.

Core без службы: туннель — заглушка, аплинк кладём в снимок пробера руками,
круги сторожа гоняем вызовом _watch_once без ожиданий."""

import json
import threading

import pytest

from dualvpn import buildconfig, probe, service, tunnel

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


class _Alive:
    returncode = None

    def poll(self):
        return None


class _Tunnel:
    def __init__(self, prober):
        self.prober = prober
        self.uplink = OFFICE
        self.proc = None
        self.log_start = None
        self.fail = False
        self.starts = 0
        self.corp = tunnel.Side("corp", "корп")
        self.personal = tunnel.Side("personal", "личный")
        self.sides = (self.corp, self.personal)
        for side in self.sides:
            side.proc = _Alive()
        self.out = buildconfig.PERSONAL_SOCKS_TAG
        self.outs = []           # переключения выхода по порядку
        self.restarts = []       # kind перезапущенных процессов
        self.side_fail = ""
        self.delay_ms = None     # что ответит проверка через личный
        self.mends = 0           # сверок маршрутов к пирам

    def start(self, _profile):
        self.starts += 1
        if self.fail:
            return "не поднялся"
        s = self.prober.snapshot()
        self.uplink = (s["iface"], s["gw"])
        return ""

    def stop(self):
        self.uplink = None

    def restart_side(self, side):
        self.restarts.append(side.kind)
        if self.side_fail:
            side.proc = None
            return self.side_fail
        side.proc = _Alive()
        return ""

    def mend_peer_routes(self):
        self.mends += 1
        return []

    def out_now(self):
        return self.out

    def set_out(self, tag):
        self.out = tag
        self.outs.append(tag)
        return True

    def delay(self, _tag):
        return self.delay_ms


def _core(monkeypatch):
    core = service.Core.__new__(service.Core)
    core.lock = threading.Lock()
    core.busy = ""
    core.last_error = ""
    core.log_lock = threading.Lock()
    core._paths, core._ip_names = {}, {}
    core._log_at, core._side_after, core._side_noted = {}, {}, {}
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
    """Журнал основного sing-box: old — строки прошлого запуска до начала текущего."""
    path = tmp_path / "vpn.log"
    path.write_bytes(old.encode())
    core.tunnel.log_start = (str(path), len(old.encode()))
    return path


def _side_log(core, tmp_path, kind="personal", old=""):
    """Журнал процесса туннеля: таймауты туннеля теперь там."""
    side = getattr(core.tunnel, kind)
    path = tmp_path / f"{kind}.log"
    path.write_bytes(old.encode())
    side.log_start = (str(path), len(old.encode()))
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


def test_маршруты_к_пирам_сверяются_каждый_круг(monkeypatch):
    core = _core(monkeypatch)

    _rounds(core, 3)

    assert core.tunnel.mends == 3


def test_на_новой_сети_и_без_шлюза_маршруты_не_сверяются(monkeypatch):
    """Ставить пира через старый шлюз бессмысленно: маршруты поставит переподключение."""
    core = _core(monkeypatch)
    _net(core, HOME)
    _rounds(core, service.UPLINK_SETTLE - 1)
    core.prober.set(iface=None, gw="")
    _rounds(core, 2)

    assert core.tunnel.mends == 0


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


def test_выключение_посреди_круга_новую_сеть_не_включает(monkeypatch):
    core = _core(monkeypatch)
    _net(core, HOME)
    state = _rounds(core, service.UPLINK_SETTLE - 1)
    # Последний круг ждёт проверку личного, а человек тем временем выключает.
    core.tunnel.out = buildconfig.DIRECT_TAG
    monkeypatch.setattr(core.tunnel, "delay", lambda _tag: core._do_stop() and None)

    _rounds(core, 1, state)

    assert core.tunnel.starts == 0
    assert core.tunnel.uplink is None


def test_выключение_между_проверкой_и_повтором_повторы_не_зацикливает(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.fail = True
    _net(core, HOME)
    state = _rounds(core, service.UPLINK_SETTLE)
    starts = core.tunnel.starts
    real = service.time.monotonic
    stopped = []

    def monotonic():
        # «Выключить» успевает между проверкой счётчика повторов и его уменьшением.
        if not stopped:
            stopped.append(core._do_stop())
        return real()

    monkeypatch.setattr(service, "time", type(
        "T", (), {"monotonic": staticmethod(monotonic), "time": service.time.time}))

    _rounds(core, service.RECONNECT_TRIES * 3, state)

    assert core.tunnel.starts == starts
    assert core._retry_left == 0


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

def test_таймауты_личного_уводят_выход_и_перезапускают_только_его(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    _append(log, _timeout("34.117.59.81:443"), _timeout("172.217.23.238:443"))
    state = _rounds(core, 1)
    assert core.tunnel.restarts == []

    _append(log, _timeout("160.79.104.10:443"))
    _rounds(core, 1, state)

    assert core.tunnel.restarts == ["personal"]
    assert core.tunnel.outs == [buildconfig.DIRECT_TAG]
    assert core.tunnel.starts == 0
    assert core.busy == ""


def test_таймауты_в_основном_журнале_туннель_не_трогают(monkeypatch, tmp_path):
    """Таймауты туннеля пишет его процесс; основной их не видит."""
    core = _core(monkeypatch)
    _append(_sing_log(core, tmp_path), *_three_dead())

    _rounds(core, 2)

    assert core.tunnel.restarts == [] and core.tunnel.starts == 0


def test_таймауты_к_одному_адресу_при_живой_задержке_не_трогают(monkeypatch, tmp_path):
    """Лежит один сайт, а не туннель: личный отвечает через свой socks."""
    core = _core(monkeypatch)
    core.tunnel.delay_ms = 120
    log = _side_log(core, tmp_path)
    _append(log, *[_timeout("160.79.104.10:443")] * 5)

    _rounds(core, 3)

    assert core.tunnel.restarts == [] and core.tunnel.outs == []


def test_таймауты_к_одному_адресу_без_задержки_уводят_выход_и_перезапускают(
        monkeypatch, tmp_path):
    """13:25 6 октября: таймауты шли к одному адресу, личный молчал."""
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    _append(log, *[_timeout("2.16.106.32:80")] * 3)

    _rounds(core, 1)

    assert core.tunnel.restarts == ["personal"]
    assert core.tunnel.outs == [buildconfig.DIRECT_TAG]


def test_таймауты_разных_туннелей_не_складываются(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    _append(_side_log(core, tmp_path, "corp"), _timeout("10.10.0.5:443", "wg-corp"))
    _append(_side_log(core, tmp_path), _timeout("34.117.59.81:443"),
            _timeout("172.217.23.238:443"))

    _rounds(core, 1)

    assert core.tunnel.restarts == []


def test_повтор_раньше_паузы_не_перезапускает(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    _append(log, *_three_dead())
    state = _rounds(core, 1)
    assert core.tunnel.restarts == ["personal"]

    core.tunnel.out = buildconfig.PERSONAL_SOCKS_TAG
    _append(log, *_three_dead())
    _rounds(core, 3, state)

    assert core.tunnel.restarts == ["personal"]
    # Выход уводим и внутри паузы: интернет перезапуска не ждёт.
    assert core.tunnel.out == buildconfig.DIRECT_TAG


def test_ошибки_прошлого_запуска_не_в_счёт(monkeypatch, tmp_path):
    """open_log продолжает свежий файл: строки до заголовка — чужой сеанс."""
    core = _core(monkeypatch)
    _side_log(core, tmp_path, old="".join(_three_dead()))

    _rounds(core, 3)

    assert core.tunnel.restarts == []


def test_недописанная_строка_дочитывается_на_следующем_круге(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    line = _timeout("9.9.9.9:443")
    _append(log, _timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"), line[:40])
    state = _rounds(core, 1)
    assert core.tunnel.restarts == []

    _append(log, line[40:])
    _rounds(core, 1, state)

    assert core.tunnel.restarts == ["personal"]


def test_упавший_корп_перезапускается_один(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.corp.proc = _Proc()

    _rounds(core, 1)

    assert core.tunnel.restarts == ["corp"]
    assert core.tunnel.outs == [] and core.tunnel.starts == 0
    [line] = _said(core, "перезапускаю корп процесс")
    assert "код 1" in line
    assert core.prober._remeasure.is_set()


def test_упавший_личный_выход_напрямую_и_перезапуск(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.personal.proc = _Proc()

    _rounds(core, 1)

    assert core.tunnel.outs == [buildconfig.DIRECT_TAG]
    assert core.tunnel.restarts == ["personal"]
    assert core.prober.snapshot()["out"] == buildconfig.DIRECT_TAG


def test_мёртвый_конфиг_перезапускается_раз_в_паузу(monkeypatch):
    """Человек выбрал: без предела попыток, но не чаще DEAD_GAP."""
    core = _core(monkeypatch)
    core.tunnel.side_fail = "личный процесс упал на старте: bad config"
    core.tunnel.personal.proc = _Proc()
    state = _rounds(core, 5)
    assert core.tunnel.restarts == ["personal"]
    assert _said(core, "bad config")
    assert len(_said(core, "жду")) == 1

    core._side_after["personal"] = 0.0          # пауза прошла
    _rounds(core, 1, state)

    assert core.tunnel.restarts == ["personal", "personal"]
    assert core.tunnel.starts == 0


def test_ожил_личный_выход_возвращается_на_него(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.out = buildconfig.DIRECT_TAG
    core.tunnel.delay_ms = 120

    _rounds(core, 1)

    assert core.tunnel.outs == [buildconfig.PERSONAL_SOCKS_TAG]
    assert core.tunnel.restarts == []
    assert _said(core, "120 мс")
    assert core.prober.snapshot()["out"] == buildconfig.PERSONAL_SOCKS_TAG


def test_живой_но_не_везущий_личный_перезапускается(monkeypatch):
    """Выход напрямую — трафика через личный нет, таймаутов не будет: решает проверка."""
    core = _core(monkeypatch)
    core.tunnel.out = buildconfig.DIRECT_TAG

    state = _rounds(core, 1)
    assert core.tunnel.restarts == ["personal"]
    assert core.tunnel.outs == []

    core._side_after["personal"] = 0.0
    _rounds(core, 3, state)                     # проверка не чаще BACK_EVERY
    assert core.tunnel.restarts == ["personal"]


def test_выключение_посреди_круга_перезапуск_не_делает(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.corp.proc = _Proc()
    core.lock.acquire()                          # идёт «Выключить»

    _rounds(core, 1)

    assert core.tunnel.restarts == []


def test_выключил_и_включил_посреди_круга_новый_туннель_не_перезапускает(monkeypatch):
    core = _core(monkeypatch)
    core.tunnel.out = buildconfig.DIRECT_TAG

    def delay(_tag):
        # Пока круг ждёт проверку личного, человек выключает и включает снова.
        core._do_stop()
        core._do_start()
        return None

    monkeypatch.setattr(core.tunnel, "delay", delay)

    _rounds(core, 1)

    assert core.tunnel.restarts == []


def _corp_dead():
    return (_timeout("172.15.0.228:3000", "wg-corp"),
            _timeout("10.160.138.4:443", "wg-corp"),
            _timeout("10.160.138.4:443", "wg-corp"))


def _corp_says(monkeypatch, core, ip):
    asked = []
    monkeypatch.setattr(core.prober, "corp_answer", lambda: asked.append(1) or ip)
    return asked


def test_таймауты_корпа_при_живом_корпе_не_перезапускают(monkeypatch, tmp_path):
    """6 октября в 12:03 таймауты корпа перезапустили sing-box, хотя корп работал."""
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path, "corp")
    asked = _corp_says(monkeypatch, core, "10.20.0.4")
    _append(log, *_corp_dead())

    _rounds(core, 1)

    assert core.tunnel.restarts == []
    assert asked == [1]
    [line] = _said(core, "корп отвечает")
    assert "wg-corp" in line and "DNS 10.20.0.4" in line
    assert core._dead_hits == ()


def test_таймауты_корпа_при_молчащем_корпе_перезапускают_только_его(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path, "corp")
    asked = _corp_says(monkeypatch, core, "")
    _append(log, *_corp_dead())

    _rounds(core, 1)

    assert core.tunnel.restarts == ["corp"]
    assert core.tunnel.outs == [] and core.tunnel.starts == 0
    assert asked == [1]
    assert not _said(core, "корп отвечает")


def test_мёртвый_личный_корп_не_спрашивает(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    asked = _corp_says(monkeypatch, core, "10.20.0.4")
    _append(log, *_three_dead())

    _rounds(core, 1)

    assert core.tunnel.restarts == ["personal"]
    assert asked == []


def test_живой_корп_не_сбивает_счёт_новой_сети(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path, "corp")
    _corp_says(monkeypatch, core, "10.20.0.4")
    _net(core, HOME)
    state = _rounds(core, service.UPLINK_SETTLE - 1)

    _append(log, *_corp_dead())
    _rounds(core, 1, state)

    assert core.tunnel.starts == 1
    assert core.tunnel.uplink == HOME


# ------------------------------------------------------------ журнал сторожа

def _said(core, text):
    return [line for line in core.logged if text in line]


def _three_dead():
    return (_timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"), _timeout("9.9.9.9:443"))


def test_мёртвый_туннель_в_журнале_с_тегом_числом_и_адресами(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    _append(log, _timeout("34.117.59.81:443"), _timeout("172.217.23.238:443"),
            _timeout("34.117.59.81:443"))

    _rounds(core, 1)

    [line] = _said(core, "перезапускаю личный процесс")
    assert "awg-personal" in line
    assert "таймаутов 3" in line
    assert "172.217.23.238, 34.117.59.81" in line


def test_мёртвый_в_паузе_пишется_один_раз(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    _append(log, *_three_dead())
    state = _rounds(core, 1)

    for _ in range(3):
        _append(log, *_three_dead())
        state = _rounds(core, 1, state)

    assert len(_said(core, "жду")) == 1


def test_в_паузе_мёртвого_смена_сети_переподключает(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    _append(log, *_three_dead())
    state = _rounds(core, 1)
    assert core.tunnel.restarts == ["personal"] and core.tunnel.starts == 0

    _net(core, HOME)
    for _ in range(service.UPLINK_SETTLE):
        _append(log, *_three_dead())
        state = _rounds(core, 1, state)

    assert core.tunnel.starts == 1


def test_таймауты_старой_сети_новому_туннелю_не_в_счёт(monkeypatch, tmp_path):
    """После переподключения туннель другой: два таймаута через мёртвый кабель
    и один на Wi-Fi — не три подряд."""
    core = _core(monkeypatch)
    core.tunnel.delay_ms = None
    log = _side_log(core, tmp_path)
    _append(log, _timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"))
    state = _rounds(core, 1)
    _net(core, HOME)
    state = _rounds(core, service.UPLINK_SETTLE, state)
    assert core.tunnel.starts == 1

    _append(log, _timeout("9.9.9.9:443"))
    _rounds(core, 1, state)

    assert core.tunnel.restarts == []


def test_пауза_перезапуска_со_старой_сети_новую_не_держит(monkeypatch, tmp_path):
    """Личный перезапускали на кабеле; на Wi-Fi он упал — поднимать сразу, не ждать DEAD_GAP."""
    core = _core(monkeypatch)
    core.tunnel.personal.proc = _Proc()
    state = _rounds(core, 1)
    assert core.tunnel.restarts == ["personal"]
    _net(core, HOME)
    state = _rounds(core, service.UPLINK_SETTLE, state)
    assert core.tunnel.starts == 1

    core.tunnel.personal.proc = _Proc()
    waits = len(_said(core, "перезапуска нет"))
    _rounds(core, 1, state)

    assert core.tunnel.restarts == ["personal", "personal"]
    assert len(_said(core, "перезапуска нет")) == waits


def test_без_шлюза_мёртвый_не_перезапускает(monkeypatch, tmp_path):
    """Wi-Fi отвалился или компьютер проснулся: таймауты от сети, а не от
    туннеля, и без сети перезапуск ничего не даст."""
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    _net(core, (None, ""))
    _append(log, *_three_dead())
    core.tunnel.corp.proc = _Proc()

    _rounds(core, 3)

    assert core.tunnel.restarts == [] and core.tunnel.outs == []
    assert not _said(core, "перезапускаю")
    assert not _said(core, "жду")


def test_таймауты_без_шлюза_не_копятся(monkeypatch, tmp_path):
    core = _core(monkeypatch)
    log = _side_log(core, tmp_path)
    _net(core, (None, ""))
    _append(log, _timeout("1.1.1.1:443"), _timeout("8.8.8.8:443"))
    state = _rounds(core, 1)

    _net(core, OFFICE)
    _append(log, _timeout("9.9.9.9:443"))
    _rounds(core, 1, state)

    assert core.tunnel.restarts == []


def test_выключенный_туннель_выход_в_статусе_пуст(monkeypatch):
    core = _core(monkeypatch)
    _rounds(core, 1)
    assert core.prober.snapshot()["out"] == buildconfig.PERSONAL_SOCKS_TAG

    core.tunnel.uplink = None
    _rounds(core, 1)

    assert core.prober.snapshot()["out"] == ""


def test_команда_log_сводит_три_журнала_по_времени(monkeypatch, tmp_path):
    monkeypatch.setattr(service.paths, "LOGS", str(tmp_path))
    (tmp_path / "vpn-2026-10-06_090000.log").write_text(
        "+0300 2026-10-06 09:00:01 INFO a\n+0300 2026-10-06 09:00:05 INFO c\n",
        encoding="utf-8")
    (tmp_path / "corp-2026-10-06_090000.log").write_text(
        "+0300 2026-10-06 09:00:03 ERROR b\n  трассировка\n", encoding="utf-8")
    (tmp_path / "personal-2026-10-06_090000.log").write_text(
        "+0300 2026-10-06 09:00:09 WARN d\n", encoding="utf-8")

    lines = service.Core._tail_log(4)

    assert lines == ["[корп] +0300 2026-10-06 09:00:03 ERROR b", "[корп]   трассировка",
                     "+0300 2026-10-06 09:00:05 INFO c",
                     "[личный] +0300 2026-10-06 09:00:09 WARN d"]


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
