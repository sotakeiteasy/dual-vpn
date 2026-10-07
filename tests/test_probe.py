"""Пробер: сетевые проверки идут по событию и не накапливаются.

Сеть и WMI здесь не трогаем — подменяем probe_fast (туннель «поднят»),
probe_slow (висит, пока тест не отпустит), запись status.json и HTTP-клиент.
"""

import threading
import time
import urllib.error
import urllib.request

import pytest

from dualvpn import probe


def _wait(cond, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not cond() and time.monotonic() < deadline:
        time.sleep(0.01)
    return cond()


def _run_loop(monkeypatch, net, slow):
    """Цикл пробера с «сетью» net.up вместо WMI и slow вместо сети."""
    monkeypatch.setattr(probe, "FAST_EVERY", 0.01)
    monkeypatch.setattr(probe.Prober, "probe_fast",
                        lambda self: self.set(tun=net["up"], r_low=net["up"]))
    monkeypatch.setattr(probe.Prober, "probe_slow", slow)
    monkeypatch.setattr(probe.Prober, "write_status", lambda self: None)
    p = probe.Prober()
    loop = threading.Thread(target=p.run, daemon=True)
    loop.start()
    return p, loop


@pytest.mark.parametrize("out, state", [("direct", "direct"), ("personal-socks", "leak")])
def test_адрес_провайдера_на_запасном_выходе_не_утечка(monkeypatch, tmp_path, out, state):
    real = tmp_path / "real-ip"
    real.write_text("5.6.7.8", encoding="utf-8")
    monkeypatch.setattr(probe.paths, "REAL_IP_FILE", str(real))
    monkeypatch.setattr(probe.Prober, "peer_addrs", lambda self: {})
    monkeypatch.setattr(probe.Prober, "_exit_info", lambda self: {"ip": "5.6.7.8"})
    p = probe.Prober()
    p.set(out=out)

    p._slow_exit()

    assert p.snapshot()["exit_state"] == state


def _stop_loop(p, loop):
    p.stop_event.set()
    loop.join(2)
    # Поток проверки не должен пережить снятие подмен monkeypatch.
    _wait(lambda: not p.slow_busy.is_set())


def test_сетевая_проверка_один_раз_на_подъёме_а_не_по_расписанию(monkeypatch):
    net = {"up": True}
    calls = []
    p, loop = _run_loop(monkeypatch, net, lambda self: calls.append(1))
    try:
        assert _wait(lambda: calls)
        time.sleep(0.3)               # десятки кругов — повторов быть не должно
        assert calls == [1]

        # Туннель упал и поднялся — новый подъём меряем заново.
        net["up"] = False
        time.sleep(0.1)
        net["up"] = True
        assert _wait(lambda: len(calls) == 2)
        time.sleep(0.2)
        assert calls == [1, 1]
    finally:
        _stop_loop(p, loop)


def test_remeasure_проверяет_заново_без_видимого_падения(monkeypatch):
    net = {"up": True}
    calls = []
    p, loop = _run_loop(monkeypatch, net, lambda self: calls.append(1))
    try:
        assert _wait(lambda: calls)

        # Переподключение уложилось между кругами — цикл туннель упавшим не видел.
        p.remeasure()
        assert _wait(lambda: len(calls) == 2)
        time.sleep(0.2)
        assert calls == [1, 1]
    finally:
        _stop_loop(p, loop)


def test_проверка_на_подъёме_при_занятой_идёт_после_её_конца(monkeypatch):
    release = threading.Event()
    calls = []

    def slow(self):
        calls.append(1)
        if len(calls) == 1:
            release.wait(5)

    net = {"up": False}
    p, loop = _run_loop(monkeypatch, net, slow)
    first = threading.Thread(target=p.check_now, daemon=True)
    try:
        first.start()
        assert _wait(lambda: calls)
        # Туннель поднялся, пока шла проверка по запросу: её ответ мерил
        # ещё прежнее состояние, своя проверка не теряется, а ждёт.
        net["up"] = True
        time.sleep(0.2)
        assert calls == [1]

        release.set()
        assert _wait(lambda: len(calls) == 2)
        time.sleep(0.2)
        assert calls == [1, 1]
    finally:
        release.set()
        first.join(2)
        _stop_loop(p, loop)


def test_check_now_при_идущей_проверке_ждёт_её_а_не_запускает_вторую(monkeypatch):
    release = threading.Event()
    calls = []

    def slow(self):
        calls.append(1)
        release.wait(5)

    monkeypatch.setattr(probe.Prober, "probe_slow", slow)
    p = probe.Prober()

    first = threading.Thread(target=p.check_now, daemon=True)
    first.start()
    time.sleep(0.1)
    second = threading.Thread(target=p.check_now, daemon=True)
    second.start()
    time.sleep(0.3)
    # Второй вызов ждёт первую проверку, своей не запускает.
    assert calls == [1] and second.is_alive()

    release.set()
    first.join(2)
    second.join(2)
    assert not second.is_alive() and calls == [1]
    assert not p.slow_busy.is_set()


def test_check_now_без_идущей_проверки_проверяет_сразу(monkeypatch):
    calls = []
    monkeypatch.setattr(probe.Prober, "probe_slow", lambda self: calls.append(1))
    p = probe.Prober()
    p.check_now()
    p.check_now()
    assert calls == [1, 1]


def test_части_probe_slow_идут_параллельно_а_не_складываются(monkeypatch):
    started = []

    def part(name):
        def run(self):
            started.append(name)
            time.sleep(0.3)
        return run

    for name in ("_slow_exit", "_slow_v6", "_slow_corp_dns", "_slow_corp_http"):
        monkeypatch.setattr(probe.Prober, name, part(name))
    monkeypatch.setattr(probe.Prober, "probe_fast", lambda self: None)

    t0 = time.monotonic()
    probe.Prober().probe_slow()

    assert time.monotonic() - t0 < 0.9
    assert sorted(started) == ["_slow_corp_dns", "_slow_corp_http",
                               "_slow_exit", "_slow_v6"]


def test_личный_проверен_раньше_молчащего_корпа(monkeypatch):
    corp_go = threading.Event()
    for name in ("_slow_exit", "_slow_v6", "_slow_corp_dns"):
        monkeypatch.setattr(probe.Prober, name, lambda self: None)
    monkeypatch.setattr(probe.Prober, "_slow_corp_http",
                        lambda self: corp_go.wait(2))
    monkeypatch.setattr(probe.Prober, "probe_fast", lambda self: None)
    p = probe.Prober()
    check = threading.Thread(target=p.check_now, daemon=True)
    check.start()

    assert _wait(lambda: p.snapshot().get("personal_seq") == 1)
    assert p.snapshot()["check_seq"] == 1
    assert p.snapshot().get("corp_seq", 0) == 0

    corp_go.set()
    check.join(2)
    assert p.snapshot()["corp_seq"] == 1


def _exit_services(monkeypatch, answers):
    """Сервисы адреса выхода без сети: url → (через сколько, ответ)."""
    def get(url, _timeout):
        wait, text = answers.get(url, (0.0, ""))
        time.sleep(wait)
        return text

    monkeypatch.setattr(probe.Prober, "_get", staticmethod(get))


def test_сервисы_выхода_спрашиваются_разом_а_не_по_очереди(monkeypatch):
    _exit_services(monkeypatch, {
        "https://ipinfo.io/json": (0.3, ""),
        "https://ipwho.is/": (0.3, "429"),
        "https://api.ipify.org": (0.3, ""),
        "https://ifconfig.me/ip": (0.3, "5.6.7.8"),
    })

    t0 = time.monotonic()
    info = probe.Prober()._exit_info()

    assert info == {"ip": "5.6.7.8"}
    assert time.monotonic() - t0 < 0.9


def test_быстрый_голый_адрес_не_перебивает_адрес_со_страной(monkeypatch):
    _exit_services(monkeypatch, {
        "https://ipinfo.io/json": (0.2, '{"ip": "1.2.3.4", "country": "NL"}'),
        "https://api.ipify.org": (0.0, "1.2.3.4"),
    })

    info = probe.Prober()._exit_info()

    assert info == {"ip": "1.2.3.4", "country": "NL"}


def test_ipwho_разбирается_в_поля_ipinfo(monkeypatch):
    _exit_services(monkeypatch, {
        "https://ipwho.is/": (0.0, '{"ip": "1.2.3.4", "country_code": "NL", '
                                   '"city": "Amsterdam", "connection": {"org": "AS1"}}'),
    })

    info = probe.Prober()._exit_info()

    assert info == {"ip": "1.2.3.4", "country": "NL", "city": "Amsterdam", "org": "AS1"}


def _slow_parts(monkeypatch, up=True, **st):
    """Части probe_slow без сети: каждая кладёт в снимок свою долю st.
    Быстрый опрос после них видит туннель поднятым, если up."""
    def part(*keys):
        def run(self):
            self.set(**{k: st[k] for k in keys if k in st})
        return run

    monkeypatch.setattr(probe.Prober, "_slow_exit",
                        part("exit_ip", "exit_country", "exit_org", "exit_state"))
    monkeypatch.setattr(probe.Prober, "_slow_v6", part("v6_leak"))
    monkeypatch.setattr(probe.Prober, "_slow_corp_dns", part("corp_ip"))
    monkeypatch.setattr(probe.Prober, "_slow_corp_http", part("corp_http"))
    monkeypatch.setattr(probe.Prober, "probe_fast",
                        lambda self: self.set(tun=45 if up else None, r_low=up))


def test_итог_проверки_сети_в_журнале(monkeypatch):
    _slow_parts(monkeypatch, exit_ip="185.1.2.3", exit_country="NL",
                exit_state="tunnel", corp_ip="10.1.1.1", corp_http="",
                v6_leak="2a00::1")
    monkeypatch.setattr(probe.paths, "site_env", lambda: {"CORP_PROBE": "corp.example"})
    logged = []

    probe.Prober(logged.append).probe_slow()

    [line] = logged
    assert "выход 185.1.2.3 (NL), tunnel" in line
    assert "корп DNS 10.1.1.1" in line
    assert "корп HTTPS молчит" in line
    assert "утечка IPv6 2a00::1" in line


def test_туннель_опустился_во_время_проверки_выход_не_tunnel(monkeypatch):
    # 13:52 06.10: проверку начали при живом туннеле, кончили после его
    # остановки — адрес провайдера ушёл в журнал с меткой «tunnel».
    _slow_parts(monkeypatch, up=False, exit_ip="46.242.14.241", exit_state="tunnel")
    monkeypatch.setattr(probe.paths, "site_env", lambda: {})
    logged = []
    p = probe.Prober(logged.append)

    p.probe_slow()

    assert p.snapshot()["exit_state"] == "unknown"
    assert "выход 46.242.14.241, unknown" in logged[0]


def test_итог_без_хоста_корпа_так_и_пишет(monkeypatch):
    _slow_parts(monkeypatch)
    monkeypatch.setattr(probe.paths, "site_env", lambda: {})
    logged = []

    probe.Prober(logged.append).probe_slow()

    [line] = logged
    assert "выход не узнал" in line
    assert "CORP_PROBE не задан" in line
    assert "IPv6 без утечки" in line


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(monkeypatch, *answers):
    """HTTP-клиент отвечает по очереди: исключением или ответом."""
    calls = []

    class _Opener:
        def open(self, req, timeout):
            calls.append(req.get_method())
            a = answers[len(calls) - 1]
            if isinstance(a, Exception):
                raise a
            return a

    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: _Opener())
    return calls


def _http_error(code):
    return urllib.error.HTTPError("https://corp/", code, "", {}, None)


def test_http_code_редирект_и_403_значат_сервер_достижим(monkeypatch):
    for code in (302, 403):
        calls = _opener(monkeypatch, _http_error(code))

        assert probe.Prober._http_code("https://corp/") == str(code)
        assert calls == ["HEAD"]


def test_http_code_потерянная_попытка_повторяется(monkeypatch):
    calls = _opener(monkeypatch, TimeoutError(), _Resp())

    assert probe.Prober._http_code("https://corp/") == "200"
    assert len(calls) == 2


def test_http_code_нет_ответа_после_всех_попыток_пусто(monkeypatch):
    calls = _opener(monkeypatch, *[urllib.error.URLError("down")] * probe.CORP_TRIES)

    assert probe.Prober._http_code("https://corp/") == ""
    assert len(calls) == probe.CORP_TRIES


def test_dns_ask_потерянный_пакет_повторяется(monkeypatch):
    answers = iter(["", "10.0.0.8"])
    monkeypatch.setattr(probe.winnet, "resolve4_via",
                        lambda name, server, timeout: next(answers))

    assert probe.Prober._dns_ask("10.0.0.1", "corp") == "10.0.0.8"


def test_corp_answer_спрашивает_корп_dns_из_конфига(monkeypatch):
    asked = []
    monkeypatch.setattr(probe.paths, "site_env", lambda: {"CORP_PROBE": "git.corp"})
    monkeypatch.setattr(probe.Prober, "corp_dns", lambda self: "10.0.0.1")
    monkeypatch.setattr(probe.winnet, "resolve4_via",
                        lambda name, server, timeout: asked.append((name, server))
                        or "10.0.0.8")

    assert probe.Prober().corp_answer() == "10.0.0.8"
    assert asked == [("git.corp", "10.0.0.1")]


def test_corp_answer_без_corp_probe_не_спрашивает(monkeypatch):
    monkeypatch.setattr(probe.paths, "site_env", lambda: {})
    monkeypatch.setattr(probe.Prober, "corp_dns", lambda self: "10.0.0.1")
    monkeypatch.setattr(probe.winnet, "resolve4_via",
                        lambda *a, **kw: pytest.fail("спросил без CORP_PROBE"))

    assert probe.Prober().corp_answer() == ""
