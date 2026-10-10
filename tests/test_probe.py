"""Пробер: сетевые проверки идут по событию и не накапливаются.

Сеть и WMI здесь не трогаем — подменяем probe_fast (туннель «поднят»),
probe_slow (висит, пока тест не отпустит), запись status.json и HTTP-клиент.
"""

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from tunnelvpn import probe


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
    monkeypatch.setattr(probe.Prober, "main_tag", staticmethod(lambda: "wg-home"))
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


def _plan(monkeypatch, *items):
    """Что проверять — без tunnels.json и собранного конфига."""
    monkeypatch.setattr(probe.Prober, "check_plan", staticmethod(lambda: list(items)))


def _p_work(**over):
    p = {"id": "work", "name": "Работа", "mode": "list", "host": "git.corp.example",
         "dns": "10.0.0.1", "running": True}
    p.update(over)
    return p


def _p_home(**over):
    p = {"id": "home", "name": "Личный", "mode": "all", "host": "", "dns": "",
         "running": True}
    p.update(over)
    return p


def _checks(p):
    return {tid: (c["result"], c["answer"]) for tid, c in p.snapshot()["checks"].items()}


def test_части_probe_slow_идут_параллельно_а_не_складываются(monkeypatch):
    started = []

    def part(name):
        def run(self, *p):
            started.append((name, *(x["id"] for x in p)))
            time.sleep(0.3)
        return run

    for name in ("_slow_exit", "_slow_v6", "_slow_dns", "_slow_http"):
        monkeypatch.setattr(probe.Prober, name, part(name))
    monkeypatch.setattr(probe.Prober, "probe_fast", lambda self: None)
    _plan(monkeypatch, _p_work(), _p_work(id="work-2", dns=""), _p_home())

    t0 = time.monotonic()
    probe.Prober().probe_slow()

    assert time.monotonic() - t0 < 0.9
    assert sorted(started) == [("_slow_dns", "work"), ("_slow_exit",),
                               ("_slow_http", "work-2"), ("_slow_v6",)]


def test_основной_проверен_раньше_молчащего_рабочего(monkeypatch):
    work_go = threading.Event()
    for name in ("_slow_exit", "_slow_v6"):
        monkeypatch.setattr(probe.Prober, name, lambda self: None)
    monkeypatch.setattr(probe.Prober, "_slow_dns",
                        lambda self, p: work_go.wait(2) and "")
    monkeypatch.setattr(probe.Prober, "probe_fast", lambda self: None)
    _plan(monkeypatch, _p_work(), _p_home())
    p = probe.Prober()
    check = threading.Thread(target=p.check_now, daemon=True)
    check.start()

    assert _wait(lambda: (p.snapshot().get("checks") or {}).get("home", {}).get("seq") == 1)
    s = p.snapshot()
    assert s["check_seq"] == 1 and s["personal_seq"] == 1
    assert "work" not in s["checks"] and s.get("corp_seq", 0) == 0

    work_go.set()
    check.join(2)
    s = p.snapshot()
    assert s["checks"]["work"] == {"result": "error", "answer": "", "seq": 1}
    assert s["corp_seq"] == 1


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


def _slow_parts(monkeypatch, up=True, dns=None, http=None, **st):
    """Части probe_slow без сети: выход и IPv6 кладут в снимок свою долю
    st, DNS и HTTPS туннеля отвечают из dns/http {id: ответ}. Быстрый опрос
    после них видит туннель поднятым, если up. Возвращает список вопросов."""
    asked = []

    def part(*keys):
        def run(self):
            self.set(**{k: st[k] for k in keys if k in st})
        return run

    def answer(how, table):
        def run(self, p):
            asked.append((how, p["id"]))
            return (table or {}).get(p["id"], "")
        return run

    monkeypatch.setattr(probe.Prober, "_slow_exit",
                        part("exit_ip", "exit_country", "exit_org", "exit_state"))
    monkeypatch.setattr(probe.Prober, "_slow_v6", part("v6_leak"))
    monkeypatch.setattr(probe.Prober, "_slow_dns", answer("dns", dns))
    monkeypatch.setattr(probe.Prober, "_slow_http", answer("http", http))
    monkeypatch.setattr(probe.Prober, "probe_fast",
                        lambda self: self.set(tun=45 if up else None, r_low=up))
    return asked


def _work(**over):
    t = {"id": "work", "name": "Работа", "mode": "list", "include": []}
    t.update(over)
    return t


def _home(**over):
    t = {"id": "home", "name": "Личный", "mode": "all"}
    t.update(over)
    return t


def _tunnels(monkeypatch, *items):
    """tunnels.json с этими туннелями — без записи на диск."""
    data = probe.tunnels.validate({"tunnels": list(items)})
    monkeypatch.setattr(probe.tunnels, "load", lambda: data)


def test_итог_проверки_сети_в_журнале(monkeypatch):
    _slow_parts(monkeypatch, exit_ip="185.1.2.3", exit_country="NL",
                exit_state="tunnel", v6_leak="2a00::1", dns={"work": "10.1.1.1"},
                http={"work-2": "403"})
    _plan(monkeypatch, _p_work(), _p_work(id="work-2", name="Вики", dns=""), _p_home())
    logged = []

    probe.Prober(logged.append).probe_slow()

    [line] = logged
    parts = line.split("; ")
    assert "выход 185.1.2.3 (NL), tunnel" in line
    assert any(x.startswith("«Работа» DNS 10.1.1.1 (") and "HTTPS" not in x for x in parts)
    assert any(x.startswith("«Вики» HTTPS 403 (") for x in parts)
    assert "утечка IPv6 2a00::1" in line


def test_итоги_по_туннелям_и_старые_поля_первого_по_списку(monkeypatch):
    _slow_parts(monkeypatch, exit_ip="185.1.2.3", exit_state="tunnel",
                dns={"work": "10.1.1.1"}, http={"work-2": "403"})
    _plan(monkeypatch, _p_work(), _p_work(id="work-2", dns=""), _p_home())
    p = probe.Prober()

    p.probe_slow()

    assert _checks(p) == {"work": ("up", "10.1.1.1"), "work-2": ("up", "HTTP 403"),
                          "home": ("up", "185.1.2.3")}
    s = p.snapshot()
    assert (s["corp_dns"], s["corp_ip"], s["corp_http"]) == ("10.0.0.1", "10.1.1.1", "")


def test_по_списку_с_dns_проверяется_только_dns(monkeypatch):
    # HTTPS к домену мог бы уйти в соседний туннель: его адрес бывает в «не пускать».
    asked = _slow_parts(monkeypatch, dns={"work": "203.0.113.9"})
    _plan(monkeypatch, _p_work())
    p = probe.Prober()

    p.probe_slow()

    assert asked == [("dns", "work")]
    assert _checks(p) == {"work": ("up", "203.0.113.9")}
    assert p.snapshot()["corp_http"] == ""


def test_по_списку_без_dns_проверяется_только_https(monkeypatch):
    asked = _slow_parts(monkeypatch)
    _plan(monkeypatch, _p_work(dns=""))
    p = probe.Prober()

    p.probe_slow()

    assert asked == [("http", "work")]
    assert _checks(p) == {"work": ("error", "")}


@pytest.mark.parametrize("st", [
    {},
    {"exit_ip": "5.6.7.8", "exit_state": "leak"},
    {"exit_ip": "5.6.7.8", "exit_state": "direct"},
])
def test_основной_без_выхода_с_утечкой_или_напрямую_молчит(monkeypatch, st):
    _slow_parts(monkeypatch, **st)
    _plan(monkeypatch, _p_home())
    p = probe.Prober()

    p.probe_slow()

    assert _checks(p)["home"][0] == "error"


def test_запасной_выход_напрямую_у_основного_молчит(monkeypatch):
    _slow_parts(monkeypatch, exit_ip="185.1.2.3", exit_state="tunnel")
    _plan(monkeypatch, _p_home())
    p = probe.Prober()
    p.set(out=probe.buildconfig.DIRECT_TAG)

    p.probe_slow()

    assert _checks(p)["home"][0] == "error"


def test_не_поднятый_туннель_не_проверяется_и_без_итога(monkeypatch):
    asked = _slow_parts(monkeypatch, exit_ip="185.1.2.3", exit_state="tunnel")
    _plan(monkeypatch, _p_work(running=False), _p_home(running=False))
    logged = []
    p = probe.Prober(logged.append)

    p.probe_slow()

    assert asked == []
    assert _checks(p) == {"work": ("", ""), "home": ("", "")}
    assert "«Работа»" not in logged[0]


def test_итоги_удалённых_туннелей_не_остаются(monkeypatch):
    _slow_parts(monkeypatch, exit_ip="185.1.2.3", exit_state="tunnel")
    _plan(monkeypatch, _p_home())
    p = probe.Prober()
    p.set(checks={"gone": {"result": "up", "answer": "10.0.0.8", "seq": 1}})

    p.probe_slow()

    assert set(p.snapshot()["checks"]) == {"home"}


def test_туннель_опустился_итоги_стираются_номера_остаются(monkeypatch):
    net = {"up": False}
    p, loop = _run_loop(monkeypatch, net, lambda self: None)
    p.set(checks={"work": {"result": "up", "answer": "10.0.0.8", "seq": 3}})

    try:
        assert _wait(lambda: p.snapshot()["checks"]["work"]["result"] == "")
        assert p.snapshot()["checks"]["work"] == {"result": "", "answer": "", "seq": 3}
    finally:
        _stop_loop(p, loop)


def test_туннель_опустился_во_время_проверки_выход_не_tunnel(monkeypatch):
    # 13:52 06.10: проверку начали при живом туннеле, кончили после его
    # остановки — адрес провайдера ушёл в журнал с меткой «tunnel».
    _slow_parts(monkeypatch, up=False, exit_ip="46.242.14.241", exit_state="tunnel")
    _plan(monkeypatch)
    logged = []
    p = probe.Prober(logged.append)

    p.probe_slow()

    assert p.snapshot()["exit_state"] == "unknown"
    assert "выход 46.242.14.241, unknown" in logged[0]


def test_итог_без_dns_и_домена_в_пускать_так_и_пишет(monkeypatch):
    asked = _slow_parts(monkeypatch)
    _plan(monkeypatch, _p_work(host="", dns=""), _p_home())
    logged = []
    p = probe.Prober(logged.append)

    p.probe_slow()

    [line] = logged
    assert "выход не узнал" in line
    assert "«Работа» не проверял (ни DNS в конфиге, ни домена в «пускать»)" in line
    assert "IPv6 без утечки" in line
    assert asked == []
    assert _checks(p)["work"] == ("none", "")


def test_без_домена_в_пускать_конфиг_проверяется_по_dns(monkeypatch):
    # wg0-korolev: «не с чем проверить», хотя его DNS отвечал — конфиг жив.
    asked = _slow_parts(monkeypatch, dns={"work": probe.DNS_NO_ADDR})
    _plan(monkeypatch, _p_work(host=""))
    logged = []
    p = probe.Prober(logged.append)

    p.probe_slow()

    assert asked == [("dns", "work")]
    assert _checks(p) == {"work": ("up", "по DNS")}
    assert "«Работа» DNS отвечает (" in logged[0]


def test_dns_отвечает_а_домена_не_знает_это_правила(monkeypatch):
    # В «пускать» личного конфига вписали рабочий домен: сервер жив, не те правила.
    _slow_parts(monkeypatch, dns={"work": probe.DNS_NO_ADDR})
    _plan(monkeypatch, _p_work())
    logged = []
    p = probe.Prober(logged.append)

    p.probe_slow()

    assert _checks(p) == {"work": ("rules", "git.corp.example")}
    assert p.snapshot()["corp_ip"] == ""
    assert "«Работа» DNS отвечает, но «git.corp.example» не знает (" in logged[0]


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
    answers = iter([(False, ""), (True, "10.0.0.8")])
    monkeypatch.setattr(probe.winnet, "dns_ask_via",
                        lambda name, server, timeout: next(answers))

    assert probe.Prober._dns_ask("10.0.0.1", "corp") == "10.0.0.8"


def test_dns_ask_ответ_без_адреса_окончателен(monkeypatch):
    asked = []
    monkeypatch.setattr(probe.winnet, "dns_ask_via",
                        lambda name, server, timeout: asked.append(name) or (True, ""))

    assert probe.Prober._dns_ask("10.0.0.1", "corp") == probe.DNS_NO_ADDR
    assert asked == ["corp"]


def test_dns_ask_молчит_после_всех_попыток_пусто(monkeypatch):
    monkeypatch.setattr(probe.winnet, "dns_ask_via",
                        lambda name, server, timeout: (False, ""))

    assert probe.Prober._dns_ask("10.0.0.1", "corp") == ""


@pytest.mark.parametrize("plan, name", [
    ([_p_work(), _p_work(id="work-2", host="wiki.corp.example", dns="10.0.0.2")],
     "wiki.corp.example"),
    ([_p_work(id="work-2", host="", dns="10.0.0.2")], probe.DNS_ASK_NAME),
])
def test_tunnel_answer_спрашивает_dns_этого_туннеля(monkeypatch, plan, name):
    asked = []
    _plan(monkeypatch, *plan)
    monkeypatch.setattr(probe.winnet, "dns_ask_via",
                        lambda name, server, timeout: asked.append((name, server))
                        or (True, "10.0.0.8"))

    assert probe.Prober().tunnel_answer("work-2") == "10.0.0.8"
    assert asked == [(name, "10.0.0.2")]


@pytest.mark.parametrize("tid, plan", [
    ("work", [_p_work(dns="")]),
    ("gone", [_p_work()]),
])
def test_tunnel_answer_не_спрашивает_когда_нечем(monkeypatch, tid, plan):
    _plan(monkeypatch, *plan)
    monkeypatch.setattr(probe.winnet, "dns_ask_via",
                        lambda *a, **kw: pytest.fail("спросил без DNS"))

    assert probe.Prober().tunnel_answer(tid) == ""


def test_check_plan_по_tunnels_json_и_собранному_конфигу(monkeypatch, tmp_path):
    _tunnels(monkeypatch,
             _work(include=["198.51.100.7", "*.corp.example", "git.corp.example"]),
             _work(id="work-2", include=["other.example"]),
             _home(include=["home.example"]))
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "outbounds": [{"type": "socks", "tag": "socks-work"},
                      {"type": "socks", "tag": "socks-home"}],
        "dns": {"servers": [{"tag": "dns", "server": "1.1.1.1"},
                            {"tag": "dns-work", "server": "10.0.0.1"}]}}),
        encoding="utf-8")
    monkeypatch.setattr(probe.paths, "CONFIG_JSON", str(cfg))

    plan = probe.Prober.check_plan()

    assert plan == [
        _p_work(),
        _p_work(id="work-2", host="other.example", dns="", running=False),
        _p_home(),
    ]


def test_check_plan_испорченный_tunnels_json_пусто(monkeypatch):
    def broken():
        raise ValueError("tunnels.json не читается")
    monkeypatch.setattr(probe.tunnels, "load", broken)

    assert probe.Prober.check_plan() == []


def test_corp_probe_первый_домен_первого_туннеля_по_списку(monkeypatch):
    _tunnels(monkeypatch,
             _work(include=["198.51.100.7", "*.corp.example", "git.corp.example",
                            "wiki.corp.example"]),
             _work(id="work-2", include=["other.example"]),
             _home())

    assert probe.Prober.corp_probe() == "git.corp.example"


@pytest.mark.parametrize("items", [
    [],
    [{"id": "home", "name": "Личный", "mode": "all"}],
    [{"id": "work", "name": "Работа", "mode": "list", "include": ["*.corp.example"]}],
])
def test_corp_probe_пусто_когда_проверять_нечем(monkeypatch, items):
    _tunnels(monkeypatch, *items)

    assert probe.Prober.corp_probe() == ""


def test_испорченный_tunnels_json_проверку_не_роняет(monkeypatch):
    def broken():
        raise ValueError("tunnels.json не читается")
    monkeypatch.setattr(probe.tunnels, "load", broken)

    assert probe.Prober.corp_probe() == ""
    assert probe.Prober.current_profile() == ""


def test_профиль_это_активный_конфиг_основного_туннеля(monkeypatch):
    _tunnels(monkeypatch, _work(active="corp"), _home(active="nl-1"))
    assert probe.Prober.current_profile() == "nl-1"

    _tunnels(monkeypatch, _work(active="corp"))
    assert probe.Prober.current_profile() == ""


def _exit(monkeypatch, tmp_path, ip, real, main_id):
    """Проверка выхода: сервис отвечает ip, без VPN наш адрес real."""
    real_file = tmp_path / "real_ip"
    real_file.write_text(real, encoding="utf-8")
    monkeypatch.setattr(probe.paths, "REAL_IP_FILE", str(real_file))
    monkeypatch.setattr(probe.Prober, "_exit_info", lambda self: {"ip": ip})
    monkeypatch.setattr(probe.Prober, "peer_addrs", lambda self: {
        "wg-work": "198.51.100.7", "wg-home": "203.0.113.9"})
    monkeypatch.setattr(probe.Prober, "main_tag",
                        staticmethod(lambda: probe.buildconfig.ep_tag(main_id)
                                     if main_id else ""))
    p = probe.Prober()
    p._slow_exit()
    return p.snapshot()["exit_state"]


def test_выход_адресом_сервера_основного_это_туннель(monkeypatch, tmp_path):
    # Одноногий сервер: адрес выхода совпал с адресом пира основного туннеля.
    assert _exit(monkeypatch, tmp_path, "203.0.113.9", "203.0.113.9", "home") == "tunnel"


def test_адрес_сервера_не_основного_туннеля_выходом_не_считается(monkeypatch, tmp_path):
    assert _exit(monkeypatch, tmp_path, "198.51.100.7", "198.51.100.7", "home") == "leak"


@pytest.mark.parametrize("ip", ["203.0.113.9", "5.6.7.8"])
def test_без_основного_туннеля_выход_напрямую_а_не_утечка(monkeypatch, tmp_path, ip):
    # Всё, что не забрал туннель «по списку», без основного идёт напрямую —
    # так задумано: адрес провайдера не «Трафик мимо туннеля».
    assert _exit(monkeypatch, tmp_path, ip, ip, None) == "direct"
