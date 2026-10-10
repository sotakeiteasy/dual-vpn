"""Конфиги: куда и под каким именем ложится файл, что убирается и что выбрано.

Конфиг лежит в папке своего туннеля (conf\\tunnels\\<id>), а туннель — тот,
через чей пункт конфиг добавили: «рабочий» — первый туннель «по списку»,
«личный» — основной; без пункта — выбранный по AllowedIPs и DNS. Ошибка здесь
не падает сразу: второй рабочий или не тот
личный ломают сборку только при следующем включении, когда человек уже не
помнит, что менял.
"""

import os
import shutil

import pytest

from dualvpn import buildconfig, paths, service, tunnels
from dualvpn.service import Core

WG = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = y\n"

WORK = {"id": "work", "name": "Работа", "mode": "list"}
HOME = {"id": "home", "name": "Личный", "mode": "all"}


def _wg(allowed, dns=""):
    """Конфиг с нужными AllowedIPs и DNS: по ним служба выбирает место."""
    lines = ["[Interface]", "PrivateKey = x", "Address = 10.0.0.2/32"]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["", "[Peer]", "PublicKey = y", "Endpoint = 203.0.113.9:51820"]
    if allowed:
        lines.append(f"AllowedIPs = {allowed}")
    return "\n".join(lines) + "\n"


FULL = _wg("0.0.0.0/0")


def _clean():
    for d in (paths.CONF_TUNNELS, paths.CONF_CORP, paths.CONF_PERSONAL):
        shutil.rmtree(d, ignore_errors=True)
    for f in os.listdir(paths.CONF):
        if os.path.isfile(os.path.join(paths.CONF, f)):
            os.remove(os.path.join(paths.CONF, f))
    if os.path.exists(paths.PROFILE_FILE):
        os.remove(paths.PROFILE_FILE)


def _core():
    # Без __init__: туннель и пробер здесь не нужны, нужна только работа с conf\.
    core = Core.__new__(Core)
    core.logged = []
    core.log = core.logged.append
    return core


@pytest.fixture
def core():
    """Установка 0.4: tunnels.json с рабочим и личным, конфигов нет."""
    _clean()
    tunnels.save({"tunnels": [WORK, HOME]})
    yield _core()
    _clean()


@pytest.fixture
def old():
    """Установка до 0.4: tunnels.json ещё нет."""
    _clean()
    yield _core()
    _clean()


def _files(tid):
    try:
        return sorted(os.listdir(tunnels.conf_dir(tid)))
    except FileNotFoundError:
        return []


def _put(tid, name, text=WG):
    os.makedirs(tunnels.conf_dir(tid), exist_ok=True)
    with open(os.path.join(tunnels.conf_dir(tid), name), "w", encoding="utf-8") as fh:
        fh.write(text)


def _put_in(folder, name):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), "w", encoding="utf-8") as fh:
        fh.write(WG)


def _active(tid):
    return tunnels.find(tunnels.load(), tid)["active"]


def _tunnel(tid):
    return tunnels.find(tunnels.load(), tid)


def _ids():
    return [t["id"] for t in tunnels.load()["tunnels"]]


@pytest.mark.parametrize("given, expected", [
    ("nl-1", "nl-1"),
    ("nl-1.conf", "nl-1"),
    ("wg0 ivanov.CONF", "wg0 ivanov"),
    ("Офис Иванов", "Офис Иванов"),
    ('a<b>c:d"e/f\\g|h?i*j', "a_b_c_d_e_f_g_h_i_j"),
    ("tab\tname", "tab_name"),
    ("../secret", "_secret"),
    ("nl.", "nl"),
    ("  nl  ", "nl"),
    ("CON", "_CON"),
    ("nul.conf", "_nul"),
    ("com1.backup", "_com1.backup"),
    ("", "config"),
    ("...", "config"),
    ("x" * 100, "x" * buildconfig.NAME_MAX),
])
def test_имя_чистится_а_не_отклоняется(given, expected):
    assert buildconfig.safe_name(given) == expected


def test_замена_рабочего_убирает_прежние(core):
    _put("work", "wg0-old.conf")
    _put("work", "wg.conf")
    _put("home", "nl-1.conf")

    r = core._add_config("Офис Иванов", WG, kind="corp")

    assert r["ok"] and r["name"] == "Офис Иванов"
    assert r["corp"] == ["Офис Иванов"] and r["profiles"] == ["nl-1"]
    # Рабочий ровно один, со своим именем и выбран; личные не тронуты.
    assert _files("work") == ["Офис Иванов.conf"]
    assert _active("work") == "Офис Иванов"
    assert _files("home") == ["nl-1.conf"]
    # Замена — тот же доступ с новым файлом: туннель зовётся им в окне.
    assert r["place"] == "replace" and _tunnel("work")["name"] == "Офис Иванов"


def test_тип_задаёт_пункт_а_не_имя(core):
    """wg-home раньше стал бы рабочим по имени; теперь он личный, раз его
    добавили как личный, и имя своё сохраняет."""
    _put("work", "corp.conf")

    r = core._add_config("wg-home", WG, kind="personal")

    assert r["ok"] and r["name"] == "wg-home"
    assert _files("home") == ["wg-home.conf"]
    assert _files("work") == ["corp.conf"]
    assert _active("home") == "wg-home"


def test_добавленный_личный_ложится_рядом_и_выбирается(core):
    _put("home", "nl-1.conf")

    core._add_config("nl-2", WG, kind="personal")

    assert _files("home") == ["nl-1.conf", "nl-2.conf"]
    assert _active("home") == "nl-2"
    # Профиль больше не в state\profile, а в tunnels.json.
    assert not os.path.exists(paths.PROFILE_FILE)


def test_недопустимые_знаки_не_ломают_добавление(core):
    r = core._add_config("my:vpn?", WG, kind="personal")
    assert r["ok"] and r["name"] == "my_vpn_"
    assert _files("home") == ["my_vpn_.conf"]


@pytest.mark.parametrize("kind", ["home", "../corp"])
def test_неизвестный_тип_не_ложится(core, kind):
    r = core._add_config("nl-1", WG, kind=kind)
    assert not r["ok"]
    assert _files("work") == [] and _files("home") == []


def test_без_туннеля_этого_типа_конфиг_не_ложится(core):
    tunnels.save({"tunnels": [HOME]})

    r = core._add_config("corp", WG, kind="corp")

    assert not r["ok"] and "нет туннеля" in r["error"]
    assert _files("work") == []


def test_испорченный_tunnels_json_не_затирается(core):
    with open(paths.TUNNELS_JSON, "w", encoding="utf-8") as fh:
        fh.write("{не json")

    for r in (core._add_config("nl-1", WG, kind="personal"),
              core._remove_config("nl-1", "personal"),
              core._set_profile("nl-1")):
        assert not r["ok"] and "tunnels.json" in r["error"]

    with open(paths.TUNNELS_JSON, encoding="utf-8") as fh:
        assert fh.read() == "{не json"
    assert _files("home") == []


def test_личный_с_тем_же_именем_перезаписывается(core):
    core._add_config("nl-1", WG, kind="personal")
    core._add_config("nl-1", WG.replace("x", "z"), kind="personal")
    assert _files("home") == ["nl-1.conf"]
    r = core._read_config("nl-1", "personal")
    assert r["ok"] and "PrivateKey = z" in r["text"]


def test_чтение_конфига_неизвестного_типа_отказывает(core):
    _put("home", "nl-1.conf")
    assert not core._read_config("nl-1", "home")["ok"]


def test_удаление_выбранного_личного_переключает_на_другой(core):
    _put("work", "corp.conf")
    core._add_config("nl-2", WG, kind="personal")
    core._add_config("nl-1", WG, kind="personal")

    r = core._remove_config("nl-1", "personal")

    assert r["ok"] and r["profiles"] == ["nl-2"]
    # Не corp: рабочий личным туннелем не бывает.
    assert _active("home") == "nl-2"


def test_удаление_последнего_личного_сбрасывает_выбор(core):
    _put("work", "corp.conf")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-1", "personal")

    assert _active("home") == ""


def test_удаление_невыбранного_выбор_не_трогает(core):
    core._add_config("nl-2", WG, kind="personal")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-2", "personal")

    assert _active("home") == "nl-1"


def test_удаление_рабочего_профиль_не_трогает(core):
    """Имя рабочего может совпасть с выбранным личным — папки разные."""
    _put("work", "nl-1.conf")
    core._add_config("nl-1", WG, kind="personal")

    core._remove_config("nl-1", "corp")

    assert _files("work") == [] and _files("home") == ["nl-1.conf"]
    assert _active("home") == "nl-1"


def test_удаление_несуществующего_ничего_не_меняет(core):
    core._add_config("nl-1", WG, kind="personal")

    r = core._remove_config("nl-2", "personal")

    assert not r["ok"]
    assert _active("home") == "nl-1"


def test_профиль_это_активный_конфиг_основного(core):
    _put("home", "nl-1.conf")
    _put("home", "nl-2.conf")

    assert core._set_profile("nl-2") == {"ok": True, "profile": "nl-2"}
    assert _active("home") == "nl-2"

    r = core._set_profile("nl-3")
    assert not r["ok"] and "nl-3" in r["error"]
    assert _active("home") == "nl-2"
    assert not os.path.exists(paths.PROFILE_FILE)


def test_bom_от_блокнота_не_мешает(core):
    r = core._add_config("nl-1", "﻿" + WG, kind="personal")
    assert r["ok"]
    assert core._read_config("nl-1", "personal")["text"].startswith("[Interface]")


@pytest.mark.parametrize("text", ["", "CORP_DOMAINS=\"x.local\"\n", "[Interface]\n"])
def test_не_конфиг_не_ложится_и_ничего_не_удаляет(core, text):
    _put("work", "wg0-old.conf")
    r = core._add_config("corp", text, kind="corp")
    assert not r["ok"]
    assert _files("work") == ["wg0-old.conf"]
    assert _active("work") == ""


# ------------------------------------------------- переезд старой установки

def test_плоский_conf_переезжает_в_туннели(old):
    for f in ("corp.conf", "wg0-ivanov.conf", "personal.conf", "awg-home.conf",
              "nl-1.conf"):
        _put_in(paths.CONF, f)
    with open(os.path.join(paths.CONF, "site.env"), "w", encoding="utf-8") as fh:
        fh.write("CORP_DOMAINS=corp.example\n")

    old._migrate()

    assert _files("work") == ["corp.conf", "wg0-ivanov.conf"]
    assert _files("home") == ["awg-home.conf", "nl-1.conf", "personal.conf"]
    # site.env остаётся рядом копией, старых папок типов нет.
    assert sorted(os.listdir(paths.CONF)) == ["site.env.bak", "tunnels", "tunnels.json"]
    data = tunnels.load()
    # Профиль был пуст — берём тот, что сборка до 0.3 взяла бы сама.
    assert tunnels.find(data, "home")["active"] == "personal"
    assert tunnels.find(data, "work")["include"] == ["corp.example"]


def test_переезд_не_меняет_выбранный_профиль(old):
    _put_in(paths.CONF, "personal.conf")
    _put_in(paths.CONF, "nl-1.conf")
    with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
        fh.write("nl-1")

    old._migrate()

    assert _active("home") == "nl-1"


def test_папки_типов_переезжают_в_туннели(old):
    """Установка 0.3: конфиги уже по папкам corp и personal."""
    _put_in(paths.CONF_CORP, "corp.conf")
    _put_in(paths.CONF_PERSONAL, "nl-1.conf")
    _put_in(paths.CONF_PERSONAL, "nl-2.conf")
    with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
        fh.write("nl-2")

    old._migrate()

    assert _files("work") == ["corp.conf"] and _files("home") == ["nl-1.conf", "nl-2.conf"]
    assert _active("work") == "corp" and _active("home") == "nl-2"
    assert not os.path.exists(paths.CONF_CORP) and not os.path.exists(paths.CONF_PERSONAL)


def test_повторный_переезд_ничего_не_трогает(core):
    _put("home", "nl-1.conf")
    _put_in(paths.CONF_PERSONAL, "nl-2.conf")
    before = tunnels.load()

    core._migrate()

    assert tunnels.load() == before
    assert _files("home") == ["nl-1.conf"]
    assert os.listdir(paths.CONF_PERSONAL) == ["nl-2.conf"]
    assert not os.path.exists(paths.PROFILE_FILE)


def test_сбой_переезда_в_журнале_а_не_падением(old, monkeypatch):
    def broken(log=print):
        raise ValueError("туннелей 9, больше 8 нельзя")
    monkeypatch.setattr(tunnels, "migrate", broken)

    old._migrate()

    assert any("не перенести" in line and "больше 8" in line for line in old.logged)



# --------------------------------------------- конфиги по id туннеля

def test_конфиг_ложится_в_туннель_по_id_и_выбирается(core):
    _put("work", "old.conf")

    r = core._add_config("vpn-2", WG, tunnel="work")

    assert r["ok"] and r["tunnel"] == "work"
    # По id прежние не убираются: «один рабочий» — правило старого пункта.
    assert _files("work") == ["old.conf", "vpn-2.conf"]
    assert _active("work") == "vpn-2"


def test_туннель_находится_по_имени_без_учёта_регистра(core):
    r = core._add_config("nl-1", WG, tunnel="личный")
    assert r["ok"] and _files("home") == ["nl-1.conf"]


def test_id_туннеля_важнее_типа(core):
    r = core._add_config("nl-1", WG, kind="corp", tunnel="home")
    assert r["ok"] and _files("home") == ["nl-1.conf"] and _files("work") == []


@pytest.mark.parametrize("tid", ["nope", "../work", 5])
def test_неизвестный_туннель_отказывает(core, tid):
    r = core._add_config("nl-1", WG, tunnel=tid)
    assert not r["ok"] and "нет туннеля" in r["error"]
    assert _files("work") == [] and _files("home") == []


def test_чтение_и_удаление_по_id(core):
    _put("home", "nl-1.conf")
    _put("home", "nl-2.conf")
    core._set_active("nl-1", tunnel="home")

    assert core._read_config("nl-1", tunnel="home")["text"] == WG
    r = core._remove_config("nl-1", tunnel="home")

    assert r["ok"] and _files("home") == ["nl-2.conf"]
    assert _active("home") == "nl-2"


def test_чтение_с_недопустимым_именем_отказывает(core):
    r = core._read_config("..\\..\\x", tunnel="home")
    assert not r["ok"] and "недопустимое имя" in r["error"]


def test_выбор_конфига_туннеля(core):
    _put("work", "a.conf")
    _put("work", "b.conf")

    assert core._set_active("b", tunnel="work") == {"ok": True, "tunnel": "work",
                                                     "active": "b"}
    assert _active("work") == "b"

    r = core._set_active("c", tunnel="work")
    assert not r["ok"] and "c.conf" in r["error"] and _active("work") == "b"


def test_туннель_по_списку_выключается_и_включается(core):
    """Флаг в tunnels.json: переживает перезагрузку службы."""
    _put("work", "corp.conf")

    assert core._set_enabled("work", False) == {"ok": True, "tunnel": "work",
                                                 "enabled": False}
    assert _tunnel("work")["enabled"] is False and _files("work") == ["corp.conf"]
    assert core._set_enabled("Работа", True)["enabled"] is True
    assert _tunnel("work")["enabled"] is True


def test_основной_флагом_не_выключается(core):
    """Основной выключает «Всё остальное напрямую» — set-tunnel {mode: list}."""
    r = core._set_enabled("home", False)

    assert not r["ok"] and "напрямую" in r["error"]
    assert _tunnel("home")["enabled"] is True


@pytest.mark.parametrize("on", [None, 0, "false"])
def test_вкл_выкл_только_true_или_false(core, on):
    """Строка «false» из канала — не False: молча включённый туннель хуже отказа."""
    r = core._set_enabled("work", on)

    assert not r["ok"] and _tunnel("work")["enabled"] is True


def test_вкл_выкл_через_handle(core):
    r = core.handle("set-enabled", {"tunnel": "work", "on": False}, is_admin=False)

    assert r["ok"] and _tunnel("work")["enabled"] is False


def test_выключенный_не_становится_основным(core):
    """Выключил человек — повышение после ухода основного его не включает."""
    nl = {"id": "t1", "name": "nl", "mode": "list", "enabled": False}
    fi = {"id": "t2", "name": "fi", "mode": "list"}
    tunnels.save({"tunnels": [HOME, nl, fi]})
    for tid, name in (("home", "de"), ("t1", "nl"), ("t2", "fi")):
        _put(tid, name + ".conf", FULL)

    assert core._remove_tunnel("home")["ok"]

    assert [_tunnel(i)["mode"] for i in ("t1", "t2")] == ["list", "all"]
    assert _tunnel("t1")["enabled"] is False


# ------------------------------------------------- команды tunnels.json

def test_новый_туннель_получает_свободный_id(core):
    os.makedirs(tunnels.conf_dir("t1"))      # папка, оставшаяся от удаления

    r = core._add_tunnel("Офис 2", "list")

    assert r == {"ok": True, "id": "t2"}
    t = tunnels.find(tunnels.load(), "t2")
    assert (t["name"], t["mode"], t["include"]) == ("Офис 2", "list", [])


def test_второй_туннель_на_весь_трафик_не_добавляется(core):
    r = core._add_tunnel("Ещё личный", "all")
    assert not r["ok"] and "только один" in r["error"]
    assert len(tunnels.load()["tunnels"]) == 2


def test_списки_разбираются_а_непонятое_возвращается(core):
    r = core._set_tunnel("work", {"include": "a.ru, 1.2.3.4; *.b.ru  foo_bar",
                                  "name": "Офис"})

    # Сохранённые списки — в ответе: окно показывает «сохранено N» рядом с непонятым.
    assert r == {"ok": True, "rejected": {"include": ["foo_bar"]},
                 "include": ["a.ru", "1.2.3.4/32", "*.b.ru"], "exclude": [],
                 "mode": "list"}
    t = tunnels.find(tunnels.load(), "work")
    assert t["include"] == ["a.ru", "1.2.3.4/32", "*.b.ru"]
    assert t["name"] == "Офис" and t["exclude"] == []


def test_длинный_список_отклоняется_целиком(core, monkeypatch):
    monkeypatch.setattr("dualvpn.service.MAX_RULES", 2)

    r = core._set_tunnel("work", {"include": "a.ru b.ru c.ru"})

    assert not r["ok"] and "больше 2" in r["error"]
    assert tunnels.find(tunnels.load(), "work")["include"] == []


def test_всё_остальное_без_полного_конфига_не_ставится(core):
    _put("work", "corp.conf", _wg("10.53.0.0/16"))

    r = core._set_tunnel("work", {"mode": "all"})

    assert not r["ok"] and "0.0.0.0/0" in r["error"]
    assert [_tunnel(i)["mode"] for i in ("work", "home")] == ["list", "all"]


def test_всё_остальное_через_туннель_переключает_основной(core):
    _put("work", "nl.conf", FULL)
    _put("home", "de.conf", FULL)

    r = core._set_tunnel("work", {"mode": "all"})

    assert r["ok"]
    assert [_tunnel(i)["mode"] for i in ("work", "home")] == ["all", "list"]


def test_всё_остальное_напрямую(core):
    assert core._set_tunnel("home", {"mode": "list"})["ok"]
    assert tunnels.main_tunnel(tunnels.load()) is None


def test_одна_запись_у_двух_туннелей_отказ(core):
    core._add_tunnel("Лаб", "list")
    core._set_tunnel("t1", {"include": "a.ru"})

    r = core._set_tunnel("work", {"include": "b.ru a.ru"})

    assert not r["ok"] and "«a.ru» уже в «Лаб»" in r["error"]
    assert _tunnel("work")["include"] == []


def test_вложенный_домен_не_дубль(core):
    core._add_tunnel("Лаб", "list")
    core._set_tunnel("t1", {"include": "a.ru"})

    assert core._set_tunnel("work", {"include": "x.a.ru"})["ok"]


def test_адрес_в_сетях_конфига_другого_туннеля_только_через_его_не_пускать(core):
    _put("work", "corp.conf", _wg("10.53.0.0/16"))
    core._add_tunnel("Лаб", "list")

    r = core._set_tunnel("t1", {"include": "10.53.1.5"})
    assert not r["ok"] and "«не пускать»" in r["error"] and "«Работа»" in r["error"]

    assert core._set_tunnel("work", {"exclude": "10.53.1.0/24"})["ok"]
    assert core._set_tunnel("t1", {"include": "10.53.1.5"})["ok"]

    # Убрать исключение назад — снова дубль, уже со стороны «Работы».
    r = core._set_tunnel("work", {"exclude": ""})
    assert not r["ok"] and _tunnel("work")["exclude"] == ["10.53.1.0/24"]


def test_подсеть_шире_чужой_тоже_дубль(core):
    _put("work", "corp.conf", _wg("10.53.1.0/24"))
    core._add_tunnel("Лаб", "list")

    r = core._set_tunnel("t1", {"include": "10.53.0.0/16"})

    assert not r["ok"] and _tunnel("t1")["include"] == []


def test_прежний_основной_со_списком_проверяется_на_дубль(core):
    _put("work", "nl.conf", FULL)
    data = tunnels.load()
    tunnels.find(data, "home")["include"] = ["a.ru"]     # набрано, пока был основным
    tunnels.find(data, "work")["include"] = ["a.ru"]
    tunnels.save(data)
    core._add_tunnel("Лаб", "list")
    _put("t1", "de.conf", FULL)

    r = core._set_tunnel("t1", {"mode": "all"})

    assert not r["ok"] and "«a.ru» уже в" in r["error"]
    assert [_tunnel(i)["mode"] for i in ("work", "home", "t1")] == ["list", "all", "list"]


def test_все_дубли_полями_а_не_первый(core):
    core._add_tunnel("Лаб", "list")
    _put("t1", "lab.conf", _wg("10.53.0.0/16"))
    core._set_tunnel("t1", {"include": "a.ru"})

    r = core._set_tunnel("work", {"include": "a.ru 10.53.1.5 d.ru"})

    # Окно ставит их под поле разом: по одной на «Сохранить» — исправлять по кругу.
    assert not r["ok"]
    texts = [p["text"] for p in r["problems"]]
    assert {p["field"] for p in r["problems"]} == {"include"} and len(texts) == 2
    assert texts[0] == "«a.ru» уже в «Лаб»"
    assert "«10.53.1.5/32»" in texts[1] and "«Лаб»" in texts[1]
    assert all(t in r["error"] for t in texts)
    assert _tunnel("work")["include"] == []


def test_полный_без_пускать_и_без_основного_становится_основным(core):
    tunnels.save({"tunnels": [{**WORK, "include": ["a.ru"]}]})
    _put("work", "nl.conf", FULL)

    r = core._set_tunnel("work", {"include": ""})

    assert r["ok"] and r["mode"] == "all"
    assert _tunnel("work")["mode"] == "all"


def test_полный_без_пускать_при_основном_уходит_к_нему_запасным(core):
    tunnels.save({"tunnels": [{**WORK, "include": ["a.ru"]}, {**HOME, "active": "de"}]})
    _put("work", "nl.conf", FULL)
    _put("home", "de.conf", FULL)

    r = core._set_tunnel("work", {"include": ""})

    assert r == {"ok": True, "moved": {"tunnel": "home", "name": "nl", "main": "Личный"}}
    assert _ids() == ["home"] and _tunnel("home")["active"] == "de"
    assert tunnels.list_confs("home") == ["de", "nl"]
    assert not os.path.exists(tunnels.conf_dir("work"))


def test_полный_без_пускать_с_не_пускать_остаётся_туннелем(core):
    tunnels.save({"tunnels": [{**WORK, "include": ["a.ru"], "exclude": ["b.ru"]}, HOME]})
    _put("work", "nl.conf", FULL)
    _put("home", "de.conf", FULL)

    r = core._set_tunnel("work", {"include": ""})

    # У запасного своих списков нет: «не пускать» молча не теряется.
    assert not r["ok"]
    assert [p["field"] for p in r["problems"]] == ["include"]
    assert "запасным к «Личный»" in r["error"] and "«не пускать»" in r["error"]
    assert _tunnel("work")["include"] == ["a.ru"]
    assert tunnels.list_confs("work") == ["nl"]


def test_полный_с_непонятым_в_пускать_не_уходит_запасным(core):
    tunnels.save({"tunnels": [{**WORK, "include": ["a.ru"]}, HOME]})
    _put("work", "nl.conf", FULL)
    _put("home", "de.conf", FULL)

    r = core._set_tunnel("work", {"include": "foo_bar"})

    # Список пуст, но человек что-то вписал: с удалённым туннелем это пропало бы.
    assert not r["ok"]
    assert r["problems"] == [{"field": "include", "text": "не понял: foo_bar"}]
    assert _ids() == ["work", "home"]


def test_полный_без_пускать_с_тем_же_именем_в_основном_отказ_полем(core):
    tunnels.save({"tunnels": [{**WORK, "include": ["a.ru"]}, HOME]})
    _put("work", "nl.conf", FULL)
    _put("home", "nl.conf", FULL)

    r = core._set_tunnel("work", {"include": ""})

    assert not r["ok"]
    assert r["problems"] == [{"field": "include", "text": "в «Личный» уже есть nl.conf"}]
    assert _ids() == ["work", "home"] and _tunnel("work")["include"] == ["a.ru"]


def test_полный_без_пускать_с_несколькими_конфигами_не_переносится(core):
    tunnels.save({"tunnels": [{**WORK, "include": ["a.ru"], "active": "nl"}, HOME]})
    _put("work", "nl.conf", FULL)
    _put("work", "fi.conf", FULL)
    _put("home", "de.conf", FULL)

    r = core._set_tunnel("work", {"include": ""})

    assert not r["ok"] and "несколько конфигов" in r["error"]
    assert tunnels.list_confs("work") == ["fi", "nl"]


def test_неполный_без_пускать_остаётся_по_списку(core):
    tunnels.save({"tunnels": [{**WORK, "include": ["a.ru"]}]})
    _put("work", "corp.conf", _wg("10.53.0.0/16"))

    r = core._set_tunnel("work", {"include": ""})

    # Везёт свои AllowedIPs — ему «пускать» не нужно.
    assert r["ok"] and _tunnel("work")["mode"] == "list"


def test_всё_остальное_напрямую_не_отменяется_повышением(core):
    _put("home", "de.conf", FULL)
    core._add_tunnel("Лаб", "list")
    _put("t1", "lab.conf")

    assert core._set_tunnel("home", {"mode": "list"})["ok"]
    assert core._remove_tunnel("t1")["ok"]

    assert tunnels.main_tunnel(tunnels.load()) is None


@pytest.mark.parametrize("remove", [
    lambda core: core._remove_tunnel("home"),
    lambda core: core._remove_config("de", tunnel="home", drop_tunnel=True),
])
def test_удалён_основной_повышается_первый_полный_без_пускать(core, remove):
    nl = {"id": "t1", "name": "nl", "mode": "list"}
    fi = {"id": "t2", "name": "fi", "mode": "list"}
    tunnels.save({"tunnels": [{**WORK, "include": ["a.ru"]}, HOME, nl, fi]})
    for tid, name in (("work", "w"), ("home", "de"), ("t1", "nl"), ("t2", "fi")):
        _put(tid, name + ".conf", FULL)

    assert remove(core)["ok"]

    # У «Работы» есть «пускать» — она туннелирует; из двух пустых — первый.
    assert [_tunnel(i)["mode"] for i in ("work", "t1", "t2")] == ["list", "all", "list"]
    assert any("«nl»" in line and "основным" in line for line in core.logged)


def test_вынесенный_из_основного_не_повышается_обратно(core):
    _put("home", "de.conf", FULL)

    r = core._move_config("home", "de", "new", drop_tunnel=True)

    assert r["ok"] and _ids() == ["work", r["tunnel"]]
    assert _tunnel(r["tunnel"])["mode"] == "list"


def test_удаление_туннеля_убирает_его_конфиги(core):
    _put("work", "corp.conf")

    r = core._remove_tunnel("work")

    assert r["ok"]
    assert [t["id"] for t in tunnels.load()["tunnels"]] == ["home"]
    assert not os.path.exists(tunnels.conf_dir("work"))


def test_уровень_журнала(core):
    assert core._set_log_level("debug")["ok"]
    assert tunnels.load()["log_level"] == "debug"
    assert not core._set_log_level("громко")["ok"]
    assert tunnels.load()["log_level"] == "debug"


def test_туннели_со_списками_и_конфигами(core):
    _put("home", "nl-1.conf")
    core._set_tunnel("work", {"exclude": "198.51.100.7"})

    r = core._get_tunnels()

    assert r["ok"] and r["log_level"] == "info"
    work, home = r["tunnels"]
    assert work["exclude"] == ["198.51.100.7/32"] and home["confs"] == ["nl-1"]


def test_испорченный_tunnels_json_команды_туннелей_не_затирают(core):
    with open(paths.TUNNELS_JSON, "w", encoding="utf-8") as fh:
        fh.write("{не json")

    for r in (core._get_tunnels(), core._add_tunnel("x", "list"),
              core._set_tunnel("work", {"name": "x"}), core._remove_tunnel("work"),
              core._set_log_level("debug"),
              core._set_site('CORP_DOMAINS="a.ru"')):
        assert not r["ok"] and "tunnels.json" in r["error"]

    with open(paths.TUNNELS_JSON, encoding="utf-8") as fh:
        assert fh.read() == "{не json"


# ----------------------------------------- site.env старого окна → tunnels.json

def test_поля_окна_пишутся_в_первый_туннель_по_списку(core):
    r = core._set_site('CORP_DOMAINS="corp.example *.x.example"\n'
                       'CORP_PROBE="git.corp.example"\nCORP_HOSTS="a b"\n'
                       'SB_CORP_EXCLUDE="198.51.100.7"\nSB_LOG_LEVEL="Debug"\n')

    assert r["ok"]
    data = tunnels.load()
    work = tunnels.find(data, "work")
    assert work["include"] == ["corp.example", "*.x.example"]
    assert work["exclude"] == ["198.51.100.7/32"]
    assert data["log_level"] == "debug"
    assert not os.path.exists(os.path.join(paths.CONF, "site.env"))


def test_поля_окна_читаются_из_tunnels_json(core):
    core._set_tunnel("work", {"include": "corp.example", "exclude": "203.0.113.9"})

    env = paths.parse_env(core._read_site())

    assert env == {"CORP_DOMAINS": "corp.example", "CORP_PROBE": "corp.example",
                   "SB_CORP_EXCLUDE": "203.0.113.9/32"}


def test_пустые_поля_окна_очищают_списки(core):
    core._set_tunnel("work", {"include": "corp.example"})
    core._set_log_level("debug")

    assert core._set_site("")["ok"]

    data = tunnels.load()
    assert tunnels.find(data, "work")["include"] == [] and data["log_level"] == "info"
    assert core._read_site() == ""


def test_непонятое_в_полях_окна_отказывает(core):
    r = core._set_site('CORP_DOMAINS="corp.example foo_bar"\nSB_CORP_EXCLUDE="foo_bar 1.2.3"')

    assert not r["ok"] and r["error"] == "не понял: foo_bar, 1.2.3"
    assert tunnels.find(tunnels.load(), "work")["include"] == []


# ------------------------------------- «Добавить конфиг…» без туннеля

CORP = _wg("10.10.0.0/16", "10.53.0.4")


def test_полный_ложится_в_основной_запасным(core):
    """Выбранный остаётся: запасной добавляют впрок, а не чтобы сменить выход.
    Единственный прежний без выбора и был активным — он и фиксируется."""
    _put("home", "nl-1.conf", FULL)

    r = core._add_config("nl-2", FULL)

    assert r["ok"] and (r["tunnel"], r["place"]) == ("home", "all")
    assert _files("home") == ["nl-1.conf", "nl-2.conf"]
    assert _active("home") == "nl-1"


def test_полный_в_пустой_основной_выбирается(core):
    core._add_config("nl-1", FULL)
    assert _active("home") == "nl-1"


def test_полный_без_основного_создаёт_его(core):
    tunnels.save({"tunnels": [WORK]})

    r = core._add_config("nl-1", FULL)

    assert r["ok"] and r["tunnel"] == "t1"
    t = _tunnel("t1")
    assert (t["name"], t["mode"], t["active"]) == ("nl-1", "all", "nl-1")
    assert _files("t1") == ["nl-1.conf"]


def test_свои_сети_новый_туннель_по_списку(core):
    _put("work", "corp.conf", CORP)

    r = core._add_config("Офис 2", _wg("192.168.77.0/24", "10.0.0.53"))

    assert r["ok"] and (r["tunnel"], r["place"]) == ("t1", "list")
    t = _tunnel("t1")
    assert (t["name"], t["mode"], t["active"]) == ("Офис 2", "list", "Офис 2")
    assert _files("work") == ["corp.conf"]


def test_общий_частный_dns_молча_заменяет(core):
    """Тот же DNS рабочей сети — новый доступ туда же: правила и id остаются."""
    _put("work", "corp.conf", CORP)
    core._set_tunnel("work", {"include": "corp.example"})

    r = core._add_config("wg-new", _wg("10.20.0.0/16", "10.53.0.4"))

    assert r["ok"] and (r["tunnel"], r["place"]) == ("work", "replace")
    assert _files("work") == ["wg-new.conf"]
    t = _tunnel("work")
    assert (t["name"], t["active"], t["include"]) == ("wg-new", "wg-new", ["corp.example"])
    assert _ids() == ["work", "home"]


def test_общий_публичный_dns_не_повод_заменять(core):
    _put("work", "corp.conf", _wg("10.10.0.0/16", "1.1.1.1"))

    r = core._add_config("other", _wg("192.168.77.0/24", "1.1.1.1"))

    assert r["ok"] and r["place"] == "list"
    assert _files("work") == ["corp.conf"]


def test_пересечение_сетей_спрашивает_и_ничего_не_пишет(core):
    _put("work", "corp.conf", CORP)

    r = core._add_config("wg-new", _wg("10.10.5.0/24", "10.0.0.53"))

    assert not r["ok"]
    assert r["ask"] == {"id": "work", "name": "Работа", "conf": "corp"}
    assert _files("work") == ["corp.conf"] and _ids() == ["work", "home"]
    assert not os.path.exists(tunnels.conf_dir("t1"))


def test_ответ_заменить(core):
    _put("work", "corp.conf", CORP)
    core._set_tunnel("work", {"exclude": "198.51.100.7"})

    r = core._add_config("wg-new", _wg("10.10.5.0/24"), tunnel="work", place="replace")

    assert r["ok"] and r["place"] == "replace"
    assert _files("work") == ["wg-new.conf"]
    assert _tunnel("work")["exclude"] == ["198.51.100.7/32"]


def test_ответ_отдельный_туннель(core):
    _put("work", "corp.conf", CORP)

    r = core._add_config("wg-new", _wg("10.10.5.0/24"), place="new")

    assert r["ok"] and (r["tunnel"], r["place"]) == ("t1", "list")
    assert _files("work") == ["corp.conf"] and _files("t1") == ["wg-new.conf"]


def test_замена_без_туннеля_отказывает(core):
    r = core._add_config("wg-new", _wg("192.168.77.0/24"), place="replace")

    assert not r["ok"]
    assert _ids() == ["work", "home"] and not os.path.exists(tunnels.conf_dir("t1"))


def test_замена_в_основном_отказывает(core):
    _put("home", "nl-1.conf", FULL)

    r = core._add_config("nl-2", FULL, tunnel="home", place="replace")

    assert not r["ok"] and "не туннель «по списку»" in r["error"]
    assert _files("home") == ["nl-1.conf"]


def test_в_туннель_с_общим_частным_dns_заменяет(core):
    """Трей шлёт только tunnel: тот же DNS сети — замена, как авто в окне."""
    _put("work", "corp.conf", CORP)
    core._set_tunnel("work", {"include": "corp.example"})

    r = core._add_config("wg-new", _wg("10.20.0.0/16", "10.53.0.4"), tunnel="work")

    assert r["ok"] and (r["tunnel"], r["place"]) == ("work", "replace")
    assert _files("work") == ["wg-new.conf"]
    t = _tunnel("work")
    assert (t["name"], t["active"], t["include"]) == ("wg-new", "wg-new", ["corp.example"])


@pytest.mark.parametrize("old_dns, new_dns", [("10.0.0.53", "10.53.0.4"),
                                              ("1.1.1.1", "1.1.1.1")])
def test_в_туннель_без_общего_частного_dns_кладёт_рядом(core, old_dns, new_dns):
    _put("work", "corp.conf", _wg("10.10.0.0/16", old_dns))

    r = core._add_config("wg-new", _wg("10.10.0.0/16", new_dns), tunnel="work")

    assert r["ok"] and r["place"] == "to"
    assert _files("work") == ["corp.conf", "wg-new.conf"]
    assert _active("work") == "wg-new"


def test_в_основной_с_тем_же_dns_кладёт_рядом(core):
    """Замена — только в туннеле «по списку»: у основного прежний остаётся запасным."""
    _put("home", "nl-1.conf", _wg("0.0.0.0/0", "10.53.0.4"))

    r = core._add_config("nl-2", _wg("0.0.0.0/0", "10.53.0.4"), tunnel="home")

    assert r["ok"] and r["place"] == "to"
    assert _files("home") == ["nl-1.conf", "nl-2.conf"]


@pytest.mark.parametrize("place", ["", "new"])
def test_потолок_туннелей_до_записи_файла(core, place):
    extra = [{"id": f"x{i}", "name": f"X{i}", "mode": "list"} for i in range(6)]
    tunnels.save({"tunnels": [WORK, HOME, *extra]})

    r = core._add_config("Офис 9", _wg("192.168.77.0/24"), place=place)

    assert not r["ok"] and "больше нельзя" in r["error"]
    assert len(_ids()) == tunnels.MAX_TUNNELS
    assert not os.path.exists(tunnels.conf_dir("t1"))


@pytest.mark.parametrize("allowed", ["", "::/0"])
def test_без_сетей_в_allowedips_не_ложится(core, allowed):
    r = core._add_config("odd", _wg(allowed))

    assert not r["ok"] and "AllowedIPs" in r["error"]
    assert _ids() == ["work", "home"] and _files("home") == []


# ------------------------------------- удаление последнего конфига туннеля

def test_последний_конфиг_с_drop_tunnel_уносит_туннель(core):
    _put("work", "corp.conf")

    r = core._remove_config("corp", tunnel="work", drop_tunnel=True)

    assert r["ok"] and _ids() == ["home"]
    assert not os.path.exists(tunnels.conf_dir("work"))


def test_без_drop_tunnel_пустой_туннель_хранит_правила(core):
    _put("work", "corp.conf")
    core._set_tunnel("work", {"include": "corp.example"})

    assert core._remove_config("corp", tunnel="work")["ok"]

    assert _ids() == ["work", "home"]
    assert _tunnel("work")["include"] == ["corp.example"] and _active("work") == ""


def test_drop_tunnel_не_трогает_туннель_с_конфигами(core):
    _put("work", "a.conf")
    _put("work", "b.conf")

    assert core._remove_config("a", tunnel="work", drop_tunnel=True)["ok"]

    assert _ids() == ["work", "home"] and _files("work") == ["b.conf"]


# --------------------------------------------- move-config: полный конфиг

def test_полный_из_основного_в_свой_туннель(core):
    _put("home", "nl-1.conf", FULL)
    _put("home", "nl-2.conf", FULL)
    core._set_active("nl-1", tunnel="home")

    r = core._move_config("home", "nl-1", "new")

    assert r == {"ok": True, "tunnel": "t1", "name": "nl-1"}
    t = _tunnel("t1")
    assert (t["name"], t["mode"], t["active"]) == ("nl-1", "list", "nl-1")
    assert _files("t1") == ["nl-1.conf"] and _files("home") == ["nl-2.conf"]
    assert _active("home") == "nl-2"


def test_полный_из_списка_обратно_в_основной(core):
    nl = {"id": "t1", "name": "nl-1", "mode": "list", "active": "nl-1"}
    tunnels.save({"tunnels": [WORK, {**HOME, "active": "nl-2"}, nl]})
    _put("t1", "nl-1.conf", FULL)
    _put("home", "nl-2.conf", FULL)

    r = core._move_config("t1", "nl-1", "all", drop_tunnel=True)

    assert r["ok"] and r["tunnel"] == "home"
    assert _files("home") == ["nl-1.conf", "nl-2.conf"] and _active("home") == "nl-2"
    assert _ids() == ["work", "home"]
    assert not os.path.exists(tunnels.conf_dir("t1"))


def test_в_основной_без_основного_он_создаётся(core):
    nl = {"id": "t1", "name": "nl-1", "mode": "list", "active": "nl-1"}
    tunnels.save({"tunnels": [WORK, nl]})
    _put("t1", "nl-1.conf", FULL)

    r = core._move_config("t1", "nl-1", "all")

    t = _tunnel(r["tunnel"])
    assert (t["mode"], t["active"]) == ("all", "nl-1")
    # Без drop_tunnel пустой туннель остаётся со своими правилами.
    assert _active("t1") == "" and _files("t1") == []


@pytest.mark.parametrize("tid, name, to, error", [
    ("work", "corp", "all", "0.0.0.0/0"),
    ("work", "corp", "new", "не туннель «весь остальной трафик»"),
    ("home", "nl-1", "all", "не туннель «по списку»"),
    ("home", "nl-1", "home", "new или all"),
    ("home", "nope", "new", "нет конфига"),
])
def test_перенос_не_того_отказывает(core, tid, name, to, error):
    _put("work", "corp.conf", CORP)
    _put("home", "nl-1.conf", FULL)

    r = core._move_config(tid, name, to)

    assert not r["ok"] and error in r["error"]
    assert _files("work") == ["corp.conf"] and _files("home") == ["nl-1.conf"]
    assert _ids() == ["work", "home"]


def test_перенос_на_занятое_имя_отказывает(core):
    nl = {"id": "t1", "name": "nl-1", "mode": "list"}
    tunnels.save({"tunnels": [WORK, HOME, nl]})
    _put("t1", "nl-1.conf", FULL)
    _put("home", "nl-1.conf", WG)

    r = core._move_config("t1", "nl-1", "all")

    assert not r["ok"] and "уже есть" in r["error"]
    assert _files("t1") == ["nl-1.conf"]
    assert core._read_config("nl-1", tunnel="home")["text"] == WG


@pytest.mark.parametrize("drop, ok", [(True, True), (False, False)])
def test_потолок_при_переносе_считает_удаляемый(core, drop, ok):
    """Восемь туннелей без основного: перенос с удалением источника не
    добавляет девятый, без удаления — добавил бы."""
    extra = [{"id": f"x{i}", "name": f"X{i}", "mode": "list"} for i in range(7)]
    tunnels.save({"tunnels": [WORK, *extra]})
    _put("x0", "nl-1.conf", FULL)

    r = core._move_config("x0", "nl-1", "all", drop_tunnel=drop)

    assert r["ok"] is ok
    assert ("x0" in _ids()) is not drop
    assert _files("x0") == ([] if ok else ["nl-1.conf"])


def test_сбой_записи_туннелей_возвращает_файл(core, monkeypatch):
    _put("home", "nl-1.conf", FULL)

    def broken(data):
        raise OSError("диск занят")
    monkeypatch.setattr(tunnels, "save", broken)

    r = core._move_config("home", "nl-1", "new")

    assert not r["ok"] and "диск занят" in r["error"]
    assert _files("home") == ["nl-1.conf"] and _files("t1") == []


# ------------------------------------------------ full в статусе

def test_полнота_конфига_перечитывается_после_правки(core, monkeypatch):
    """Статус спрашивают каждые пару секунд: файл читается заново, только
    когда сменилось время правки."""
    monkeypatch.setattr(service, "_full_cache", {})
    _put("home", "nl-1.conf", FULL)
    path = tunnels.conf_path("home", "nl-1")
    os.utime(path, ns=(1_000_000_000, 1_000_000_000))

    assert service._conf_full("home", "nl-1") is True
    _put("home", "nl-1.conf", CORP)
    os.utime(path, ns=(2_000_000_000, 2_000_000_000))
    assert service._conf_full("home", "nl-1") is False
    assert service._conf_full("home", "") is False
    assert service._conf_full("home", "nope") is False
