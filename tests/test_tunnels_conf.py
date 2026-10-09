"""Туннели: conf\\tunnels.json, его проверка и переезд со старой пары.

Файл приходит и руками, и через канал службы с правами SYSTEM, поэтому
проверка отвечает и за смысл (один «весь остальной трафик», потолок), и за
безопасность (id и имя конфига становятся путями). Переезд случается один
раз на машине человека: ошибку в нём не перезапустить — потерянные правила
или выбранный не тот конфиг он заметит, только когда что-то перестанет
открываться.
"""

import json
import os
import shutil

import pytest

from dualvpn import paths, tunnels

WG = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = y\n"


@pytest.fixture(autouse=True)
def clean_conf():
    for d in (paths.CONF_TUNNELS, paths.CONF_CORP, paths.CONF_PERSONAL):
        shutil.rmtree(d, ignore_errors=True)
    for f in (paths.TUNNELS_JSON, paths.PROFILE_FILE,
              os.path.join(paths.CONF, "site.env"),
              os.path.join(paths.CONF, "site.env.bak")):
        if os.path.exists(f):
            os.remove(f)
    yield


def _tunnel(**over):
    t = {"id": "work", "name": "Работа", "mode": "list", "active": "",
         "include": [], "exclude": []}
    t.update(over)
    return t


def _data(*ts, **over):
    d = {"version": 1, "log_level": "info", "tunnels": list(ts)}
    d.update(over)
    return d


def _put(kind, name):
    os.makedirs(os.path.join(paths.CONF, kind), exist_ok=True)
    with open(os.path.join(paths.CONF, kind, name), "w", encoding="utf-8") as fh:
        fh.write(WG)


def _site(text):
    with open(os.path.join(paths.CONF, "site.env"), "w", encoding="utf-8") as fh:
        fh.write(text)


def _profile(name):
    with open(paths.PROFILE_FILE, "w", encoding="utf-8") as fh:
        fh.write(name)


# ---------------------------------------------------------------- проверка

def test_нет_файла_пустой_список():
    assert tunnels.load() == {"version": 1, "log_level": "info", "tunnels": []}


def test_запись_и_чтение_дают_то_же():
    data = _data(_tunnel(include=["corp.example"], exclude=["198.51.100.7/32"]),
                 _tunnel(id="home", name="Личный", mode="all", active="nl-1"))
    assert tunnels.save(data) == data
    assert tunnels.load() == data


def test_списки_нормализуются_при_записи():
    saved = tunnels.save(_data(_tunnel(include=["A.RU", "https://b.ru/x", "a.ru"],
                                       exclude=["1.2.3.4"])))
    assert saved["tunnels"][0]["include"] == ["a.ru", "b.ru"]
    assert saved["tunnels"][0]["exclude"] == ["1.2.3.4/32"]


def test_непонятная_запись_в_списке_отказ_с_её_именем():
    """Молча выкинуть её — значит пустить адрес не туда, куда просили."""
    with pytest.raises(ValueError, match="foo_bar"):
        tunnels.validate(_data(_tunnel(include=["a.ru", "foo_bar"])))


def test_два_туннеля_на_весь_трафик_отказ():
    with pytest.raises(ValueError, match="только один"):
        tunnels.validate(_data(_tunnel(id="a", mode="all"),
                               _tunnel(id="b", mode="all")))


def test_ни_одного_all_допустимо():
    """Тогда всё, что не забрали туннели, идёт напрямую."""
    data = _data(_tunnel(id="a"), _tunnel(id="b"))
    assert tunnels.validate(data) == data
    assert tunnels.main_tunnel(data) is None


def test_потолок_туннелей():
    ok = _data(*(_tunnel(id=f"t{i}") for i in range(tunnels.MAX_TUNNELS)))
    tunnels.validate(ok)
    with pytest.raises(ValueError, match="больше 8"):
        tunnels.validate(_data(*(_tunnel(id=f"t{i}")
                                 for i in range(tunnels.MAX_TUNNELS + 1))))


def test_повтор_id_отказ():
    with pytest.raises(ValueError, match="повторяются"):
        tunnels.validate(_data(_tunnel(), _tunnel(name="Другой")))


@pytest.mark.parametrize("tid", [
    "", "Work", "../x", "a/b", "a\\b", "-a", "a-", "a_b", "a.b", "раб",
    "con", "nul", "com1", "a" * 33, None, 5,
])
def test_недопустимый_id_отказ(tid):
    with pytest.raises(ValueError, match="id"):
        tunnels.validate(_data(_tunnel(id=tid)))


@pytest.mark.parametrize("tid", ["work", "home", "a", "nl-2", "0", "a" * 32])
def test_допустимый_id(tid):
    tunnels.validate(_data(_tunnel(id=tid)))


@pytest.mark.parametrize("active", ["..\\..\\Windows\\x", "a/b", "nl.", "CON"])
def test_имя_активного_конфига_проверяется(active):
    """Имя станет путём файла, который служба читает с правами SYSTEM."""
    with pytest.raises(ValueError, match="имя конфига"):
        tunnels.validate(_data(_tunnel(active=active)))


def test_conf_path_не_выпускает_из_папки_туннеля():
    with pytest.raises(ValueError):
        tunnels.conf_path("work", "..\\x")
    with pytest.raises(ValueError):
        tunnels.conf_path("..", "x")
    assert tunnels.conf_path("work", "corp") == os.path.join(
        paths.CONF_TUNNELS, "work", "corp.conf")


@pytest.mark.parametrize("over, msg", [
    ({"mode": "proxy"}, "режим"),
    ({"name": "  "}, "пустое имя"),
    ({"name": None}, "пустое имя"),
    ({"include": "a.ru"}, "списком"),
])
def test_поля_туннеля_проверяются(over, msg):
    with pytest.raises(ValueError, match=msg):
        tunnels.validate(_data(_tunnel(**over)))


def test_имя_туннеля_обрезается_и_схлопывает_пробелы():
    t = tunnels.validate(_data(_tunnel(name="  Офис \n  Иванов " + "я" * 60)))
    assert t["tunnels"][0]["name"].startswith("Офис Иванов я")
    assert len(t["tunnels"][0]["name"]) == tunnels.NAME_MAX_LEN


def test_уровень_журнала_проверяется():
    with pytest.raises(ValueError, match="уровень журнала"):
        tunnels.validate(_data(log_level="verbose"))
    assert tunnels.validate(_data(log_level="debug"))["log_level"] == "debug"


def test_испорченный_json_отказ_а_не_пустой_список():
    with open(paths.TUNNELS_JSON, "w", encoding="utf-8") as fh:
        fh.write("{не json")
    with pytest.raises(ValueError, match="не читается"):
        tunnels.load()


def test_чужая_версия_отказ():
    with pytest.raises(ValueError, match="версия"):
        tunnels.validate(_data(version=2))


def test_лишние_поля_не_сохраняются():
    saved = tunnels.save(_data(_tunnel(lishnee="x"), lishnee="y"))
    assert "lishnee" not in saved
    assert "lishnee" not in saved["tunnels"][0]


# ---------------------------------------------------------- активный конфиг

def test_активный_конфиг_по_имени():
    _put("tunnels/work", "a.conf")
    _put("tunnels/work", "b.conf")
    assert tunnels.active_conf(_tunnel(active="b")) == tunnels.conf_path("work", "b")


def test_без_выбора_берётся_единственный():
    _put("tunnels/work", "a.conf")
    assert tunnels.active_conf(_tunnel()) == tunnels.conf_path("work", "a")


def test_пустой_слот_без_конфига():
    assert tunnels.active_conf(_tunnel()) is None


def test_несколько_без_выбора_отказ():
    """Собрать «какой-нибудь» значило бы молча включить не тот сервер."""
    _put("tunnels/work", "a.conf")
    _put("tunnels/work", "b.conf")
    with pytest.raises(ValueError, match="несколько"):
        tunnels.active_conf(_tunnel())


def test_выбранный_пропал_отказ():
    _put("tunnels/work", "a.conf")
    with pytest.raises(ValueError, match="нет конфига «b»"):
        tunnels.active_conf(_tunnel(active="b"))


# ------------------------------------------------------------------ переезд

SITE_ENV = """\
# настройки рабочей сети
CORP_DOMAINS="corp.example"
CORP_PROBE=git.corp.example
CORP_HOSTS="git.corp.example wiki.corp.example"
SB_CORP_EXCLUDE="198.51.100.7 203.0.113.9"
SB_LOG_LEVEL=debug
"""


def test_переезд_нынешней_установки():
    _site(SITE_ENV)
    _put("corp", "corp.conf")
    _put("personal", "nl-1.conf")
    _put("personal", "de-2.conf")
    _profile("nl-1")

    data = tunnels.migrate(log=lambda _: None)

    assert data == {
        "version": 1, "log_level": "debug",
        "tunnels": [
            {"id": "work", "name": "Работа", "mode": "list", "active": "corp",
             "include": ["corp.example"],
             "exclude": ["198.51.100.7/32", "203.0.113.9/32"]},
            {"id": "home", "name": "Личный", "mode": "all", "active": "nl-1",
             "include": [], "exclude": []},
        ],
    }
    assert tunnels.load() == data
    assert tunnels.list_confs("work") == ["corp"]
    assert tunnels.list_confs("home") == ["de-2", "nl-1"]
    assert not os.path.exists(paths.CONF_CORP)
    assert not os.path.exists(paths.CONF_PERSONAL)
    assert not os.path.exists(os.path.join(paths.CONF, "site.env"))
    with open(os.path.join(paths.CONF, "site.env.bak"), encoding="utf-8") as fh:
        assert fh.read() == SITE_ENV


def test_повторный_переезд_ничего_не_меняет():
    _site(SITE_ENV)
    _put("corp", "corp.conf")
    _put("personal", "nl-1.conf")
    tunnels.migrate(log=lambda _: None)
    with open(paths.TUNNELS_JSON, encoding="utf-8") as fh:
        before = fh.read()
    # Новый site.env после переезда не должен перетереть правила.
    _site('CORP_DOMAINS="other.ru"\n')

    assert tunnels.migrate(log=lambda _: None) is None

    with open(paths.TUNNELS_JSON, encoding="utf-8") as fh:
        assert fh.read() == before
    assert os.path.exists(os.path.join(paths.CONF, "site.env"))


def test_переезд_без_site_env_и_конфигов():
    """Свежая установка: два пустых слота, как пара в окне до сих пор."""
    data = tunnels.migrate(log=lambda _: None)
    assert [(t["id"], t["mode"], t["active"]) for t in data["tunnels"]] == [
        ("work", "list", ""), ("home", "all", "")]
    assert data["log_level"] == "info"


def test_без_профиля_берётся_единственный_личный():
    _put("personal", "nl-1.conf")
    data = tunnels.migrate(log=lambda _: None)
    assert tunnels.find(data, "home")["active"] == "nl-1"


def test_профиль_на_несуществующий_конфиг_не_переносится():
    _put("personal", "nl-1.conf")
    _put("personal", "de-2.conf")
    _profile("gone")
    data = tunnels.migrate(log=lambda _: None)
    assert tunnels.find(data, "home")["active"] == ""


def test_непонятное_в_site_env_в_журнал_а_не_молча():
    _site('CORP_DOMAINS="corp.example foo_bar"\nSB_LOG_LEVEL=loud\n')
    lines = []
    data = tunnels.migrate(log=lines.append)
    assert tunnels.find(data, "work")["include"] == ["corp.example"]
    assert data["log_level"] == "info"
    assert any("foo_bar" in x for x in lines)


def test_оборванный_переезд_доделывается():
    """Файлы уже в новой папке, tunnels.json ещё нет: активный не теряется."""
    os.makedirs(tunnels.conf_dir("work"))
    with open(tunnels.conf_path("work", "corp"), "w", encoding="utf-8") as fh:
        fh.write(WG)
    data = tunnels.migrate(log=lambda _: None)
    assert tunnels.find(data, "work")["active"] == "corp"


def test_файл_переезда_читается_как_json_с_кириллицей():
    tunnels.migrate(log=lambda _: None)
    with open(paths.TUNNELS_JSON, encoding="utf-8") as fh:
        assert "Работа" in fh.read()
    with open(paths.TUNNELS_JSON, encoding="utf-8") as fh:
        assert json.load(fh)["version"] == 1
