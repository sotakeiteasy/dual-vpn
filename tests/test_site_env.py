"""Настройки рабочей сети: окно читает site.env, правит и пишет обратно.

Файл живёт дольше приложения и правится в том числе руками, поэтому важно,
что запись не портит уже написанное, а чтение переносит формат, который
человек мог набрать по-своему.
"""

from dualvpn import window


def test_читается_обычный_файл():
    text = 'CORP_DOMAINS="example.local corp.example.com"\nCORP_PROBE=git.example.local\n'
    assert window._parse_env(text) == {
        "CORP_DOMAINS": "example.local corp.example.com",
        "CORP_PROBE": "git.example.local",
    }


def test_export_и_кавычки_снимаются():
    """Файл писали и руками, и по образцу — формы записи бывают разные."""
    text = "export CORP_PROBE='git.example.local'\n"
    assert window._parse_env(text) == {"CORP_PROBE": "git.example.local"}


def test_комментарии_и_мусор_игнорируются():
    text = "# комментарий\n\nCORP_PROBE=x\nбез-знака-равно\n"
    assert window._parse_env(text) == {"CORP_PROBE": "x"}


def test_пустой_файл_даёт_пустые_настройки():
    assert window._parse_env("") == {}
    assert window._parse_env(None) == {}


def test_запись_пропускает_пустые_поля():
    """Пустое поле значит «не задано» — писать его в файл незачем."""
    out = window._format_env({"CORP_PROBE": "git.example.local",
                              "CORP_DOMAINS": "",
                              "CORP_HOSTS": "   "})
    assert 'CORP_PROBE="git.example.local"' in out
    assert "CORP_DOMAINS" not in out
    assert "CORP_HOSTS" not in out


def test_запись_и_чтение_дают_исходное():
    values = {
        "CORP_DOMAINS": "example.local corp.example.com",
        "CORP_PROBE": "git.example.local",
        "CORP_HOSTS": "git.example.local wiki.example.local",
        "SB_CORP_EXCLUDE": "198.51.100.7/32",
    }
    assert window._parse_env(window._format_env(values)) == values


def test_неизвестные_поля_не_попадают_в_файл():
    """Пишем только то, что понимаем: чужой ключ мог прийти из вёрстки
    по ошибке, и молча сохранять его в конфиг не стоит."""
    out = window._format_env({"CORP_PROBE": "x", "ЧТО_ТО_ЛИШНЕЕ": "y"})
    assert "ЧТО_ТО_ЛИШНЕЕ" not in out
