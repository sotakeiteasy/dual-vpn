"""Туннели: conf\\tunnels.json и папки их конфигов.

Туннель — это слот: имя, режим, списки правил и папка conf\\tunnels\\<id>\\
с конфигами, из которых один активный. Настройки принадлежат слоту, а не
файлу: заменили .conf — правила остались.

    {"version": 1, "log_level": "info",
     "tunnels": [
       {"id": "work", "name": "Работа", "mode": "list", "active": "corp",
        "include": ["corp.example"], "exclude": ["198.51.100.7/32"]},
       {"id": "home", "name": "Личный", "mode": "all", "active": "nl-1",
        "include": [], "exclude": []}]}

Режим list — через туннель идёт только то, что в его списках и AllowedIPs;
all — весь остальной трафик. all может быть не больше чем у одного.

id и имя конфига приходят через канал службы, у которой права SYSTEM, и
становятся путями на диске. Поэтому всё, что пришло снаружи, проверяется
здесь, а не там, где пишут файл.
"""

import json
import os
import re

from . import paths, routelist

VERSION = 1
# Каждый туннель — это свой процесс sing-box, порт на loopback и UDP-сессия
# с сервером. Восьми хватает с запасом; больше — скорее ошибка, чем замысел.
MAX_TUNNELS = 8
MODES = ("list", "all")
NAME_MAX_LEN = 40
# Уровни журнала sing-box. Статистика адресов и сторож службы читают строки
# info и error, поэтому по умолчанию info.
LOG_LEVELS = ("trace", "debug", "info", "warn", "error", "fatal", "panic")

# id — имя папки и часть тегов sing-box: только то, что безопасно в обоих.
_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")

# Имя конфига — это имя файла. В Windows в нём запрещены эти знаки и
# управляющие символы, а CON, NUL, COM1… — имена устройств: файл nul.conf
# не создать вовсе. Длину режем, чтобы путь в ProgramData не упёрся в MAX_PATH.
_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL",
             *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
NAME_MAX = 80


def safe_name(name):
    """Имя, под которым конфиг ляжет в папку туннеля, из имени файла человека.

    Не отказывает никогда: недопустимые знаки становятся «_», пустое имя —
    «config». Так добавление не ломается из-за имени, как у wg-quick, где
    неподходящее имя файла — это ошибка.
    """
    stem = (name or "").strip()
    if stem.lower().endswith(".conf"):
        stem = stem[:-5]
    stem = _BAD_CHARS.sub("_", stem)
    # Точка и пробел в конце Windows молча отрезает: «nl.» и «nl» стали бы
    # одним файлом, а ссылка в профиле — на несуществующий.
    stem = stem[:NAME_MAX].strip(" .")
    if stem.split(".")[0].upper() in _RESERVED:
        stem = f"_{stem}"
    return stem or "config"


def check_name(name):
    """Имя, пришедшее через канал, должно быть уже безопасным — то, что мы
    сами отдали в списке. Иначе «..\\..\\Windows» стал бы записью с правами
    системы."""
    if not name or safe_name(name) != name:
        raise ValueError(f"недопустимое имя конфига: {name!r}")
    return name


def check_id(tid):
    """id туннеля: латиница в нижнем регистре, цифры и дефис, не имя устройства."""
    if (not isinstance(tid, str) or not _ID.match(tid)
            or tid.split(".")[0].upper() in _RESERVED):
        raise ValueError(f"недопустимый id туннеля: {tid!r}")
    return tid


def conf_dir(tid):
    return os.path.join(paths.CONF_TUNNELS, check_id(tid))


def conf_path(tid, name):
    return os.path.join(conf_dir(tid), f"{check_name(name)}.conf")


def list_confs(tid):
    """Имена конфигов туннеля, без .conf."""
    try:
        return sorted(f[:-5] for f in os.listdir(conf_dir(tid))
                      if f.lower().endswith(".conf"))
    except OSError:
        return []


def empty():
    return {"version": VERSION, "log_level": "info", "tunnels": []}


def _check_list(tunnel, key):
    items = tunnel.get(key, [])
    if not isinstance(items, list):
        raise ValueError(f"туннель {tunnel['id']}: {key} должен быть списком")
    entries, rejected = routelist.parse_list(items)
    if rejected:
        raise ValueError(f"туннель {tunnel['id']}: в {key} непонятное: "
                         f"{', '.join(rejected)}")
    return entries


def _check_tunnel(raw):
    if not isinstance(raw, dict):
        raise ValueError("туннель должен быть объектом")
    tid = check_id(raw.get("id"))
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"туннель {tid}: пустое имя")
    name = " ".join(name.split())[:NAME_MAX_LEN]
    mode = raw.get("mode")
    if mode not in MODES:
        raise ValueError(f"туннель {tid}: режим {mode!r}, ожидаю list или all")
    active = raw.get("active") or ""
    if active:
        if not isinstance(active, str):
            raise ValueError(f"туннель {tid}: active должен быть строкой")
        check_name(active)
    tunnel = {"id": tid, "name": name, "mode": mode, "active": active}
    tunnel["include"] = _check_list(raw, "include")
    tunnel["exclude"] = _check_list(raw, "exclude")
    return tunnel


def validate(data):
    """Проверенная и нормализованная копия, иначе ValueError с причиной."""
    if not isinstance(data, dict):
        raise ValueError("tunnels.json: ожидаю объект")
    if data.get("version", VERSION) != VERSION:
        raise ValueError(f"tunnels.json: версия {data.get('version')!r} "
                         f"не поддерживается")
    level = data.get("log_level") or "info"
    if level not in LOG_LEVELS:
        raise ValueError(f"tunnels.json: уровень журнала {level!r}, "
                         f"ожидаю один из {', '.join(LOG_LEVELS)}")
    raw = data.get("tunnels", [])
    if not isinstance(raw, list):
        raise ValueError("tunnels.json: tunnels должен быть списком")
    if len(raw) > MAX_TUNNELS:
        raise ValueError(f"туннелей {len(raw)}, больше {MAX_TUNNELS} нельзя")
    tunnels = [_check_tunnel(t) for t in raw]
    ids = [t["id"] for t in tunnels]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise ValueError(f"повторяются id туннелей: {', '.join(dup)}")
    alls = [t["id"] for t in tunnels if t["mode"] == "all"]
    if len(alls) > 1:
        raise ValueError(f"«весь остальной трафик» может забирать только один "
                         f"туннель, а не {', '.join(alls)}")
    return {"version": VERSION, "log_level": level, "tunnels": tunnels}


def load():
    """Туннели из conf\\tunnels.json. Нет файла — пустой список.

    Испорченный файл — ValueError: молча подставить пустой значило бы
    поднять VPN без правил, которые человек ждёт.
    """
    try:
        with open(paths.TUNNELS_JSON, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return empty()
    except ValueError as exc:
        raise ValueError(f"tunnels.json не читается: {exc}") from None
    return validate(data)


def save(data):
    """Проверяет и пишет через временный файл. Возвращает то, что записано."""
    data = validate(data)
    os.makedirs(paths.CONF, exist_ok=True)
    tmp = paths.TUNNELS_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, paths.TUNNELS_JSON)
    return data


def find(data, tid):
    """Туннель по id, иначе None."""
    return next((t for t in data["tunnels"] if t["id"] == tid), None)


def main_tunnel(data):
    """Туннель, который забирает весь остальной трафик, иначе None."""
    return next((t for t in data["tunnels"] if t["mode"] == "all"), None)


# --------------------------------------------------------------- переезд

# До 0.4 туннелей было ровно два, и тип задавала папка. Они становятся
# слотами с этими id: так старые пункты окна и трея находят свой туннель.
LEGACY = {"corp": ("work", "Работа", "list"),
          "personal": ("home", "Личный", "all")}


def _move_confs(src, tid):
    """Переносит .conf из старой папки типа в папку туннеля."""
    moved = []
    try:
        files = sorted(os.listdir(src))
    except OSError:
        return moved
    os.makedirs(conf_dir(tid), exist_ok=True)
    for f in files:
        path = os.path.join(src, f)
        if not f.lower().endswith(".conf") or not os.path.isfile(path):
            continue
        name = safe_name(f)
        os.replace(path, conf_path(tid, name))
        moved.append(name)
    return moved


def _current_profile():
    try:
        with open(paths.PROFILE_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def migrate(log=print):
    """Из conf\\site.env и conf\\corp|personal — в tunnels.json, один раз.

    Есть tunnels.json — ничего не делает и возвращает None. Иначе переносит
    конфиги, пишет файл и возвращает его содержимое. Порядок такой, чтобы
    оборванный переезд доделался при следующем запуске: файлы сначала,
    tunnels.json потом, site.env — последним и не удаляется, а остаётся
    рядом как site.env.bak.
    """
    if os.path.exists(paths.TUNNELS_JSON):
        return None
    env = paths.site_env()

    for kind, (tid, _, _) in LEGACY.items():
        src = os.path.join(paths.CONF, kind)
        for name in _move_confs(src, tid):
            log(f"→ {name}.conf перенесён в conf\\tunnels\\{tid}")
        try:
            os.rmdir(src)
        except OSError:
            pass

    def rules(key):
        entries, rejected = routelist.parse(env.get(key, ""))
        if rejected:
            log(f"!! {key} в site.env: не понял {', '.join(rejected)} — пропускаю")
        return entries

    work_confs = list_confs("work")
    home_confs = list_confs("home")
    profile = _current_profile()
    if profile not in home_confs:
        profile = home_confs[0] if len(home_confs) == 1 else ""
    level = env.get("SB_LOG_LEVEL", "").strip().lower()

    data = {
        "version": VERSION,
        "log_level": level if level in LOG_LEVELS else "info",
        "tunnels": [
            {"id": "work", "name": "Работа", "mode": "list",
             # Рабочий был один; два бывали только после переезда из плоского
             # conf\, и тогда сборка всё равно требовала оставить один.
             "active": work_confs[0] if work_confs else "",
             "include": rules("CORP_DOMAINS"),
             "exclude": rules("SB_CORP_EXCLUDE")},
            {"id": "home", "name": "Личный", "mode": "all",
             "active": profile, "include": [], "exclude": []},
        ],
    }
    data = save(data)
    log("→ настройки туннелей перенесены в conf\\tunnels.json")

    site = os.path.join(paths.CONF, "site.env")
    if os.path.exists(site):
        try:
            os.replace(site, site + ".bak")
        except OSError as exc:
            log(f"!! site.env не переименовать: {exc}")
    return data
