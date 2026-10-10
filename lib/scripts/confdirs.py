"""
Где лежат конфиги и какой личный выбран.

    conf/corp/        рабочий WireGuard — ровно один файл
    conf/personal/    личные — сколько угодно, один выбран профилем

Роль задаёт папка, имя файла может быть любым. Раньше роль угадывалась по
имени (corp.conf, wg0-*.conf, awg-*.conf), и файл с непривычным именем
молча становился не тем, чем его добавили.

Общий модуль для окна, службы (`vpn`) и build-config.py. Windows
(windows/vpn.ps1) папок не заводит: без них build-config.py ищет по именам
в conf/, как раньше.
"""

import os
import re

KINDS = ("corp", "personal")

# Прежние правила имён. Нужны только чтобы разложить по папкам то, что уже
# лежит прямо в conf/, и для Windows, где папок нет. Регистр не важен.
# Корп-файл обычно приходит от админов как wg0-<фамилия>.conf.
CORP_PAT = (r"^corp\.conf$", r"^wg[-_0-9].*\.conf$", r"^wg\.conf$")
PERSONAL_PAT = (r"^personal\.conf$", r"^(awg|amnezia).*\.conf$")


def kind_dir(conf, kind):
    return os.path.join(conf, kind)


def conf_path(conf, kind, name):
    """Путь к конфигу name (без .conf) нужного вида."""
    return os.path.join(conf, kind, f"{name}.conf")


def has_dirs(conf):
    return any(os.path.isdir(kind_dir(conf, k)) for k in KINDS)


def names(conf, kind):
    """Имена конфигов вида kind без .conf, по алфавиту."""
    try:
        files = os.listdir(kind_dir(conf, kind))
    except OSError:
        return []
    return sorted(f[:-5] for f in files if f.lower().endswith(".conf"))


def legacy_kind(file_name):
    """Вид файла, лежащего прямо в conf/, по прежним правилам имён."""
    return "corp" if any(re.match(p, file_name, re.I) for p in CORP_PAT) else "personal"


def _owned_like_parent(path):
    """Служба работает от root, а окно — от человека. Созданное root'ом в
    каталоге данных окно потом не смогло бы ни переписать, ни заменить."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:     # на Windows его нет
        return
    st = os.stat(os.path.dirname(path))
    os.chown(path, st.st_uid, st.st_gid)


def sort_out(conf):
    """Заводит папки и раскладывает по ним .conf, лежащие прямо в conf/.

    Идемпотентно: зовут и окно, и служба при каждом старте. Файл, чьё имя в
    папке уже занято, остаётся на месте — чужое не затираем. Возвращает
    [(имя файла, вид)] того, что переехало.
    """
    try:
        loose = sorted(f for f in os.listdir(conf)
                       if f.lower().endswith(".conf")
                       and os.path.isfile(os.path.join(conf, f)))
    except OSError:
        return []

    # Окно и служба могут раскладывать одновременно: уже сделанное другим
    # не ошибка.
    for kind in KINDS:
        d = kind_dir(conf, kind)
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            continue
        _owned_like_parent(d)

    moved = []
    for f in loose:
        kind = legacy_kind(f)
        dst = os.path.join(kind_dir(conf, kind), f)
        if os.path.exists(dst):
            continue
        try:
            os.rename(os.path.join(conf, f), dst)
        except FileNotFoundError:
            continue
        moved.append((f, kind))
    return moved


def read_profile(conf, state):
    """Сохранённый профиль, если его файл на месте; иначе ''."""
    try:
        with open(os.path.join(state, "profile"), encoding="utf-8") as fh:
            name = fh.read().strip()
    except OSError:
        return ""
    if name.lower().endswith(".conf"):
        name = name[:-5]
    return name if name in names(conf, "personal") else ""


def save_profile(state, name):
    """Пишет профиль заменой файла: прежний мог создать root."""
    os.makedirs(state, exist_ok=True)
    path = os.path.join(state, "profile")
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(name)
    _owned_like_parent(tmp)
    os.replace(tmp, path)


def profile(conf, state):
    """Выбранный личный конфиг; по умолчанию — первый по алфавиту, и он
    сразу запоминается: иначе выбор менялся бы с каждым добавленным файлом."""
    name = read_profile(conf, state)
    if name:
        return name
    have = names(conf, "personal")
    if not have:
        return ""
    save_profile(state, have[0])
    return have[0]


if __name__ == "__main__":
    # `python3 confdirs.py <conf>` — так раскладку зовёт vpn.
    import sys
    for f, k in sort_out(sys.argv[1]):
        print(f"→ {f} moved to conf/{k}/")
