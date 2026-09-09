"""Где что лежит. Единственное место, которое знает раскладку на диске.

Код и данные разведены намеренно. Код переписывается установщиком при каждом
обновлении, поэтому конфиги, журнал владения и состояние обязаны жить снаружи —
иначе обновление стирало бы их вместе со старой версией.

    код    C:\\Program Files\\DualVPN        (в разработке — корень репозитория)
    данные C:\\ProgramData\\DualVPN

Данные лежат в ProgramData, а не в профиле пользователя, потому что писать в них
должна служба под LocalSystem, а читать — трей под обычным пользователем.
Права раздаёт установщик: conf\\ виден только SYSTEM и администраторам (там
приватные ключи), state\\ доступен пользователям на чтение — оттуда трей берёт
status.json и логи.
"""

import os
import sys

# BASE — где лежит сам exe (или корень репозитория при запуске из исходников).
# Из lib/dualvpn/paths.py до корня — два уровня вверх.
if getattr(sys, "frozen", False):
    BASE = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# BUNDLE — где лежат вложенные в сборку файлы: вёрстка окна, VERSION,
# бинарники. У обычной сборки это та же папка, что и exe, а у однофайловой
# (портативной) — временный каталог, куда PyInstaller всё распаковал.
# Без этого различия портативная версия искала бы ui/index.html рядом с
# собой и не находила: там лежит только сам exe.
BUNDLE = getattr(sys, "_MEIPASS", BASE)

# DUALVPN_DATA перекрывает раскладку. Этим пользуются и прогоны из исходников,
# и портативная версия: она кладёт данные рядом с exe, а не в ProgramData,
# чтобы папку можно было унести целиком вместе с конфигами.
DATA = os.environ.get("DUALVPN_DATA") or os.path.join(
    os.environ.get("ProgramData", r"C:\ProgramData"), "DualVPN"
)

CONF = os.path.join(DATA, "conf")
STATE = os.path.join(DATA, "state")
LOGS = os.path.join(STATE, "logs")

# Бинарники едут внутри сборки, поэтому ищем их в BUNDLE, а не рядом с exe.
BIN = BUNDLE if getattr(sys, "frozen", False) else os.path.join(BASE, "lib", "bin")
SINGBOX = os.path.join(BIN, "sing-box.exe")
WINTUN = os.path.join(BIN, "wintun.dll")

# Вёрстка окна. В onedir-сборке PyInstaller 6+ данные (--add-data) лежат в
# BUNDLE\dualvpn\ui — это подпапка _internal, а НЕ там же, где сам exe, и уж
# точно не там, куда указывает __file__ у модуля window.py: в частности,
# window.py брал путь через __file__ раньше, и в собранном виде промахивался
# мимо index.html — окно падало ещё до показа, а трей тихо принимал это за
# «процесс не открылся» и на следующем клике перезапускал сам себя.
UI_DIR = (os.path.join(BUNDLE, "dualvpn", "ui") if getattr(sys, "frozen", False)
          else os.path.join(BASE, "lib", "dualvpn", "ui"))

CONFIG_JSON = os.path.join(STATE, "config.json")
STATUS_JSON = os.path.join(STATE, "status.json")
PROFILE_FILE = os.path.join(STATE, "profile")
REAL_IP_FILE = os.path.join(STATE, "real-ip")

# Журнал того, что мы навесили на систему: единственный источник правды для
# уборки. Переживает и падение службы, и перезагрузку, поэтому «аварийно
# выключился» лечится следующим запуском, а не руками.
OWNED_FILE = os.path.join(STATE, "owned")

# Адрес tun из buildconfig.py — по нему опознаём свой интерфейс.
TUN_IP = "172.19.0.1"

SERVICE_NAME = "DualVPN"
SERVICE_DISPLAY = "DualVPN"
PIPE_NAME = r"\\.\pipe\DualVPN"


def ensure_dirs():
    """Создаёт каталоги данных. Зовётся и службой, и установщиком."""
    for d in (DATA, CONF, STATE, LOGS):
        os.makedirs(d, exist_ok=True)


def version():
    try:
        with open(os.path.join(BUNDLE, "VERSION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "?"


def site_env():
    """Настройки рабочей сети из conf\\site.env.

    Домены, проверочные хосты, исключения из маршрутов — они у каждого свои и
    в репозиторий не попадают. Без файла корп-часть просто не проверяется.
    """
    out = {}
    try:
        with open(os.path.join(CONF, "site.env"), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k.startswith("export "):
                    k = k[len("export "):].strip()
                out[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out
