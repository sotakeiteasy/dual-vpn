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

# Собранный .exe кладёт всё рядом с собой; из исходников поднимаемся от
# lib/dualvpn/paths.py на два уровня до корня репозитория.
if getattr(sys, "frozen", False):
    BASE = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# DUALVPN_DATA перекрывает раскладку — этим пользуются прогоны из исходников и
# selftest, чтобы не трогать настоящие данные в ProgramData.
DATA = os.environ.get("DUALVPN_DATA") or os.path.join(
    os.environ.get("ProgramData", r"C:\ProgramData"), "DualVPN"
)

CONF = os.path.join(DATA, "conf")
STATE = os.path.join(DATA, "state")
LOGS = os.path.join(STATE, "logs")

# Бинарники лежат при коде: их version-lock'ает установщик вместе с ним.
BIN = BASE if getattr(sys, "frozen", False) else os.path.join(BASE, "lib", "bin")
SINGBOX = os.path.join(BIN, "sing-box.exe")
WINTUN = os.path.join(BIN, "wintun.dll")

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
        with open(os.path.join(BASE, "VERSION"), encoding="utf-8") as fh:
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
