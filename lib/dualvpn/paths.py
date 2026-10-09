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
import re
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
# До 0.4 тип туннеля задавала папка. Нужны только для переезда в туннели.
CONF_CORP = os.path.join(CONF, "corp")
CONF_PERSONAL = os.path.join(CONF, "personal")
# Туннели — слоты с правилами (tunnels.py): список в tunnels.json, конфиги
# каждого — в conf\tunnels\<id>\.
TUNNELS_JSON = os.path.join(CONF, "tunnels.json")
CONF_TUNNELS = os.path.join(CONF, "tunnels")
STATE = os.path.join(DATA, "state")
LOGS = os.path.join(STATE, "logs")
# Журналы процессов — <префикс>-<дата>.log, дата в таком виде.
LOG_STAMP = "%Y-%m-%d_%H%M%S"

# Бинарники. У установленной версии build.ps1 кладёт их рядом с exe (BASE),
# а BUNDLE у onedir-сборки PyInstaller 6 — это _internal\: искали там и
# писали «нет sing-box.exe». У портативной они внутри сборки, то есть в BUNDLE.
if getattr(sys, "frozen", False):
    BIN = BASE if os.path.isfile(os.path.join(BASE, "sing-box.exe")) else BUNDLE
else:
    BIN = os.path.join(BASE, "lib", "bin")
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
# Туннели — отдельные процессы sing-box, их конфиги: buildconfig.side_json.
STATUS_JSON = os.path.join(STATE, "status.json")
PROFILE_FILE = os.path.join(STATE, "profile")
REAL_IP_FILE = os.path.join(STATE, "real-ip")
# Последние удачные адреса пиров {имя: IPv4}: запасной путь, когда не отвечает
# ни один DNS. Адрес сервера не секрет, поэтому в state\, а не в conf\.
PEER_IPS_FILE = os.path.join(STATE, "peer-ips.json")

# Журнал того, что мы навесили на систему: единственный источник правды для
# уборки. Переживает и падение службы, и перезагрузку, поэтому «аварийно
# выключился» лечится следующим запуском, а не руками.
OWNED_FILE = os.path.join(STATE, "owned")

# Адрес tun из buildconfig.py — по нему опознаём свой интерфейс.
TUN_IP = "172.19.0.1"
# Второй адрес той же /30: его sing-box отдаёт системе как DNS туннеля.
TUN_DNS = "172.19.0.2"

SERVICE_NAME = "DualVPN"
SERVICE_DISPLAY = "DualVPN"
PIPE_NAME = r"\\.\pipe\DualVPN"


def ensure_dirs():
    """Создаёт каталоги данных. Зовётся и службой, и установщиком."""
    for d in (DATA, CONF, CONF_TUNNELS, STATE, LOGS):
        os.makedirs(d, exist_ok=True)


def log_files(prefix):
    """Журналы процесса prefix в LOGS по возрастанию даты.

    Имя сверяется с шаблоном целиком: иначе журналы tunnel-work попали бы
    и в выборку tunnel-work-2.
    """
    pat = re.compile(rf"^{re.escape(prefix)}-\d{{4}}-\d{{2}}-\d{{2}}_\d{{6}}\.log$")
    try:
        names = os.listdir(LOGS)
    except OSError:
        return []
    return [os.path.join(LOGS, n) for n in sorted(names) if pat.match(n)]


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
