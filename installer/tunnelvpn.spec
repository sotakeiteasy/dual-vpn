# PyInstaller: три exe за один проход.
#
#   TunnelVPN-Tray.exe      оконный    значок в трее (установленная версия)
#   tunnelvpn.exe           консольный CLI и хост службы
#   TunnelVPN-Portable.exe  оконный    всё в одном файле, без установки
#
# Первые два делят одну папку. Разными вызовами PyInstaller их собрать нельзя —
# каждый onedir-вызов делает свой каталог со своей копией рантайма, и sing-box
# с wintun лёг бы в сборку дважды. Здесь два EXE и один COLLECT, поэтому общее
# лежит один раз.
#
# Служба обязана быть консольной: StartServiceCtrlDispatcher у оконного
# процесса не поднимается, и диспетчер отваливается по таймауту (ошибка 1053).

import os
import re

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo,
    VarStruct, VSVersionInfo)

# SPECPATH — это КАТАЛОГ со spec-файлом (installer/), а не путь к самому файлу.
# Отсюда до корня ровно один уровень: второй dirname уводил на папку выше
# репозитория, и PyInstaller не находил entry_cli.py.
ROOT = os.path.dirname(os.path.abspath(SPECPATH))
INST = os.path.join(ROOT, "installer")
ICON = os.path.join(INST, "TunnelVPN.ico")

with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as fh:
    VERSION = fh.read().strip()


def version_info(description, filename):
    """Ресурс версии exe. Без него у FileDescription пусто, и диспетчер задач
    вместо «TunnelVPN» показывает имя файла.

    Числовая версия — только цифры из VERSION («0.2.9-beta» → 0.2.9.0):
    суффикс в FixedFileInfo не помещается, он остаётся в строковых полях.
    """
    nums = [int(n) for n in re.findall(r"\d+", VERSION.split("-")[0])][:4]
    nums += [0] * (4 - len(nums))
    strings = [
        StringStruct("CompanyName", "Enkeym"),
        StringStruct("FileDescription", description),
        StringStruct("FileVersion", VERSION),
        StringStruct("InternalName", filename),
        StringStruct("OriginalFilename", filename + ".exe"),
        StringStruct("ProductName", "TunnelVPN"),
        StringStruct("ProductVersion", VERSION),
    ]
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=tuple(nums), prodvers=tuple(nums)),
        kids=[
            # 0409 — английский (США), 04B0 — Unicode: таблица по умолчанию,
            # её Windows находит без перевода.
            StringFileInfo([StringTable("040904B0", strings)]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ])

# Путь внутри сборки — тот, где его ищет paths.UI_DIR во frozen.
datas = [
    (os.path.join(ROOT, "lib", "tunnelvpn", "ui"), "tunnelvpn/ui"),
    (os.path.join(ROOT, "VERSION"), "."),
]

# Модули службы pywin32 подтягиваются через getattr, статический анализ их
# не видит и в сборку не кладёт.
hidden = [
    "win32timezone", "servicemanager", "win32serviceutil",
    "win32service", "win32event", "win32pipe", "win32file",
    "win32security", "ntsecuritycon", "win32api",
    # WMI в winnet: импортируются внутри функций.
    "pythoncom", "win32com.client", "win32process",
]

cli_a = Analysis(
    [os.path.join(INST, "entry_cli.py")],
    pathex=[os.path.join(ROOT, "lib")],
    datas=datas, hiddenimports=hidden,
)
tray_a = Analysis(
    [os.path.join(INST, "entry_tray.py")],
    pathex=[os.path.join(ROOT, "lib")],
    datas=datas, hiddenimports=hidden,
)

# MERGE учит второй пакет брать общие модули из первого, а не нести свою копию.
MERGE((cli_a, "entry_cli", "tunnelvpn"), (tray_a, "entry_tray", "TunnelVPN"))

cli_pyz = PYZ(cli_a.pure)
tray_pyz = PYZ(tray_a.pure)

cli_exe = EXE(
    cli_pyz, cli_a.scripts, [], exclude_binaries=True,
    name="tunnelvpn", console=True, icon=ICON,
    version=version_info("TunnelVPN", "tunnelvpn"),
)
# Имя трея обязано отличаться от CLI не только регистром: в Windows
# TunnelVPN.exe и tunnelvpn.exe — один файл, трей ложился поверх CLI, и
# установщик, звавший «tunnelvpn.exe service install», запускал трей и висел на нём.
tray_exe = EXE(
    tray_pyz, tray_a.scripts, [], exclude_binaries=True,
    name="TunnelVPN-Tray", console=False, icon=ICON,
    version=version_info("TunnelVPN Tray", "TunnelVPN-Tray"),
    # Трей работает от администратора, но права поднимает сам (tray.run), а
    # не манифестом: с requireAdministrator ярлык спрашивал UAC и тогда, когда
    # трей уже есть и нужно только показать окно. Окно запускается из трея и
    # наследует права. Автозапуск — задачей планировщика с наивысшими правами.
)

COLLECT(
    cli_exe, cli_a.binaries, cli_a.datas,
    tray_exe, tray_a.binaries, tray_a.datas,
    name="TunnelVPN",
)


# --------------------------------------------------------- портативная версия
#
# Отдельный однофайловый exe: ни установки, ни службы, ни распакованной папки.
# Внутрь кладём и sing-box.exe с wintun.dll — иначе «портативная» версия всё
# равно требовала бы носить рядом два файла, и смысл терялся бы.
#
# В MERGE выше её включать нельзя: MERGE учит сборки брать общие модули друг у
# друга, а onefile обязан быть самодостаточным.

portable_datas = datas + [
    (os.path.join(ROOT, "lib", "bin", "sing-box.exe"), "."),
    (os.path.join(ROOT, "lib", "bin", "wintun.dll"), "."),
]

portable_a = Analysis(
    [os.path.join(INST, "entry_portable.py")],
    pathex=[os.path.join(ROOT, "lib")],
    datas=portable_datas, hiddenimports=hidden,
)
portable_pyz = PYZ(portable_a.pure)

portable_exe = EXE(
    portable_pyz, portable_a.scripts,
    portable_a.binaries, portable_a.datas, [],
    name="TunnelVPN-Portable",
    console=False, icon=ICON,
    version=version_info("TunnelVPN Portable", "TunnelVPN-Portable"),
    # Манифест requireAdministrator: UAC спрашивается один раз при запуске.
    # Без него процесс не сможет ни создать адаптер, ни править маршруты, и
    # приложение молча не заработало бы.
    uac_admin=True,
)
