# PyInstaller: три exe за один проход.
#
#   DualVPN.exe           оконный    значок в трее (установленная версия)
#   dualvpn.exe           консольный CLI и хост службы
#   DualVPN-Portable.exe  оконный    всё в одном файле, без установки
#
# Первые два делят одну папку. Разными вызовами PyInstaller их собрать нельзя —
# каждый onedir-вызов делает свой каталог со своей копией рантайма, и sing-box
# с wintun лёг бы в сборку дважды. Здесь два EXE и один COLLECT, поэтому общее
# лежит один раз.
#
# Служба обязана быть консольной: StartServiceCtrlDispatcher у оконного
# процесса не поднимается, и диспетчер отваливается по таймауту (ошибка 1053).

import os

# SPECPATH — это КАТАЛОГ со spec-файлом (installer/), а не путь к самому файлу.
# Отсюда до корня ровно один уровень: второй dirname уводил на папку выше
# репозитория, и PyInstaller не находил entry_cli.py.
ROOT = os.path.dirname(os.path.abspath(SPECPATH))
INST = os.path.join(ROOT, "installer")
ICON = os.path.join(INST, "DualVPN.ico")

datas = [
    (os.path.join(ROOT, "lib", "dualvpn", "ui"), "dualvpn/ui"),
    (os.path.join(ROOT, "VERSION"), "."),
]

# Модули службы pywin32 подтягиваются через getattr, статический анализ их
# не видит и в сборку не кладёт.
hidden = [
    "win32timezone", "servicemanager", "win32serviceutil",
    "win32service", "win32event", "win32pipe", "win32file",
    "win32security", "ntsecuritycon", "win32api",
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
MERGE((cli_a, "entry_cli", "dualvpn"), (tray_a, "entry_tray", "DualVPN"))

cli_pyz = PYZ(cli_a.pure)
tray_pyz = PYZ(tray_a.pure)

cli_exe = EXE(
    cli_pyz, cli_a.scripts, [], exclude_binaries=True,
    name="dualvpn", console=True, icon=ICON,
)
tray_exe = EXE(
    tray_pyz, tray_a.scripts, [], exclude_binaries=True,
    name="DualVPN", console=False, icon=ICON,
)

COLLECT(
    cli_exe, cli_a.binaries, cli_a.datas,
    tray_exe, tray_a.binaries, tray_a.datas,
    name="DualVPN",
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
    name="DualVPN-Portable",
    console=False, icon=ICON,
    # Манифест requireAdministrator: UAC спрашивается один раз при запуске.
    # Без него процесс не сможет ни создать адаптер, ни править маршруты, и
    # приложение молча не заработало бы.
    uac_admin=True,
)
