# PyInstaller: два exe, одна общая папка.
#
# Разными вызовами PyInstaller их собрать нельзя — каждый onedir-вызов делает
# свой каталог со своей копией рантайма, и sing-box.exe с wintun.dll легли бы
# в сборку дважды. Здесь два EXE и один COLLECT, поэтому общее лежит один раз.
#
#   DualVPN.exe  оконный    значок в трее, обычный запуск пользователем
#   dualvpn.exe  консольный CLI и хост службы
#
# Служба обязана быть консольной: StartServiceCtrlDispatcher у оконного
# процесса не поднимается, и диспетчер отваливается по таймауту (ошибка 1053).

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(SPECPATH)))
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
