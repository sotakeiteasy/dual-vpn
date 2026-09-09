# Сборка DualVPN: два exe через PyInstaller, затем установщик через Inno Setup.
#
#   powershell -ExecutionPolicy Bypass -File installer\build.ps1
#
# Готовый установщик кладётся в installer\Output\DualVPN-<версия>-setup.exe.
# Запускать из корня репозитория или откуда угодно — путь вычисляется сам.

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Bin = Join-Path $Root 'lib\bin'
$Inst = Join-Path $Root 'installer'
$Version = (Get-Content (Join-Path $Root 'VERSION') -Raw).Trim()

Write-Host "-> DualVPN $Version, корень: $Root"

# --- Бинарники должны быть на месте ДО сборки: PyInstaller кладёт их внутрь
# сборки, и без них установщик соберётся, а приложение работать не будет.
foreach ($f in 'sing-box.exe', 'wintun.dll') {
    if (-not (Test-Path (Join-Path $Bin $f))) {
        Write-Host "нет lib\bin\$f - см. README, раздел «Из исходников»"
        exit 1
    }
}

# --- Окружение сборки
$Venv = Join-Path $Root 'lib\venv'
if (-not (Test-Path $Venv)) {
    Write-Host '-> создаю окружение...'
    & python -m venv $Venv
}
$Py = Join-Path $Venv 'Scripts\python.exe'
& $Py -m pip install -q --upgrade pip
& $Py -m pip install -q -r (Join-Path $Root 'requirements.txt')
& $Py -m pip install -q pyinstaller pystray pywebview pillow

# --- Значок
& $Py (Join-Path $Inst 'make_icon.py') (Join-Path $Inst 'DualVPN.ico')

Push-Location $Root
try {
    Write-Host '-> собираю DualVPN.exe и dualvpn.exe...'
    & $Py -m PyInstaller --noconfirm --clean `
        --distpath (Join-Path $Root 'dist') `
        --workpath (Join-Path $Root 'build') `
        (Join-Path $Inst 'dualvpn.spec')

    # Бинарники кладём рядом с exe: paths.BIN у собранной версии — это папка
    # приложения, и sing-box ищет wintun.dll в своём каталоге.
    $Dist = Join-Path $Root 'dist\DualVPN'
    Copy-Item (Join-Path $Bin 'sing-box.exe') $Dist -Force
    Copy-Item (Join-Path $Bin 'wintun.dll') $Dist -Force
} finally {
    Pop-Location
}

# --- Установщик
$Iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $Iscc) {
    Write-Host '-> Inno Setup не найден, собраны только exe в dist\'
    Write-Host '   поставить: winget install JRSoftware.InnoSetup'
    exit 0
}

& $Iscc "/DMyVersion=$Version" (Join-Path $Inst 'dualvpn.iss')
Write-Host "-> готово: installer\Output\DualVPN-$Version-setup.exe"
