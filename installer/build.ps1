# Сборка TunnelVPN: три exe через PyInstaller, затем установщик через Inno Setup.
#
#   powershell -ExecutionPolicy Bypass -File installer\build.ps1
#
# Готовый установщик кладётся в installer\Output\TunnelVPN-<версия>-setup.exe.
# Запускать из корня репозитория или откуда угодно — путь вычисляется сам.
#
# ВАЖНО: файл сохранён в UTF-8 С BOM. Windows PowerShell 5.1 (powershell.exe,
# в отличие от pwsh) без BOM читает скрипт как ANSI: кириллица в строках и
# комментариях рассыпается, парсер спотыкается на «Missing closing '}'», и
# сборка падает ещё до первой команды. Не пересохраняй без BOM.

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Bin = Join-Path $Root 'lib\bin'
$Inst = Join-Path $Root 'installer'
$Version = (Get-Content (Join-Path $Root 'VERSION') -Raw).Trim()

Write-Host "-> TunnelVPN $Version, корень: $Root"

# --- Бинарники должны быть на месте ДО сборки: PyInstaller кладёт их внутрь
# сборки, и без них установщик соберётся, а приложение работать не будет.
foreach ($f in 'sing-box.exe', 'wintun.dll') {
    if (-not (Test-Path (Join-Path $Bin $f))) {
        Write-Host "нет lib\bin\$f - см. README, раздел «Из исходников»"
        exit 1
    }
}

# --- Окружение сборки
# Установленное приложение несёт Python внутри себя, и его версия задаётся
# здесь. В CI (.github/workflows/build.yml) — та же, иначе релизы и локальные
# сборки работали бы на разных рантаймах.
$PyVersion = '3.14'
$Venv = Join-Path $Root 'lib\venv'
$Cfg = Join-Path $Venv 'pyvenv.cfg'
$Have = ''
if (Test-Path $Cfg) {
    $m = Select-String -Path $Cfg -Pattern '^version(_info)?\s*=\s*(\S+)' | Select-Object -First 1
    if ($m) { $Have = $m.Matches[0].Groups[2].Value }
}
# Окружение на другой версии пересоздаём: иначе новый Python до сборки
# не дошёл бы никогда.
if (-not $Have.StartsWith("$PyVersion.")) {
    # Лаунчер py, а если его нет или он этой версии не знает (на раннере CI
    # Python ставит setup-python) — python из PATH. Берём только нужную версию.
    $SysPy = $null
    foreach ($cand in @(@('py', "-$PyVersion"), @('python'))) {
        if (-not (Get-Command $cand[0] -ErrorAction SilentlyContinue)) { continue }
        $rest = @($cand | Select-Object -Skip 1)
        try {
            $out = & $cand[0] @rest -c "import sys; print('%d.%d' % sys.version_info[:2], sys.executable)" 2>$null
        } catch { continue }
        if ($LASTEXITCODE -eq 0 -and "$out" -match "^$([regex]::Escape($PyVersion)) (.+)$") {
            $SysPy = $Matches[1]
            break
        }
    }
    if (-not $SysPy) {
        throw "нет Python $PyVersion — поставить: winget install Python.Python.$PyVersion"
    }
    if (Test-Path $Venv) {
        Write-Host "-> окружение на Python $Have, пересоздаю на $PyVersion..."
        Remove-Item $Venv -Recurse -Force
    } else {
        Write-Host '-> создаю окружение...'
    }
    & $SysPy -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw "venv на $SysPy вернул $LASTEXITCODE" }
}
$Py = Join-Path $Venv 'Scripts\python.exe'
& $Py -m pip install -q --upgrade pip
& $Py -m pip install -q -r (Join-Path $Root 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw "pip install вернул $LASTEXITCODE" }
# PyInstaller нужен только сборке, поэтому он не в requirements.txt.
& $Py -m pip install -q pyinstaller==6.22.3
if ($LASTEXITCODE -ne 0) { throw "pip install pyinstaller вернул $LASTEXITCODE" }

# --- Значок
& $Py (Join-Path $Inst 'make_icon.py') (Join-Path $Inst 'TunnelVPN.ico')

Push-Location $Root
try {
    Write-Host '-> собираю exe (установочные + портативный)...'
    & $Py -m PyInstaller --noconfirm --clean `
        --distpath (Join-Path $Root 'dist') `
        --workpath (Join-Path $Root 'build') `
        (Join-Path $Inst 'tunnelvpn.spec')
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller вернул $LASTEXITCODE" }

    # Бинарники кладём рядом с exe: paths.BIN у обычной сборки — это папка
    # приложения, и sing-box ищет wintun.dll в своём каталоге.
    # Портативному это не нужно: у него оба файла уже внутри.
    $Dist = Join-Path $Root 'dist\TunnelVPN'
    Copy-Item (Join-Path $Bin 'sing-box.exe') $Dist -Force
    Copy-Item (Join-Path $Bin 'wintun.dll') $Dist -Force

    # Дымовая проверка: установщик зовёт tunnelvpn.exe для службы, и если под
    # этим именем окажется не CLI (так было, когда трей назывался DualVPN.exe
    # и ложился поверх), установка зависает намертво. Лучше упасть здесь.
    $Cli = Join-Path $Dist 'tunnelvpn.exe'
    $p = Start-Process $Cli -ArgumentList 'version' -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $Root 'build\cli-version.txt')
    if (-not $p.WaitForExit(30000)) {
        Stop-Process -Id $p.Id -Force
        throw 'tunnelvpn.exe version не ответил за 30 с — под этим именем не CLI?'
    }
    $out = Get-Content (Join-Path $Root 'build\cli-version.txt') -Raw
    if ($out -notmatch [regex]::Escape($Version)) {
        throw "tunnelvpn.exe version: ждали $Version, получили: $out"
    }
    # Служба ищет sing-box.exe и wintun.dll там же, где их видит version.
    # Раз они уже не там, где их кладёт сборка, — установленная версия не
    # поднимет туннель, хотя всё остальное в ней работает.
    if ($out -match 'MISSING') {
        throw "tunnelvpn.exe не находит бинарники:`n$out"
    }
    if (-not (Test-Path (Join-Path $Dist 'TunnelVPN-Tray.exe'))) {
        throw 'нет TunnelVPN-Tray.exe в dist\TunnelVPN'
    }
    # Ресурс версии собирает tunnelvpn.spec. Пустое описание — и диспетчер
    # задач снова покажет вместо «TunnelVPN» имя файла.
    foreach ($exe in (Join-Path $Dist 'tunnelvpn.exe'), (Join-Path $Dist 'TunnelVPN-Tray.exe'),
                     (Join-Path $Root 'dist\TunnelVPN-Portable.exe')) {
        $desc = (Get-Item $exe).VersionInfo.FileDescription
        if (-not $desc) { throw "у $exe нет FileDescription — ресурс версии не собрался" }
    }
} finally {
    Pop-Location
}

$Portable = Join-Path $Root 'dist\TunnelVPN-Portable.exe'
if (Test-Path $Portable) {
    $mb = [math]::Round((Get-Item $Portable).Length / 1MB)
    Write-Host "-> портативный: dist\TunnelVPN-Portable.exe ($mb МБ)"
}

# --- Установщик
$Iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    # winget ставит Inno Setup только для пользователя, без прав
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $Iscc) {
    Write-Host '-> Inno Setup не найден, собраны только exe в dist\'
    Write-Host '   поставить: winget install JRSoftware.InnoSetup'
    exit 0
}

& $Iscc "/DMyVersion=$Version" (Join-Path $Inst 'tunnelvpn.iss')
if ($LASTEXITCODE -ne 0) { throw "Inno Setup вернул $LASTEXITCODE" }
Write-Host "-> готово: installer\Output\TunnelVPN-$Version-setup.exe"
