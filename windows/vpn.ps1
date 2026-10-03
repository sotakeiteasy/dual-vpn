# Личный AmneziaWG + корпоративный WireGuard одновременно, через sing-box-lx.
#
#   Запуск (от Администратора):
#     powershell -ExecutionPolicy Bypass -File C:\dual-vpn\windows\vpn.ps1
#
#   Другой личный сервер — имя файла из conf\ без .conf:
#     powershell -ExecutionPolicy Bypass -File C:\dual-vpn\windows\vpn.ps1 my-server
#
#   Проверка: поднять, проверить оба туннеля, опустить:
#     powershell -ExecutionPolicy Bypass -File C:\dual-vpn\windows\vpn.ps1 -Diag
#
# Ctrl+C — останавливает и убирает за собой маршруты.

param(
    [string]$Personal = '',
    [switch]$Diag,
    # Куда писать вывод. Нужно, когда скрипт запущен в отдельном окне
    # администратора и его вывод иначе не увидеть.
    [string]$Log = ''
)

$ErrorActionPreference = 'Stop'
# Скрипт лежит в windows/, корень проекта — на уровень выше.
$Base = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Conf = Join-Path $Base 'conf'
$State = Join-Path $Base 'lib\state'
$SingBox = Join-Path $Base 'lib\bin\sing-box.exe'
$Config = Join-Path $State 'config.json'
$SbLog = Join-Path $State 'sing-box.log'
$TunIp = '172.19.0.1'   # адрес tun из build-config.py, по нему ищем интерфейс
$Proc = $null
$Peers = @()
$AddedRoutes = @()

if ($Log) { Start-Transcript -Path $Log -Force | Out-Null }

function Say([string]$msg) { Write-Host $msg }

function Quit([int]$code) {
    if ($Log) { Stop-Transcript | Out-Null }
    exit $code
}

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Say "нужны права администратора: запусти windows\vpn.cmd, он запросит их сам"
        Quit 1
    }
}

function Find-Python {
    # python.exe из Microsoft Store бывает заглушкой, которая открывает магазин
    # вместо запуска, поэтому проверяем, что он действительно отвечает.
    foreach ($name in 'python', 'py', 'python3') {
        $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if (-not $cmd) { continue }
        $out = & $cmd.Source -c 'import sys; print(sys.version_info[0])' 2>$null
        if ($LASTEXITCODE -eq 0 -and "$out".Trim() -eq '3') { return $cmd.Source }
    }
    return $null
}

# conf\site.env: строки вида KEY="значение", как на macOS.
# Оттуда берутся CORP_DOMAINS, CORP_PROBE, CORP_HOSTS, SB_CORP_EXCLUDE.
function Load-SiteEnv {
    $path = Join-Path $Conf 'site.env'
    if (-not (Test-Path $path)) { return }
    foreach ($line in Get-Content -Path $path -Encoding UTF8) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        if ($line -notmatch '^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { continue }
        $key = $Matches[1]
        $val = $Matches[2].Trim()
        if ($val.Length -ge 2 -and (($val[0] -eq '"' -and $val[-1] -eq '"') -or
                                    ($val[0] -eq "'" -and $val[-1] -eq "'"))) {
            $val = $val.Substring(1, $val.Length - 2)
        }
        # Переменная из окружения важнее файла — как `: ${X:=}` в vpn.
        if (-not [Environment]::GetEnvironmentVariable($key)) {
            [Environment]::SetEnvironmentVariable($key, $val)
        }
    }
}

function Cleanup {
    Say ""
    Say "-> останавливаю sing-box..."
    if ($script:Proc -and -not $script:Proc.HasExited) {
        $script:Proc.Kill()
        $script:Proc.WaitForExit(10000) | Out-Null
    }
    foreach ($r in $script:AddedRoutes) {
        Remove-NetRoute -DestinationPrefix $r -Confirm:$false -ErrorAction SilentlyContinue
    }
    $script:AddedRoutes = @()
    Say "-> готово, сеть вернулась в исходное состояние"
}

function Show-SingBoxLog {
    if (Test-Path $SbLog) {
        Say "--- последние строки sing-box.log ---"
        Get-Content -Path $SbLog -Tail 25 -Encoding UTF8 | ForEach-Object { Say "  $_" }
    }
}

# Проверки для -Diag: что видно снаружи и как резолвятся и открываются
# корп-хосты. Ничего не меняет, только смотрит.
function Test-Https([string]$url) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
        return "$($r.StatusCode)"
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) { return [string][int]$_.Exception.Response.StatusCode }
        return "ошибка: $($_.Exception.Message)"
    } catch {
        return "ошибка: $($_.Exception.Message)"
    }
}

function Test-Tcp([string]$addr, [int]$port) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($addr, $port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(5000)) { return $false }
        $c.EndConnect($ar)
        return $true
    } catch { return $false } finally { $c.Close() }
}

function Run-Diag {
    $ok = $true
    Say ""
    Say "== проверка =="

    try {
        $ip = (Invoke-WebRequest -Uri 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 10).Content.Trim()
        Say "  внешний IP (личный туннель): $ip"
    } catch {
        Say "  внешний IP: не получен ($($_.Exception.Message))"; $ok = $false
    }
    foreach ($u in 'https://www.google.com', 'https://github.com') {
        $res = Test-Https $u
        Say "  $u -> $res"
        if ($res -like 'ошибка*') { $ok = $false }
    }

    $hosts = @()
    if ($env:CORP_PROBE) { $hosts += $env:CORP_PROBE }
    if ($env:CORP_HOSTS) { $hosts += ($env:CORP_HOSTS -split '\s+' | Where-Object { $_ }) }
    $hosts = $hosts | Select-Object -Unique
    if (-not $hosts) { Say "  корп-хостов в site.env нет (CORP_PROBE/CORP_HOSTS) - корп не проверяю" }
    foreach ($h in $hosts) {
        $addr = (Resolve-DnsName -Name $h -Type A -DnsOnly -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
        if (-not $addr) { Say "  $h -> не резолвится"; $ok = $false; continue }
        $tcp = if (Test-Tcp $addr 443) { 'порт 443 открыт' } else { 'порт 443 не отвечает' }
        $res = Test-Https "https://$h"
        Say "  $h -> $addr, $tcp, https: $res"
        if ($res -like 'ошибка*') { $ok = $false }
    }

    if ($ok) { Say "== всё работает ==" } else { Say "== есть проблемы, см. выше =="; Show-SingBoxLog }
    return $ok
}

Require-Admin
New-Item -ItemType Directory -Force -Path $State | Out-Null

if (-not (Test-Path $SingBox)) {
    Say "нет $SingBox"
    Say "скачай sing-box-lx для windows-amd64: https://github.com/Leadaxe/sing-box-lx/releases"
    Say "и положи sing-box.exe (и libcronet.dll, если есть) в lib\bin\"
    Quit 1
}
$Python = Find-Python
if (-not $Python) {
    Say "не найден Python 3: поставь с python.org и отметь «Add python.exe to PATH»"
    Quit 1
}

Load-SiteEnv
# strict_route: без него Windows резолвит корп-домены DNS-ом провайдера.
$env:SB_STRICT_ROUTE = '1'

# --- Профиль личного туннеля: build-config.py читает его из окружения.
# Проверяем имя здесь, чтобы не падать после того, как уже что-то поднято.
if (-not $Personal) { $Personal = $env:SB_PERSONAL }
if ($Personal) {
    $Personal = $Personal -replace '\.conf$', ''
    $pconf = Join-Path $Conf "$Personal.conf"
    if (-not (Test-Path $pconf)) {
        Say "нет профиля <$Personal>: не найден $pconf"
        Say "личные конфиги в conf\:"
        Get-ChildItem $Conf -Filter *.conf -ErrorAction SilentlyContinue |
            ForEach-Object { Say ("  " + $_.BaseName) }
        Quit 1
    }
    $env:SB_PERSONAL = $Personal
    Say "-> личный профиль: $Personal"
}

# Остался sing-box от прошлого запуска (окно закрыли крестиком) — снимаем:
# второй экземпляр не поднимет tun с тем же адресом.
Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $SingBox } |
    ForEach-Object {
        Say "-> снимаю старый sing-box (pid $($_.Id))"
        $_.Kill(); $_.WaitForExit(10000) | Out-Null
    }

# Другой VPN (AmneziaVPN, WireGuard) уже забрал весь трафик парой маршрутов
# 0/1 + 128/1. С ним sing-box уходит наружу через чужой туннель, а если
# там тот же личный ключ — клиенты выбивают друг друга с сервера.
# Свой tun к этому моменту уже снят, поэтому всё найденное — чужое.
$foreign = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in '0.0.0.0/1', '128.0.0.0/1' } |
    Select-Object -ExpandProperty InterfaceAlias -Unique)
if ($foreign.Count -gt 0) {
    Say "весь трафик уже забрал другой VPN: $($foreign -join ', ')"
    Say "отключи его и запусти снова - два VPN одновременно идут друг через друга"
    Quit 1
}

# --- Пересобираем config.json из conf\*.conf
Say "-> собираю конфиг из conf\..."
& $Python (Join-Path $Base 'lib\scripts\build-config.py') --force
if ($LASTEXITCODE -ne 0) { Say "не удалось собрать конфиг - правь conf\*.conf"; Quit 1 }

& $SingBox check -c $Config
if ($LASTEXITCODE -ne 0) { Say "конфиг не прошёл проверку"; Quit 1 }

# --- Шлюз по умолчанию: до старта, пока туннель не перебил маршруты
$def = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
       Where-Object { $_.NextHop -ne '0.0.0.0' } |
       Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
if (-not $def) { Say "нет маршрута по умолчанию - сеть не поднята?"; Quit 1 }
$GW = $def.NextHop
$UplinkIf = $def.InterfaceIndex
Say "-> аплинк: индекс $UplinkIf, шлюз $GW"

# --- Адреса пиров из конфига. build-config.py уже резолвил имена в адреса.
$cfg = Get-Content -Path $Config -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($e in $cfg.endpoints) {
    foreach ($p in $e.peers) {
        $h = "$($p.address)".Trim()
        if (-not $h) { continue }
        if ($h -match '^[\d\.]+$') { $Peers += $h; continue }
        try {
            $ip = (Resolve-DnsName -Name $h -Type A -ErrorAction Stop |
                   Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
            if ($ip) { $Peers += $ip }
        } catch { }
    }
}
$Peers = @($Peers | Select-Object -Unique)
if ($Peers.Count -eq 0) { Say "не определить адреса пиров - прерываю, иначе будет петля"; Quit 1 }
Say "-> пиры (пойдут мимо туннеля): $($Peers -join ', ')"

# Всё, что поднимает туннель. Отдельной функцией, чтобы `return` выходил
# отсюда, а не из всего скрипта мимо уборки.
function Start-Tunnel {
    # --- Пиры мимо туннеля: ставим ДО старта, чтобы петля не возникла вообще
    foreach ($p in $Peers) {
        $prefix = "$p/32"
        if (-not (Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue)) {
            New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $UplinkIf `
                         -NextHop $GW -RouteMetric 1 -PolicyStore ActiveStore `
                         -ErrorAction SilentlyContinue | Out-Null
            $script:AddedRoutes += $prefix
        }
    }

    Say "-> запускаю sing-box..."
    # В -Diag лог sing-box уходит в файл, чтобы не мешать выводу проверок.
    # В обычном режиме он идёт прямо в окно, как на macOS в `vpn start`.
    $spArgs = @{
        FilePath     = $SingBox
        ArgumentList = @('run', '-c', "`"$Config`"")
        NoNewWindow  = $true
        PassThru     = $true
    }
    if ($Diag) {
        Remove-Item $SbLog -ErrorAction SilentlyContinue
        $spArgs.ArgumentList += '--disable-color'
        $spArgs.RedirectStandardError = $SbLog
        $spArgs.RedirectStandardOutput = "$SbLog.out"
    }
    $script:Proc = Start-Process @spArgs

    # --- Ждём tun (sing-box поднимает его как отдельный адаптер)
    $tunIdx = $null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        if ($Proc.HasExited) { break }
        $a = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -eq $TunIp } | Select-Object -First 1
        if ($a) { $tunIdx = $a.InterfaceIndex; break }
    }
    if ($Proc.HasExited) {
        Say "sing-box упал на старте (код $($Proc.ExitCode))"
        Show-SingBoxLog
        $script:ExitCode = 1
        return
    }
    if (-not $tunIdx) { Say "tun не поднялся за 30с"; Show-SingBoxLog; $script:ExitCode = 1; return }
    Say "-> tun: интерфейс $tunIdx"

    # --- Обе половины адресного пространства на tun.
    # sing-box с auto_route ставит их сам; это страховка на случай, если нет.
    foreach ($half in '0.0.0.0/1', '128.0.0.0/1') {
        if (-not (Get-NetRoute -DestinationPrefix $half -InterfaceIndex $tunIdx -ErrorAction SilentlyContinue)) {
            New-NetRoute -DestinationPrefix $half -InterfaceIndex $tunIdx `
                         -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore `
                         -ErrorAction SilentlyContinue | Out-Null
            $script:AddedRoutes += $half
        }
    }
    Say "-> маршруты выставлены"

    if ($Diag) {
        # Рукопожатия идут не сразу: даём туннелям пару секунд.
        Start-Sleep -Seconds 3
        if (-not (Run-Diag)) { $script:ExitCode = 1 }
        return
    }

    Say "-> работает. Ctrl+C для остановки."
    # Ждём кусками: в одном долгом WaitForExit PowerShell не замечает Ctrl+C.
    while (-not $Proc.WaitForExit(500)) { }
    if ($Proc.ExitCode -ne 0) { Say "sing-box завершился с кодом $($Proc.ExitCode)" }
}

$ExitCode = 0
try {
    Start-Tunnel
}
finally {
    Cleanup
}
Quit $ExitCode
