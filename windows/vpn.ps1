# Личный AmneziaWG + корпоративный WireGuard одновременно, через sing-box-lx.
#
#   Запуск (от Администратора):
#     powershell -ExecutionPolicy Bypass -File C:\dual-vpn\windows\vpn.ps1
#
#   Другой личный сервер — имя файла из conf\ без .conf:
#     powershell -ExecutionPolicy Bypass -File C:\dual-vpn\windows\vpn.ps1 my-server
#
# Ctrl+C — останавливает и убирает за собой маршруты.

param([string]$Personal = '')

$ErrorActionPreference = 'Stop'
# Скрипт лежит в windows/, корень проекта — на уровень выше.
$Base = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Proc = $null
$Peers = @()
$AddedRoutes = @()

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "нужны права администратора: запусти PowerShell от имени Администратора"
        exit 1
    }
}

function Cleanup {
    Write-Host ""
    Write-Host "-> останавливаю sing-box..."
    if ($script:Proc -and -not $script:Proc.HasExited) {
        $script:Proc.Kill()
        $script:Proc.WaitForExit(10000) | Out-Null
    }
    foreach ($r in $script:AddedRoutes) {
        Remove-NetRoute -DestinationPrefix $r -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Host "-> готово, сеть вернулась в исходное состояние"
}

Require-Admin

# --- Профиль личного туннеля: build-config.py читает его из окружения.
# Проверяем имя здесь, чтобы не падать после того, как уже что-то поднято.
if (-not $Personal) { $Personal = $env:SB_PERSONAL }
if ($Personal) {
    $Personal = $Personal -replace '\.conf$', ''
    $pconf = Join-Path $Base "conf\$Personal.conf"
    if (-not (Test-Path $pconf)) {
        Write-Host "нет профиля <$Personal>: не найден $pconf"
        Write-Host "личные конфиги в conf\:"
        Get-ChildItem (Join-Path $Base 'conf') -Filter *.conf -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Host ("  " + $_.BaseName) }
        exit 1
    }
    $env:SB_PERSONAL = $Personal
    Write-Host "-> личный профиль: $Personal"
}

# --- Пересобираем config.json из conf\*.conf
Write-Host "-> собираю конфиг из conf\..."
& python "$Base\lib\scripts\build-config.py"
if ($LASTEXITCODE -ne 0) { Write-Host "не удалось собрать конфиг - правь conf\*.conf"; exit 1 }

& "$Base\lib\bin\sing-box.exe" check -c "$Base\lib\state\config.json"
if ($LASTEXITCODE -ne 0) { Write-Host "конфиг не прошёл проверку"; exit 1 }

# --- Шлюз по умолчанию: до старта, пока туннель не перебил маршруты
$def = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
       Where-Object { $_.NextHop -ne '0.0.0.0' } |
       Sort-Object RouteMetric | Select-Object -First 1
if (-not $def) { Write-Host "нет маршрута по умолчанию - сеть не поднята?"; exit 1 }
$GW = $def.NextHop
$UplinkIf = $def.InterfaceIndex
Write-Host "-> аплинк: индекс $UplinkIf, шлюз $GW"

# --- Адреса пиров из конфига: резолвим, пока DNS ещё не в туннеле
$hosts = & python -c @"
import json,sys
c=json.load(open(r'$Base\lib\state\config.json'))
for e in c.get('endpoints',[]):
    for p in e.get('peers',[]):
        print(p['address'])
"@
foreach ($h in $hosts) {
    $h = $h.Trim()
    if (-not $h) { continue }
    if ($h -match '^[\d\.]+$') { $Peers += $h }
    else {
        try {
            $ip = (Resolve-DnsName -Name $h -Type A -ErrorAction Stop |
                   Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
            if ($ip) { $Peers += $ip }
        } catch { }
    }
}
if ($Peers.Count -eq 0) { Write-Host "не определить адреса пиров - прерываю, иначе будет петля"; exit 1 }
Write-Host "-> пиры (пойдут мимо туннеля): $($Peers -join ', ')"

try {
    # --- Пиры мимо туннеля: ставим ДО старта, чтобы петля не возникла вообще
    foreach ($p in $Peers) {
        $prefix = "$p/32"
        if (-not (Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue)) {
            New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $UplinkIf `
                         -NextHop $GW -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
            $AddedRoutes += $prefix
        }
    }

    Write-Host "-> запускаю sing-box..."
    $Proc = Start-Process -FilePath "$Base\lib\bin\sing-box.exe" `
                          -ArgumentList "run", "-c", "$Base\lib\state\config.json" `
                          -NoNewWindow -PassThru

    # --- Ждём tun (sing-box поднимает его как отдельный адаптер)
    $tunIdx = $null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        if ($Proc.HasExited) { Write-Host "sing-box упал на старте"; Cleanup; exit 1 }
        $a = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -eq '172.19.0.1' } | Select-Object -First 1
        if ($a) { $tunIdx = $a.InterfaceIndex; break }
    }
    if (-not $tunIdx) { Write-Host "tun не поднялся за 30с"; Cleanup; exit 1 }
    Write-Host "-> tun: интерфейс $tunIdx"

    # --- Обе половины адресного пространства на tun.
    # Если sing-box поставил их сам - New-NetRoute просто ничего не изменит.
    foreach ($half in '0.0.0.0/1', '128.0.0.0/1') {
        if (-not (Get-NetRoute -DestinationPrefix $half -InterfaceIndex $tunIdx -ErrorAction SilentlyContinue)) {
            New-NetRoute -DestinationPrefix $half -InterfaceIndex $tunIdx `
                         -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
            $AddedRoutes += $half
        }
    }
    Write-Host "-> маршруты выставлены"
    Write-Host "-> работает. Ctrl+C для остановки."

    $Proc.WaitForExit()
}
finally {
    Cleanup
}
