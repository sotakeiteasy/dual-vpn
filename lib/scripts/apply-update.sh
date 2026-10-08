#!/bin/bash
# Ставит новую версию приложения поверх установленной. Зовётся из окна
# через osascript с правами администратора — уже после сверки sha256 образа.
#
#   sudo bash apply-update.sh /путь/к/новому/DualVPN.app
#
# Сам скрипт берётся из установленного приложения, а не из скачанного: что
# и куда копировать под root, решает код, которому уже доверились. Код новой
# версии (её установщик службы) идёт под root только после подмены, то есть
# после сверки суммы — служба и так исполняет его от root.
set -euo pipefail

LABEL=local.singbox-lx
PLIST=/Library/LaunchDaemons/$LABEL.plist
APP=/Applications/DualVPN.app
NEW=${1:-}
PB=/usr/libexec/PlistBuddy
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

[ "$(id -u)" = 0 ] || { echo "нужен root: sudo bash $0 <DualVPN.app>"; exit 1; }
[ -f "$NEW/Contents/Info.plist" ] || { echo "нет приложения: $NEW"; exit 1; }
ID=$("$PB" -c "Print :CFBundleIdentifier" "$NEW/Contents/Info.plist" 2>/dev/null || true)
[ "$ID" = local.dualvpn ] || { echo "это не DualVPN: ${ID:-без идентификатора}"; exit 1; }

# Служба запущена из этого приложения (установка из DMG)? Тогда после
# подмены её надо переставить: работающий процесс держит старые файлы и
# переживает замену, но новый код заработает только с перезапуском, а
# описание службы и права в sudoers у новой версии могут быть другими.
# При установке из исходников служба живёт в репозитории — её не трогаем.
FROM_APP=0
RUNNING=0
if [ -f "$PLIST" ] && \
   [ "$("$PB" -c "Print :ProgramArguments:1" "$PLIST" 2>/dev/null || true)" = "$APP/Contents/Resources/vpn" ]; then
  FROM_APP=1
  # pid у службы есть, только пока поднят туннель.
  launchctl print "system/$LABEL" 2>/dev/null | grep -q $'^\tpid = ' && RUNNING=1
fi

# Сначала полная копия рядом, потом подмена двумя переименованиями: оборвись
# копирование — установленное приложение останется целым.
rm -rf "$APP.new" "$APP.old"
# ditto, а не cp -R: он корректно переносит бандлы.
ditto "$NEW" "$APP.new"
chown -R root:wheel "$APP.new"
[ -d "$APP" ] && mv "$APP" "$APP.old"
mv "$APP.new" "$APP"
rm -rf "$APP.old"

# Путь тот же, а версия новая — пусть LaunchServices перечитает бандл.
# От имени человека: база у каждого своя.
if [ -x "$LSREGISTER" ] && [ -n "${SUDO_USER:-}" ]; then
  sudo -u "$SUDO_USER" "$LSREGISTER" -f "$APP" >/dev/null 2>&1 || true
fi

# Установщик новой версии: он перепишет описание службы и sudoers и
# перезагрузит её. Сама служба при загрузке туннель не поднимает
# (RunAtLoad=false), поэтому был поднят — поднимаем снова, не был — нет.
if [ "$FROM_APP" = 1 ]; then
  bash "$APP/Contents/Resources/install-daemon.sh"
  if [ "$RUNNING" = 1 ]; then
    launchctl kickstart "system/$LABEL"
    echo "туннель поднят снова"
  fi
fi

echo "установлено: $("$PB" -c "Print :CFBundleShortVersionString" "$APP/Contents/Info.plist")"
