#!/bin/bash
# Переносит конфиги из прежней установки в новый каталог данных.
#
#   bash migrate-data.sh <plist установленной службы> <новый каталог данных>
#
# Зовёт install-daemon.sh при установке из .app — до того, как перепишет
# plist: где жили данные, записано только в старом описании службы. Обычный
# случай — переезд с установки из исходников (данные в репозитории) на DMG.
#
# Только копирует: исходники и их конфиги остаются как были.
set -euo pipefail

OLD_PLIST=${1:?plist службы}
DATA=${2:?каталог данных}

[ -f "$OLD_PLIST" ] || exit 0
OLD=$(/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:DUALVPN_DATA" \
        "$OLD_PLIST" 2>/dev/null || true)
[ -n "$OLD" ] && [ "$OLD" != "$DATA" ] || exit 0
ls "$OLD"/conf/*.conf >/dev/null 2>&1 || exit 0

# В новом месте уже свои конфиги: переезд был раньше или человек начал с
# нуля. Чужое поверх не кладём.
if ls "$DATA"/conf/*.conf >/dev/null 2>&1; then
  exit 0
fi

mkdir -p "$DATA/conf" "$DATA/lib/state"
# -p: внутри приватные ключи, права 600 должны переехать вместе с ними.
cp -p "$OLD"/conf/*.conf "$DATA/conf/"
if [ -f "$OLD/conf/site.env" ]; then
  cp -p "$OLD/conf/site.env" "$DATA/conf/"
fi
if [ -f "$OLD/lib/state/profile" ]; then
  cp -p "$OLD/lib/state/profile" "$DATA/lib/state/"
fi
echo "→ конфиги перенесены из $OLD"
