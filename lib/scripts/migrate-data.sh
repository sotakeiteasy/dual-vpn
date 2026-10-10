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

# Конфиги лежат прямо в conf/ (до 0.1.13) или по папкам conf/corp и
# conf/personal. Прямо в conf/ их потом разложит confdirs.py.
has_confs() {
  local f
  for f in "$1"/conf/*.conf "$1"/conf/corp/*.conf "$1"/conf/personal/*.conf; do
    if [ -f "$f" ]; then return 0; fi
  done
  return 1
}
has_confs "$OLD" || exit 0

# В новом месте уже свои конфиги: переезд был раньше или человек начал с
# нуля. Чужое поверх не кладём.
if has_confs "$DATA"; then
  exit 0
fi

mkdir -p "$DATA/conf" "$DATA/lib/state"
# -p: внутри приватные ключи, права 600 должны переехать вместе с ними.
for F in "$OLD"/conf/*.conf; do
  if [ -f "$F" ]; then cp -p "$F" "$DATA/conf/"; fi
done
for KIND in corp personal; do
  if [ -d "$OLD/conf/$KIND" ]; then
    cp -Rp "$OLD/conf/$KIND" "$DATA/conf/"
  fi
done
if [ -f "$OLD/conf/site.env" ]; then
  cp -p "$OLD/conf/site.env" "$DATA/conf/"
fi
if [ -f "$OLD/lib/state/profile" ]; then
  cp -p "$OLD/lib/state/profile" "$DATA/lib/state/"
fi
echo "→ конфиги перенесены из $OLD"
