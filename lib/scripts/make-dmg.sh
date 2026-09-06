#!/bin/bash
# Собирает DMG для релиза: приложение плюс ярлык на «Программы».
#
#   bash lib/scripts/make-dmg.sh
#
# Результат — dist/DualVPN-<версия>.dmg
set -euo pipefail

BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VER=$(cat "$BASE/VERSION")
APP="$BASE/lib/scripts/dist/DualVPN.app"
OUT="$BASE/dist"
DMG="$OUT/DualVPN-$VER.dmg"
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

# Снять копию с учёта в LaunchServices. Просто удалить папку мало: запись
# переживает удаление, и Launchpad со Spotlight продолжают показывать вторую
# «DualVPN» рядом с установленной — ровно эта пара и появлялась после сборки.
unregister() {
  [ -x "$LSREGISTER" ] || return 0
  [ -e "$1" ] || return 0
  "$LSREGISTER" -u "$1" >/dev/null 2>&1 || true
}

# Пересобираем всегда. Иначе образ молча уезжает из старой сборки: у .app
# и DMG разные команды, и легко отдать людям вчерашнее приложение.
echo "→ пересобираю приложение…"
rm -rf "$BASE/lib/scripts/build" "$BASE/lib/scripts/dist"
if [ -x "$BASE/lib/venv/bin/python" ]; then
  PY="$BASE/lib/venv/bin/python"
else
  echo "нет окружения — запусти сперва install.sh"; exit 1
fi
(cd "$BASE/lib/scripts" && "$PY" setup.py py2app >/dev/null)
[ -d "$APP" ] || { echo "сборка не дала приложения — смотри вывод py2app"; exit 1; }

echo "→ проверяю…"
bash "$BASE/lib/scripts/selftest.sh" >/dev/null || {
  echo "проверки не прошли — образ не собираю"; exit 1; }

# Права на исполнение теряются, если приложение переносили не тем способом,
# а без них ни туннель не поднимется, ни служба не установится.
chmod +x "$APP/Contents/Resources/sing-box" "$APP/Contents/Resources/vpn"
chmod +x "$APP/Contents/Resources/"*.sh 2>/dev/null || true

mkdir -p "$OUT"
# Чтобы Spotlight не показывал содержимое папки сборок в поиске и Launchpad.
: >"$OUT/.metadata_never_index"
rm -f "$DMG"

STAGE=$(mktemp -d)
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"      # чтобы перетащить мышью

# UDZO — сжатие: без него образ весит столько же, сколько распакованный бандл.
hdiutil create -quiet -volname "DualVPN $VER" -srcfolder "$STAGE" \
  -ov -format UDZO "$DMG"
unregister "$STAGE/DualVPN.app"
rm -rf "$STAGE"

# Промежуточная сборка Spotlight'ом индексируется, и в Launchpad появляется
# второе приложение — рядом с установленным. Приложение уже внутри образа,
# держать копию незачем.
unregister "$APP"
rm -rf "$BASE/lib/scripts/build" "$BASE/lib/scripts/dist"

echo "готово: $DMG"
echo "размер: $(du -h "$DMG" | cut -f1)"
shasum -a 256 "$DMG"
