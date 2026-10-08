#!/bin/bash
# Печатает раздел версии из CHANGELOG.md — без заголовка, как есть.
# Раздела нет или он пустой — выходит с ошибкой: выпуск без описания не идёт.
#
#   bash lib/scripts/changelog.sh 0.1.7
set -euo pipefail

BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VER=${1:-}
[ -n "$VER" ] || { echo "нужен номер: bash $0 X.Y.Z" >&2; exit 1; }

# Раздел — от «## X.Y.Z» до следующего «## ». Пустые строки по краям срезаем.
TEXT=$(awk -v v="$VER" '
  /^## / { on = ($2 == v); next }
  on
' "$BASE/CHANGELOG.md" | sed -e '/./,$!d')
[ -n "${TEXT//[[:space:]]/}" ] || {
  echo "в CHANGELOG.md нет раздела «## ${VER}» — опиши, что в версии нового" >&2; exit 1; }
printf '%s\n' "$TEXT"
