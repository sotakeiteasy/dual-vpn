#!/bin/bash
# Выпуск macOS-версии: номер в VERSION, коммит, тег mac-vX.Y.Z, пуш.
# Образ собирает и выкладывает в Releases GitHub Actions (.github/workflows/mac.yml).
#
#   bash lib/scripts/release.sh 0.1.4
set -euo pipefail

BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VER=${1:-}
TAG="mac-v$VER"

[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "нужен номер вида 0.1.4: bash $0 X.Y.Z"; exit 1; }

cd "$BASE"
# Выпуск — только из main: теги Windows-версии ставятся в своей ветке, а
# релиз macOS из чужой ветки собрал бы не тот код.
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || { echo "выпуск — только из main"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "в дереве незакоммиченные правки"; exit 1; }
git fetch -q origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || {
  echo "main расходится с origin/main — сперва git pull или git push"; exit 1; }
! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || { echo "тег $TAG уже есть"; exit 1; }

OLD=$(cat VERSION)
# sort -V: номер обязан расти, иначе приложения у людей не увидят обновления.
[ "$(printf '%s\n%s\n' "$OLD" "$VER" | sort -V | tail -1)" = "$VER" ] && [ "$OLD" != "$VER" ] || {
  echo "номер $VER не больше текущего $OLD"; exit 1; }
# Раздел станет описанием релиза: без него люди увидят пустую страницу.
bash "$BASE/lib/scripts/changelog.sh" "$VER" >/dev/null

PY="$BASE/lib/venv/bin/python"
[ -x "$PY" ] || PY=python3
echo "→ тесты…"
"$PY" -m unittest discover -s tests >/dev/null 2>&1 || {
  echo "тесты упали: $PY -m unittest discover -s tests"; exit 1; }
if command -v node >/dev/null; then
  node --test tests/test_view.js >/dev/null 2>&1 || {
    echo "js-тесты упали: node --test tests/test_view.js"; exit 1; }
fi

printf '%s\n' "$VER" > VERSION
git add VERSION
git commit -q -m "Выпуск macOS $VER"
git tag "$TAG"
git push -q origin main "$TAG"

echo "готово: $TAG отправлен, сборка — https://github.com/sotakeiteasy/dual-vpn/actions"
