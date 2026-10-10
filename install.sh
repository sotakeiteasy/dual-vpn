#!/bin/bash
# Полная установка: демон + приложение в меню-баре.
#
#   bash install.sh            поставить
#   bash install.sh remove     снять
#
# Запускать БЕЗ sudo: пароль спросится один раз, там где он правда нужен.
set -euo pipefail

BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VENV="$BASE/lib/venv"
APP_NAME="DualVPN.app"
# Прежние имена: их надо снести, иначе в Launchpad копятся значки.
OLD_APPS=("singbox-lx.app" "VPN-lx.app")

[ "$(id -u)" != 0 ] || { echo "запускай без sudo: bash $0 ${1:-}"; exit 1; }

if [ "${1:-}" = remove ]; then
  sudo bash "$BASE/lib/scripts/install-daemon.sh" remove
  sudo rm -rf "/Applications/$APP_NAME" "${OLD_APPS[@]/#//Applications/}"
  rm -rf "$BASE/lib/scripts/build" "$BASE/lib/scripts/dist"
  echo "снято. Проект не тронут, папку можно удалить руками."
  exit 0
fi

# --- проверки до того, как что-то менять -----------------------------------

[ -x "$BASE/lib/bin/sing-box" ] || {
  echo "нет lib/bin/sing-box — скачай бинарник, см. README, шаг 2"; exit 1; }

# Конфиги по папкам conf/corp и conf/personal; прямо в conf/ — до 0.1.13,
# их разложит служба.
HAVE_CONF=""
for F in "$BASE"/conf/*.conf "$BASE"/conf/corp/*.conf "$BASE"/conf/personal/*.conf; do
  if [ -f "$F" ]; then HAVE_CONF=1; break; fi
done
[ -n "$HAVE_CONF" ] || {
  echo "в conf/corp и conf/personal нет ни одного .conf — положи свои конфиги, см. README, шаг 3"
  exit 1; }

# Пароль — сразу, а не после сборки. Иначе установка минутами стояла на
# приглашении посреди вывода, а собранная копия в dist/ тем временем
# находилась Spotlight'ом: её запускали вместо установленной и видели две
# DualVPN разных версий. Кеш sudo живёт 5 минут — на сборку и проверки хватает.
echo "→ нужен пароль администратора (служба и /Applications)…"
sudo -v || { echo "без пароля не поставить"; exit 1; }

# --- окружение и сборка (от пользователя, root тут не нужен) ---------------

if [ ! -x "$VENV/bin/python" ]; then
  echo "→ создаю окружение…"
  python3 -m venv "$VENV"
fi
echo "→ ставлю зависимости…"
"$VENV/bin/pip" install -q --upgrade pip
# pyobjc-framework-WebKit нужен окну: rumps тянет только Cocoa. В моём
# окружении он оказался случайно, вместе с отброшенной pywebview, поэтому
# сборка проходила у меня и падала из чистого клона.
"$VENV/bin/pip" install -q rumps py2app pyobjc-framework-WebKit

echo "→ рисую значки…"
"$VENV/bin/python" "$BASE/lib/scripts/make-icons.py" >/dev/null

echo "→ собираю приложение…"
rm -rf "$BASE/lib/scripts/build" "$BASE/lib/scripts/dist"
# py2app кладёт результат рядом с setup.py, поэтому собираем из его папки.
(cd "$BASE/lib/scripts" && "$VENV/bin/python" setup.py py2app >/dev/null)

BUILT="$BASE/lib/scripts/dist/$APP_NAME"
[ -d "$BUILT" ] || { echo "сборка не дала $APP_NAME — смотри вывод py2app"; exit 1; }

# До того, как трогать систему. Один раз уже уехало в /Applications приложение,
# которое падало на старте, — проверка ровно про это.
echo "→ проверяю сборку…"
if ! bash "$BASE/lib/scripts/selftest.sh"; then
  echo
  echo "проверки не прошли — в систему ничего не ставлю."
  exit 1
fi

# --- системная часть: демон, права, приложение в /Applications -------------

echo "→ ставлю демона (нужен пароль администратора)…"
sudo bash "$BASE/lib/scripts/install-daemon.sh"

sudo rm -rf "/Applications/$APP_NAME" "${OLD_APPS[@]/#//Applications/}"
# ditto, а не cp -R: он корректно переносит бандлы вместе с подписью.
sudo ditto "$BUILT" "/Applications/$APP_NAME"
sudo chown -R root:wheel "/Applications/$APP_NAME"

# Иначе рядом остаётся вторая копия приложения: Spotlight её индексирует,
# и в Launchpad видно два DualVPN — установленный и сборочный. Одного
# удаления мало: запись в LaunchServices переживает файл, снимаем явно.
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
# `|| true`: под set -e любой отказ lsregister оборвал бы установку до
# удаления dist/ — и в поиске осталась бы вторая DualVPN. Снятие с учёта —
# уборка, а не условие успеха.
if [ -x "$LSREGISTER" ]; then "$LSREGISTER" -u "$BUILT" >/dev/null 2>&1 || true; fi
rm -rf "$BASE/lib/scripts/build" "$BASE/lib/scripts/dist"

cat <<EOF

готово.

Приложение: /Applications/$APP_NAME  (папка проекта остаётся singbox-lx)
Первый запуск: правой кнопкой по нему → «Открыть» → «Открыть» ещё раз.
Так один раз, дальше открывается обычно. Приложение не подписано, поэтому
macOS переспрашивает — это ожидаемо.

Дальше значок появится в меню-баре, включение и выключение оттуда.
Панель для разбора полётов никуда не делась: sudo $BASE/vpn ui
EOF
