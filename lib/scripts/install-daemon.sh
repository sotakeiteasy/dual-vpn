#!/bin/bash
# Ставит демона и права на управление им. Запускать один раз, из-под sudo.
#
#   sudo bash lib/scripts/install-daemon.sh          поставить
#   sudo bash lib/scripts/install-daemon.sh remove   снять
set -euo pipefail

LABEL=local.singbox-lx
LABEL_FILE=$LABEL.plist
PLIST=/Library/LaunchDaemons/$LABEL.plist

# В папке проекта скрипт лежит в lib/scripts, внутри .app — прямо в
# Contents/Resources рядом с vpn. Различаем по наличию vpn рядом.
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ -f "$HERE/vpn" ]; then
  BASE="$HERE"
  PLIST_SRC="$HERE/launchd/$LABEL_FILE"
else
  BASE=$(cd "$HERE/../.." && pwd)
  PLIST_SRC="$BASE/lib/launchd/$LABEL_FILE"
fi
SUDOERS=/etc/sudoers.d/singbox-lx
APP=/Applications/DualVPN.app
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

[ "$(id -u)" = 0 ] || { echo "нужен root: sudo bash $0 ${1:-}"; exit 1; }

# Убрать за установочным образом.
#
# Смонтированный DMG LaunchServices берёт на учёт, и запись переживает
# отмонтирование: в Spotlight и Launchpad остаётся вторая «DualVPN»,
# указывающая на /Volumes/DualVPN <версия>. Снять её потом нечем — lsregister
# отвечает -10814 на путь, которого больше нет, и выручает только полная
# перестройка базы. Поэтому снимаем с учёта и отмонтируем, пока том ещё на
# месте: тогда мёртвой записи просто не возникает.
#
# lsregister — от имени человека, а не root: база у каждого своя.
eject_images() {
  local v
  for v in /Volumes/DualVPN*; do
    [ -d "$v" ] || continue
    [ -x "$LSREGISTER" ] && sudo -u "$USER_NAME" "$LSREGISTER" -u "$v" >/dev/null 2>&1
    if hdiutil detach "$v" -quiet 2>/dev/null; then
      echo "→ образ отмонтирован: $v"
    else
      # Занят Finder'ом — не беда, но сказать надо: иначе запись останется.
      echo "→ не смог отмонтировать $v — извлеки его сам, иначе в поиске"
      echo "  останется вторая «DualVPN»"
    fi
  done
}

# Кому разрешаем кнопки: тот, кто вызвал sudo, а не root.
USER_NAME=${SUDO_USER:-$(stat -f %Su /dev/console)}

if [ "${1:-}" = remove ]; then
  launchctl bootout system/$LABEL 2>/dev/null || true
  rm -f "$PLIST" "$SUDOERS"
  echo "снято: $PLIST, $SUDOERS"

  # Приложение и его след в LaunchServices. Без снятия с учёта запись живёт
  # дальше и продолжает показывать «DualVPN» в поиске уже после удаления.
  if [ -d "$APP" ]; then
    [ -x "$LSREGISTER" ] && sudo -u "$USER_NAME" "$LSREGISTER" -u "$APP" >/dev/null 2>&1
    rm -rf "$APP"
    echo "снято: $APP"
  fi
  eject_images

  # Данные — только по явной просьбе: это конфиги, которые человек приносил
  # руками, и восстановить их нам неоткуда.
  if [ "${2:-}" = --all ]; then
    # Только свой каталог в Application Support. Установку из исходников не
    # трогаем ни при каких флагах: там рядом с данными лежит рабочая копия
    # репозитория, и снести её этот скрипт права не имеет.
    D="/Users/$USER_NAME/Library/Application Support/DualVPN"
    [ -d "$D" ] && { rm -rf "$D"; echo "снято: $D"; }
    rm -f "/Users/$USER_NAME/Library/Logs/singbox-lx-menubar.log"
    echo "данные удалены"
  else
    echo "данные оставлены; чтобы снести и их: sudo bash $0 remove --all"
  fi
  exit 0
fi

# Путь к проекту у каждого свой, поэтому в шаблоне он подставляется здесь.
# Куда класть конфиги и состояние. Внутри .app код переписывается при каждом
# обновлении, поэтому данные живут в домашней папке; при установке из
# исходников — рядом с кодом, там они уже лежат.
case "$BASE" in
  *.app/Contents/Resources)
    DATA="/Users/$USER_NAME/Library/Application Support/DualVPN" ;;
  *)
    DATA="$BASE" ;;
esac
mkdir -p "$DATA/conf" "$DATA/lib/state"
# Переезд с другой установки (обычно — из исходников): её конфиги берём с
# собой. Пока plist ещё старый — новый путь к данным в нём ниже затрёт старый.
case "$BASE" in
  *.app/Contents/Resources) bash "$HERE/migrate-data.sh" "$PLIST" "$DATA" ;;
esac
chown -R "$USER_NAME" "$DATA" 2>/dev/null || true

sed -e "s|@@BASE@@|$BASE|g" -e "s|@@DATA@@|$DATA|g" "$PLIST_SRC" > "$PLIST"
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null

# bootout перед bootstrap: иначе повторная установка упадёт с "already loaded".
# Он асинхронный, и если демон в этот момент держит туннель, откат маршрутов
# занимает секунды. bootstrap сразу следом получал "Bootstrap failed: 5".
launchctl bootout system/$LABEL 2>/dev/null || true
for _ in $(seq 1 60); do
  launchctl print system/$LABEL >/dev/null 2>&1 || break
  sleep 0.5
done
if launchctl print system/$LABEL >/dev/null 2>&1; then
  echo "демон не выгружается за 30с — останови туннель и попробуй снова"; exit 1
fi

if ! launchctl bootstrap system "$PLIST"; then
  echo "launchctl bootstrap не сработал; plist на месте, но служба не поднята"
  exit 1
fi

# Права ровно на две команды и ровно на этот демон — не на launchctl вообще.
# Третья строка — аварийный путь: если службы нет или она уже упала, а
# маршруты висят, «Выключить» вызывает уборку напрямую. Без этого кнопка в
# таком состоянии просто ругалась, и разгребать приходилось из терминала.
cat > "$SUDOERS.tmp" <<EOF
$USER_NAME ALL=(root) NOPASSWD: /bin/launchctl kickstart -k system/$LABEL
$USER_NAME ALL=(root) NOPASSWD: /bin/launchctl kill INT system/$LABEL
$USER_NAME ALL=(root) NOPASSWD: $BASE/vpn stop
EOF
chmod 440 "$SUDOERS.tmp"
chown root:wheel "$SUDOERS.tmp"
# Битый файл в sudoers.d ломает sudo целиком, поэтому сначала проверка.
if visudo -cf "$SUDOERS.tmp" >/dev/null; then
  mv "$SUDOERS.tmp" "$SUDOERS"
else
  rm -f "$SUDOERS.tmp"
  echo "sudoers не прошёл проверку — права не выданы, кнопки будут спрашивать пароль"
fi

eject_images

echo "готово."
echo "  данные:     $DATA"
echo "  поднять:    sudo launchctl kickstart -k system/$LABEL"
echo "  остановить: sudo launchctl kill INT system/$LABEL"
echo "  снять:      sudo bash $0 remove"
