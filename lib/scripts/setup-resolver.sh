#!/bin/bash
# Прописывает корп-домены в /etc/resolver (macOS split-DNS).
#
#   sudo ./vpn dns          установить
#   sudo ./vpn dns-remove   убрать
#
# Зачем это нужно: системный DNS macOS смотрит на локальный роутер (192.168.x.1),
# а маршрут до локальной подсети специфичнее, чем 0.0.0.0/1 на tun. Поэтому
# DNS-запросы физически не попадают в sing-box, и его правила hijack-dns /
# dns.rules для них не работают. Файлы в /etc/resolver заставляют macOS слать
# запросы по этим доменам прямо на корп-DNS, а тот уже идёт в туннель.
#
# Адрес DNS берётся из строки DNS= в conf/corp.conf.

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Корп-конфиг: corp.conf либо то, как его отдают админы — wg0-<фамилия>.conf.
# Логика та же, что в build-config.py; регистр не важен.
CORP_CONF=""
for RE in '^corp\.conf$' '^wg[-_0-9].*\.conf$' '^wg\.conf$'; do
  NAME=$(ls -1 "$BASE/conf" 2>/dev/null | grep -iE "$RE" | head -1)
  if [ -n "$NAME" ]; then
    CORP_CONF="$BASE/conf/$NAME"
    break
  fi
done

# Внутренние домены компании. Домен самого корп-сервера сюда добавлять НЕЛЬЗЯ:
# его имя должно резолвиться публично, иначе для подъёма туннеля понадобится
# DNS, доступный только через уже поднятый туннель (замкнутый круг).
# Скрипт такие домены отсекает сам, но лучше их тут и не писать.
DOMAINS="${CORP_DOMAINS:-}"

# Аргументы (кроме remove) переопределяют список.
MODE="install"
if [ "$1" = "remove" ]; then MODE="remove"; shift; fi
[ -n "$1" ] && DOMAINS="$*"

if [ "$(id -u)" != "0" ]; then
  echo "нужен root: sudo $BASE/vpn dns"
  exit 1
fi

if [ -z "$CORP_CONF" ] || [ ! -f "$CORP_CONF" ]; then
  echo "в $BASE/conf нет корп-конфига (corp.conf или wg0-<фамилия>.conf)"
  exit 1
fi
echo "корп-конфиг: $(basename "$CORP_CONF")"

# Отсечь домен корп-endpoint, если он попал в список
EP_HOST=$(grep -iE '^[[:space:]]*Endpoint[[:space:]]*=' "$CORP_CONF" | head -1 |
          cut -d= -f2 | tr -d ' \t' | rev | cut -d: -f2- | rev | tr 'A-Z' 'a-z')
FILTERED=""
for d in $DOMAINS; do
  case "$EP_HOST" in
    *"$d") echo "пропускаю $d — на нём живёт корп-endpoint ($EP_HOST)" ;;
    *)     FILTERED="$FILTERED $d" ;;
  esac
done
DOMAINS="$FILTERED"

if [ -z "$DOMAINS" ]; then
  echo "список доменов пуст — нечего делать"
  exit 1
fi

if [ "$MODE" = "remove" ]; then
  for d in $DOMAINS; do
    rm -f "/etc/resolver/$d" && echo "убран /etc/resolver/$d"
  done
  rmdir /etc/resolver 2>/dev/null
  killall -HUP mDNSResponder 2>/dev/null
  echo "готово"
  exit 0
fi

DNS_IP=$(grep -iE '^[[:space:]]*DNS[[:space:]]*=' "$CORP_CONF" | head -1 |
         cut -d= -f2 | tr -d ' \t' | cut -d, -f1)
if [ -z "$DNS_IP" ]; then
  echo "в $CORP_CONF нет строки DNS = ..."
  exit 1
fi

mkdir -p /etc/resolver
for d in $DOMAINS; do
  echo "nameserver $DNS_IP" > "/etc/resolver/$d"
  echo "$d -> $DNS_IP"
done
killall -HUP mDNSResponder 2>/dev/null
echo "готово. Проверить: dig +short git.$DOMAINS"
