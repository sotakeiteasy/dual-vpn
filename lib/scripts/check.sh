#!/bin/bash
# Снимает срез состояния сети. НИЧЕГО НЕ МЕНЯЕТ и ничего не запускает.
#
#   sudo ./vpn check [метка]
#
# Смысл в том, чтобы один и тот же измеритель прогнать в разных условиях
# и сравнить отчёты построчно:
#
#   под нашим стеком      sudo ./vpn check singbox
#   под WireGuard.app     sudo ./vpn check wgapp
#   вообще без туннелей   sudo ./vpn check none
#
# Сравнивать можно только замеры из ОДНОГО места: в офисе корп-ресурсы
# доступны напрямую, и там отчёт ничего не докажет.

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LABEL="${1:-check}"
OUT="$BASE/lib/state/check-$LABEL.txt"

# Что проверяем. Первый столбец — имя, дальше можно не трогать.
HOSTS="${CORP_HOSTS:-}"

exec > >(tee "$OUT") 2>&1

echo "=== СРЕЗ [$LABEL] $(date '+%Y-%m-%d %H:%M:%S') ==="
echo

echo "--- где мы находимся ---"
route -n get default 2>/dev/null | awk '/interface:|gateway:/ {print "  " $0}'
echo "  внешний IPv4: $(curl -4 -s -m 10 https://ipinfo.io/json 2>/dev/null |
      python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print(d.get("ip",""), d.get("country",""), d.get("org","")[:30])
except Exception: print("нет ответа")' 2>/dev/null)"
V6=$(ifconfig 2>/dev/null | awk '/inet6 /&&$2!~/^fe80|^fd|^fc/{print $2; exit}')
echo "  глобальный IPv6 на интерфейсах: ${V6:-нет}"

echo
echo "--- туннельные интерфейсы ---"
for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
  A=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2; exit}')
  [ -n "$A" ] && echo "  $i  $A"
done

echo
echo "--- маршруты по умолчанию ---"
netstat -rn -f inet 2>/dev/null | grep -E '^(0/1|128\.0/1|default)' | sed 's/^/  /'

echo
echo "--- DNS системы ---"
scutil --dns 2>/dev/null | grep 'nameserver\[0\]' | sort -u | sed 's/^/  /'
echo "--- /etc/resolver ---"
if ls /etc/resolver/* >/dev/null 2>&1; then
  for f in /etc/resolver/*; do
    echo "  $(basename "$f") -> $(awk '/nameserver/{print $2; exit}' "$f")"
  done
else
  echo "  пусто"
fi

# Корп-DNS берём из СОБРАННОГО конфига (тег dns-corp). Читать conf/*.conf
# нельзя: там первым попадётся личный, и «корп-колонка» покажет публичный DNS.
CORP_DNS=$(python3 -c '
import json, sys
try:
    c = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
for s in c.get("dns", {}).get("servers", []):
    if s.get("tag") == "dns-corp":
        print(s.get("server", ""))
' "$BASE/lib/state/config.json" 2>/dev/null)

# Если конфиг ещё не собран (например, меряем под WireGuard.app) — из корп-.conf
if [ -z "$CORP_DNS" ]; then
  CORP_CONF=""
  for RE in '^corp\.conf$' '^wg[-_0-9].*\.conf$' '^wg\.conf$'; do
    NAME=$(ls -1 "$BASE/conf" 2>/dev/null | grep -iE "$RE" | head -1)
    [ -n "$NAME" ] && { CORP_CONF="$BASE/conf/$NAME"; break; }
  done
  [ -n "$CORP_CONF" ] && CORP_DNS=$(grep -iE '^[[:space:]]*DNS[[:space:]]*=' "$CORP_CONF" |
    head -1 | cut -d= -f2 | tr -d ' \t' | cut -d, -f1)
fi

echo
echo "--- имена: системный резолвер / корп-DNS ${CORP_DNS:-(не задан)} ---"
# Резолвим ОДИН раз и переиспользуем: повторный опрос давал разные ответы
# и создавал ложную картину «то работает, то нет».
RESOLVED=""
for H in $HOSTS; do
  SYS=$(dig +short +time=4 +tries=3 "$H" 2>/dev/null | grep -E '^[0-9.]+$' | tr '\n' ' ')
  if [ -n "$CORP_DNS" ]; then
    CORP=$(dig +short +time=4 +tries=3 "@$CORP_DNS" "$H" 2>/dev/null | grep -E '^[0-9.]+$' | tr '\n' ' ')
  else
    CORP="-"
  fi
  printf '  %-26s sys[%s] corp[%s]\n' "$H" "${SYS:-—}" "${CORP:-—}"
  RESOLVED="$RESOLVED$H|${SYS:-$CORP}
"
done

echo
echo "--- стабильность корп-DNS: 5 запросов подряд ---"
if [ -n "$CORP_DNS" ]; then
  OK=0
  for i in 1 2 3 4 5; do
    A=$(dig +short +time=3 +tries=1 "@$CORP_DNS" "${CORP_PROBE:-}" 2>/dev/null | grep -cE '^[0-9.]+$')
    [ "${A:-0}" -gt 0 ] && OK=$((OK + 1))
    printf '%s' "$([ "${A:-0}" -gt 0 ] && echo ' ok' || echo ' —')"
  done
  echo "   -> ответов: $OK из 5"
else
  echo "  корп-DNS не определён"
fi

echo
echo "--- каждый адрес: куда идёт и что отвечает по HTTPS ---"
echo "$RESOLVED" | while IFS='|' read -r H IPS; do
  [ -z "$H" ] && continue
  if [ -z "$IPS" ] || [ "$IPS" = "—" ]; then
    printf '  %-26s не резолвится\n' "$H"
    continue
  fi
  for IP in $IPS; do
    VIA=$(route -n get "$IP" 2>/dev/null | awk '/interface:/{print $2; exit}')
    # nc -z здесь бесполезен: под gVisor локальный стек принимает TCP на любой
    # адрес, не дожидаясь удалённой стороны, и «порт открыт» ничего не значит.
    # Меряем то, что видит браузер: полный запрос с TLS.
    # Один запрос, не два: раньше на каждый адрес уходило по 2×15с,
    # и на неотвечающем узле это выглядело как зависший скрипт.
    R=$(curl -s -o /dev/null -m 8 -w '%{http_code} %{time_connect}/%{time_appconnect}' \
           --resolve "$H:443:$IP" "https://$H/" 2>/dev/null)
    CODE=${R%% *}
    printf '  %-26s %-16s via %-7s HTTP %-4s tcp/tls %s\n' \
           "$H" "$IP" "${VIA:-?}" "${CODE:-000}" "${R#* }"
    [ "${CODE:-000}" = "000" ] && echo "      ^ нет ответа за 8с"
  done
done

echo
echo "Отчёт: $OUT"
