#!/bin/bash
# Диагностика: запускает БОЕВОЙ `vpn start`, снимает метрики, гасит его.
# Никакой отдельной логики запуска — тестируется ровно то, что работает в бою.
#
#   sudo ./vpn diag

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="$BASE/lib/state/diag.log"
: > "$LOG"

say() { echo "$@" | tee -a "$LOG"; }

cleanup() {
  say ""
  say "=== ГЛУШУ, ВОЗВРАЩАЮ СЕТЬ ==="
  [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null
  sleep 5
  pkill -f "$BASE/lib/bin/sing-box" 2>/dev/null
  sleep 2
  say "--- маршруты после остановки ---"
  netstat -rn -f inet | grep -E '^(0/1|128\.0/1|default)' | tee -a "$LOG"
  say ""
  say "Отчёт: $LOG"
}
trap cleanup EXIT

if [ "$(id -u)" != "0" ]; then echo "нужен root: sudo $BASE/vpn diag"; exit 1; fi

say "=== ДО ЗАПУСКА ==="
say "--- аплинк ---"
route -n get default 2>/dev/null | grep -E 'interface:|gateway:' | tee -a "$LOG"
say "--- IPv6 у системы (если есть — будет течь мимо туннеля) ---"
ifconfig | grep 'inet6 2a03' | tee -a "$LOG" || say "нет глобального IPv6"

say ""
say "=== СТАРТ ЧЕРЕЗ vpn start (боевой путь) ==="
bash "$BASE/vpn" start >> "$LOG" 2>&1 &
PID=$!
sleep 40

say ""
say "=== СОСТОЯНИЕ ==="
TUN=$(grep -o 'tun: utun[0-9]*' "$LOG" | tail -1 | awk '{print $2}')
say "tun: ${TUN:-НЕ ПОДНЯЛСЯ}"
if grep -q 'received handshake response\|маршруты выставлены' "$LOG"; then
  say "старт: OK"
else
  say "старт: ПРОВАЛ — vpn.sh не дошёл до выставления маршрутов"
fi

say ""
say "--- маршруты ---"
netstat -rn -f inet | grep -E '^(0/1|128\.0/1|default)' | tee -a "$LOG"

say ""
say "=== ЛИЧНЫЙ ТУННЕЛЬ ==="
say "--- IPv4 (должен быть NL) ---"
curl -4 -s --max-time 20 https://ipinfo.io/country 2>&1 | tee -a "$LOG"
curl -4 -s --max-time 20 https://ipinfo.io/ip 2>&1 | tee -a "$LOG"; say ""
say "--- IPv6 (ЛЮБОЙ ответ здесь = утечка, туннель v6 не несёт) ---"
curl -6 -s --max-time 10 https://ifconfig.me 2>&1 | tee -a "$LOG" || say "нет ответа — утечки нет, это хорошо"
say ""

say "=== РЕАЛЬНЫЕ САЙТЫ (то, что ломалось в браузере) ==="
for U in https://chatgpt.com https://claude.com https://www.youtube.com; do
  say "--- $U ---"
  curl -s --max-time 20 -o /dev/null -w "HTTP %{http_code}  (v%{http_version}, ip %{remote_ip})\n" "$U" 2>&1 | tee -a "$LOG"
done

say ""
say "=== КОРПОРАТИВНЫЙ ТУННЕЛЬ ==="
say "--- DNS на корп-сервер ---"
dig +short +time=5 +tries=1 "@${CORP_DNS:-}" "${CORP_PROBE:-}" 2>&1 | tee -a "$LOG"
say "--- HTTPS (ждём 302) ---"
curl -s --max-time 20 -o /dev/null -w 'HTTP %{http_code}  (ip %{remote_ip})\n' "https://${CORP_PROBE:-}" 2>&1 | tee -a "$LOG"

say ""
say "=== ОШИБКИ ==="
grep -iE 'error|fatal|too long|did not complete|unreachable|refused' "$LOG" | grep -viE '^---|say ' | tail -15
