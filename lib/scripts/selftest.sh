#!/bin/bash
# Проверки, которые можно прогнать без установки и без root.
#
#   bash lib/scripts/selftest.sh
#
# Появились после того, как в /Applications уехало приложение, падавшее на
# первой же русской строке: сборка «прошла», а работать не могло.

BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VENV="$BASE/lib/venv"
PY="$VENV/bin/python"
[ -x "$PY" ] || PY=python3
FAIL=0

ok()   { printf "  ok   %s\n" "$1"; }
bad()  { printf "  БЕДА %s\n" "$1"; FAIL=1; }
head() { printf "\n%s\n" "$1"; }

# ---------------------------------------------------------------- синтаксис

head "синтаксис"
for f in "$BASE/vpn" "$BASE/install.sh" "$BASE/lib/scripts/install-daemon.sh" \
         "$BASE/lib/scripts/selftest.sh"; do
  bash -n "$f" 2>/dev/null && ok "$(basename "$f")" || bad "$(basename "$f")"
done
for f in "$BASE"/lib/scripts/*.py; do
  "$PY" -c "import ast,io,sys; ast.parse(io.open(sys.argv[1],encoding='utf-8').read())" "$f" \
    && ok "$(basename "$f")" || bad "$(basename "$f")"
done

# ---------------------------------------------------------------- кодировки

head "кодировки (в .app локаль ASCII — без encoding падает на русском)"
# И чтение тоже: build-config.py читал .conf без encoding, и кириллица
# в комментарии уронила бы сборку под ASCII-локалью.
BADENC=$(grep -nE '\bopen\(' "$BASE"/lib/scripts/*.py \
         | grep -v 'encoding=' | grep -v '"rb"' | grep -v 'def open_log')
if [ -n "$BADENC" ]; then
  echo "$BADENC"
  bad "есть работа с текстовым файлом без encoding"
else
  ok "везде явный encoding"
fi

# ---------------------------------------------------------------- методы окна

head "методы окна (данные для интерфейса)"
# Дважды правка срезом «от якоря до якоря» вырезала попутные определения, и
# приложение падало уже в работе — тесты этого не видели, потому что окно
# открывалось, а падало только при обращении к данным.
"$PY" - "$BASE" <<'PYEOF' && ok "методы окна на месте, данные считаются" || bad "исключение в методах окна"
import json, sys, os
base = sys.argv[1]
sys.path.insert(0, os.path.join(base, "lib", "scripts"))
try:
    import window
except Exception as e:                      # AppKit есть не везде
    print("  (пропуск: не импортируется —", e, ")")
    sys.exit(0)
w = window.Window.__new__(window.Window)
w.base = w.data = base          # код и данные: в проекте это одно место
w.state = os.path.join(base, "lib", "state")
w.log = lambda *a: None
c = w.configs()
assert set(c) >= {"corp", "personal", "corp_ambiguous", "personal_ambiguous"}, c
assert isinstance(w.status().get("up"), bool)
assert isinstance(w.howto().get("corp_nets"), list)
assert isinstance(w.tail(), list)
assert isinstance(w.err_count(), int)
# site.env читал только vpn на bash: у пробера имя для проверки оставалось
# пустым, и окно показывало «корп не отвечает» при рабочем туннеле.
import importlib
sys.path.insert(0, os.path.join(base, "lib", "scripts"))
os.environ["DUALVPN_DATA"] = base
import tui
importlib.reload(tui)
site = os.path.join(base, "conf", "site.env")
if os.path.exists(site) and "CORP_PROBE" in open(site, encoding="utf-8").read():
    assert tui.CORP_PROBE, "site.env есть, а пробер имя для проверки не увидел"

v = w.version()
assert v["app"] and v["app"] != "?", v      # VERSION должен читаться
# Правки срезом «от якоря до якоря» трижды вырезали попутные определения,
# и каждый раз это всплывало только в работе. Проверяем структурно: всё, что
# код зовёт как self.X(), должно существовать у класса.
import ast, re
src = open(os.path.join(base, "lib", "scripts", "window.py"), encoding="utf-8").read()
tree = ast.parse(src)
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Window")
have = {m.name for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
have |= {t.id for m in cls.body if isinstance(m, ast.Assign)
         for t in m.targets if isinstance(t, ast.Name)}
have |= set(vars(window.Window)) | {"base", "data", "state", "log", "launchctl",
                                    "win", "view", "timer", "bridge"}
called = {n.attr for n in ast.walk(cls)
          if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
          and n.value.id == "self"}
missing = sorted(called - have)
assert not missing, "нет таких членов класса: " + ", ".join(missing)

for bad_name in ("../x", "a/b", "..", ""):
    assert not window.Window._safe(bad_name), bad_name
assert window.Window._safe("personal")
PYEOF

# ---------------------------------------------------------------- plist

head "plist демона"
plutil -lint "$BASE/lib/launchd/local.singbox-lx.plist" >/dev/null 2>&1 \
  && ok "валидный" || bad "не проходит plutil"
grep -q '@@BASE@@' "$BASE/lib/launchd/local.singbox-lx.plist" \
  && ok "шаблон пути на месте" || bad "нет @@BASE@@ — путь захардкожен"
TMP=$(mktemp)
sed "s|@@BASE@@|$BASE|g" "$BASE/lib/launchd/local.singbox-lx.plist" > "$TMP"
plutil -lint "$TMP" >/dev/null 2>&1 && ok "валиден после подстановки" || bad "ломается после подстановки"
"$PY" - "$TMP" <<'PYEOF' && ok "RunAtLoad выключен (нет автозапуска)" || bad "RunAtLoad не false"
import plistlib, sys
d = plistlib.load(open(sys.argv[1], "rb"))
sys.exit(0 if d.get("RunAtLoad") is False else 1)
PYEOF
rm -f "$TMP"

# ---------------------------------------------------------------- ротация

head "ротация логов"
"$PY" - "$BASE" <<'PYEOF' && ok "python: держит 10 файлов" || bad "python: ротация не держит 10"
import importlib.util, os, sys, tempfile
base = sys.argv[1]
spec = importlib.util.spec_from_file_location("t", os.path.join(base, "lib/scripts/tui.py"))
m = importlib.util.module_from_spec(spec); sys.modules["t"] = m; spec.loader.exec_module(m)
m.STATE = tempfile.mkdtemp()
d = os.path.join(m.STATE, "logs")
for i in range(13):
    m.open_log().close()
    os.rename(os.path.join(d, sorted(os.listdir(d))[-1]), os.path.join(d, "ui-2026-01-01_%06d.log" % i))
    os.path.islink(os.path.join(m.STATE, "ui.log")) and os.unlink(os.path.join(m.STATE, "ui.log"))
sys.exit(0 if len(os.listdir(d)) == 10 else 1)
PYEOF

D=$(mktemp -d); for i in $(seq -w 1 13); do : > "$D/ui-2026-01-01_0000$i.log"; done
N=$(ls -1 "$D"/ui-*.log | awk -v k=10 '{a[NR]=$0} END {for (i=1;i<=NR-k;i++) print a[i]}' | wc -l | tr -d ' ')
[ "$N" = 3 ] && ok "bash: отбирает лишние 3 из 13" || bad "bash: отобрал $N вместо 3"
rm -rf "$D"

# ---------------------------------------------------------------- .app

head "собранное приложение"
APP="$BASE/lib/scripts/dist/DualVPN.app"
if [ ! -d "$APP" ]; then
  echo "  (пропуск: не собрано, сборка идёт в install.sh)"
else
  codesign -v "$APP" 2>/dev/null && ok "подпись цела" || bad "подпись битая — Finder откажется открывать"
  [ -f "$APP/Contents/Resources/ui/index.html" ] \
    && ok "страница окна в бандле" || bad "ui/index.html не попал в бандл"

  LOG="$HOME/Library/Logs/singbox-lx-menubar.log"
  rm -f "$LOG"; ERR=$(mktemp)
  # Окно открываем сами: иначе проверялся бы только значок в меню-баре.
  VPNLX_TEST_WINDOW=1 "$APP/Contents/MacOS/DualVPN" >/dev/null 2>"$ERR" &
  P=$!
  "$PY" -c "import time; time.sleep(10)"
  if kill -0 $P 2>/dev/null; then ok "живо через 10с"; else bad "упало на старте"; fi
  kill $P 2>/dev/null; wait $P 2>/dev/null
  [ -s "$ERR" ] && { bad "пишет в stderr:"; tail -5 "$ERR"; } || ok "stderr чистый"
  # Собранное приложение самодостаточно: код внутри бандла, данные снаружи.
  # Раньше путь брался из установленной службы, и тест ловил чужую копию.
  FOUND=$(sed -n 's/.*проект: //p' "$LOG" 2>/dev/null | tail -1)
  DATA=$(sed -n 's/.*данные: //p' "$LOG" 2>/dev/null | tail -1)
  case "$FOUND" in
    *"/DualVPN.app/Contents/Resources") ok "код найден в бандле" ;;
    "")  bad "путь к коду не определился" ;;
    *)   bad "код ищется вне бандла: $FOUND" ;;
  esac
  # Данные должны совпасть с тем, что прибито в службе: пока окно решало это
  # само, оно показывало пустой лог и «рабочий молчит» при живом туннеле.
  WANT=$(/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:DUALVPN_DATA" \
    /Library/LaunchDaemons/local.singbox-lx.plist 2>/dev/null || true)
  case "$DATA" in
    "") bad "путь к данным не определился" ;;
    *"/DualVPN.app/Contents/"*) bad "данные внутри программы: обновление их сотрёт" ;;
    *) if [ -n "$WANT" ] && [ "$DATA" != "$WANT" ]; then
         bad "окно и служба смотрят в разные каталоги: $DATA против $WANT"
       elif [ -n "$WANT" ]; then
         ok "данные там же, где у службы: $DATA"
       else
         ok "данные вне бандла: $DATA"
       fi ;;
  esac
  # Всё, чем программа поднимает туннель, должно лежать внутри и запускаться.
  for F in vpn sing-box install-daemon.sh build-config.py; do
    [ -x "$APP/Contents/Resources/$F" ] || [ -f "$APP/Contents/Resources/$F" ] \
      && ok "в бандле: $F" || bad "в бандле нет $F"
  done

  grep -q "значок не найден" "$LOG" 2>/dev/null \
    && bad "значок меню-бара не найден" || ok "значок меню-бара на месте"
  for I in ok bad default; do
    [ -f "$APP/Contents/Resources/ui/icons/menubar-$I.png" ] \
      || bad "нет картинки состояния: $I"
  done
  [ -f "$APP/Contents/Resources/DualVPN.icns" ] \
    && ok "значок приложения в бандле" || bad "нет значка приложения"

  grep -q "окно: создано" "$LOG" 2>/dev/null \
    && ok "окно открывается" || bad "окно не открылось"
  # Сообщение приходит из JS через мост, то есть проверена вся цепочка сразу.
  grep -q "окно: страница загрузилась" "$LOG" 2>/dev/null \
    && ok "страница загрузилась и мост работает" || bad "страница не отозвалась"
  # Настоящий текст исключения из JS: WKWebView обезличивает его в
  # «Script error», поэтому страница ловит и присылает сама.
  if grep -q "ОШИБКА JS" "$LOG" 2>/dev/null; then
    grep "ОШИБКА JS" "$LOG" | head -3
    bad "исключения в JS"
  else
    ok "исключений в JS нет"
  fi
  # Каждая ветка отрисовки отчитывается сама; молчание = исключение внутри неё.
  grep -q "окно: версия" "$LOG" 2>/dev/null \
    && ok "версия показана" || bad "версия не доехала до окна"
  for W in status confs howto logs; do
    grep -q "окно: отрисовано $W" "$LOG" 2>/dev/null \
      && ok "отрисовка: $W" || bad "отрисовка $W не отработала (исключение в JS?)"
  done
  rm -f "$ERR"
fi

head "итог"
[ $FAIL = 0 ] && echo "  всё зелёное" || echo "  есть провалы, смотри выше"
exit $FAIL
