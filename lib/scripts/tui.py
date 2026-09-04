#!/usr/bin/env python3
"""
Консольная панель: статус обоих туннелей сверху, логи sing-box снизу.

Запускается через `sudo ./vpn ui`. Сам поднимает `vpn start` дочерним процессом
и читает его вывод, поэтому боевой путь запуска ровно один — никакой отдельной
логики старта здесь нет.

Только стандартная библиотека: curses есть в любом python3.
"""

import collections
import curses
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.environ.get("DUALVPN_DATA") or BASE
STATE = os.path.join(DATA, "lib", "state")
VPN = os.path.join(BASE, "vpn")
TUN_IP = "172.19.0.1"

def site_env():
    """Настройки рабочей сети из conf/site.env.

    Их читал только vpn на bash, а пробер — нет: имя для проверки оставалось
    пустым, dig уходил в никуда, и окно показывало «корп не отвечает» при
    полностью рабочем туннеле.
    """
    out = {}
    try:
        with open(os.path.join(DATA, "conf", "site.env"), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k.startswith("export "):
                    k = k[len("export "):].strip()
                out[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


# Переменная окружения важнее файла: так её можно переопределить на запуск.
SITE = site_env()
CORP_PROBE = os.environ.get("CORP_PROBE") or SITE.get("CORP_PROBE", "")

FAST_EVERY = 2.0    # локальные проверки: интерфейсы, маршруты, процесс
SLOW_EVERY = 20.0   # сетевые: внешний IP, корп-DNS, корп-HTTPS

LOG = collections.deque(maxlen=4000)
ST = {}             # состояние для панели, пишется пробером, читается отрисовкой
LOCK = threading.Lock()
STOP = threading.Event()


def sh(cmd, timeout=10):
    """Запускает команду, возвращает stdout или '' — исключения наружу не летят."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def set_st(**kw):
    with LOCK:
        ST.update(kw)


# ----------------------------------------------------------------- пробы

def probe_fast():
    iface = ""
    gw = ""
    out = sh(["route", "-n", "get", "default"], 4)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            iface = line.split(":", 1)[1].strip()
        elif line.startswith("gateway:"):
            gw = line.split(":", 1)[1].strip()

    tun = ""
    for i in sh(["ifconfig", "-l"], 4).split():
        if i.startswith("utun") and TUN_IP in sh(["ifconfig", i], 4):
            tun = i
            break

    routes = sh(["netstat", "-rn", "-f", "inet"], 6)
    set_st(
        iface=iface, gw=gw, tun=tun,
        r_low=bool(re.search(r"^0/1\s", routes, re.M)),
        r_high=bool(re.search(r"^128\.0/1\s", routes, re.M)),
        pid=sh(["pgrep", "-f", os.path.join(BASE, "lib", "bin", "sing-box")], 4).replace("\n", ","),
    )

    resolvers = []
    try:
        for f in sorted(os.listdir("/etc/resolver")):
            with open(os.path.join("/etc/resolver", f), encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("nameserver"):
                        resolvers.append(f"{f}→{line.split()[1]}")
                        break
    except OSError:
        pass
    # Файл появляется, когда `vpn start` выключил IPv6 на время сеанса
    set_st(resolvers=resolvers,
           v6_off=os.path.exists(os.path.join(STATE, "ipv6.saved")))


def peer_addrs():
    """Адреса пиров из собранного конфига: {tag: address}."""
    out = {}
    try:
        with open(os.path.join(STATE, "config.json"), encoding="utf-8") as fh:
            cfg = json.load(fh)
        for e in cfg.get("endpoints", []):
            peers = e.get("peers") or []
            if peers:
                out[e.get("tag", "")] = peers[0].get("address", "")
    except Exception:
        pass
    return out


def probe_slow():
    # Личный туннель: куда мы выходим наружу
    raw = sh(["curl", "-4", "-s", "--max-time", "12", "https://ipinfo.io/json"], 15)
    peers = peer_addrs()
    try:
        info = json.loads(raw)
        ip = info.get("ip", "")
        # Сервер обычно одноногий, поэтому выходной адрес совпадает с адресом
        # пира — это и есть подтверждение, что трафик идёт через личный туннель.
        # Совпадение с адресом пира — обычный случай для одноногого сервера,
        # но не единственный верный: сервер может выходить другим адресом.
        # Утечка — это когда нас видно тем же адресом, что и без туннеля.
        real = ""
        try:
            with open(os.path.join(STATE, "real-ip"), encoding="utf-8") as fh:
                real = fh.read().strip()
        except OSError:
            pass
        # Три исхода, а не два: «подтверждено», «утечка» и «не могу сказать».
        # Молча считать неизвестность утечкой — значит пугать зря.
        if not ip:
            state = "unknown"
        elif ip == peers.get("awg-personal"):
            state = "tunnel"              # одноногий сервер, адреса совпали
        elif real and ip == real:
            state = "leak"                # нас видно тем же адресом, что и без VPN
        elif real:
            state = "tunnel"              # адрес другой — значит не наш провайдер
        else:
            state = "unknown"             # реальный адрес не знаем, сравнивать не с чем
        set_st(exit_ip=ip, exit_country=info.get("country", ""),
               exit_city=info.get("city", ""), exit_org=info.get("org", "")[:26],
               exit_real=real, exit_state=state,
               exit_is_peer=(state == "tunnel"))
    except Exception:
        set_st(exit_ip="", exit_country="", exit_city="", exit_org="",
               exit_is_peer=False, exit_state="unknown")

    # IPv6: любой ответ здесь означает, что трафик идёт мимо туннеля
    v6 = sh(["curl", "-6", "-s", "--max-time", "6", "https://ifconfig.me"], 8)
    set_st(v6_leak=v6 if re.match(r"^[0-9a-fA-F:]+$", v6 or "") else "")

    # Корп-DNS берём из собранного конфига, а не хардкодим
    corp_dns = ""
    try:
        with open(os.path.join(STATE, "config.json"), encoding="utf-8") as fh:
            cfg = json.load(fh)
        for s in cfg.get("dns", {}).get("servers", []):
            if s.get("tag") == "dns-corp":
                corp_dns = s.get("server", "")
    except Exception:
        pass

    if corp_dns:
        got = sh(["dig", "+short", "+time=4", "+tries=1",
                  f"@{corp_dns}", CORP_PROBE], 8)
        ip = next((l for l in got.splitlines() if re.match(r"^[\d.]+$", l)), "")
        set_st(corp_dns=corp_dns, corp_ip=ip)
    else:
        set_st(corp_dns="", corp_ip="")

    code = sh(["curl", "-s", "--max-time", "12", "-o", "/dev/null",
               "-w", "%{http_code}", f"https://{CORP_PROBE}"], 15)
    set_st(corp_http=code if code and code != "000" else "")


def write_status():
    """Кладёт состояние в lib/state/status.json — его читают снаружи.

    Панель держит всё в памяти и умирает вместе с окном, так что узнать
    состояние туннеля, не открывая её, было нечем. Пишем через временный файл
    и os.replace: читатель либо видит прошлую версию целиком, либо новую, но
    никогда не половину.
    """
    path = os.path.join(STATE, "status.json")
    tmp = path + ".tmp"
    with LOCK:
        data = dict(ST)
    data["updated"] = time.time()
    data["up"] = bool(data.get("tun")) and bool(data.get("r_low"))
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1, default=str)
        os.replace(tmp, path)
    except OSError:
        pass


def prober():
    last_slow = 0.0
    was_up = False
    while not STOP.is_set():
        probe_fast()
        with LOCK:
            up = bool(ST.get("tun")) and bool(ST.get("r_low"))

        # До того как поднялся tun и встали маршруты, мерить выход наружу
        # бессмысленно: получим свой реальный адрес и покажем его ещё 20 секунд,
        # как будто туннель не работает. Ждём готовности и меряем сразу после.
        if up and not was_up:
            last_slow = 0.0
        was_up = up

        if up and time.time() - last_slow > SLOW_EVERY:
            last_slow = time.time()
            # Отдельным потоком: probe_slow ходит в сеть с таймаутами до 12с,
            # и в цикле он останавливал обновление статуса на полминуты. Снаружи
            # это выглядело как «туннель отвалился и вернулся» — кнопка в окне
            # прыгала между «Включить» и «Выключить».
            threading.Thread(target=probe_slow, daemon=True).start()
        elif not up:
            set_st(exit_ip="", corp_ip="", corp_http="", v6_leak="",
                   exit_is_peer=False)
        write_status()
        STOP.wait(FAST_EVERY)


# ----------------------------------------------------------------- логи

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def adopt_legacy(d):
    """Забирает логи старой схемы (ui.log + ui.log.1) в logs/ по их mtime.

    Иначе первый же запуск после перехода снёс бы ровно те два запуска, ради
    которых история и заводилась.
    """
    for name in ("ui.log", "ui.log.1"):
        src = os.path.join(STATE, name)
        if not os.path.isfile(src) or os.path.islink(src):
            continue
        try:
            stamp = time.strftime("ui-%Y-%m-%d_%H%M%S.log",
                                  time.localtime(os.path.getmtime(src)))
            os.replace(src, os.path.join(d, stamp))
        except OSError:
            pass


KEEP_LOGS = 10      # сколько прошлых запусков держим в lib/state/logs


def open_log():
    """Открывает лог текущего запуска и подчищает старые.

    Раньше лог был один и затирался при каждом старте, так что разбирать
    «вчера не работало» было уже не по чему. Теперь файл на запуск, с датой
    в имени; ui.log — симлинк на свежий, чтобы `tail -f` по привычному пути
    и строки в README продолжали работать.
    """
    d = os.path.join(STATE, "logs")
    os.makedirs(d, exist_ok=True)
    adopt_legacy(d)
    path = os.path.join(d, time.strftime("ui-%Y-%m-%d_%H%M%S.log"))
    f = open(path, "w", encoding="utf-8")

    link = os.path.join(STATE, "ui.log")
    try:
        if os.path.islink(link) or os.path.exists(link):
            os.unlink(link)
        os.symlink(os.path.relpath(path, STATE), link)
    except OSError:
        pass

    try:
        old = sorted(x for x in os.listdir(d)
                     if x.startswith("ui-") and x.endswith(".log"))
        for name in old[:-KEEP_LOGS]:
            os.unlink(os.path.join(d, name))
    except OSError:
        pass
    return f


def reader(proc, logfile=None):
    errors = 0
    for line in proc.stdout:
        # sing-box раскрашивает вывод; без этого в панели остаётся «[36mINFO[0m»
        line = ANSI.sub("", line.rstrip("\n"))
        LOG.append(line)
        if " ERROR " in line or line.startswith("ERROR"):
            errors += 1
            # Отрезаем префикс до ERROR и идентификатор соединения — остаётся
            # сама причина. Резать по последней "]" нельзя: скобки есть и
            # внутри текста, вроде outbound/wireguard[awg-personal].
            msg = line.split(" ERROR ", 1)[-1].strip()
            msg = re.sub(r"^\[[^\]]*\]\s*", "", msg)
            set_st(err_count=errors, err_last=(msg or line)[:110])
        # Дублируем на диск: панель закрывается вместе с причиной падения,
        # а разбираться потом приходится именно по ней.
        if logfile:
            try:
                logfile.write(line + "\n")
                logfile.flush()
            except Exception:
                pass
        # Рукопожатия видны только в логе, отдельной пробой их не достать
        if "handshake" in line.lower():
            if "awg-personal" in line:
                set_st(hs_personal=time.strftime("%H:%M:%S"))
            elif "wg-corp" in line:
                set_st(hs_corp=time.strftime("%H:%M:%S"))
    code = proc.wait()
    msg = f"— процесс завершился, код {code} —"
    LOG.append(msg)
    set_st(exited=code)
    if logfile:
        try:
            logfile.write(msg + "\n")
            logfile.flush()
        except Exception:
            pass


# ----------------------------------------------------------------- отрисовка

OK, BAD, WARN, DIM, HEAD = 1, 2, 3, 4, 5


CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def put(win, y, x, text, attr=0):
    """Пишет строку в пределах окна.

    curses считает ширину в ячейках, а не в символах: строка из «широких»
    (CJK, эмодзи) или управляющих байтов вылезает за край и addnstr отдаёт ERR,
    роняя весь интерфейс. Поэтому чистим текст, режем с запасом и всё равно
    страхуемся try — отрисовка не должна убивать процесс с туннелем.
    """
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w - 1:
        return
    text = CTRL.sub("", text.replace("\t", "    "))
    try:
        win.addnstr(y, x, text, w - x - 2, attr)
    except curses.error:
        pass


def flag(val, good_text=None, bad_text="—"):
    return (good_text or str(val)) if val else bad_text


def draw_status(win, started):
    """Шесть строк: вердикт, затем техника для разбора.

    Строка 0 — и есть статус: сразу видно, работает туннель или нет.
    Часы и pid ушли вниз, к остальным техническим полям.
    """
    win.erase()
    with LOCK:
        s = dict(ST)

    # Вторая и третья колонки прячутся на узком терминале, чтобы не обрезаться
    _, w = win.getmaxyx()
    c2 = 46 if w >= 62 else None
    c3 = 76 if w >= 88 else None

    R_PERSONAL, R_CORP, R_NET, R_MISC, R_ERR = range(5)

    pid = s.get("pid") or ""
    exited = s.get("exited")
    ready = bool(s.get("tun")) and bool(s.get("r_low"))
    ip, country = s.get("exit_ip", ""), s.get("exit_country", "")

    # Подсказка по клавишам — в первой строке, отдельная шапка не нужна:
    # состояние туннелей и так видно построчно ниже.
    if c2:
        off = s.get("scroll", 0)
        hint = (f"⏸ прокрутка −{off}  [G] к концу"
                if off else "[q] выход  [↑↓/колесо] лог")
        put(win, R_ERR, c2, hint,
            curses.color_pair(WARN if off else DIM) |
            (curses.A_BOLD if off else 0))

    # --- личный
    put(win, R_PERSONAL, 1, "личный", curses.A_BOLD)
    if ip:
        mark = "✓" if s.get("exit_is_peer") else "!"
        put(win, R_PERSONAL, 10, f"{mark} {country} {s.get('exit_city','')}  {ip}",
            curses.color_pair(OK if s.get("exit_is_peer") else BAD))
        if c2:
            put(win, R_PERSONAL, c2, s.get("exit_org", ""), curses.color_pair(DIM))
    else:
        put(win, R_PERSONAL, 10, "выход наружу не проверен", curses.color_pair(DIM))
    hs = s.get("hs_personal")
    if c3 and hs:
        put(win, R_PERSONAL, c3, f"hs {hs}", curses.color_pair(DIM))

    # --- корп
    corp_ip, corp_http = s.get("corp_ip", ""), s.get("corp_http", "")
    put(win, R_CORP, 1, "корп", curses.A_BOLD)
    if corp_ip:
        put(win, R_CORP, 10, f"{CORP_PROBE} → {corp_ip}", curses.color_pair(OK))
    else:
        put(win, R_CORP, 10, f"{CORP_PROBE} не резолвится", curses.color_pair(BAD))
    if c2:
        if corp_http:
            good = corp_http.startswith(("2", "3"))
            put(win, R_CORP, c2, f"HTTP {corp_http}",
                curses.color_pair(OK if good else WARN))
        else:
            put(win, R_CORP, c2, "HTTP нет ответа", curses.color_pair(BAD))
    hs = s.get("hs_corp")
    if c3 and hs:
        put(win, R_CORP, c3, f"hs {hs}", curses.color_pair(DIM))

    # --- сеть
    tun = s.get("tun", "")
    r_low, r_high = s.get("r_low"), s.get("r_high")
    up = int(time.time() - started)
    put(win, R_NET, 1, "сеть", curses.A_BOLD)
    put(win, R_NET, 10, f"tun {flag(tun)}", curses.color_pair(OK if tun else BAD))
    put(win, R_NET, 24, f"0/1 {'✓' if r_low else '✗'}",
        curses.color_pair(OK if r_low else BAD))
    put(win, R_NET, 33, f"128/1 {'✓' if r_high else '✗'}",
        curses.color_pair(OK if r_high else BAD))
    if c2:
        put(win, R_NET, c2, f"аплинк {s.get('iface','?')} → {s.get('gw','?')}",
            curses.color_pair(DIM))
    if c3:
        put(win, R_NET, c3,
            f"{up // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d} "
            + (f"pid {pid}" if pid
               else (f"УПАЛ, код {exited}" if exited is not None else "старт…")),
            curses.color_pair(DIM))

    # --- утечки и резолвер
    put(win, R_MISC, 1, "прочее", curses.A_BOLD)
    leak = s.get("v6_leak", "")
    if leak:
        v6_txt, v6_col = f"IPv6 идёт МИМО туннеля: {leak[:22]}", BAD
    elif s.get("v6_off"):
        v6_txt, v6_col = "IPv6 выключен на время сеанса", OK
    else:
        v6_txt, v6_col = "IPv6 не течёт", OK
    put(win, R_MISC, 10, v6_txt, curses.color_pair(v6_col))
    res = s.get("resolvers") or []
    if c2:
        put(win, R_MISC, c2,
            " ".join(res) if res else "resolver пуст — корп отдаст 403",
            curses.color_pair(DIM if res else BAD))

    # --- ошибки: без них бывает «сверху всё зелёное, а связи нет»
    n = s.get("err_count", 0)
    put(win, R_ERR, 1, "ошибки", curses.A_BOLD)
    if n:
        put(win, R_ERR, 10, f"{n}  {s.get('err_last','')}", curses.color_pair(BAD))
    else:
        put(win, R_ERR, 10, "нет", curses.color_pair(OK))

    win.noutrefresh()


def max_offset(win):
    """Насколько далеко можно уйти вверх, чтобы окно осталось полным.

    Раньше потолком было len(LOG)-1: окно уезжало за начало буфера, строк
    оставалось меньше высоты и низ панели пустел.
    """
    h, _ = win.getmaxyx()
    return max(0, len(LOG) - h)


def draw_log(win, offset):
    win.erase()
    h, _ = win.getmaxyx()
    lines = list(LOG)
    end = len(lines) - offset
    view = lines[max(0, end - h):end]
    for i, line in enumerate(view):
        attr = 0
        low = line.lower()
        if any(k in low for k in ("error", "fatal", "failed")):
            attr = curses.color_pair(BAD)
        elif "handshake" in low or "started" in low:
            attr = curses.color_pair(OK)
        elif line.startswith("→"):
            attr = curses.color_pair(WARN) | curses.A_BOLD
        put(win, i, 0, line, attr)
    win.noutrefresh()


def main(stdscr):
    curses.curs_set(0)
    curses.use_default_colors()
    for pair, fg in ((OK, curses.COLOR_GREEN), (BAD, curses.COLOR_RED),
                     (WARN, curses.COLOR_YELLOW), (DIM, curses.COLOR_CYAN),
                     (HEAD, curses.COLOR_BLACK)):
        curses.init_pair(pair, fg, -1)
    curses.init_pair(HEAD, curses.COLOR_BLACK, curses.COLOR_GREEN)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    try:
        # Прокрутка жестом/колесом. Побочный эффект: выделение текста мышью
        # в терминале потребует зажать Option (macOS).
        curses.mousemask(curses.BUTTON4_PRESSED |
                         getattr(curses, "BUTTON5_PRESSED", 1 << 21))
        curses.mouseinterval(0)
    except curses.error:
        pass

    proc = subprocess.Popen(
        ["bash", VPN, "start"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
        start_new_session=True,   # чтобы Ctrl+C терминала не убил его в обход нас
    )
    started = time.time()

    try:
        logfile = open_log()
        logfile.write(f"=== {time.strftime('%Y-%m-%d %H:%M:%S')} vpn ui ===\n")
    except OSError:
        logfile = None

    threading.Thread(target=reader, args=(proc, logfile), daemon=True).start()
    threading.Thread(target=prober, daemon=True).start()

    offset = 0          # прокрутка логов: 0 = хвост
    status_h = 5
    sw = lw = None
    last_size = None
    try:
        while True:
            h, w = stdscr.getmaxyx()

            # Окна пересоздаём только при изменении размера: derwin на каждом
            # кадре плодит объекты и мусорит.
            if (h, w) != last_size:
                last_size = (h, w)
                stdscr.clear()
                sw = lw = None
                if h > status_h + 1 and w > 20:
                    sw = stdscr.derwin(status_h, w, 0, 0)
                    lw = stdscr.derwin(h - status_h - 1, w, status_h + 1, 0)

            if sw is None:
                put(stdscr, 0, 0, "терминал слишком мал")
                stdscr.noutrefresh()
            else:
                try:
                    stdscr.hline(status_h, 0, curses.ACS_HLINE, max(0, w - 1))
                except curses.error:
                    pass
                stdscr.noutrefresh()
                # Отрисовка ни при каких данных не должна ронять процесс:
                # внутри работает туннель, и упасть здесь — значит оборвать сеть.
                try:
                    set_st(scroll=offset)
                    draw_status(sw, started)
                    draw_log(lw, offset)
                except curses.error:
                    pass
            try:
                curses.doupdate()
            except curses.error:
                pass

            # Вычитываем ВСЕ накопившиеся события за кадр. По одному за кадр
            # при паузе 0.2с зажатая стрелка давала 5 строк в секунду —
            # это и выглядело как «виснет».
            page = max(1, h - status_h - 2)
            cap = max_offset(lw) if lw is not None else 0
            quit_now = False
            acted = False
            while True:
                ch = stdscr.getch()
                if ch == -1:
                    break
                acted = True
                if ch in (ord("q"), ord("Q")):
                    quit_now = True
                    break
                elif ch in (curses.KEY_UP, ord("k")):
                    offset = min(offset + 1, cap)
                elif ch in (curses.KEY_DOWN, ord("j")):
                    offset = max(0, offset - 1)
                elif ch == curses.KEY_PPAGE:
                    offset = min(offset + page, cap)
                elif ch == curses.KEY_NPAGE:
                    offset = max(0, offset - page)
                elif ch in (curses.KEY_HOME, ord("g")):
                    offset = cap
                elif ch in (curses.KEY_END, ord("G"), 27):   # 27 = Esc
                    offset = 0
                elif ch == curses.KEY_MOUSE:
                    # Колесо и жест двумя пальцами приходят сюда
                    try:
                        _, _, _, _, bs = curses.getmouse()
                    except curses.error:
                        continue
                    if bs & curses.BUTTON4_PRESSED:          # вверх
                        offset = min(offset + 3, cap)
                    elif bs & getattr(curses, "BUTTON5_PRESSED", 1 << 21):
                        offset = max(0, offset - 3)
                elif ch == curses.KEY_RESIZE:
                    stdscr.clear()
                    last_size = None

            if quit_now:
                break
            if proc.poll() is not None and not LOG:
                break
            # После нажатия перерисовываемся сразу, иначе прокрутка «залипает»
            if not acted:
                time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        STOP.set()
        # Иначе после нажатия q экран просто замирает на несколько секунд,
        # пока откатываются маршруты, и кажется, что клавиша не сработала.
        try:
            stdscr.erase()
            put(stdscr, 0, 0, "останавливаю туннели и откатываю маршруты…")
            stdscr.refresh()
        except curses.error:
            pass
        # SIGINT, а не kill: у `vpn start` на нём висит откат маршрутов
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
        # Иначе снаружи останется файл, описывающий поднятый туннель, которого нет.
        try:
            os.unlink(os.path.join(STATE, "status.json"))
        except OSError:
            pass


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit(f"нужен root: sudo {BASE}/vpn ui")
    curses.wrapper(main)
    print("остановлено, маршруты откачены")
