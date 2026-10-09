"""Командная строка DualVPN — то же, что делает трей, но из консоли.

    dualvpn status              что сейчас поднято
    dualvpn start [ПРОФИЛЬ]     поднять
    dualvpn stop                опустить и откатить маршруты
    dualvpn list                туннели и их конфиги (* — активный)
    dualvpn use ТУННЕЛЬ КОНФИГ  выбрать конфиг туннеля (туннель — id или имя)
    dualvpn profile ИМЯ         выбрать конфиг основного туннеля
    dualvpn log [N]             последние строки журнала sing-box
    dualvpn version

    dualvpn tray [--background] значок в трее и окно (обычный способ запуска);
                                --background — только значок, без окна
    dualvpn window              окно с состоянием, конфигами и логом
                                (--resident --hidden — так его зовёт трей)
    dualvpn admin-op ОП ЗАПРОС ОТВЕТ
                                служебное: окно зовёт так себя же с правами
                                администратора на одну команду в conf\\ —
                                руками вводить незачем

Управление службой (нужны права администратора):

    dualvpn service install     поставить и запустить службу
    dualvpn service remove      снять службу
    dualvpn service start|stop|restart
    dualvpn service console     запустить логику службы прямо здесь, без установки

Команды туннеля идут в службу через канал — сами они систему не трогают.
"""

import os
import sys

from . import ipc, paths

# Весь вывод здесь русский, а консоль на английской Windows — cp1252, где
# кириллицы нет вовсе. Без этого `dualvpn status` падал бы с UnicodeEncodeError
# вместо того, чтобы показать состояние. errors='replace' страхует и на
# экзотических кодовых страницах: лучше вопросительные знаки, чем исключение.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


_MODES = {"list": "по списку", "all": "весь остальной трафик"}


def _check_text(t):
    """Итог последней проверки туннеля для строки status; '' — не поднят."""
    if t.get("checking"):
        return "проверяю…"
    return {"up": f"отвечает {t.get('answer') or ''}".rstrip(),
            "error": "молчит",
            "none": "не с чем проверить: в «пускать» нет домена"}.get(t.get("check"), "")


def _print_status(st):
    up = st.get("up")
    print(f"DualVPN {st.get('version', '?')}: "
          f"{'работает' if up else 'выключен'}")
    if st.get("busy"):
        print(f"  сейчас   : {st['busy']}")
    if st.get("last_error"):
        print(f"  ошибка   : {st['last_error']}")
    print(f"  профиль  : {st.get('profile') or 'единственный конфиг основного'}")
    for t in st.get("tunnels") or []:
        check = _check_text(t) if up else ""
        print(f"  туннель  : {t.get('name')} [{t.get('id')}], {_MODES.get(t.get('mode'), '?')}"
              f" — {t.get('active') or 'конфиг не выбран'}"
              + (f"; {check}" if check else ""))
    print(f"  sing-box : {st.get('pid') or 'не запущен'}")
    print(f"  tun      : {st.get('tun') or 'нет'}")
    print(f"  аплинк   : интерфейс {st.get('iface')} / шлюз {st.get('gw') or '—'}")
    print(f"  маршруты : 0.0.0.0/1 {'есть' if st.get('r_low') else 'нет'}, "
          f"128.0.0.0/1 {'есть' if st.get('r_high') else 'нет'}")
    print(f"  IPv6     : {'заблокирован' if st.get('v6_off') else 'как есть'}"
          + (f"  !! утечка {st['v6_leak']}" if st.get("v6_leak") else ""))
    if up:
        state = {"tunnel": "через туннель", "leak": "!! УТЕЧКА, адрес провайдера",
                 "direct": "запасной, напрямую: личный не работает",
                 "unknown": "не удалось проверить"}.get(st.get("exit_state"), "?")
        # Выход сторож переключает раньше, чем проверка выхода его перемерит.
        if st.get("out") == "direct":
            state = "запасной, напрямую: личный не работает"
        print(f"  выход    : {st.get('exit_ip') or '—'} "
              f"{st.get('exit_country') or ''} {st.get('exit_city') or ''} — {state}")
        # HTTPS проверяют только у туннеля без DNS.
        http = f"   HTTP {st['corp_http']}" if st.get("corp_http") else ""
        print(f"  корп-DNS : {st.get('corp_dns') or 'нет'} "
              f"→ {st.get('corp_ip') or '—'}{http}")
    print(f"  автозапуск: {'да' if st.get('autostart') else 'нет'}")


def _call(op, **payload):
    try:
        return ipc.call(op, **payload)
    except ipc.NotRunning as exc:
        print(exc)
        print("поставить службу: dualvpn service install (от администратора)")
        sys.exit(1)


def _apply():
    """Выбранный конфиг — сразу на живой VPN: служба перезапускает только
    процесс туннеля, у которого он сменился (решение #14)."""
    r = _call("apply")
    if not r.get("ok"):
        print(f"не вышло: {r.get('error')}")
        return 1
    applied = r.get("applied")
    if applied == "off":
        print("  VPN выключен — применится при включении")
    elif applied == "sides":
        names = ", ".join(r.get("restarted") or [])
        print(f"  перезапущен процесс: {names}" if names
              else "  перезапускать нечего: конфиг уже в работе")
    elif applied == "full":
        print("  VPN перезапущен")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "status"

    if cmd in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0

    if cmd in ("version", "-v", "--version"):
        print(f"DualVPN {paths.version()}")
        # Где ищем бинарники — по этим строкам build.ps1 проверяет сборку.
        # MISSING латиницей: вывод читает PowerShell, кодировки там разные.
        for f in (paths.SINGBOX, paths.WINTUN):
            print(f + ("" if os.path.isfile(f) else "  MISSING"))
        return 0

    if cmd == "service":
        # win32serviceutil разбирает argv сам, поэтому подсовываем ему свой.
        from . import service
        sub = argv[1] if len(argv) > 1 else ""
        if sub == "console":
            service.run_in_console()
            return 0
        if sub == "run":
            # Так нас зовёт диспетчер служб у собранного exe — руками эту
            # команду вводить незачем.
            service.run_dispatcher()
            return 0
        sys.argv = [sys.argv[0]] + argv[1:]
        service.handle_command_line()
        return 0

    if cmd == "tray":
        from . import tray
        tray.run(background="--background" in argv[1:])
        return 0

    if cmd == "window":
        from . import window
        window.open_window(resident="--resident" in argv[1:],
                           hidden="--hidden" in argv[1:])
        return 0

    if cmd == "admin-op":
        # Короткий elevated-заход: окно попросило у пользователя UAC ровно на
        # одну команду в conf\ (add-config, read-config, ...), запустило этот
        # процесс с правами через ShellExecuteEx (runas) и ждёт результат
        # в файле — сам процесс интерактивно ничего не показывает.
        if len(argv) < 4:
            print("использование: dualvpn admin-op ОП ФАЙЛ-ЗАПРОСА ФАЙЛ-ОТВЕТА")
            return 1
        op, payload_file, result_file = argv[1], argv[2], argv[3]
        import json
        try:
            with open(payload_file, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError):
            payload = {}
        try:
            r = ipc.call(op, **payload)
        except ipc.NotRunning as exc:
            r = {"ok": False, "error": str(exc)}
        try:
            with open(result_file, "w", encoding="utf-8") as fh:
                json.dump(r, fh, ensure_ascii=False)
        except OSError:
            pass
        return 0

    if cmd == "status":
        r = _call("status")
        _print_status(r.get("status", {}))
        return 0

    if cmd == "start":
        profile = argv[1] if len(argv) > 1 else ""
        print("→ включаю, это занимает до 30 секунд…")
        r = _call("start", profile=profile)
        if not r.get("ok"):
            print(f"не вышло: {r.get('error')}")
            return 1
        print("→ включено")
        return 0

    if cmd == "stop":
        r = _call("stop")
        print("→ выключено" if r.get("ok") else f"не вышло: {r.get('error')}")
        return 0 if r.get("ok") else 1

    if cmd == "list":
        items = _call("status").get("status", {}).get("tunnels") or []
        for t in items:
            print(f"{t.get('name')} [{t.get('id')}], {_MODES.get(t.get('mode'), '?')}:")
            for name in t.get("confs") or []:
                print(f"  {'*' if name == t.get('active') else ' '} {name}")
            if not t.get("confs"):
                print("    (нет конфигов)")
        if not items:
            print("туннелей нет")
        return 0

    if cmd == "use":
        if len(argv) < 3:
            print("укажи туннель и конфиг: dualvpn use home nl-1")
            return 1
        r = _call("set-active", tunnel=argv[1], name=argv[2])
        if not r.get("ok"):
            print(f"не вышло: {r.get('error')}")
            return 1
        print(f"→ туннель {r.get('tunnel')}: {argv[2]}")
        return _apply()

    if cmd == "profile":
        if len(argv) < 2:
            print("укажи имя: dualvpn profile nl-1")
            return 1
        r = _call("set-profile", profile=argv[1])
        if not r.get("ok"):
            print(f"не вышло: {r.get('error')}")
            return 1
        print(f"→ основной туннель: {argv[1]}")
        return _apply()

    if cmd == "log":
        n = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 200
        for line in _call("log", lines=n).get("lines", []):
            print(line)
        return 0

    print(f"неизвестная команда: {cmd}")
    print("см. dualvpn help")
    return 1


if __name__ == "__main__":
    sys.exit(main())
