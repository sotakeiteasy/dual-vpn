"""Командная строка DualVPN — то же, что делает трей, но из консоли.

    dualvpn status              что сейчас поднято
    dualvpn start [ПРОФИЛЬ]     поднять
    dualvpn stop                опустить и откатить маршруты
    dualvpn list                какие конфиги видны
    dualvpn profile ИМЯ         выбрать личный конфиг по умолчанию
    dualvpn log [N]             последние строки журнала sing-box
    dualvpn version

    dualvpn tray                значок в трее (обычный способ запуска)
    dualvpn window              окно с состоянием, конфигами и логом

Управление службой (нужны права администратора):

    dualvpn service install     поставить и запустить службу
    dualvpn service remove      снять службу
    dualvpn service start|stop|restart
    dualvpn service console     запустить логику службы прямо здесь, без установки

Команды туннеля идут в службу через канал — сами они систему не трогают.
"""

import sys

from . import ipc, paths


def _print_status(st):
    up = st.get("up")
    print(f"DualVPN {st.get('version', '?')}: "
          f"{'работает' if up else 'выключен'}")
    if st.get("busy"):
        print(f"  сейчас   : {st['busy']}")
    if st.get("last_error"):
        print(f"  ошибка   : {st['last_error']}")
    print(f"  профиль  : {st.get('profile') or 'personal (по умолчанию)'}")
    print(f"  sing-box : {st.get('pid') or 'не запущен'}")
    print(f"  tun      : {st.get('tun') or 'нет'}")
    print(f"  аплинк   : интерфейс {st.get('iface')} / шлюз {st.get('gw') or '—'}")
    print(f"  маршруты : 0.0.0.0/1 {'есть' if st.get('r_low') else 'нет'}, "
          f"128.0.0.0/1 {'есть' if st.get('r_high') else 'нет'}")
    print(f"  IPv6     : {'заблокирован' if st.get('v6_off') else 'как есть'}"
          + (f"  !! утечка {st['v6_leak']}" if st.get("v6_leak") else ""))
    if up:
        state = {"tunnel": "через туннель", "leak": "!! УТЕЧКА, адрес провайдера",
                 "unknown": "не удалось проверить"}.get(st.get("exit_state"), "?")
        print(f"  выход    : {st.get('exit_ip') or '—'} "
              f"{st.get('exit_country') or ''} {st.get('exit_city') or ''} — {state}")
        print(f"  корп-DNS : {st.get('corp_dns') or 'нет'} "
              f"→ {st.get('corp_ip') or '—'}   HTTP {st.get('corp_http') or '—'}")
    print(f"  автозапуск: {'да' if st.get('autostart') else 'нет'}")


def _call(op, **payload):
    try:
        return ipc.call(op, **payload)
    except ipc.NotRunning as exc:
        print(exc)
        print("поставить службу: dualvpn service install (от администратора)")
        sys.exit(1)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "status"

    if cmd in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0

    if cmd in ("version", "-v", "--version"):
        print(f"DualVPN {paths.version()}")
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
        tray.run()
        return 0

    if cmd == "window":
        from . import window
        window.open_window()
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
        r = _call("list-profiles")
        profiles = r.get("profiles") or []
        print(f"конфиги в {paths.CONF}:")
        for name in profiles:
            print(f"  {name}")
        if not profiles:
            print("  (пусто)")
        return 0

    if cmd == "profile":
        if len(argv) < 2:
            print("укажи имя: dualvpn profile nl-1")
            return 1
        r = _call("set-profile", profile=argv[1])
        print(f"→ личный профиль: {argv[1]}" if r.get("ok")
              else f"не вышло: {r.get('error')}")
        return 0 if r.get("ok") else 1

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
