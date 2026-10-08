#!/usr/bin/env python3
"""
Включение, выключение и перезапуск туннеля: по одной операции за раз, в фоне.

Раньше каждая кнопка дёргала launchctl прямо из обработчика и сразу
отпускалась. Отсюда три беды:

  * «Включить», нажатое, пока служба ещё разбирала маршруты после
    «Выключить», делало kickstart -k и убивало уборку на середине;
  * «Перезапустить» было тем же kickstart -k: launchd шлёт TERM и тут же
    поднимает новый процесс, не дожидаясь, пока старый уберёт за собой;
  * результат не проверялся никем. Служба падала на битом конфиге, а окно
    25 секунд показывало «включаю…» и молча отпускало кнопку.

Здесь операция доводится до конца: команда, затем ожидание настоящего
результата (туннель поднят / служба завершилась и сеть чистая / служба
сообщила причину отказа), с таймаутом. Перезапуск — это полное выключение и
полное включение, а не сигнал.

Модуль без AppKit: вся работа с системой — через объект `ops` (см. Ops), чтобы
логику можно было гонять в тестах без launchd и root.
"""

import os
import re
import threading
import time

IDLE = "idle"
STARTING = "starting"
STOPPING = "stopping"
RESTARTING = "restarting"


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def read_tail(path, keep=400, max_bytes=220_000):
    """Последние `keep` строк лога без раскраски.

    Читаем только хвост файла: sing-box пишет строку на соединение, за
    четверть часа набегают сотни килобайт, а перечитывается это каждые две
    секунды. Демон пишет лог через `exec >>`, без снятия ANSI-кодов — без
    чистки фильтр «только ошибки» не находил ни одной: перед ERROR стоял
    не пробел, а \\x1b[31m.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(0, size - max_bytes))
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    return ANSI.sub("", raw).splitlines()[-keep:]


def last_session(lines):
    """Строки только последнего запуска службы — от последней шапки «===».

    Служба дописывает лог при перезапусках, поэтому в файле лежит несколько
    попыток. Без отсечки причина от прошлой, неудачной, попадала бы в окно
    поверх нормально работающего туннеля.
    """
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].startswith("==="):
            return lines[i:]
    return lines


def read_last_error(path, since=0.0):
    """Причина отказа, записанная службой (vpn: fail_start), или ''."""
    try:
        if os.path.getmtime(path) < since:
            return ""
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


# Строка сторожа в логе службы (vpn: run_singbox) и сколько строк хвоста
# смотреть: между строкой и проверкой sing-box успевает написать десяток своих.
RESTART_MARK = "→ перезапускаю sing-box: "
RESTART_TAIL = 40


def restart_step(lines):
    """Шаг «перезапускаю sing-box: …» по последней такой строке лога, или ''."""
    for line in reversed(lines):
        if line.startswith(RESTART_MARK):
            return line[len("→ "):] + "…"
    return ""


class Ops:
    """Что контроллер умеет делать с системой. Реальная реализация — в menubar.py.

    Все методы возвращают быстро (секунды), не бросают исключений и
    возвращают строку ошибки или '' там, где речь о команде.
    """

    def kickstart(self):
        """Запустить службу. '' или текст ошибки."""
        raise NotImplementedError

    def stop(self):
        """Попросить службу выключиться (с запасной уборкой). '' или ошибка."""
        raise NotImplementedError

    def stop_direct(self):
        """Уборка в обход службы — когда та не выходит сама. '' или ошибка."""
        raise NotImplementedError

    def daemon_running(self):
        """Жив ли процесс службы."""
        raise NotImplementedError

    def is_up(self):
        """Поднят ли туннель: наш tun есть и маршруты на нём стоят."""
        raise NotImplementedError

    def last_error(self, since=0.0):
        """Причина, по которой служба не поднялась, записанная ею самой.

        Только если запись не старше `since` (время по часам системы).
        """
        raise NotImplementedError

    def clear_error(self):
        """Забыть записанную причину."""
        raise NotImplementedError

    def session_tail(self, n):
        """Последние n строк лога текущего запуска службы."""
        raise NotImplementedError


class Controller:
    # Старт — это сборка конфига, выключение IPv6 (networksetup думает до
    # 15 с), ожидание tun (до 30 с внутри vpn) и выставление маршрутов.
    START_TIMEOUT = 75.0
    # Выключение: sing-box до 10 с на TERM, ещё 5 на KILL, плюс уборка
    # маршрутов и возврат IPv6. Если служба к этому сроку не вышла,
    # убираем напрямую; если и после этого не чисто — это уже ошибка.
    STOP_ESCALATE = 25.0
    STOP_TIMEOUT = 45.0
    # Сколько служба может «не существовать», прежде чем решим, что она
    # завершилась. launchd показывает процесс не мгновенно после kickstart.
    GONE_GRACE = 3.0

    def __init__(self, ops, on_change=None, clock=time.time, sleep=time.sleep,
                 poll=0.5, log=None):
        self.ops = ops
        self.on_change = on_change or (lambda: None)
        self.clock = clock
        self.sleep = sleep
        self.poll = poll
        self.log = log or (lambda _m: None)

        self._lock = threading.Lock()
        self._thread = None
        self.phase = IDLE
        self.step = ""          # что происходит прямо сейчас, для людей
        self.error = ""         # чем закончилась последняя неудачная операция
        self.error_log = []     # хвост лога службы на момент неудачи

    # ------------------------------------------------------------ снаружи

    def busy(self):
        return self.phase != IDLE

    def snapshot(self):
        """Состояние для отрисовки. Ошибку службы берём и тогда, когда операцию
        запускали не мы: служба могла упасть сама, пока окно было закрыто."""
        with self._lock:
            snap = {"phase": self.phase, "step": self.step, "busy": self.busy(),
                    "error": self.error, "error_log": list(self.error_log)}
        if not snap["busy"] and not snap["error"]:
            err = self.ops.last_error()
            if err:
                snap["error"] = err
                snap["error_log"] = self.ops.session_tail(12)
        return snap

    def start(self):
        return self._launch(STARTING, self._do_start)

    def stop(self):
        return self._launch(STOPPING, self._do_stop)

    def restart(self):
        return self._launch(RESTARTING, self._do_restart)

    def dismiss(self):
        """Человек прочитал ошибку и закрыл её."""
        with self._lock:
            self.error = ""
            self.error_log = []
        self.ops.clear_error()
        self.on_change()

    def wait(self, timeout=None):
        """Дождаться конца текущей операции (для тестов и выхода)."""
        t = self._thread
        if t is not None:
            t.join(timeout)

    # ------------------------------------------------------------ внутри

    def _launch(self, phase, body):
        """Запускает операцию, если никакая другая не идёт.

        Вторая команда, пока идёт первая, отбрасывается, а не встаёт в
        очередь: «Выключить, Включить, Выключить» кликом подряд — это почти
        всегда дребезг, а не намерение.
        """
        with self._lock:
            if self.phase != IDLE:
                self.log(f"управление: {phase} отброшено, идёт {self.phase}")
                return False
            self.phase = phase
            self.step = ""
            self.error = ""
            self.error_log = []
            self._thread = threading.Thread(target=self._run, args=(phase, body),
                                            daemon=True)
            thread = self._thread
        self.log(f"управление: {phase}")
        self.on_change()
        thread.start()
        return True

    def _run(self, phase, body):
        try:
            err = body()
        except Exception as e:           # операция не имеет права залипнуть
            err = f"внутренняя ошибка: {e}"
        with self._lock:
            self.phase = IDLE
            self.step = ""
            if err:
                self.error = err
        if err:
            self.log(f"управление: {phase} не удалось — {err}")
            try:
                tail = self.ops.session_tail(12)
            except Exception:
                tail = []
            with self._lock:
                self.error_log = tail
        else:
            self.log(f"управление: {phase} готово")
        self.on_change()

    def _set_step(self, text):
        with self._lock:
            self.step = text
        self.on_change()

    def _do_start(self):
        self._set_step("запускаю службу…")
        t0 = self.clock()
        # Старая причина к новой попытке отношения не имеет. Если стереть не
        # вышло (чужой владелец файла), отсечёт проверка по времени ниже.
        self.ops.clear_error()
        if self.ops.is_up():
            return ""
        err = self.ops.kickstart()
        if err:
            return err

        self._set_step("поднимаю туннель…")
        seen = False
        gone_at = None
        while self.clock() - t0 < self.START_TIMEOUT:
            if self.ops.is_up():
                return ""
            # Служба сама сообщила причину — это главный путь отказа.
            why = self.ops.last_error(since=t0)
            if why:
                return why
            # Сторож службы перезапускает sing-box, когда тот стартовал без
            # сокетов WireGuard: это лишние секунды, и человек должен видеть, на что.
            step = restart_step(self.ops.session_tail(RESTART_TAIL))
            if step and step != self.step:
                self._set_step(step)
            if self.ops.daemon_running():
                seen = True
                gone_at = None
            else:
                now = self.clock()
                if gone_at is None:
                    gone_at = now
                # Не было процесса вовсе или он уже вышел — решаем не сразу:
                # launchd показывает его не мгновенно, а причина пишется
                # перед самым выходом.
                elif now - gone_at >= self.GONE_GRACE and (seen or now - t0 > 2 * self.GONE_GRACE):
                    return (self.ops.last_error(since=t0)
                            or "служба завершилась, не подняв туннель — причина в логе")
            self.sleep(self.poll)

        # Полуподнятое состояние хуже выключенного: маршруты могли встать,
        # а трафик не идёт. Убираем за собой и говорим, что не вышло.
        self._set_step("не поднялся — убираю…")
        self._stop_and_wait()
        return f"туннель не поднялся за {int(self.START_TIMEOUT)} с"

    def _do_stop(self):
        # Раз выключили руками, старая причина отказа больше не актуальна.
        self.ops.clear_error()
        return self._stop_and_wait()

    def _stop_and_wait(self):
        self._set_step("выключаю…")
        t0 = self.clock()
        err = self.ops.stop()
        if err:
            return err

        escalated = False
        while True:
            if not self.ops.daemon_running() and not self.ops.is_up():
                return ""
            elapsed = self.clock() - t0
            if elapsed >= self.STOP_TIMEOUT:
                return (f"не выключился за {int(self.STOP_TIMEOUT)} с — "
                        f"посмотри лог, возможно, остались маршруты")
            if elapsed >= self.STOP_ESCALATE and not escalated:
                escalated = True
                self._set_step("служба не выходит — убираю напрямую…")
                self.log("управление: служба не вышла сама, уборка напрямую")
                err = self.ops.stop_direct()
                if err:
                    return err
            self.sleep(self.poll)

    def _do_restart(self):
        err = self._stop_and_wait()
        if err:
            return f"перезапуск: не выключился — {err}"
        return self._do_start()
