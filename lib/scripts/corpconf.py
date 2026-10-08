"""
Рабочий конфиг с сайта wg.media-effect.ru: запрос кода на почту и обмен
кода на свежий конфиг.

Браузер для этого не нужен: у сайта открытый JSON API, тот же, которым
пользуется его страница. Код из письма человек вписывает в окне сам — почту
программа не читает и паролей от неё не хранит.

Сеть — через /usr/bin/curl, как в update.py: Python внутри .app не видит
системных сертификатов. Почта и код уходят телом через stdin, а не в
аргументах: аргументы видны любому в списке процессов.
"""

import json
import re
import socket
import subprocess

SITE = "https://wg.media-effect.ru"
MAIL = "https://mail.media-effect.ru/"
DOMAIN = "media-effect.ru"
CURL = "/usr/bin/curl"
TIMEOUT = 20
# Логин идёт в имя файла (wg0-<логин>.conf), поэтому только безопасные символы.
EMAIL_RE = re.compile(r"([A-Za-z0-9._-]+)@" + re.escape(DOMAIN))


class CorpConfError(Exception):
    """Не вышло; текст — для человека."""


def check_email(email):
    """Почта без пробелов в нижнем регистре или CorpConfError.

    Сайт выдаёт конфиги только на рабочую почту — проверяем до запроса,
    чтобы не ждать отказа по сети.
    """
    email = (email or "").strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise CorpConfError(f"нужна рабочая почта вида имя@{DOMAIN}")
    return email


def file_name(email):
    """Имя, под которым сайт отдаёт конфиг: оно же подходит под CORP_PAT."""
    return f"wg0-{EMAIL_RE.fullmatch(check_email(email)).group(1)}.conf"


def client_name():
    """Имя компьютера — его же подставила бы страница сайта."""
    try:
        r = subprocess.run(["/usr/sbin/scutil", "--get", "ComputerName"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return socket.gethostname()


def _post(path, payload):
    """Ответ сайта словарём. Ошибку сайт объясняет в message — её и показываем."""
    try:
        r = subprocess.run(
            [CURL, "-sS", "--fail-with-body", "--max-time", str(TIMEOUT),
             "-H", "Content-Type: application/json", "--data-binary", "@-",
             SITE + path],
            input=json.dumps(payload).encode(), capture_output=True,
            timeout=TIMEOUT + 10)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CorpConfError(f"сеть: {e}") from e
    try:
        body = json.loads(r.stdout or b"null")
    except ValueError:
        body = None
    if isinstance(body, dict) and body.get("success") is False:
        raise CorpConfError(body.get("message") or "сайт отказал")
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip()
        raise CorpConfError(f"сеть: {err or f'curl вернул {r.returncode}'}")
    if not isinstance(body, dict) or not body.get("success"):
        raise CorpConfError("сайт ответил непонятно")
    return body


def request(email, name):
    """Просит сайт выслать код. Сколько минут он живёт."""
    body = _post("/api/request-config", {"email": check_email(email), "client_name": name})
    return body.get("expires_in_minutes") or 10


def verify(email, code):
    """Меняет код на конфиг. Текст конфига или CorpConfError."""
    code = (code or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        raise CorpConfError("код — 6 цифр из письма")
    return parse_config(_post("/api/verify-code", {"email": check_email(email), "code": code}))


def parse_config(body):
    """Конфиг из ответа — только если это и правда конфиг WireGuard."""
    text = body.get("config") if isinstance(body, dict) else None
    if not isinstance(text, str) or "[Interface]" not in text or "PrivateKey" not in text:
        raise CorpConfError("сайт прислал не конфиг WireGuard")
    return text
