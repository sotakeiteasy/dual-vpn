"""
Обновление из релизов GitHub: найти новую версию, скачать, проверить, открыть.

Ставит её apply-update.sh — под root, из уже установленного приложения.

Релизы macOS и Windows лежат в одном репозитории, и «Latest» у них один на
двоих. Поэтому свой релиз ищем по префиксу тега в списке, а не через
releases/latest: там вполне может оказаться Windows-версия.

Сеть — через /usr/bin/curl, а не urllib. Python внутри .app несёт свой
OpenSSL, которому неоткуда взять системные сертификаты, а curl берёт их из
связки ключей. И скачанное curl'ом не получает атрибута карантина: Gatekeeper
не потребует «Открыть» у новой версии.
"""

import hashlib
import json
import os
import re
import subprocess

REPO = "sotakeiteasy/dual-vpn"
API = f"https://api.github.com/repos/{REPO}/releases?per_page=30"
DOWNLOAD_PREFIX = f"https://github.com/{REPO}/releases/download/"
TAG_PREFIX = "mac-v"              # Windows-релизы — теги v*
APP_NAME = "DualVPN.app"
CURL = "/usr/bin/curl"
HDIUTIL = "/usr/bin/hdiutil"
API_TIMEOUT = 20
DMG_TIMEOUT = 600                 # образ ~60 МБ, на медленной сети — минуты


class UpdateError(Exception):
    """Обновление не удалось; текст — для человека."""


def parse_version(text):
    """'0.1.4' → (0, 1, 4). Всё, что не X.Y.Z, — None: сравнивать не с чем."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", (text or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def pick(releases, current):
    """Самый новый релиз macOS выше current — или None.

    Драфты и пре-релизы не предлагаем; релиз без образа или без его суммы —
    тоже: ставить непроверенное нельзя, а проверить его нечем.
    """
    cur = parse_version(current)
    if cur is None:
        return None                     # своя версия неизвестна — не с чем сравнить
    best = None
    for r in releases or []:
        tag = r.get("tag_name") or ""
        if not tag.startswith(TAG_PREFIX) or r.get("draft") or r.get("prerelease"):
            continue
        num = tag[len(TAG_PREFIX):]
        ver = parse_version(num)
        if ver is None or ver <= cur:
            continue
        name = f"DualVPN-{num}.dmg"
        # Качаем только с самого GitHub: адрес приходит в ответе, и без этой
        # проверки curl пошёл бы туда, куда его укажут.
        urls = {a.get("name"): a.get("browser_download_url")
                for a in r.get("assets") or []
                if (a.get("browser_download_url") or "").startswith(DOWNLOAD_PREFIX)}
        if not urls.get(name) or not urls.get(name + ".sha256"):
            continue
        if best is None or ver > best[0]:
            best = (ver, {"version": num, "name": name,
                          "dmg_url": urls[name], "sha_url": urls[name + ".sha256"],
                          "page": r.get("html_url") or "",
                          # Описание релиза — раздел версии из CHANGELOG.md.
                          "notes": (r.get("body") or "").strip()})
    return best[1] if best else None


def _curl(args, timeout):
    """Тело ответа байтами; при любой ошибке — UpdateError с причиной от curl."""
    try:
        r = subprocess.run([CURL, "-fsSL", "--max-time", str(timeout), *args],
                           capture_output=True, timeout=timeout + 10)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise UpdateError(f"network: {e}") from e
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip()
        raise UpdateError(f"network: {err or f'curl returned {r.returncode}'}")
    return r.stdout


def check(current):
    """Есть ли версия новее current. None — нет; ошибка сети — UpdateError."""
    body = _curl(["-H", "Accept: application/vnd.github+json", API], API_TIMEOUT)
    try:
        releases = json.loads(body)
    except ValueError as e:
        raise UpdateError("GitHub didn't return JSON") from e
    if not isinstance(releases, list):
        raise UpdateError("GitHub didn't return a release list")
    return pick(releases, current)


def expected_sha(text, name):
    """Сумма образа из файла .sha256 (формат `shasum -a 256`)."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name \
                and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            return parts[0].lower()
    raise UpdateError(f"no checksum line for {name}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(info, dest):
    """Скачивает образ в dest и сверяет сумму. Путь к образу или UpdateError.

    Не совпало — образ удаляется: дальше его никто не должен даже открыть.
    """
    want = expected_sha(_curl([info["sha_url"]], API_TIMEOUT).decode("utf-8", "replace"),
                        info["name"])
    dmg = os.path.join(dest, info["name"])
    _curl(["-o", dmg, info["dmg_url"]], DMG_TIMEOUT)
    got = sha256_file(dmg)
    if got != want:
        os.unlink(dmg)
        raise UpdateError("image checksum mismatch — download deleted")
    return dmg


def mount(dmg, point):
    """Открывает образ в point и возвращает путь к приложению внутри.

    -nobrowse: том не виден в Finder, и LaunchServices не заводит на него
    вторую «DualVPN» (см. eject_images в install-daemon.sh).
    """
    r = subprocess.run([HDIUTIL, "attach", "-nobrowse", "-readonly", "-noautoopen",
                        "-mountpoint", point, dmg], capture_output=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise UpdateError(f"couldn't open the image: {(r.stderr or '').strip()[:160]}")
    app = os.path.join(point, APP_NAME)
    if not os.path.isdir(app):
        unmount(point)
        raise UpdateError(f"{APP_NAME} not found in the image")
    return app


def unmount(point):
    subprocess.run([HDIUTIL, "detach", point, "-quiet"], capture_output=True)
