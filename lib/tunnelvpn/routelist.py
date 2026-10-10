"""Списки «Пускать через туннель» и «Не пускать»: разбор того, что ввёл человек.

В поле вставляют что угодно: адрес из письма, ссылку из браузера, строку из
чужого конфига. Поэтому разбор терпимый к форме записи и строгий к сути:

    1.2.3.4             -> 1.2.3.4/32
    10.0.0.5/8          -> 10.0.0.0/8
    git.x.su            -> git.x.su       (вместе со всеми поддоменами)
    *.x.su              -> *.x.su         (только поддомены)
    https://git.x.su/a  -> git.x.su
    git.x.su:22         -> git.x.su       (порт маршрутизации не нужен)
    пример.рф           -> xn--e1afmkfd.xn--p1ai

Разделители — пробел, перевод строки, «,» и «;». Двоеточие разделителем не
считается: оно входит и в IPv6, и в host:port. Всё, что не удалось понять,
возвращается отдельно: окно показывает это человеку, молча ничего не пропадает.
"""

import ipaddress
import re
import urllib.parse

_SPLIT = re.compile(r"[\s,;]+")
# Метка домена по RFC 1123: буквы, цифры и дефис не по краям.
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _ip(token):
    """IPv4/IPv6 адрес или подсеть в каноническом виде, иначе None."""
    try:
        return str(ipaddress.ip_network(token, strict=False))
    except ValueError:
        return None


def _domain(token):
    """Домен в нижнем регистре и punycode, иначе None.

    Нужна хотя бы одна точка: слово без неё — скорее опечатка, чем имя,
    а domain_suffix из одной метки забрал бы в туннель целую зону.
    """
    token = token.rstrip(".")
    if not token or "." not in token:
        return None
    try:
        token = token.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    token = token.lower()
    labels = token.split(".")
    if len(token) > 253 or not all(_LABEL.match(x) for x in labels):
        return None
    # «1.2.3» — не домен, а недописанный адрес: у имени зона не из цифр.
    if labels[-1].isdigit():
        return None
    return token


def _host(token):
    """Хост из URL или host:port; токен без них — как есть."""
    if "://" in token:
        try:
            return urllib.parse.urlsplit(token).hostname or ""
        except ValueError:
            return ""
    if token.startswith("["):
        # [2001:db8::1]:443
        return token[1:].partition("]")[0]
    host, sep, port = token.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host
    return token


def _one(token):
    """Одна запись в нормальном виде, иначе None."""
    token = token.strip().lower()
    if not token:
        return None
    found = _ip(token)
    if found:
        return found
    host = _host(token)
    found = _ip(host)
    if found:
        return found
    if host.startswith("*."):
        found = _domain(host[2:])
        return f"*.{found}" if found else None
    return _domain(host)


def parse(text):
    """Разбирает поле списка: (записи, непонятые).

    Записи нормализованы и без повторов, порядок — как ввёл человек.
    Непонятые — токены как есть, тоже без повторов.
    """
    entries, rejected = [], []
    for token in _SPLIT.split(text or ""):
        if not token:
            continue
        found = _one(token)
        if found is None:
            if token not in rejected:
                rejected.append(token)
        elif found not in entries:
            entries.append(found)
    return entries, rejected


def parse_list(items):
    """То же для готового списка строк — например, прочитанного из файла."""
    return parse(" ".join(str(x) for x in items or ()))
