"""Значок TunnelVPN: ico на exe, установщик и окно, его копии и значки трея."""

import itertools
import os
import re

import pytest

pytest.importorskip("PIL")

from PIL import Image  # noqa: E402

from tunnelvpn import icon  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAY_SIZES = (16, 20, 24, 32)


def _has_color(img, color, tol=40):
    """Есть ли в картинке непрозрачная точка, близкая к цвету color."""
    target = icon.rgba(color)
    px = img.tobytes()
    return any(px[i + 3] > 200 and all(abs(px[i + j] - target[j]) <= tol for j in range(3))
               for i in range(0, len(px), 4))


def test_ico_несёт_все_размеры_от_16_до_256(tmp_path):
    path = icon.write_ico(str(tmp_path / "TunnelVPN.ico"))
    with Image.open(path) as img:
        sizes = img.info["sizes"]
    assert sizes == {(s, s) for s in icon.SIZES}
    assert {(20, 20), (40, 40)} <= sizes


@pytest.mark.parametrize("size", icon.SIZES)
def test_значок_на_тёмной_подложке_со_светлой_аркой(size):
    img = icon.draw(size)
    assert img.size == (size, size)
    assert img.getpixel((size // 2, size - 2))[3] == 255          # подложка
    assert _has_color(img, icon.LIGHT)                             # арка


@pytest.mark.parametrize("size", [s for s in icon.SIZES if s <= icon.SMALL])
def test_мелкий_значок_упрощён_до_двух_полос(size):
    img = icon.draw(size)
    assert _has_color(img, icon.OK) and _has_color(img, icon.BUSY)
    assert not _has_color(img, icon.ACCENT)


def test_крупный_значок_с_тремя_полосами():
    img = icon.draw(256)
    assert all(_has_color(img, c) for c in (icon.OK, icon.ACCENT, icon.BUSY))


def test_assets_svg_копия_рисунка_icon_py():
    with open(os.path.join(ROOT, "assets", "icon.svg"), encoding="utf-8") as f:
        assert f.read() == icon.svg(), "python installer/make_icon.py --svg"


def test_значок_в_спрайте_окна_той_же_геометрии():
    with open(os.path.join(ROOT, "lib", "tunnelvpn", "ui", "index.html"), encoding="utf-8") as f:
        logo = re.search(r'<symbol id="i-logo".*?</symbol>', f.read()).group(0)
    paths = re.findall(r'\sd="([^"]+)"', logo)
    assert paths == [icon.arch_path(), *(d for d, _c in icon.stripe_paths())]


@pytest.mark.parametrize("size", TRAY_SIZES)
@pytest.mark.parametrize("state", list(icon.TRAY))
def test_значок_трея_ровно_в_размер_и_цвета_состояния(state, size):
    img = icon.tray(state, size)
    assert img.size == (size, size)
    assert _has_color(img, icon.TRAY[state][0])


@pytest.mark.parametrize("size", TRAY_SIZES)
def test_состояния_трея_различаются_без_цвета(size):
    """Форма знака, а не только цвет: в оттенках серого все шесть разные."""
    gray = {s: icon.tray(s, size).convert("LA").tobytes() for s in icon.TRAY}
    for a, b in itertools.combinations(gray, 2):
        assert gray[a] != gray[b], (a, b)


@pytest.mark.parametrize("state", list(icon.TRAY))
def test_значок_трея_с_тёмной_обводкой_для_светлой_панели(state):
    """Первая непрозрачная точка ноги арки слева — тёмная обводка."""
    img = icon.tray(state, 16)
    row = [img.getpixel((x, 13)) for x in range(16)]
    edge = next(p for p in row if p[3] > 128)
    assert max(edge[:3]) < 90, edge


def test_неизвестное_состояние_трея_выключено():
    assert icon.tray("?", 16).tobytes() == icon.tray("off", 16).tobytes()
