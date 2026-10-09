"""Значок DualVPN: один ico на exe, установщик и окно из исходников."""

import pytest

pytest.importorskip("PIL")

from PIL import Image  # noqa: E402

from dualvpn import icon  # noqa: E402


def test_ico_несёт_все_размеры_от_16_до_256(tmp_path):
    path = icon.write_ico(str(tmp_path / "DualVPN.ico"))
    with Image.open(path) as img:
        sizes = img.info["sizes"]
    assert sizes == {(s, s) for s in icon.SIZES}
    assert min(sizes) == (16, 16) and max(sizes) == (256, 256)


@pytest.mark.parametrize("size", icon.SIZES)
def test_значок_сплошной_зелёный_без_точки_в_центре(size):
    img = icon.draw(size)
    assert img.getpixel((size // 2, size // 2)) == icon.GREEN


def test_значок_трея_включённого_сплошной_зелёный():
    from dualvpn import tray

    img = tray._icon_image("up")
    assert img.getpixel((32, 32)) == tray.COLORS["up"]
