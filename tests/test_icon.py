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
