"""Рисует DualVPN.ico для exe и установщика.

Значок собирается кодом, а не лежит готовым файлом, по той же причине, что и
значок в трее: это два круга, и держать ради них бинарник в репозитории незачем.
Заодно ico и трей гарантированно не разъезжаются — форма задана в одном месте.

    python installer/make_icon.py [куда.ico]
"""

import os
import sys

from PIL import Image, ImageDraw

# Тот же зелёный, что у поднятого туннеля в трее (tray.COLORS["up"]).
GREEN = (46, 160, 67, 255)
WHITE = (255, 255, 255, 255)

# Windows берёт из ico тот размер, который ему нужен: 16 — для панели задач,
# 256 — для крупных значков в проводнике. Меньшие рисуем отдельно, а не
# уменьшением 256: тонкие детали в 16 пикселей превращаются в кашу.
SIZES = (16, 24, 32, 48, 64, 128, 256)


def draw(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = max(1, size // 10)
    d.ellipse((pad, pad, size - pad, size - pad), fill=GREEN)
    # Внутренний круг — второй туннель. На 16 пикселях он вырождается в точку,
    # поэтому даём ему минимум два пикселя, иначе просто исчезает.
    r = max(2, size // 8)
    c = size // 2
    d.ellipse((c - r, c - r, c + r, c + r), fill=WHITE)
    return img


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "DualVPN.ico")
    images = [draw(s) for s in SIZES]
    images[-1].save(out, format="ICO",
                    sizes=[(s, s) for s in SIZES], append_images=images[:-1])
    print(f"собрано: {out}")


if __name__ == "__main__":
    main()
