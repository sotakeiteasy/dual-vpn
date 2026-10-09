"""Значок DualVPN для exe, установщика и окна.

Значок собирается кодом, а не лежит готовым файлом, по той же причине, что и
значок в трее: это зелёный круг, и держать ради них бинарник в репозитории незачем.
Нужен он в двух местах: при сборке (installer/make_icon.py пишет DualVPN.ico)
и окну, запущенному из исходников, — там процесс — python.exe, и без своего
ico окно и панель задач показывали бы значок Python.
"""

# Тот же зелёный, что у поднятого туннеля в трее (tray.COLORS["up"]).
GREEN = (46, 160, 67, 255)

# Windows берёт из ico тот размер, который ему нужен: 16 — для панели задач,
# 256 — для крупных значков в проводнике. Меньшие рисуем отдельно, а не
# уменьшением 256: тонкие детали в 16 пикселей превращаются в кашу.
SIZES = (16, 24, 32, 48, 64, 128, 256)


def draw(size):
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = max(1, size // 10)
    d.ellipse((pad, pad, size - pad, size - pad), fill=GREEN)
    return img


def write_ico(path):
    """Пишет ico со всеми размерами из SIZES."""
    images = [draw(s) for s in SIZES]
    images[-1].save(path, format="ICO",
                    sizes=[(s, s) for s in SIZES], append_images=images[:-1])
    return path
