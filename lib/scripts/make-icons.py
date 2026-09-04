#!/usr/bin/env python3
"""
Готовит иконки из icon.svg: значок приложения и три состояния для меню-бара.

Рисует macOS сам — NSImage умеет SVG, поэтому сторонние конвертеры не нужны.
Цвет подставляется в сам SVG перед отрисовкой: картинка одноцветная, этого
достаточно и не требует возни со слоями.

  python3 lib/scripts/make-icons.py
"""

import os
import re
import shutil
import subprocess
import sys

from AppKit import (NSBitmapImageRep, NSColor, NSCompositeSourceOver, NSImage,
                    NSGraphicsContext, NSMakeRect, NSPNGFileType, NSBezierPath)
from Foundation import NSData

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "icon.svg")
OUT = os.path.join(ROOT, "lib", "scripts", "ui", "icons")

# Состояния значка в меню-баре. Чёрный — обычный: он рисуется как шаблон,
# и macOS сама перекрашивает его под светлую и тёмную панель.
STATES = {
    "default": "#000000",
    "ok":      "#1a9c4b",
    "bad":     "#d13b30",
}
BAR_PX = 44          # 22 точки при двойной плотности


def colored(svg_text, color):
    return re.sub(r'(fill|color)="#[0-9a-fA-F]{3,8}"',
                  lambda m: f'{m.group(1)}="{color}"', svg_text)


def render(svg_text, px, inset=0.0, bg=None, radius=0.0):
    """SVG → NSBitmapImageRep нужного размера.

    inset — поля вокруг рисунка в долях размера: у значка приложения глиф
    не должен упираться в края, иначе он выглядит крупнее соседей в Dock.
    """
    data = NSData.dataWithBytes_length_(svg_text.encode(), len(svg_text.encode()))
    img = NSImage.alloc().initWithData_(data)
    if img is None:
        sys.exit("не удалось прочитать SVG")

    rep = NSBitmapImageRep.alloc().initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel_(
        None, px, px, 8, 4, True, False, "NSCalibratedRGBColorSpace", 0, 0)
    ctx = NSGraphicsContext.graphicsContextWithBitmapImageRep_(rep)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.setCurrentContext_(ctx)

    if bg:
        NSColor.colorWithSRGBRed_green_blue_alpha_(*bg).set()
        NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(
            NSMakeRect(0, 0, px, px), radius, radius).fill()

    pad = px * inset
    img.drawInRect_fromRect_operation_fraction_(
        NSMakeRect(pad, pad, px - 2 * pad, px - 2 * pad),
        NSMakeRect(0, 0, 0, 0), NSCompositeSourceOver, 1.0)

    NSGraphicsContext.restoreGraphicsState()
    return rep


def save(rep, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = rep.representationUsingType_properties_(NSPNGFileType, None)
    data.writeToFile_atomically_(path, True)


def main():
    if not os.path.exists(SRC):
        sys.exit(f"нет {SRC}")
    with open(SRC, encoding="utf-8") as fh:
        svg = fh.read()

    for name, color in STATES.items():
        save(render(colored(svg, color), BAR_PX), os.path.join(OUT, f"menubar-{name}.png"))
    print(f"значки меню-бара: {len(STATES)} шт. в {os.path.relpath(OUT, ROOT)}")

    # Значок приложения: белый глиф на тёмном скруглённом квадрате — иначе
    # чёрный рисунок на прозрачном фоне пропадает в тёмной теме.
    white = colored(svg, "#ffffff")
    iconset = os.path.join(ROOT, "lib", "scripts", "DualVPN.iconset")
    shutil.rmtree(iconset, ignore_errors=True)
    os.makedirs(iconset)
    for size in (16, 32, 64, 128, 256, 512, 1024):
        rep = render(white, size, inset=0.22,
                     bg=(0.13, 0.15, 0.20, 1.0), radius=size * 0.22)
        save(rep, os.path.join(iconset, f"icon_{size}x{size}.png"))
        if size >= 32:
            save(rep, os.path.join(iconset, f"icon_{size // 2}x{size // 2}@2x.png"))

    icns = os.path.join(ROOT, "lib", "scripts", "DualVPN.icns")
    subprocess.run(["iconutil", "-c", "icns", iconset, "-o", icns], check=True)
    shutil.rmtree(iconset, ignore_errors=True)
    print(f"значок приложения: {os.path.relpath(icns, ROOT)}")


if __name__ == "__main__":
    main()
