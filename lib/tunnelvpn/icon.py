"""Значок TunnelVPN: приложение (exe, установщик, окно) и трей.

Значок рисуется кодом: Pillow не растрирует SVG, а тащить ради значка
растеризатор незачем. Геометрия — в сетке 32×32, той же, что у
assets/icon.svg и значка в спрайте окна (ui/index.html, i-logo): svg() собирает
файл из тех же чисел, тест сверяет копию. Поменял рисунок — перепиши копию:
python installer/make_icon.py --svg.

Нужен он при сборке (installer/make_icon.py пишет TunnelVPN.ico), окну из
исходников — там процесс — python.exe, и без своего ico окно и панель задач
показывали бы значок Python, — и трею (tray()).
"""

import math

# Палитра окна (ui/app.css): фон, «не настроено» и статусы.
BG = "#101012"
LIGHT = "#e8e8ee"
OK = "#3df5a7"
ERR = "#ff5c7a"
WARN = "#ffd23f"
BUSY = "#5ac8fa"
OFF = "#6b6b76"
ACCENT = "#fbb26a"

# Windows берёт из ico тот размер, который ему нужен: 16, 20 и 24 — мелкий
# значок при 100, 125 и 150 %, 32–64 — панель задач и проводник, 256 —
# крупные значки. До SMALL включительно — свой упрощённый рисунок (LITE), а не
# уменьшение большого: три полосы в 16 точек сливаются в одно пятно.
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
SMALL = 24

# Арка туннеля: x левой и правой ноги, y центра дуги, y низа ног. Из точки
# fan под аркой веером расходятся полосы: (x и y конца, цвет).
FULL = {
    "radius": 8,
    "arch": (7, 25, 15, 26), "arch_w": 2.6,
    "fan": (16, 14), "stripe_w": 2.2,
    "stripes": ((10.5, 26, OK), (16, 26, ACCENT), (21.5, 26, BUSY)),
}
# В мелких размерах — арка и две крайние полосы, линии толще.
LITE = {
    "radius": 6,
    "arch": (6, 26, 15, 27), "arch_w": 3.4,
    "fan": (16, 15), "stripe_w": 3.0,
    "stripes": ((11, 27, OK), (21, 27, BUSY)),
}

# Значок трея: арка цвета состояния, внутри знак формы, как у статусов окна, —
# состояния различаются и без цвета. Подложки нет, вместо неё тёмная обводка
# в одну точку экрана: на светлой панели задач она даёт край, на тёмной
# незаметна. Арка отступает от края на ширину обводки при 16 точках.
TRAY_ARCH = (4.5, 27.5, 15.5, 28)
TRAY_ARCH_W = 3.6
OUTLINE = BG
MARK = (16, 18.5)          # центр знака под аркой

# Состояние трея → цвет арки и знак.
TRAY = {
    "up": (OK, "dot"),
    "off": (OFF, "ring"),
    "busy": (BUSY, "spin"),
    "error": (ERR, "cross"),
    "fallback": (WARN, "tri"),
    # Утечка — крест на сплошном круге: VPN поднят, а трафик идёт мимо, и
    # значок не должен совпадать с «не запускается».
    "leak": (ERR, "leak"),
}


def rgba(color):
    """Цвет «#rrggbb» → (r, g, b, 255)."""
    return (*bytes.fromhex(color[1:]), 255)


def draw(size):
    """Значок приложения size×size."""
    g = LITE if size <= SMALL else FULL
    fan = g["fan"]
    ops = [_plate(g["radius"], BG), *_arch(g["arch"], g["arch_w"], LIGHT),
           *(_line(fan, (x, y), g["stripe_w"], c) for x, y, c in g["stripes"])]
    return _render(size, ops)


def tray(state, size=16):
    """Значок трея состояния state (ключ TRAY) ровно в size точек."""
    color, mark = TRAY.get(state, TRAY["off"])
    ops = [*_arch(TRAY_ARCH, TRAY_ARCH_W, color), *_mark(mark, color)]
    return _render(size, ops, outline=OUTLINE)


def arch_path(g=FULL):
    x0, x1, cy, bottom = g["arch"]
    r = (x1 - x0) / 2
    return (f"M{_n(x0)} {_n(bottom)}V{_n(cy)}"
            f"a{_n(r)} {_n(r)} 0 0 1 {_n(x1 - x0)} 0v{_n(bottom - cy)}")


def stripe_paths(g=FULL):
    """[(d, цвет)] полос."""
    fx, fy = g["fan"]
    return [(f"M{_n(fx)} {_n(fy)} {_n(x)} {_n(y)}", c) for x, y, c in g["stripes"]]


def svg():
    """Текст assets/icon.svg: большой рисунок теми же числами."""
    line = 'fill="none" stroke="{}" stroke-width="{}" stroke-linecap="round"'
    parts = [f'<rect width="32" height="32" rx="{_n(FULL["radius"])}" fill="{BG}"/>',
             f'<path d="{arch_path()}" {line.format(LIGHT, _n(FULL["arch_w"]))}/>']
    parts += [f'<path d="{d}" {line.format(c, _n(FULL["stripe_w"]))}/>'
              for d, c in stripe_paths()]
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
            + "".join(parts) + "</svg>\n")


# ------------------------------------------------------------- рисование
#
# Фигура — функция op(d, k, grow, over): рисует себя на ImageDraw d при
# k точках холста на единицу сетки, толще на grow единиц с каждой стороны и
# цветом over вместо своего (так рисуется обводка под всем рисунком).

def _render(size, ops, outline=None):
    """Фигуры в сетке 32×32 → картинка size×size. Рисуем крупно и уменьшаем:
    линия в одну-две точки без сглаживания выходит рваной. outline — цвет
    обводки шириной в одну точку результата."""
    from PIL import Image, ImageDraw

    big = max(512, size * 4)
    k = big / 32
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if outline:
        for op in ops:
            op(d, k, 32 / size, rgba(outline))
    for op in ops:
        op(d, k, 0, None)
    return img.resize((size, size), Image.LANCZOS)


def _n(v):
    return f"{v:g}"


def _mix(a, b, t):
    """Цвет a, сдвинутый к b на долю t, непрозрачный: полупрозрачная
    фигура стёрла бы обводку под собой."""
    return tuple(round(x + (y - x) * t) for x, y in zip(rgba(a), rgba(b)))


def _dot(d, x, y, r, fill):
    d.ellipse((x - r, y - r, x + r, y + r), fill=fill)


def _plate(radius, color):
    """Подложка во весь значок. Без обводки: она и есть край."""
    def op(d, k, grow, over):
        if not grow:
            d.rounded_rectangle((0, 0, 32 * k - 1, 32 * k - 1),
                                radius=radius * k, fill=color)
    return op


def _line(p, q, w, color):
    """Отрезок толщиной w с круглыми концами."""
    def op(d, k, grow, over):
        fill = over or color
        half = (w / 2 + grow) * k
        d.line([(p[0] * k, p[1] * k), (q[0] * k, q[1] * k)], fill=fill,
               width=round(2 * half))
        for x, y in (p, q):
            _dot(d, x * k, y * k, half, fill)
    return op


def _disc(c, r, color):
    def op(d, k, grow, over):
        _dot(d, c[0] * k, c[1] * k, (r + grow) * k, over or color)
    return op


def _arc(c, r, w, color, start=0, end=360):
    """Дуга радиуса r по оси линии толщиной w; углы — по часовой от «трёх
    часов». Неполная — с круглыми концами."""
    def op(d, k, grow, over):
        fill = over or color
        half = (w / 2 + grow) * k
        x, y, rr = c[0] * k, c[1] * k, r * k
        # Pillow ведёт толщину от рамки внутрь: рамка — по внешнему краю.
        d.arc((x - rr - half, y - rr - half, x + rr + half, y + rr + half),
              start, end, fill=fill, width=round(2 * half))
        if end - start < 360:
            for a in (math.radians(start), math.radians(end)):
                _dot(d, x + rr * math.cos(a), y + rr * math.sin(a), half, fill)
    return op


def _poly(pts, color):
    """Залитый многоугольник; обводка — его рёбра линией толщиной 2·grow."""
    def op(d, k, grow, over):
        fill = over or color
        d.polygon([(x * k, y * k) for x, y in pts], fill=fill)
        if grow:
            for p, q in zip(pts, pts[1:] + pts[:1]):
                _line(p, q, 0, fill)(d, k, grow, over)
    return op


def _arch(geom, w, color):
    """Арка: две ноги и полукруг между ними."""
    x0, x1, cy, bottom = geom
    r = (x1 - x0) / 2
    return [_line((x0, bottom), (x0, cy), w, color),
            _line((x1, bottom), (x1, cy), w, color),
            _arc((x0 + r, cy), r, w, color, 180, 360)]


def _cross(h, w, color):
    x, y = MARK
    return [_line((x - h, y - h), (x + h, y + h), w, color),
            _line((x + h, y - h), (x - h, y + h), w, color)]


def _mark(kind, color):
    """Знак состояния под аркой — те же формы, что у статусов окна."""
    x, y = MARK
    if kind == "dot":
        return [_disc(MARK, 5, color)]
    if kind == "ring":
        return [_arc(MARK, 4.4, 2.6, color)]
    if kind == "spin":
        # Яркая половина: четверть круга в 16 точек не отличить от кольца.
        return [_arc(MARK, 4.4, 2.6, _mix(color, OUTLINE, 0.55)),
                _arc(MARK, 4.4, 2.6, color, -90, 90)]
    if kind == "tri":
        return [_poly(((x, y - 5.6), (x + 6, y + 4.6), (x - 6, y + 4.6)), color)]
    if kind == "cross":
        return _cross(3.8, 3.0, color)
    return [_disc(MARK, 6.2, color), *_cross(2.9, 2.2, OUTLINE)]    # leak


def write_ico(path):
    """Пишет ico со всеми размерами из SIZES."""
    images = [draw(s) for s in SIZES]
    images[-1].save(path, format="ICO",
                    sizes=[(s, s) for s in SIZES], append_images=images[:-1])
    return path
