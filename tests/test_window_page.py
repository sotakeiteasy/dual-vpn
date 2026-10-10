"""Окно: адрес страницы несёт метку версии всей вёрстки.

Страница передаёт метку app.css и js/*.js: иначе после обновления WebView2
взял бы их прежние копии из своего кэша. Мок предпросмотра (ui/dev) в метку
не входит — его в сборке нет.
"""

import os

from tunnelvpn import window


def _ui(tmp_path):
    ui = tmp_path / "ui"
    (ui / "js").mkdir(parents=True)
    (ui / "dev").mkdir()
    files = {"index.html": 100, "app.css": 300, "js/core.js": 200, "dev/mock-api.js": 900}
    for name, stamp in files.items():
        path = ui / name
        path.write_text("x", encoding="utf-8")
        os.utime(path, ns=(stamp * 10**9, stamp * 10**9))
    return ui


def test_метка_по_самому_свежему_файлу_вёрстки(tmp_path):
    index = str(_ui(tmp_path) / "index.html")

    assert window._page_url(index) == f"{index}?v={300 * 10**9}"


def test_правка_скрипта_меняет_метку(tmp_path):
    ui = _ui(tmp_path)
    os.utime(ui / "js" / "core.js", ns=(500 * 10**9, 500 * 10**9))

    assert window._page_url(str(ui / "index.html")).endswith(f"?v={500 * 10**9}")
