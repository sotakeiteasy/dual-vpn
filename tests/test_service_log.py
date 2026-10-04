"""Журнал службы: по штампам соседних строк меряют шаги включения."""

import re

from dualvpn import service
from dualvpn.service import Core


def test_штамп_с_миллисекундами(monkeypatch, tmp_path):
    log = tmp_path / "service.log"
    monkeypatch.setattr(service, "SERVICE_LOG", str(log))

    Core.log(None, "→ собираю конфиг")

    assert re.fullmatch(r"\d\d:\d\d:\d\d\.\d{3} → собираю конфиг\n",
                        log.read_text(encoding="utf-8"))
