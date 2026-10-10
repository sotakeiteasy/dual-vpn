"""Общая обвязка тестов.

Данные уводим в отдельный каталог ДО импорта пакета: paths читает
TUNNELVPN_DATA при импорте и определяет раскладку один раз на весь процесс.
Без этого тесты лезли бы в настоящий C:\\ProgramData\\TunnelVPN — а на машине
разработчика там лежат живые ключи.

Тесты работают на любой ОС: всё, что здесь проверяется, — чистая логика без
обращений к сети и системе. Поведение Windows (каналы, PowerShell, службы)
так не проверить, для него нужна настоящая машина.
"""

import atexit
import os
import shutil
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA = tempfile.mkdtemp(prefix="tunnelvpn-tests-")

# Каталог свой на каждый прогон, иначе %TEMP% зарастает сотнями tunnelvpn-tests-*.
atexit.register(shutil.rmtree, _DATA, ignore_errors=True)
os.environ["TUNNELVPN_DATA"] = _DATA
for _sub in ("conf", "state", os.path.join("state", "logs")):
    os.makedirs(os.path.join(_DATA, _sub), exist_ok=True)

sys.path.insert(0, os.path.join(_ROOT, "lib"))
