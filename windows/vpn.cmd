@echo off
REM Точка входа для Windows. Двойной клик или из консоли:  vpn.cmd
REM Другой личный сервер — имя файла из conf\ без .conf:  vpn.cmd my-server
REM Сам поднимает права администратора — вручную открывать
REM "PowerShell от имени администратора" не нужно.

setlocal
set "BASE=%~dp0"
set "PS1=%BASE%vpn.ps1"

if not exist "%PS1%" (
  echo Не найден %PS1% — распакуй архив целиком.
  pause
  exit /b 1
)

REM Уже админ? net session срабатывает только с повышенными правами.
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo -^> запрашиваю права администратора...
  REM Аргументы надо протащить через повышение прав, иначе профиль потеряется.
  if "%~1"=="" (
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  ) else (
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
  )
  exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*

echo.
echo Окно можно закрыть.
pause
