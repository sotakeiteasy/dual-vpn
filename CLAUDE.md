# DualVPN

Windows app (service, tray, WebView2, sing-box). Code is edited from WSL Ubuntu but runs on Windows:
call the Windows binaries that WSL interop puts in PATH. Do not install Linux Python, pytest or sing-box.

## Run from WSL

Always launch as administrator: the tray, the CLI and every command touching the service, tunnel or routes
go through `Start-Process … -Verb RunAs` (see Limits), never as an unelevated user.

From the project root:

- Tests: `python.exe -m pytest tests -q`; one test: `python.exe -m pytest tests/<file>.py -q -k <name>`
- Dependencies: `python.exe -m pip install -r requirements.txt`
- CLI: `python.exe installer/entry_cli.py <args>`; tray: `python.exe installer/entry_tray.py`.
  From source, `lib/` must be on `PYTHONPATH`, else `No module named 'dualvpn'`:
  `PYTHONPATH="$(wslpath -w lib)" WSLENV=PYTHONPATH/w python.exe installer/entry_tray.py`
- Build and installer: `powershell.exe -NoProfile -File "$(wslpath -w installer/build.ps1)"`
- Any other Windows command: `powershell.exe -NoProfile -Command '<command>'`

## Limits

- Anything needing administrator rights (service start/install, wintun, routes): run it yourself, the user
  confirms the UAC prompt. Never hand the command back to the user:
  `powershell.exe -NoProfile -Command 'Start-Process <exe> -ArgumentList <args> -Verb RunAs -Wait'`
  (e.g. `Start-Process sc.exe -ArgumentList "start","DualVPN" -Verb RunAs -Wait`).
- Windows sees the project as `\\wsl.localhost\Ubuntu\...`: call `python.exe` and `powershell.exe`
  directly (`cmd.exe` rejects a UNC working directory) and convert path arguments with `wslpath -w`.
