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
- Build and installer: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w installer/build.ps1)"`
  (without `Bypass` the Windows execution policy refuses the script)
- Any other Windows command: `powershell.exe -NoProfile -Command '<command>'`

## Updating the installed build

The setup stops the service and drops the tunnel, so the user's connection (and this session's API calls)
goes down. Update only silently, then put everything back in the same command:

1. Note `& "C:\Program Files\DualVPN\dualvpn.exe" status` first: was the tunnel `работает`?
2. `$p = Start-Process '<setup.exe>' -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Verb RunAs -PassThru; $p.WaitForExit()`,
   via Bash `run_in_background` with output to `/tmp/`. Not `-Wait`: it waits for the whole process tree, and the
   setup ends by starting the tray, so the command never returns. Never bare `/SILENT` — that run once ended with
   the service removed and not reinstalled.
3. `sc.exe query DualVPN` must be `RUNNING`. Service missing → rerun the setup's own steps elevated:
   `dualvpn.exe service install`, `sc.exe config DualVPN start= auto`,
   `sc.exe failure DualVPN reset= 86400 actions= restart/5000/restart/10000/restart/30000`, `dualvpn.exe service start`.
4. Tunnel was up → `dualvpn.exe start` elevated; restart the tray (`DualVPN-Tray.exe`, RunAs) if it is gone.
5. Confirm with `dualvpn.exe status`: `работает`, routes present, exit через туннель.

## Limits

- Anything needing administrator rights (service start/install, wintun, routes): run it yourself, the user
  confirms the UAC prompt. Never hand the command back to the user:
  `powershell.exe -NoProfile -Command 'Start-Process <exe> -ArgumentList <args> -Verb RunAs -Wait'`
  (e.g. `Start-Process sc.exe -ArgumentList "start","DualVPN" -Verb RunAs -Wait`).
- Windows sees the project as `\\wsl.localhost\Ubuntu\...`: call `python.exe` and `powershell.exe`
  directly (`cmd.exe` rejects a UNC working directory) and convert path arguments with `wslpath -w`.
