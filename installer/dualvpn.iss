; Установщик DualVPN. Собирается из installer\build.ps1, руками звать не нужно.
;
; Что делает сверх обычного копирования файлов:
;   * заводит C:\ProgramData\DualVPN с раздельными правами на conf\ и state\
;   * ставит и запускает службу DualVPN
;   * при удалении снимает службу, но оставляет конфиги
;   * поверх установленной версии спрашивает: обновить или удалить
;   * тихое обновление возвращает туннель и трей, как они были
;
; ВАЖНО: файл в UTF-8 С BOM. Без BOM Inno Setup читает его как ANSI, и вся
; кириллица в подписях кнопок и сообщениях превращается в мусор. Та же беда,
; что и у build.ps1. Не пересохраняй без BOM.

#ifndef MyVersion
  #define MyVersion "0.0.0"
#endif

#define MyName "DualVPN"
#define MyExe "DualVPN-Tray.exe"
#define MyCli "dualvpn.exe"

[Setup]
; Тот же GUID — в UninstKey в [Code]: по нему ищется установленная версия.
AppId={{8F3A5C21-4E7B-4D96-9A1F-2C6B8D4E7A31}
AppName={#MyName}
AppVersion={#MyVersion}
AppPublisher=Enkeym
AppUpdatesURL=https://github.com/enkeym/dual-vpn
DefaultDirName={autopf}\{#MyName}
DefaultGroupName={#MyName}
UninstallDisplayIcon={app}\{#MyExe}
OutputDir=Output
OutputBaseFilename={#MyName}-{#MyVersion}-setup
SetupIconFile=DualVPN.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Служба ставится в систему и правит маршруты — без администратора никак.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
; Windows 10 1809 — минимум, где WebView2 и wintun ведут себя предсказуемо.
MinVersion=10.0.17763

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "autorun"; Description: "Запускать значок в трее при входе в систему"; \
  GroupDescription: "Дополнительно:"
Name: "desktopicon"; Description: "Значок на рабочем столе"; \
  GroupDescription: "Дополнительно:"; Flags: unchecked

[Files]
; uninsrestartdelete: файл, который при удалении занят (служба журнала событий
; держит servicemanager.pyd, если хоть раз показывала записи службы), удаляется
; при перезагрузке, а не остаётся в Program Files навсегда.
Source: "..\dist\DualVPN\*"; DestDir: "{app}"; \
  Flags: ignoreversion recursesubdirs createallsubdirs uninsrestartdelete
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Данные переживают обновление и удаление: uninsneveruninstall на conf\.
Name: "{commonappdata}\{#MyName}"
Name: "{commonappdata}\{#MyName}\conf"; Flags: uninsneveruninstall
Name: "{commonappdata}\{#MyName}\state"; Flags: uninsneveruninstall
Name: "{commonappdata}\{#MyName}\state\logs"; Flags: uninsneveruninstall

[Icons]
Name: "{group}\{#MyName}"; Filename: "{app}\{#MyExe}"
Name: "{group}\Удалить {#MyName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyName}"; Filename: "{app}\{#MyExe}"; Tasks: desktopicon
; Автозапуск трея — задачей планировщика (см. RegisterTrayTask в [Code]).

[InstallDelete]
; Ярлык автозапуска из прошлых версий: трей теперь требует администратора,
; и из «Автозагрузки» Windows его просто не запустит.
Type: files; Name: "{userstartup}\{#MyName}.lnk"
; Образцы конфигов, которые клали версии до 0.2.9: их больше не поставляем.
Type: filesandordirs; Name: "{app}\examples"

[Run]
; --- Права на данные.
; conf\ содержит приватные ключи: доступ только SYSTEM и администраторам.
; Обычный пользователь работает с конфигами через службу (см. ipc.py), а не
; напрямую по файловой системе.
Filename: "{sys}\icacls.exe"; \
  Parameters: """{commonappdata}\{#MyName}\conf"" /inheritance:r \
    /grant:r ""*S-1-5-18"":(OI)(CI)F /grant:r ""*S-1-5-32-544"":(OI)(CI)F"; \
  Flags: runhidden waituntilterminated; StatusMsg: "Настраиваю права доступа..."
; state\ читают трей и окно от обычного пользователя: там status.json и логи.
Filename: "{sys}\icacls.exe"; \
  Parameters: """{commonappdata}\{#MyName}\state"" /inheritance:r \
    /grant:r ""*S-1-5-18"":(OI)(CI)F /grant:r ""*S-1-5-32-544"":(OI)(CI)F \
    /grant:r ""*S-1-5-11"":(OI)(CI)RX"; \
  Flags: runhidden waituntilterminated

; --- Служба. Прошлую не снимаем: «service install» у существующей службы сам
; переходит в update (ChangeServiceConfig) и переписывает путь к exe. Снятие
; перед установкой только помечало службу на удаление, если кто-то держал её
; дескриптор, и install падал с 1072 — служба пропадала до перезагрузки.
Filename: "{app}\{#MyCli}"; Parameters: "service stop"; \
  Flags: runhidden waituntilterminated skipifdoesntexist; StatusMsg: "Обновляю службу..."
Filename: "{app}\{#MyCli}"; Parameters: "service install"; \
  Flags: runhidden waituntilterminated; StatusMsg: "Устанавливаю службу..."
; Автозапуск службы: значок в трее без неё бесполезен, а ждать ручного
; запуска после каждой перезагрузки — не то, чего ждут от VPN-клиента.
Filename: "{sys}\sc.exe"; Parameters: "config {#MyName} start= auto"; \
  Flags: runhidden waituntilterminated
; Служба переживает падение: маршруты без неё убрать некому.
Filename: "{sys}\sc.exe"; \
  Parameters: "failure {#MyName} reset= 86400 actions= restart/5000/restart/10000/restart/30000"; \
  Flags: runhidden waituntilterminated
Filename: "{app}\{#MyCli}"; Parameters: "service start"; \
  Flags: runhidden waituntilterminated; AfterInstall: RestoreAfterUpdate

; runascurrentuser: трей работает от администратора, а установщик уже с правами.
; По умолчанию postinstall запускает от исходного пользователя без прав, и
; трей спросил бы UAC ещё раз (см. tray.run).
Filename: "{app}\{#MyExe}"; Description: "Запустить {#MyName}"; \
  Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; Трей — отдельный процесс со своим списком открытых файлов в _internal\
; (общих с dualvpn.exe). Пока он жив, деинсталлятор не может удалить папку и
; падает на «файл занят» — снятие службы ниже этого не решает вовсе, служба
; и трей друг с другом никак не связаны. Убиваем первым делом, до всего.
; /T — вместе с окном, которое трей держит прогретым (dualvpn.exe window).
Filename: "{sys}\taskkill.exe"; Parameters: "/IM {#MyExe} /F /T"; \
  Flags: runhidden waituntilterminated; RunOnceId: "KillTray"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""{#MyName} Tray"" /F"; \
  Flags: runhidden waituntilterminated; RunOnceId: "DelTrayTask"
; Порядок важен: сначала опустить туннель, потом снимать службу. Иначе
; маршруты и правило брандмауэра останутся висеть, и сеть будет смотреть
; в удалённый адаптер.
Filename: "{app}\{#MyCli}"; Parameters: "stop"; \
  Flags: runhidden waituntilterminated; RunOnceId: "StopTunnel"
; net stop, а не «dualvpn service stop»: тот только посылает команду и сразу
; выходит, и файлы ещё заняты процессом службы, когда их начинают удалять.
Filename: "{sys}\net.exe"; Parameters: "stop {#MyName}"; \
  Flags: runhidden waituntilterminated; RunOnceId: "StopService"
; Окно, пережившее трей, держит dualvpn.exe и _internal\. Служба уже
; остановлена, так что под этим именем остались только окна.
Filename: "{sys}\taskkill.exe"; Parameters: "/IM {#MyCli} /F /T"; \
  Flags: runhidden waituntilterminated; RunOnceId: "KillWindow"
Filename: "{app}\{#MyCli}"; Parameters: "service remove"; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
; Логи и рабочее состояние уносим, конфиги — нет: их клали руками, и
; восстанавливать ключи после переустановки человек не обязан.
Type: filesandordirs; Name: "{commonappdata}\{#MyName}\state"
; Всё, что появилось в папке программы уже после установки, — её же мусор.
Type: filesandordirs; Name: "{app}"

[Code]
const
  UninstKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8F3A5C21-4E7B-4D96-9A1F-2C6B8D4E7A31}_is1';

var
  // Меню «уже установлено»; nil — ставим впервые.
  ActionPage: TInputOptionWizardPage;
  OldUninstaller: String;
  // Удаление из меню прошло — закрываем мастер без «Выйти из установки?».
  Leaving: Boolean;
  // Что было до обновления: RestoreAfterUpdate возвращает так же.
  TunnelWasUp, TrayWasRunning: Boolean;

// Закрывает трей, окно и службу: иначе файлы заняты (служба работает из
// {app}\dualvpn.exe) и обновление падает на середине, оставляя половину
// старой версии. net stop, а не sc stop: ждёт, пока служба действительно
// остановится и опустит туннель. dualvpn.exe убиваем только после неё —
// под этим именем работает и служба, и окно трея.
procedure StopEverything;
var
  ResultCode: Integer;
  Status: AnsiString;
begin
  // /T — вместе с окном, которое трей держит прогретым. 0 — было что убить.
  TrayWasRunning := Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM {#MyExe} /F /T',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  // status.json пишет служба (probe.py:write_status), отступ 1 — "up": true.
  TunnelWasUp := LoadStringFromFile(
       ExpandConstant('{commonappdata}\{#MyName}\state\status.json'), Status)
       and (Pos('"up": true', Status) > 0);
  // Служба не работала — status.json старый, туннеля не было.
  if not Exec(ExpandConstant('{sys}\net.exe'), 'stop {#MyName}',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    TunnelWasUp := False;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM {#MyCli} /F /T',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// После запуска новой службы — как было до обновления. Туннель при
// включённом автоподключении служба поднимет сама. Трей в обычном режиме
// запускает галочка на последней странице, а тихий её не показывает:
// возвращаем его так же, как при входе, — только значок.
procedure RestoreAfterUpdate;
var
  I, ResultCode: Integer;
begin
  if TunnelWasUp and not FileExists(ExpandConstant('{commonappdata}\{#MyName}\state\autostart')) then
    // Канал службы поднимается не сразу после service start.
    for I := 1 to 5 do
    begin
      if Exec(ExpandConstant('{app}\{#MyCli}'), 'start', '', SW_HIDE,
              ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
        Break;
      Sleep(3000);
    end;
  if TrayWasRunning and WizardSilent then
    Exec(ExpandConstant('{app}\{#MyExe}'), '--background', '', SW_SHOWNORMAL,
         ewNoWait, ResultCode);
end;

// Повторный запуск setup: обновить или удалить. В тихом режиме страниц нет,
// выбран первый пункт — обновление (так ставит процедура из CLAUDE.md).
procedure InitializeWizard;
var
  OldVersion, Title: String;
begin
  if not RegQueryStringValue(HKLM64, UninstKey, 'UninstallString', OldUninstaller) then
    Exit;
  RegQueryStringValue(HKLM64, UninstKey, 'DisplayVersion', OldVersion);
  if OldVersion = '{#MyVersion}' then
    Title := 'Переустановить версию {#MyVersion}'
  else
    Title := 'Обновить до версии {#MyVersion}';
  if OldVersion = '' then
    OldVersion := 'прошлая';
  ActionPage := CreateInputOptionPage(wpWelcome,
    '{#MyName} уже установлен', 'Установлена версия ' + OldVersion + '. Что сделать?',
    'При обновлении конфиги, ключи VPN и настройки остаются на месте.',
    True, False);
  ActionPage.Add(Title);
  ActionPage.Add('Удалить {#MyName}, конфиги и ключи VPN оставить');
  ActionPage.Add('Удалить {#MyName} полностью, вместе с конфигами и ключами VPN');
  ActionPage.SelectedValueIndex := 0;
end;

// Данные WebView2 окна (window.py:_storage_path). Только эти папки, не весь
// %LOCALAPPDATA%\DualVPN: туда кладёт конфиги портативная версия.
procedure DeleteWindowData;
begin
  DelTree(ExpandConstant('{localappdata}\{#MyName}\WebView2-admin'), True, True, True);
  DelTree(ExpandConstant('{localappdata}\{#MyName}\WebView2-user'), True, True, True);
  RemoveDir(ExpandConstant('{localappdata}\{#MyName}'));
end;

// Удаление прежней установкой: её деинсталлятор знает, что она ставила.
// Трей, окно и службу гасим сами, папки окна чистим тоже — деинсталляторы
// до этой версии не делали ни того, ни другого. /SILENT: вопрос про конфиги
// уже задан в меню, а прогресс пусть будет виден.
function RunUninstaller(Purge: Boolean): Boolean;
var
  ResultCode: Integer;
begin
  StopEverything;
  Result := Exec(RemoveQuotes(OldUninstaller), '/SILENT /SUPPRESSMSGBOXES /NORESTART',
                 '', SW_SHOW, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  if not Result then
  begin
    MsgBox('Удалить не получилось: деинсталлятор вернул ' + IntToStr(ResultCode) + '.' + #13#10 +
           'Попробуй через «Параметры → Приложения».', mbError, MB_OK);
    Exit;
  end;
  DeleteWindowData;
  if Purge then
    DelTree(ExpandConstant('{commonappdata}\{#MyName}'), True, True, True);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (ActionPage = nil) or (CurPageID <> ActionPage.ID) or
     (ActionPage.SelectedValueIndex = 0) then
    Exit;
  Result := False;
  if RunUninstaller(ActionPage.SelectedValueIndex = 2) then
  begin
    MsgBox('{#MyName} удалён.', mbInformation, MB_OK);
    Leaving := True;
    WizardForm.Close;
  end;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if Leaving then
    Confirm := False;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  SmPyd, Old: String;
begin
  StopEverything;

  // Версии до 0.2.7 писали в журнал событий, и служба журнала держит
  // servicemanager.pyd загруженным до перезагрузки: перезаписать его нельзя,
  // и установка встала бы на «файл занят». Загруженную DLL можно
  // переименовать — убираем её с дороги, а старую копию удалит перезагрузка.
  SmPyd := ExpandConstant('{app}\_internal\win32\servicemanager.pyd');
  if FileExists(SmPyd) and not DeleteFile(SmPyd) then
  begin
    Old := SmPyd + '.old';
    DeleteFile(Old);
    if RenameFile(SmPyd, Old) then
    begin
      RestartReplace(Old, '');
      // И папки за ним — иначе после удаления программы и перезагрузки
      // оставались бы пустые _internal\win32. Непустые Windows не тронет.
      RestartReplace(ExtractFileDir(SmPyd), '');
      RestartReplace(ExtractFileDir(ExtractFileDir(SmPyd)), '');
      RestartReplace(ExpandConstant('{app}'), '');
    end;
  end;
  Result := '';
end;

// Автозапуск трея при входе. Задача планировщика с наивысшими правами, а не
// ярлык в «Автозагрузке»: трей требует администратора, и оттуда Windows его
// не запускает. Без ограничения по времени (по умолчанию задачу снимают
// через 72 часа) и без остановки при переходе на батарею.
// --background: при входе только значок, панель управления не выскакивает.
procedure RegisterTrayTask;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -ExecutionPolicy Bypass -Command "' +
    '$u = [Security.Principal.WindowsIdentity]::GetCurrent().Name; ' +
    '$a = New-ScheduledTaskAction -Execute ''' + ExpandConstant('{app}\{#MyExe}') +
    ''' -Argument ''--background''; ' +
    '$t = New-ScheduledTaskTrigger -AtLogOn -User $u; ' +
    '$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest; ' +
    '$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) ' +
    '-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew; ' +
    'Register-ScheduledTask -TaskName ''{#MyName} Tray'' -Action $a -Trigger $t ' +
    '-Principal $p -Settings $s -Force | Out-Null"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Конфиги по умолчанию переживают удаление: в них ключи, и после
// переустановки человек не обязан их восстанавливать. Но если удаляют совсем,
// оставлять каталог молча — это мусор. Спрашиваем; по умолчанию «Нет».
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    DeleteWindowData;
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
    if MsgBox('Удалить также конфиги и ключи VPN?' + #13#10 + #13#10 +
              ExpandConstant('{commonappdata}\{#MyName}') + #13#10 + #13#10 +
              'Если собираешься поставить DualVPN заново, ответь «Нет» — ' +
              'конфиги останутся и подхватятся.',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{commonappdata}\{#MyName}'), True, True, True);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('autorun') then
      RegisterTrayTask
    else
      // Галочку сняли при обновлении — убираем задачу прошлой установки.
      Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "{#MyName} Tray" /F',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
