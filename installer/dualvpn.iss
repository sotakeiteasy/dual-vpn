; Установщик DualVPN. Собирается из installer\build.ps1, руками звать не нужно.
;
; Что делает сверх обычного копирования файлов:
;   * заводит C:\ProgramData\DualVPN с раздельными правами на conf\ и state\
;   * ставит и запускает службу DualVPN
;   * при удалении снимает службу, но оставляет конфиги
;
; ВАЖНО: файл в UTF-8 С BOM. Без BOM Inno Setup читает его как ANSI, и вся
; кириллица в подписях кнопок и сообщениях превращается в мусор. Та же беда,
; что и у build.ps1. Не пересохраняй без BOM.

#ifndef MyVersion
  #define MyVersion "0.0.0"
#endif

#define MyName "DualVPN"
#define MyExe "DualVPN.exe"
#define MyCli "dualvpn.exe"

[Setup]
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
Source: "..\dist\DualVPN\*"; DestDir: "{app}"; \
  Flags: ignoreversion recursesubdirs createallsubdirs
; Образцы конфигов кладём рядом с программой, а не в conf\: в conf\ лежат
; настоящие ключи, и подмешивать туда примеры при обновлении незачем.
Source: "..\conf\*.example"; DestDir: "{app}\examples"; Flags: ignoreversion
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
Name: "{userstartup}\{#MyName}"; Filename: "{app}\{#MyExe}"; Tasks: autorun

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

; --- Служба. Снимаем прошлую до установки новой: при обновлении в реестре
; остаётся путь к старой папке, и служба стартовала бы из уже удалённой.
Filename: "{app}\{#MyCli}"; Parameters: "service stop"; \
  Flags: runhidden waituntilterminated skipifdoesntexist; StatusMsg: "Обновляю службу..."
Filename: "{app}\{#MyCli}"; Parameters: "service remove"; \
  Flags: runhidden waituntilterminated skipifdoesntexist
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
  Flags: runhidden waituntilterminated

Filename: "{app}\{#MyExe}"; Description: "Запустить {#MyName}"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
; Порядок важен: сначала опустить туннель, потом снимать службу. Иначе
; маршруты и правило брандмауэра останутся висеть, и сеть будет смотреть
; в удалённый адаптер.
Filename: "{app}\{#MyCli}"; Parameters: "stop"; \
  Flags: runhidden waituntilterminated; RunOnceId: "StopTunnel"
Filename: "{app}\{#MyCli}"; Parameters: "service stop"; \
  Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\{#MyCli}"; Parameters: "service remove"; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
; Логи и рабочее состояние уносим, конфиги — нет: их клали руками, и
; восстанавливать ключи после переустановки человек не обязан.
Type: filesandordirs; Name: "{commonappdata}\{#MyName}\state"

[Code]
// Перед установкой закрываем трей: иначе файлы заняты и обновление падает
// на середине, оставляя половину старой версии.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM {#MyExe} /F',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;
