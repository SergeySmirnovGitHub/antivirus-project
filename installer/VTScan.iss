; Установщик VTScan (VTScan-Setup.exe) — собирается в облаке через Inno Setup (ISCC).
; Ставит приложение в свою папку %LOCALAPPDATA%\VTScan (без прав администратора),
; туда же приложение потом качает ClamAV (критерий «одна папка»). Аналог обычного
; setup.exe (как MicrosoftEdgeWebView2Setup.exe — маленький .exe, не архив).

#define MyVersion GetEnv("GITHUB_REF_NAME")
#if MyVersion == ""
  #define MyVersion "dev"
#endif

[Setup]
AppId={{8F3A1C90-7B2E-4D6F-A1E5-9C0B2D4E6F80}
AppName=VTScan
AppVersion={#MyVersion}
AppPublisher=VTScan
DefaultDirName={localappdata}\VTScan
DefaultGroupName=VTScan
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=installer\Output
OutputBaseFilename=VTScan-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SourceDir=..
; Повторный запуск = ОБНОВЛЕНИЕ существующей установки (а не дубликат):
UsePreviousAppDir=yes
CloseApplications=yes
RestartApplications=no
DisableWelcomePage=no

[Files]
Source: "dist\VTScan.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\vtscan-cli.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\VTScan"; Filename: "{app}\VTScan.exe"
Name: "{group}\Удалить VTScan"; Filename: "{uninstallexe}"
Name: "{userdesktop}\VTScan"; Filename: "{app}\VTScan.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительно:"
Name: "getclamav"; Description: "Скачать офлайн-движок ClamAV сейчас (~300 МБ)"; GroupDescription: "Дополнительно:"; Flags: unchecked

[Run]
Filename: "{app}\vtscan-cli.exe"; Parameters: "--setup-clamav"; Description: "Загрузка ClamAV"; Tasks: getclamav; Flags: postinstall
Filename: "{app}\VTScan.exe"; Description: "Запустить VTScan"; Flags: nowait postinstall skipifsilent

[Code]
{ Если VTScan уже установлен — показываем, что это ОБНОВЛЕНИЕ, а не новая установка. }
procedure InitializeWizard();
var v: String;
begin
  if RegQueryStringValue(HKCU,
       'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8F3A1C90-7B2E-4D6F-A1E5-9C0B2D4E6F80}_is1',
       'DisplayVersion', v) then
    WizardForm.WelcomeLabel2.Caption :=
      'VTScan уже установлен (версия ' + v + ').' + #13#10 + #13#10 +
      'Этот мастер ОБНОВИТ программу до версии {#MyVersion}, не создавая копий. Нажмите «Далее».';
end;

{ Перед копированием файлов принудительно закрываем запущенный VTScan, иначе при
  обновлении exe занят и Windows выдаёт «отказано в доступе». }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer;
begin
  Exec('taskkill.exe', '/F /IM VTScan.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec('taskkill.exe', '/F /IM vtscan-cli.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Sleep(700);
  Result := '';
end;
