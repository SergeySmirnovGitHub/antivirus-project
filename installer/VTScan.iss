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
