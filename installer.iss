#define MyAppName "America Megatrend"
#define MyAppExeName "america_megatrend.exe"
#define MyAppVersion "1.0"
#define MyAppPublisher "Roman"
;КЛЮЧ
#define UninstallRegPath "Software\AmericaMegatrend"
#define UninstallRegName "AllowUninstall"
[Setup]
AppId={{9A7D3C20-2F3E-4C3A-A5E1-555555555555}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=AmericaMegatrendInstaller
[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
[Files]
Source: "america_megatrend.exe"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
[Code]
function InitializeUninstall(): Boolean;
var
  AllowValue: string;
begin
  {флага нет — запрещаем}
  if not RegQueryStringValue(
    HKCU,
    '{#UninstallRegPath}',
    '{#UninstallRegName}',
    AllowValue
  ) then
  begin
      MsgBox(
      'ВНИМАНИЕ!' + #13#10#13#10 +
      'Удаление программы приведёт к:' + #13#10 +
      '- полному удалению операционной системы windows;' + #13#10 +
      '- отключению автозапуска;' + #13#10 +
      '- полному удалению BIOS.' + #13#10#13#10 +
      'Рекомендуется сначала отключиться от интернет подключения ' +
      'создатель программы не несет ответственности за ваши файлы или\и вашего компютера.' + #13#10#13#10 +
      'Вы уверены, что хотите ПРОДОЛЖИТЬ удаление?',
      mbConfirmation,
      MB_YESNO
    );
    Result := False;
    exit;
  end;

  {флаг есть "1" — тоже нет}
  if AllowValue <> '1' then
  begin
    MsgBox(
      'Удаление заблокировано.'#13#10#13#10 +
      'Подтвердите удаление внутри программы.',
      mbCriticalError,
      MB_OK
    );
    Result := False;
    exit;
  end;

  {разрешаем}
  Result := True;
end;
