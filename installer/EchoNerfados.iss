; Echo Nerfados Shield XDR — Inno Setup 6 Installer Script
; Build: scripts\package.ps1
; Version override: iscc.exe /DAppVersion=1.0.0 installer\EchoNerfados.iss

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

#define AppName      "Echo Nerfados Shield XDR"
#define AppShortName "EchoNerfados"
#define AppPublisher "Nerfados"
#define AppURL       "https://nerfados.gg"
#define AppExeName   "EchoNerfados.App.exe"
#define AppCliName   "EchoNerfados.exe"

[Setup]
; Stable GUID — do NOT change between versions (upgrade detection depends on this)
AppId={{5E8D7F2A-9C3B-4E1D-8F6A-2D7C1E4B9F3A}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppShortName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename={#AppShortName}Setup-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
; Windows 10 version 2004 (19041) minimum — required for .NET 8 and modern APIs
MinVersion=10.0.19041
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
CloseApplications=force
; Signing: if signing installer externally, set SignTool in package.ps1 instead
; SetupSignedUninstaller=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Dirs]
; ProgramData: license.nerf is placed here by the operator (admin).
; Users get read/execute only — they can read the license but cannot delete or replace it.
; Administrators get full control for deployment and updates.
; last_check (clock rollback state) lives in %LOCALAPPDATA%\EchoNerfados\ (per-user, created at runtime).
Name: "{commonappdata}\{#AppShortName}"; Permissions: users-readexec admins-full

[Files]
; GUI — main application (WPF)
Source: "..\publish\win-x64-gui\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; CLI — advanced forensic tool (verify-report, --machine-id, automation)
Source: "..\publish\win-x64\{#AppCliName}";  DestDir: "{app}"; Flags: ignoreversion

; Detection rules — use GUI publish output (same content; avoids duplication)
Source: "..\publish\win-x64-gui\rules\*"; DestDir: "{app}\rules"; Flags: ignoreversion recursesubdirs createallsubdirs

; Verification scripts
Source: "..\scripts\verify-report.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "verify-report-shortcut.bat";  DestDir: "{app}";         Flags: ignoreversion

[Icons]
; Start Menu — main entry opens GUI
Name: "{group}\{#AppName}";           Filename: "{app}\{#AppExeName}";             Comment: "Launch Echo Nerfados Shield XDR"
; Start Menu — CLI for advanced / automation use
Name: "{group}\{#AppName} (CLI)";     Filename: "{app}\{#AppCliName}";             Comment: "Command-line interface — advanced and automation use"
Name: "{group}\Verify Report";        Filename: "{app}\verify-report-shortcut.bat"; Comment: "Verify integrity of a scan report"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

; Desktop (optional task) — opens GUI
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon; Comment: "Launch Echo Nerfados Shield XDR"

[Run]
; Post-install: show Machine ID via CLI (works headless, stdout-only)
Filename: "cmd.exe"; \
  Parameters: "/k ""{app}\{#AppCliName}"" --machine-id & echo. & echo  Copy the Machine ID above to request your license. & echo  Place license.nerf in: {commonappdata}\{#AppShortName}\ & echo. & pause"; \
  Description: "Show Machine ID (needed to request a license)"; \
  Flags: postinstall skipifsilent nowait

[Code]

// ── Uninstall: ask whether to remove ProgramData ──────────────────────────────

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir   : String;
  MsgResult : Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\{#AppShortName}');
    if DirExists(DataDir) then
    begin
      MsgResult := MsgBox(
        'Do you want to remove application data?' + #13#10 + #13#10 +
        DataDir + #13#10 + #13#10 +
        'This folder contains your license.nerf, scan state and logs.' + #13#10 +
        'Select No to keep it (recommended).',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2);
      if MsgResult = IDYES then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;
