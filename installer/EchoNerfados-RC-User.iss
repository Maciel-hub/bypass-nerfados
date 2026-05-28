; Echo Nerfados Shield XDR — Inno Setup 6 Installer Script (RC Per-User)
; Per-user install: no admin required, no ProgramData, no license.nerf.
; Use only for external tester distribution while EnforceLicense=false.
; Build: iscc.exe /DAppVersion=1.0.1 /DBuildTag=+f194191 installer\EchoNerfados-RC-User.iss

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

#ifndef BuildTag
  #define BuildTag ""
#endif

#define AppName      "Echo Nerfados Shield XDR"
#define AppShortName "EchoNerfados"
#define AppPublisher "Nerfados"
#define AppURL       "https://nerfados.gg"
#define AppExeName   "EchoNerfados.App.exe"
#define AppCliName   "EchoNerfados.exe"

[Setup]
; Separate GUID from the admin installer to avoid upgrade conflicts
AppId={{A1F3C7D2-6B4E-4F8A-9C2D-3E5B8A1F7C4D}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion} (RC User)
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={localappdata}\Programs\{#AppShortName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename={#AppShortName}Setup-RC-User-{#AppVersion}{#BuildTag}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=
; Windows 10 version 2004 (19041) minimum — required for .NET 8 and modern APIs
MinVersion=10.0.19041
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#AppName} (RC User)
UninstallDisplayIcon={app}\{#AppExeName}
CloseApplications=force

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
; GUI — full WPF application bundle (App.exe, App.dll, App.deps.json, App.runtimeconfig.json, rules\, all assemblies)
Source: "..\publish\win-x64-gui\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; CLI — full forensic CLI bundle (EchoNerfados.exe, EchoNerfados.dll, deps.json, runtimeconfig.json, all assemblies)
Source: "..\publish\win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Verification scripts (not in publish dirs)
Source: "..\scripts\verify-report.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "verify-report-shortcut.bat";  DestDir: "{app}";         Flags: ignoreversion

[Icons]
; Start Menu (user programs folder — no admin required)
Name: "{group}\{#AppName}";           Filename: "{app}\{#AppExeName}";              Comment: "Launch Echo Nerfados Shield XDR"
Name: "{group}\{#AppName} (CLI)";     Filename: "{app}\{#AppCliName}";              Comment: "Command-line interface — advanced and automation use"
Name: "{group}\Verify Report";        Filename: "{app}\verify-report-shortcut.bat"; Comment: "Verify integrity of a scan report"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

; Desktop shortcut (user desktop — no admin required)
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon; Comment: "Launch Echo Nerfados Shield XDR"

[Run]
; RC per-user: license enforcement disabled — open GUI directly after setup
Filename: "{app}\{#AppExeName}"; \
  Description: "Launch Echo Nerfados Shield XDR"; \
  Flags: postinstall skipifsilent nowait shellexec

[UninstallDelete]
; Remove the per-user install directory on uninstall
Type: dirifempty; Name: "{app}"
