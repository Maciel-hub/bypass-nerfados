#Requires -Version 7.0
<#
.SYNOPSIS
    Compila o installer do EchoNerfados usando Inno Setup e, opcionalmente, assina o resultado.

.DESCRIPTION
    Ordem de execucao recomendada:
      1. BUILD.bat --gui [--tools]    # publica CLI + GUI (e opcionalmente LicenseTool)
      2. scripts\package.ps1 [-Sign]  # compila e (opcionalmente) assina o installer

    OU em pipeline unico:
      scripts\package.ps1 -Publish [-Sign]

    O installer inclui:
      - publish\win-x64-gui\EchoNerfados.App.exe  (GUI — atalho principal)
      - publish\win-x64\EchoNerfados.exe           (CLI — ferramenta avancada)
      - publish\win-x64-gui\rules\                 (regras de deteccao)

    Inno Setup 6 precisa estar instalado: https://jrsoftware.org/isinfo.php

    Assinatura do installer:
      set SIGN_PFX_PATH=echo_codesign.pfx
      set SIGN_PFX_PASSWORD=senha
      scripts\package.ps1 -Sign

.PARAMETER Publish
    Executa BUILD.bat --gui antes de compilar o installer (pipeline completo).

.PARAMETER Sign
    Assina o installer gerado usando scripts\sign.ps1.

.PARAMETER IsccPath
    Caminho explicito para iscc.exe. Se omitido, busca nos locais padrao.

.PARAMETER Version
    Versao base (ex: "1.0.0"). Se omitido, extraido do EXE publicado.

.EXAMPLE
    pwsh -File scripts\package.ps1
    pwsh -File scripts\package.ps1 -Publish -Sign
#>
[CmdletBinding()]
param(
    [switch] $Publish,
    [switch] $Sign,
    [string] $IsccPath = "",
    [string] $Version  = "",
    [ValidateSet("QA","RC")] [string] $Variant      = "RC",
    [string] $LicensePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " Echo Nerfados -- Packaging (Inno Setup) [$Variant]" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# ---- Step 0: Publish (optional) -------------------------------------------
if ($Publish) {
    Write-Host " Step 0 : Running BUILD.bat --gui..." -ForegroundColor Gray
    cmd.exe /c "BUILD.bat --gui"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "BUILD.bat --gui failed (exit $LASTEXITCODE)."
        exit 1
    }
    Write-Host "          BUILD.bat OK" -ForegroundColor Gray
}

# ---- Step 1: Verify publish output ----------------------------------------
Write-Host " Step 1 : Checking publish output..." -ForegroundColor Gray

# CLI EXE (needed for --machine-id, verify-report, and version extraction)
$exePath = "publish\win-x64\EchoNerfados.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "EchoNerfados.exe (CLI) not found at: $exePath`nRun: BUILD.bat --gui"
    exit 1
}
Write-Host "          Found: $exePath" -ForegroundColor Gray

# GUI EXE (main installer entry point)
$guiExePath = "publish\win-x64-gui\EchoNerfados.App.exe"
if (-not (Test-Path $guiExePath)) {
    Write-Error "EchoNerfados.App.exe (GUI) not found at: $guiExePath`nRun: BUILD.bat --gui"
    exit 1
}
Write-Host "          Found: $guiExePath" -ForegroundColor Gray

# QA: verify license.nerf is present at the expected source path
if ($Variant -eq "QA") {
    $licSrc = if ($LicensePath -ne "") { $LicensePath } else { "publish\win-x64\license.nerf" }
    if (-not (Test-Path $licSrc)) {
        Write-Error "QA build requires license.nerf at '$licSrc'.`nRun: pwsh -File scripts\make-qa-license.ps1"
        exit 1
    }
    Write-Host "          License: $licSrc" -ForegroundColor Gray
}

# ---- Step 2: Extract version from EXE -------------------------------------
Write-Host " Step 2 : Resolving version..." -ForegroundColor Gray
if ($Version -eq "") {
    $info    = [System.Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path $exePath).Path)
    $rawVer  = $info.ProductVersion   # e.g. "1.0.0+f99e3e1"
    $Version = ($rawVer -split '\+')[0]
}
Write-Host "          Version: $Version" -ForegroundColor Gray

# ---- Step 3: Find iscc.exe ------------------------------------------------
Write-Host " Step 3 : Locating Inno Setup compiler..." -ForegroundColor Gray
if ($IsccPath -eq "") {
    foreach ($c in @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe",
        "C:\Program Files (x86)\Inno Setup 5\ISCC.exe"
    )) {
        if (Test-Path $c) { $IsccPath = $c; break }
    }
    if ($IsccPath -eq "") {
        $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($cmd) { $IsccPath = $cmd.Source }
    }
}
if ($IsccPath -eq "" -or -not (Test-Path $IsccPath)) {
    Write-Error "Inno Setup (ISCC.exe) not found.`nInstall from: https://jrsoftware.org/isinfo.php"
    exit 1
}
Write-Host "          Found: $IsccPath" -ForegroundColor Gray

# ---- Step 4: Prepare dist\ folder ----------------------------------------
Write-Host " Step 4 : Preparing dist\ folder..." -ForegroundColor Gray
if (-not (Test-Path "dist")) { New-Item -ItemType Directory -Path "dist" | Out-Null }

# Remove stale installers for this variant so dist\ never has an ambiguous "old" file
Get-ChildItem "dist" -Filter "EchoNerfadosSetup-$Variant-*.exe" -ErrorAction SilentlyContinue |
    Remove-Item -Force
# Remove legacy files from the old pipeline (no variant in the name, e.g. EchoNerfadosSetup-1.0.0.exe)
# -Filter glob doesn't support character classes on the Windows FS API; use Where-Object regex instead
Get-ChildItem "dist" -Filter "EchoNerfadosSetup-*.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^EchoNerfadosSetup-\d' } |
    Remove-Item -Force

# ---- Step 4b: Security audit — no forbidden files in publish output --------
Write-Host " Step 4b: Auditing publish output for forbidden content..." -ForegroundColor Gray

$auditPaths = @("publish\win-x64", "publish\win-x64-gui")

$forbiddenExtensions = @('.cs', '.csproj', '.sln', '.pdb', '.pem', '.pfx', '.p12')
$forbiddenFileNames  = @('LicenseTool.exe', 'EchoHarness.exe', 'MemoryHarness.exe',
                         'echo_priv.pem', 'echo_manifest_priv.pem')
$forbiddenDirNames   = @('src', 'scripts', 'installer')

$violations = [System.Collections.Generic.List[string]]::new()

foreach ($auditPath in $auditPaths) {
    if (-not (Test-Path $auditPath)) { continue }

    Get-ChildItem $auditPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $ext  = $_.Extension.ToLower()
        $name = $_.Name
        if ($forbiddenExtensions -contains $ext) {
            $violations.Add("  [EXT]  $($_.FullName)")
        } elseif ($forbiddenFileNames -contains $name) {
            $violations.Add("  [FILE] $($_.FullName)")
        }
    }

    Get-ChildItem $auditPath -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        if ($forbiddenDirNames -contains $_.Name.ToLower()) {
            $violations.Add("  [DIR]  $($_.FullName)")
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Host ""
    Write-Host " SECURITY AUDIT FAILED" -ForegroundColor Red
    Write-Host " Forbidden files found in publish output:" -ForegroundColor Red
    $violations | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Write-Host ""
    Write-Host " Remove these files before packaging." -ForegroundColor Yellow
    Write-Host " Tip: delete publish\ folders and re-run BUILD.bat to get a clean output." -ForegroundColor Yellow
    Write-Host ""
    Write-Error "Security audit failed — $($violations.Count) violation(s) found."
    exit 1
}
Write-Host "          Audit passed — no forbidden files found." -ForegroundColor Green

# ---- Step 5: Compile installer ---------------------------------------------
Write-Host " Step 5 : Compiling installer..." -ForegroundColor Gray
$issScript = "installer\EchoNerfados.iss"

# Build tag from git commit hash (appended to filename as +abc1234)
$commit   = git rev-parse --short HEAD 2>$null
$buildTag = if ($commit) { "+$commit" } else { "" }

$isccArgs = @("/DAppVersion=$Version", "/DAppVariant=$Variant", "/DBuildTag=$buildTag")
if ($Variant -eq "QA") {
    $isccArgs += "/DIncludeLicense=1"
}

$installerOut = "dist\EchoNerfadosSetup-$Variant-$Version$buildTag.exe"

& $IsccPath @isccArgs $issScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "ISCC.exe failed (exit $LASTEXITCODE)."
    exit 1
}
if (-not (Test-Path $installerOut)) {
    Write-Error "Expected installer not found: $installerOut"
    exit 1
}
Write-Host "          OK: $installerOut" -ForegroundColor Green

# ---- Step 6: Sign installer (optional) ------------------------------------
if ($Sign) {
    Write-Host " Step 6 : Signing installer..." -ForegroundColor Gray
    pwsh -NoProfile -NonInteractive -File "scripts\sign.ps1" -TargetPath $installerOut
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Installer signing failed."
        exit 1
    }
} else {
    Write-Host " Step 6 : Signing skipped ^(use -Sign to enable^)." -ForegroundColor Gray
}

# ---- Step 7: Verify Authenticode ------------------------------------------
# exit 0 = signed valid, exit 2 = unsigned (warning only), exit 3+ = error (always fail)
Write-Host " Step 7 : Verifying Authenticode on installer..." -ForegroundColor Gray
pwsh -NoProfile -NonInteractive -File "scripts\verify-signature.ps1" -TargetPath $installerOut
$verifyExit = $LASTEXITCODE

if ($Sign -and $verifyExit -ne 0) {
    Write-Error "Authenticode verification failed ^(exit $verifyExit^) after signing."
    exit 1
}
if ($verifyExit -ge 3) {
    Write-Error "Authenticode error ^(exit $verifyExit^) on installer — investigate before distributing."
    exit 1
}
if ($verifyExit -eq 2) {
    Write-Host " [WARN] Installer is unsigned. Use -Sign to sign before distributing." -ForegroundColor Yellow
}

# ---- Summary ---------------------------------------------------------------
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " PACKAGING COMPLETE" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

$sha256 = (Get-FileHash $installerOut -Algorithm SHA256).Hash
Write-Host " Installer : $installerOut" -ForegroundColor White
Write-Host " Variant   : $Variant"      -ForegroundColor White
Write-Host " Version   : $Version"      -ForegroundColor White
Write-Host " SHA256    : $sha256"        -ForegroundColor White
Write-Host " Signed    : $(if ($Sign -and $verifyExit -eq 0) { 'YES' } else { 'NO (unsigned)' })" -ForegroundColor White
if ($Variant -eq "QA") {
    Write-Host " License   : Wildcard QA — embedded in installer" -ForegroundColor Yellow
} else {
    Write-Host " License   : NOT included — distribute license.nerf separately" -ForegroundColor Yellow
}
Write-Host ""
