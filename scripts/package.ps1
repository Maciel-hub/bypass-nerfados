#Requires -Version 7.0
<#
.SYNOPSIS
    Compila o installer do EchoNerfados usando Inno Setup e, opcionalmente, assina o resultado.

.DESCRIPTION
    Requer:
      - dotnet publish ja executado (BUILD.bat ou BUILD.bat --tools)
      - Inno Setup 6 instalado (iscc.exe)

    Assinatura do installer (opcional):
      set SIGN_PFX_PATH=echo_codesign.pfx
      set SIGN_PFX_PASSWORD=senha
      scripts\package.ps1 -Sign

.PARAMETER Sign
    Assina o installer gerado usando scripts\sign.ps1.

.PARAMETER IsccPath
    Caminho explicito para iscc.exe. Se omitido, busca nos locais padrao.

.PARAMETER Version
    Versao base (ex: "1.0.0"). Se omitido, extraido do EXE publicado.

.EXAMPLE
    pwsh -File scripts\package.ps1
    pwsh -File scripts\package.ps1 -Sign
#>
[CmdletBinding()]
param(
    [switch] $Sign,
    [string] $IsccPath = "",
    [string] $Version  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " Echo Nerfados -- Packaging (Inno Setup)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# ---- Step 1: Verify publish output ----------------------------------------
Write-Host " Step 1 : Checking publish output..." -ForegroundColor Gray
$exePath = "publish\win-x64\EchoNerfados.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "EchoNerfados.exe not found at $exePath. Run BUILD.bat first."
    exit 1
}
Write-Host "          Found: $exePath" -ForegroundColor Gray

# ---- Step 2: Extract version from EXE -------------------------------------
Write-Host " Step 2 : Resolving version..." -ForegroundColor Gray
if ($Version -eq "") {
    $info    = [System.Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path $exePath).Path)
    $rawVer  = $info.ProductVersion   # e.g. "1.0.0+67defa8"
    $Version = ($rawVer -split '\+')[0]
}
Write-Host "          Version: $Version" -ForegroundColor Gray

# ---- Step 3: Find iscc.exe ------------------------------------------------
Write-Host " Step 3 : Locating Inno Setup compiler..." -ForegroundColor Gray
if ($IsccPath -eq "") {
    $candidates = @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe",
        "C:\Program Files (x86)\Inno Setup 5\ISCC.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $IsccPath = $c; break }
    }
    if ($IsccPath -eq "") {
        $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($cmd) { $IsccPath = $cmd.Source }
    }
}
if ($IsccPath -eq "" -or -not (Test-Path $IsccPath)) {
    Write-Error "Inno Setup (ISCC.exe) not found. Install from https://jrsoftware.org/isinfo.php"
    exit 1
}
Write-Host "          Found: $IsccPath" -ForegroundColor Gray

# ---- Step 4: Create dist\ if needed ----------------------------------------
Write-Host " Step 4 : Preparing dist\ folder..." -ForegroundColor Gray
if (-not (Test-Path "dist")) { New-Item -ItemType Directory -Path "dist" | Out-Null }

# ---- Step 5: Compile installer ---------------------------------------------
Write-Host " Step 5 : Compiling installer (Inno Setup)..." -ForegroundColor Gray
$issScript    = "installer\EchoNerfados.iss"
$installerOut = "dist\EchoNerfadosSetup-$Version.exe"

& $IsccPath "/DAppVersion=$Version" $issScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "ISCC.exe failed (exit $LASTEXITCODE). Check Inno Setup output above."
    exit 1
}

if (-not (Test-Path $installerOut)) {
    Write-Error "Expected installer not found: $installerOut"
    exit 1
}
Write-Host "          Installer: $installerOut" -ForegroundColor Green

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

# ---- Step 7: Verify + summary ----------------------------------------------
Write-Host " Step 7 : Verifying installer..." -ForegroundColor Gray
pwsh -NoProfile -NonInteractive -File "scripts\verify-signature.ps1" -TargetPath $installerOut
$verifyExit = $LASTEXITCODE

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " PACKAGING COMPLETE" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

$sha256 = (Get-FileHash $installerOut -Algorithm SHA256).Hash
Write-Host " Installer : $installerOut" -ForegroundColor White
Write-Host " Version   : $Version"      -ForegroundColor White
Write-Host " SHA256    : $sha256"        -ForegroundColor White
Write-Host " Signed    : $(if ($Sign -and $verifyExit -eq 0) { 'YES' } elseif ($Sign) { 'FAILED (exit ' + $verifyExit + ')' } else { 'NO' })" -ForegroundColor $(if ($Sign -and $verifyExit -ne 0) { 'Red' } else { 'White' })
Write-Host ""

if ($Sign -and $verifyExit -ne 0) { exit 1 }
