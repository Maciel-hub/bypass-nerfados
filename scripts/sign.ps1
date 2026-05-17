#Requires -Version 7.0
<#
.SYNOPSIS
    Assina um executavel com Authenticode (SHA-256, RFC 3161 timestamp com fallback).

.DESCRIPTION
    Suporta dois modos de certificado:
      1. PFX file    -- Set-Env SIGN_PFX_PATH + SIGN_PFX_PASSWORD, ou passe -PfxPath/-PfxPassword
      2. Thumbprint  -- Set-Env SIGN_CERT_THUMBPRINT, ou passe -Thumbprint (cert ja instalado)

    Se nenhum certificado estiver configurado, emite um aviso e retorna 0 (nao falha o build).

    -NoTimestamp: pula o timestamp RFC 3161 (util para QA com self-signed sem acesso a TSA).
    -TsaTimeoutSeconds: timeout por TSA em segundos (default 30).

.EXAMPLE
    # Usando PFX
    .\scripts\sign.ps1 -PfxPath "echo_codesign.pfx" -PfxPassword "secret"

    # Usando thumbprint (cert no Windows store)
    .\scripts\sign.ps1 -Thumbprint "AB12CD..."

    # Via variaveis de ambiente (modo BUILD.bat)
    $env:SIGN_PFX_PATH = "echo_codesign.pfx"
    $env:SIGN_PFX_PASSWORD = "secret"
    .\scripts\sign.ps1

    # QA / self-signed sem timestamp
    .\scripts\sign.ps1 -NoTimestamp
#>
[CmdletBinding()]
param(
    [string]   $TargetPath        = "publish\win-x64\EchoNerfados.exe",
    [string]   $PfxPath           = $env:SIGN_PFX_PATH,
    [string]   $PfxPassword       = $env:SIGN_PFX_PASSWORD,
    [string]   $Thumbprint        = $env:SIGN_CERT_THUMBPRINT,
    [string[]] $TsaUrls           = @(
        "http://timestamp.digicert.com",
        "http://timestamp.sectigo.com",
        "http://timestamp.globalsign.com/scripts/timstamp.dll",
        "http://ts.ssl.com"
    ),
    [int]      $TsaTimeoutSeconds = 30,
    [switch]   $NoTimestamp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Locate signtool.exe ----------------------------------------------------

function Find-SignTool {
    foreach ($base in @(
        "C:\Program Files (x86)\Windows Kits\10\bin",
        "C:\Program Files\Windows Kits\10\bin"
    )) {
        if (Test-Path $base) {
            $found = Get-ChildItem "$base\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
                     Sort-Object Name -Descending | Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# ---- Try one TSA with a background-job timeout ------------------------------
# Returns $true if signing succeeded, $false otherwise.
function Invoke-SignWithTimeout {
    param(
        [string]   $Tool,          # "signtool" | "ps"
        [string]   $Target,
        [string]   $ResolvedPfx,
        [string]   $PfxPwd,
        [string]   $Thumb,
        [string]   $SignToolPath,
        [string]   $Tsa,           # empty string = no timestamp
        [int]      $TimeoutSec
    )

    $job = Start-Job -ScriptBlock {
        param($Tool, $Target, $ResolvedPfx, $PfxPwd, $Thumb, $SignToolPath, $Tsa)
        $ErrorActionPreference = "Stop"

        if ($Tool -eq "signtool") {
            $args = @("sign", "/fd", "SHA256")
            if ($Tsa -ne "") { $args += @("/td", "SHA256", "/tr", $Tsa) }
            if ($ResolvedPfx -ne "") {
                $args += @("/f", $ResolvedPfx)
                if ($PfxPwd -ne "") { $args += @("/p", $PfxPwd) }
            } elseif ($Thumb -ne "") {
                $args += @("/sha1", $Thumb)
            }
            $args += $Target
            $out = & $SignToolPath @args 2>&1
            return @{ ExitCode = $LASTEXITCODE; Output = ($out -join "`n") }
        } else {
            # PowerShell Set-AuthenticodeSignature
            $cert = $null
            if ($ResolvedPfx -ne "") {
                $sp = if ($PfxPwd -ne "") {
                    ConvertTo-SecureString $PfxPwd -AsPlainText -Force
                } else {
                    [System.Security.SecureString]::new()
                }
                $cert = Get-PfxCertificate -FilePath $ResolvedPfx -Password $sp
            } elseif ($Thumb -ne "") {
                $cert = Get-ChildItem "Cert:\CurrentUser\My\$Thumb" -ErrorAction SilentlyContinue
                if (-not $cert) {
                    $cert = Get-ChildItem "Cert:\LocalMachine\My\$Thumb" -ErrorAction SilentlyContinue
                }
                if (-not $cert) { throw "Cert thumbprint '$Thumb' not found in store." }
            }

            $splat = @{
                FilePath       = $Target
                Certificate    = $cert
                HashAlgorithm  = "SHA256"
                ErrorAction    = "SilentlyContinue"
            }
            if ($Tsa -ne "") { $splat["TimestampServer"] = $Tsa }

            $result = Set-AuthenticodeSignature @splat
            $status = if ($result) { $result.Status.ToString() } else { "null" }
            return @{ ExitCode = 0; Status = $status }
        }
    } -ArgumentList $Tool, $Target, $ResolvedPfx, $PfxPwd, $Thumb, $SignToolPath, $Tsa

    $completed = Wait-Job -Job $job -Timeout $TimeoutSec
    if (-not $completed) {
        Stop-Job  -Job $job
        Remove-Job -Job $job -Force
        return $false
    }

    $result = Receive-Job -Job $job
    Remove-Job -Job $job -Force

    if ($Tool -eq "signtool") {
        if ($result.ExitCode -ne 0) {
            Write-Host "   [WARN] signtool exit $($result.ExitCode): $($result.Output)" -ForegroundColor Yellow
            return $false
        }
        return $true
    } else {
        $status = $result.Status
        if ($status -in @("Valid", "NotTrusted")) { return $true }
        Write-Host "   [WARN] Set-AuthenticodeSignature status: $status" -ForegroundColor Yellow
        return $false
    }
}

# ============================================================================
# Main
# ============================================================================

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " Echo Nerfados -- Authenticode Signing" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# Step 1 — Resolve target
Write-Host " Step 1 : Resolving target path..." -ForegroundColor Gray
$resolvedTarget = $TargetPath
if (-not [System.IO.Path]::IsPathRooted($resolvedTarget)) {
    $resolvedTarget = Join-Path (Get-Location) $resolvedTarget
}
if (-not (Test-Path $resolvedTarget)) {
    Write-Error "Target file not found: $resolvedTarget"
    exit 1
}
Write-Host "          $resolvedTarget" -ForegroundColor Gray

# Step 2 — Check cert config
Write-Host " Step 2 : Checking certificate configuration..." -ForegroundColor Gray
$hasPfx        = -not [string]::IsNullOrEmpty($PfxPath)
$hasThumbprint = -not [string]::IsNullOrEmpty($Thumbprint)

if (-not $hasPfx -and -not $hasThumbprint) {
    Write-Host ""
    Write-Host " [WARN] No certificate configured. EXE will NOT be signed." -ForegroundColor Yellow
    Write-Host "        Set SIGN_PFX_PATH + SIGN_PFX_PASSWORD  (PFX file)" -ForegroundColor DarkYellow
    Write-Host "        Set SIGN_CERT_THUMBPRINT               (cert in Windows Store)" -ForegroundColor DarkYellow
    Write-Host ""
    exit 0
}

# Step 3 — Locate signtool
Write-Host " Step 3 : Locating signtool.exe..." -ForegroundColor Gray
$signTool = Find-SignTool
if ($signTool) {
    Write-Host "          Found: $signTool" -ForegroundColor Gray
} else {
    Write-Host "          signtool.exe not found -- will use Set-AuthenticodeSignature (PowerShell)" -ForegroundColor Yellow
    Write-Host "          To install: winget install Microsoft.WindowsSDK.Tools" -ForegroundColor DarkYellow
}
$toolMode = if ($signTool) { "signtool" } else { "ps" }

# Step 4 — Resolve PFX path
Write-Host " Step 4 : Loading certificate..." -ForegroundColor Gray
$resolvedPfx = ""
if ($hasPfx) {
    $resolvedPfx = $PfxPath
    if (-not [System.IO.Path]::IsPathRooted($resolvedPfx)) {
        $resolvedPfx = Join-Path (Get-Location) $resolvedPfx
    }
    if (-not (Test-Path $resolvedPfx)) {
        Write-Error "PFX not found: $resolvedPfx"
        exit 1
    }
    Write-Host "          PFX: $resolvedPfx" -ForegroundColor Gray
} elseif ($hasThumbprint) {
    Write-Host "          Thumbprint: $Thumbprint" -ForegroundColor Gray
}

$pfxPwdStr = if ($PfxPassword) { $PfxPassword } else { "" }
$thumbStr  = if ($Thumbprint)  { $Thumbprint  } else { "" }

# Step 5 — Sign (with or without timestamp)
Write-Host " Step 5 : Signing..." -ForegroundColor Gray
$signed = $false

if ($NoTimestamp) {
    Write-Host "          -NoTimestamp: signing without RFC 3161 timestamp (QA mode)" -ForegroundColor Yellow
    $ok = Invoke-SignWithTimeout `
        -Tool $toolMode `
        -Target $resolvedTarget `
        -ResolvedPfx $resolvedPfx `
        -PfxPwd $pfxPwdStr `
        -Thumb $thumbStr `
        -SignToolPath ($signTool ?? "") `
        -Tsa "" `
        -TimeoutSec $TsaTimeoutSeconds

    if ($ok) {
        Write-Host "          SIGNED (no timestamp)" -ForegroundColor Green
        $signed = $true
    } else {
        Write-Host "          Signing without timestamp failed." -ForegroundColor Red
    }
} else {
    foreach ($tsa in $TsaUrls) {
        Write-Host " Step 5 : Requesting timestamp from $tsa (timeout ${TsaTimeoutSeconds}s)..." -ForegroundColor Gray
        $ok = Invoke-SignWithTimeout `
            -Tool $toolMode `
            -Target $resolvedTarget `
            -ResolvedPfx $resolvedPfx `
            -PfxPwd $pfxPwdStr `
            -Thumb $thumbStr `
            -SignToolPath ($signTool ?? "") `
            -Tsa $tsa `
            -TimeoutSec $TsaTimeoutSeconds

        if ($ok) {
            Write-Host "          SIGNED with timestamp from $tsa" -ForegroundColor Green
            $signed = $true
            break
        } else {
            Write-Host "          TSA $tsa failed or timed out, trying next..." -ForegroundColor Yellow
        }
    }

    # Last resort: sign without timestamp
    if (-not $signed) {
        Write-Host " Step 5 : All TSA failed. Attempting sign without timestamp (last resort)..." -ForegroundColor Yellow
        $ok = Invoke-SignWithTimeout `
            -Tool $toolMode `
            -Target $resolvedTarget `
            -ResolvedPfx $resolvedPfx `
            -PfxPwd $pfxPwdStr `
            -Thumb $thumbStr `
            -SignToolPath ($signTool ?? "") `
            -Tsa "" `
            -TimeoutSec $TsaTimeoutSeconds

        if ($ok) {
            Write-Host "          SIGNED (no timestamp -- all TSA unreachable)" -ForegroundColor Yellow
            $signed = $true
        }
    }
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $signed) {
    Write-Error "Signing failed. Check certificate configuration and target path."
    exit 1
}
