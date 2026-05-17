#Requires -Version 7.0
<#
.SYNOPSIS
    Assina um executavel com Authenticode (SHA-256, RFC 3161 timestamp com fallback).

.DESCRIPTION
    Suporta dois modos de certificado:
      1. PFX file    -- Set-Env SIGN_PFX_PATH + SIGN_PFX_PASSWORD, ou passe -PfxPath/-PfxPassword
      2. Thumbprint  -- Set-Env SIGN_CERT_THUMBPRINT, ou passe -Thumbprint (cert ja instalado)

    Se nenhum certificado estiver configurado, emite um aviso e retorna 0 (nao falha o build).

    -NoTimestamp: pula o timestamp RFC 3161 (util para QA com self-signed).
    -TsaTimeoutSeconds: timeout por TSA para signtool.exe (default 30).
    Set-AuthenticodeSignature roda sempre no processo principal (nunca em Start-Job).

.EXAMPLE
    $env:SIGN_PFX_PATH = "echo_codesign.pfx"
    $env:SIGN_PFX_PASSWORD = "secret"
    .\scripts\sign.ps1

    .\scripts\sign.ps1 -NoTimestamp   # QA / self-signed
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

# ---- Helpers ----------------------------------------------------------------

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

# Sign with Set-AuthenticodeSignature directly in the main process.
# Returns the SignatureStatus string, or $null on exception.
function Invoke-PsSign {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert,
        [string] $Target,
        [string] $Tsa        # empty = no timestamp
    )
    $splat = @{
        FilePath      = $Target
        Certificate   = $Cert
        HashAlgorithm = "SHA256"
        ErrorAction   = "SilentlyContinue"
    }
    if ($Tsa -ne "") { $splat["TimestampServer"] = $Tsa }
    try {
        $result = Set-AuthenticodeSignature @splat
        return if ($result) { $result.Status.ToString() } else { "null" }
    } catch {
        Write-Host "   [WARN] Set-AuthenticodeSignature threw: $_" -ForegroundColor Yellow
        return $null
    }
}

# Sign with signtool.exe in a background job so we get TSA timeout control.
# Returns $true on success, $false on failure or timeout.
function Invoke-SigntoolJob {
    param(
        [string] $SignToolPath,
        [string] $Target,
        [string] $ResolvedPfx,
        [string] $PfxPwd,
        [string] $Thumb,
        [string] $Tsa,
        [int]    $TimeoutSec
    )
    $job = Start-Job -ScriptBlock {
        param($st, $target, $pfx, $pwd, $thumb, $tsa)
        $stArgs = @("sign", "/fd", "SHA256")
        if ($tsa -ne "") { $stArgs += @("/td", "SHA256", "/tr", $tsa) }
        if ($pfx -ne "") {
            $stArgs += @("/f", $pfx)
            if ($pwd -ne "") { $stArgs += @("/p", $pwd) }
        } elseif ($thumb -ne "") {
            $stArgs += @("/sha1", $thumb)
        }
        $stArgs += $target
        $out = & $st @stArgs 2>&1
        return @{ ExitCode = $LASTEXITCODE; Output = ($out -join "`n") }
    } -ArgumentList $SignToolPath, $Target, $ResolvedPfx, $PfxPwd, $Thumb, $Tsa

    $done = Wait-Job -Job $job -Timeout $TimeoutSec
    if (-not $done) {
        Stop-Job $job -PassThru | Remove-Job -Force
        Write-Host "   [WARN] signtool timed out after ${TimeoutSec}s" -ForegroundColor Yellow
        return $false
    }
    $r = Receive-Job $job
    Remove-Job $job -Force
    if ($r.ExitCode -ne 0) {
        Write-Host "   [WARN] signtool exit $($r.ExitCode): $($r.Output)" -ForegroundColor Yellow
        return $false
    }
    return $true
}

# ============================================================================
# Main
# ============================================================================

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " Echo Nerfados -- Authenticode Signing" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# Step 1 — resolve target
Write-Host " Step 1 : Resolving target..." -ForegroundColor Gray
$resolvedTarget = $TargetPath
if (-not [System.IO.Path]::IsPathRooted($resolvedTarget)) {
    $resolvedTarget = Join-Path (Get-Location) $resolvedTarget
}
if (-not (Test-Path $resolvedTarget)) {
    Write-Error "Target not found: $resolvedTarget"
    exit 1
}
Write-Host "          $resolvedTarget" -ForegroundColor Gray

# Step 2 — check cert config
Write-Host " Step 2 : Checking certificate configuration..." -ForegroundColor Gray
$hasPfx        = -not [string]::IsNullOrEmpty($PfxPath)
$hasThumbprint = -not [string]::IsNullOrEmpty($Thumbprint)

if (-not $hasPfx -and -not $hasThumbprint) {
    Write-Host ""
    Write-Host " [WARN] No certificate configured. EXE will NOT be signed." -ForegroundColor Yellow
    Write-Host "        SIGN_PFX_PATH + SIGN_PFX_PASSWORD  (PFX file)" -ForegroundColor DarkYellow
    Write-Host "        SIGN_CERT_THUMBPRINT               (cert in Windows Store)" -ForegroundColor DarkYellow
    Write-Host ""
    exit 0
}

# Step 3 — locate signtool
Write-Host " Step 3 : Locating signtool.exe..." -ForegroundColor Gray
$signTool = Find-SignTool
if ($signTool) {
    Write-Host "          Found: $signTool" -ForegroundColor Gray
} else {
    Write-Host "          Not found -- will use Set-AuthenticodeSignature (PowerShell)" -ForegroundColor Yellow
    Write-Host "          Install: winget install Microsoft.WindowsSDK.Tools" -ForegroundColor DarkYellow
}

# Step 4 — resolve PFX path and load cert (PS native path: load in main process)
Write-Host " Step 4 : Loading certificate..." -ForegroundColor Gray
$resolvedPfx = ""
$pfxPwdStr   = if ($PfxPassword)  { $PfxPassword } else { "" }
$thumbStr    = if ($Thumbprint)   { $Thumbprint  } else { "" }

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
    Write-Host "          Thumbprint: $thumbStr" -ForegroundColor Gray
}

# Load cert in main process for Set-AuthenticodeSignature (cert object must not cross job boundary)
$cert = $null
if (-not $signTool) {
    Write-Host "          Loading cert object in main process..." -ForegroundColor Gray
    if ($hasPfx) {
        $sp   = if ($pfxPwdStr -ne "") {
            ConvertTo-SecureString $pfxPwdStr -AsPlainText -Force
        } else {
            [System.Security.SecureString]::new()
        }
        $cert = Get-PfxCertificate -FilePath $resolvedPfx -Password $sp
    } elseif ($hasThumbprint) {
        $cert = Get-ChildItem "Cert:\CurrentUser\My\$thumbStr" -ErrorAction SilentlyContinue
        if (-not $cert) {
            $cert = Get-ChildItem "Cert:\LocalMachine\My\$thumbStr" -ErrorAction SilentlyContinue
        }
        if (-not $cert) {
            Write-Error "Certificate thumbprint '$thumbStr' not found in store."
            exit 1
        }
    }
    Write-Host "          Subject: $($cert.Subject)" -ForegroundColor Gray
}

# Step 5 — sign
Write-Host " Step 5 : Signing..." -ForegroundColor Gray
$signed = $false

if ($NoTimestamp) {
    Write-Host "          -NoTimestamp: signing without RFC 3161 timestamp" -ForegroundColor Yellow

    if ($signTool) {
        $stArgs = @("sign", "/fd", "SHA256")
        if ($hasPfx) {
            $stArgs += @("/f", $resolvedPfx)
            if ($pfxPwdStr -ne "") { $stArgs += @("/p", $pfxPwdStr) }
        } elseif ($hasThumbprint) {
            $stArgs += @("/sha1", $thumbStr)
        }
        $stArgs += $resolvedTarget
        Write-Host "          Running signtool sign /fd SHA256 (no timestamp)..." -ForegroundColor Gray
        $out = & $signTool @stArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            $signed = $true
        } else {
            Write-Host "   [WARN] signtool exit $LASTEXITCODE`: $($out -join ' ')" -ForegroundColor Yellow
        }
    } else {
        # Set-AuthenticodeSignature directly in main process -- no Start-Job
        Write-Host "          Set-AuthenticodeSignature (main process, no timestamp)..." -ForegroundColor Gray
        $status = Invoke-PsSign -Cert $cert -Target $resolvedTarget -Tsa ""
        Write-Host "          Status: $status" -ForegroundColor Gray
        if ($status -in @("Valid", "NotTrusted")) {
            $signed = $true
        } else {
            Write-Host "   [WARN] Unexpected status: $status" -ForegroundColor Yellow
        }
    }
} else {
    # Try each TSA with timeout
    foreach ($tsa in $TsaUrls) {
        Write-Host " Step 5 : TSA $tsa (timeout ${TsaTimeoutSeconds}s)..." -ForegroundColor Gray

        if ($signTool) {
            $ok = Invoke-SigntoolJob `
                -SignToolPath $signTool `
                -Target $resolvedTarget `
                -ResolvedPfx $resolvedPfx `
                -PfxPwd $pfxPwdStr `
                -Thumb $thumbStr `
                -Tsa $tsa `
                -TimeoutSec $TsaTimeoutSeconds
            if ($ok) { $signed = $true; break }
        } else {
            # Set-AuthenticodeSignature in main process -- no Start-Job
            $status = Invoke-PsSign -Cert $cert -Target $resolvedTarget -Tsa $tsa
            Write-Host "          Status: $status" -ForegroundColor Gray
            if ($status -in @("Valid", "NotTrusted")) { $signed = $true; break }
            Write-Host "          TSA $tsa failed, trying next..." -ForegroundColor Yellow
        }
    }

    # Last resort: sign without timestamp
    if (-not $signed) {
        Write-Host " Step 5 : All TSA failed. Signing without timestamp (last resort)..." -ForegroundColor Yellow
        if ($signTool) {
            $ok = Invoke-SigntoolJob `
                -SignToolPath $signTool `
                -Target $resolvedTarget `
                -ResolvedPfx $resolvedPfx `
                -PfxPwd $pfxPwdStr `
                -Thumb $thumbStr `
                -Tsa "" `
                -TimeoutSec $TsaTimeoutSeconds
            if ($ok) { $signed = $true }
        } else {
            $status = Invoke-PsSign -Cert $cert -Target $resolvedTarget -Tsa ""
            Write-Host "          Status: $status" -ForegroundColor Gray
            if ($status -in @("Valid", "NotTrusted")) { $signed = $true }
        }
    }
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

if ($signed) {
    Write-Host " RESULT: SIGNED OK" -ForegroundColor Green
} else {
    Write-Error "Signing failed. Check certificate and target path."
    exit 1
}
