#Requires -Version 7.0
<#
.SYNOPSIS
    Assina um executável com Authenticode (SHA-256, RFC 3161 timestamp com fallback).

.DESCRIPTION
    Suporta dois modos de certificado:
      1. PFX file    — Set-Env SIGN_PFX_PATH + SIGN_PFX_PASSWORD, ou passe -PfxPath/-PfxPassword
      2. Thumbprint  — Set-Env SIGN_CERT_THUMBPRINT, ou passe -Thumbprint (cert já instalado)

    Se nenhum certificado estiver configurado, emite um aviso e retorna 0 (não falha o build).

.EXAMPLE
    # Usando PFX
    .\scripts\sign.ps1 -PfxPath "echo_codesign.pfx" -PfxPassword "secret"

    # Usando thumbprint (cert no Windows store)
    .\scripts\sign.ps1 -Thumbprint "AB12CD..."

    # Via variáveis de ambiente (modo BUILD.bat)
    $env:SIGN_PFX_PATH = "echo_codesign.pfx"
    $env:SIGN_PFX_PASSWORD = "secret"
    .\scripts\sign.ps1
#>
[CmdletBinding()]
param(
    [string]   $TargetPath   = "publish\win-x64\EchoNerfados.exe",
    [string]   $PfxPath      = $env:SIGN_PFX_PATH,
    [string]   $PfxPassword  = $env:SIGN_PFX_PASSWORD,
    [string]   $Thumbprint   = $env:SIGN_CERT_THUMBPRINT,
    [string[]] $TsaUrls      = @(
        "http://timestamp.digicert.com",          # Primary
        "http://timestamp.sectigo.com",            # Fallback 1
        "http://timestamp.globalsign.com/scripts/timstamp.dll",  # Fallback 2
        "http://ts.ssl.com"                        # Fallback 3
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Locate signtool.exe ───────────────────────────────────────────────────────

function Find-SignTool {
    # Search latest Windows SDK in standard install paths
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
    # Fall back to PATH
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# ── Main ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Echo Nerfados — Authenticode Signing" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

# Resolve target path
$resolvedTarget = $TargetPath
if (-not [System.IO.Path]::IsPathRooted($resolvedTarget)) {
    $resolvedTarget = Join-Path (Get-Location) $resolvedTarget
}
if (-not (Test-Path $resolvedTarget)) {
    Write-Error "Arquivo alvo não encontrado: $resolvedTarget"
    exit 1
}
Write-Host " Alvo     : $resolvedTarget" -ForegroundColor Gray

# Check if signing is configured
$hasPfx        = -not [string]::IsNullOrEmpty($PfxPath)
$hasThumbprint = -not [string]::IsNullOrEmpty($Thumbprint)

if (-not $hasPfx -and -not $hasThumbprint) {
    Write-Host ""
    Write-Host " [AVISO] Nenhum certificado configurado. Artefato NÃO assinado." -ForegroundColor Yellow
    Write-Host " Para assinar, configure:" -ForegroundColor Yellow
    Write-Host "   SIGN_PFX_PATH + SIGN_PFX_PASSWORD   (arquivo PFX)" -ForegroundColor DarkYellow
    Write-Host "   SIGN_CERT_THUMBPRINT                 (cert no Windows Store)" -ForegroundColor DarkYellow
    Write-Host ""
    exit 0
}

# Locate signtool
$signTool = Find-SignTool
if ($signTool) {
    Write-Host " SignTool : $signTool (signtool.exe)" -ForegroundColor Gray
} else {
    Write-Host " SignTool : Set-AuthenticodeSignature (PowerShell nativo — signtool.exe não encontrado)" -ForegroundColor Yellow
    Write-Host "           Para instalar signtool: winget install Microsoft.WindowsSDK.Tools" -ForegroundColor DarkYellow
}

# ── Resolve PFX path and load cert object (needed for PS fallback) ─────────────

$resolvedPfx = ""
if ($hasPfx) {
    $resolvedPfx = $PfxPath
    if (-not [System.IO.Path]::IsPathRooted($resolvedPfx)) {
        $resolvedPfx = Join-Path (Get-Location) $resolvedPfx
    }
    if (-not (Test-Path $resolvedPfx)) {
        Write-Error "PFX não encontrado: $resolvedPfx"
        exit 1
    }
}

# ── Try signing with each TSA (primary + fallback) ───────────────────────────

$signed = $false

foreach ($tsa in $TsaUrls) {
    Write-Host " TSA      : $tsa" -ForegroundColor Gray

    try {
        if ($signTool) {
            # ── Mode A: signtool.exe ──────────────────────────────────────────
            $stArgs = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $tsa)

            if ($hasPfx) {
                $stArgs += @("/f", $resolvedPfx)
                if (-not [string]::IsNullOrEmpty($PfxPassword)) {
                    $stArgs += @("/p", $PfxPassword)
                }
            } elseif ($hasThumbprint) {
                $stArgs += @("/sha1", $Thumbprint)
            }

            $stArgs += $resolvedTarget
            $output = & $signTool @stArgs 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host " Status   : " -ForegroundColor Gray -NoNewline
                Write-Host "ASSINADO COM SUCESSO (signtool)" -ForegroundColor Green
                $signed = $true
                break
            } else {
                Write-Host " [WARN] signtool TSA $tsa falhou (exit $LASTEXITCODE): $output" -ForegroundColor Yellow
            }
        } else {
            # ── Mode B: Set-AuthenticodeSignature (PowerShell nativo) ─────────
            $cert = $null
            if ($hasPfx) {
                $securePass = if ([string]::IsNullOrEmpty($PfxPassword)) {
                    [System.Security.SecureString]::new()
                } else {
                    ConvertTo-SecureString $PfxPassword -AsPlainText -Force
                }
                $cert = Get-PfxCertificate -FilePath $resolvedPfx -Password $securePass
            } elseif ($hasThumbprint) {
                $cert = Get-ChildItem "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
                if (-not $cert) {
                    $cert = Get-ChildItem "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
                }
                if (-not $cert) {
                    Write-Error "Certificado com thumbprint '$Thumbprint' não encontrado no store."
                    exit 1
                }
            }

            $result = Set-AuthenticodeSignature `
                -FilePath $resolvedTarget `
                -Certificate $cert `
                -HashAlgorithm SHA256 `
                -TimestampServer $tsa `
                -ErrorAction SilentlyContinue

            if ($result -and $result.Status -in @("Valid", "NotTrusted")) {
                Write-Host " Status   : " -ForegroundColor Gray -NoNewline
                Write-Host "ASSINADO COM SUCESSO (Set-AuthenticodeSignature)" -ForegroundColor Green
                $signed = $true
                break
            } else {
                $statusMsg = if ($result) { $result.Status } else { "null" }
                Write-Host " [WARN] Set-AuthenticodeSignature TSA $tsa falhou: $statusMsg" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host " [WARN] Erro ao tentar TSA ${tsa}: $_" -ForegroundColor Yellow
    }
}

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if (-not $signed) {
    Write-Error "Assinatura falhou em todos os TSA configurados."
    exit 1
}
