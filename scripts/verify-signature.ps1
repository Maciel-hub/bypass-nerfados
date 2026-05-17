#Requires -Version 7.0
<#
.SYNOPSIS
    Verifica e exibe o status de assinatura Authenticode de um executável.

.DESCRIPTION
    Usa Get-AuthenticodeSignature para mostrar:
    - Status (Válida / Não assinado / Inválida)
    - Sujeito e emissor do certificado
    - Thumbprint e validade
    - Timestamp

.EXAMPLE
    .\scripts\verify-signature.ps1
    .\scripts\verify-signature.ps1 -TargetPath "publish\win-x64\EchoNerfados.exe"
    .\scripts\verify-signature.ps1 -TargetPath "publish\tools\LicenseTool.exe"
#>
[CmdletBinding()]
param(
    [string] $TargetPath = "publish\win-x64\EchoNerfados.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$resolvedTarget = $TargetPath
if (-not [System.IO.Path]::IsPathRooted($resolvedTarget)) {
    $resolvedTarget = Join-Path (Get-Location) $resolvedTarget
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Echo Nerfados — Verificação de Assinatura Authenticode" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

if (-not (Test-Path $resolvedTarget)) {
    Write-Host " [ERRO] Arquivo não encontrado: $resolvedTarget" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    exit 1
}

Write-Host (" Arquivo  : " + $resolvedTarget) -ForegroundColor Gray

$sig = Get-AuthenticodeSignature -FilePath $resolvedTarget

# ── Status ────────────────────────────────────────────────────────────────────

switch ($sig.Status) {
    "Valid" {
        Write-Host " Status   : " -ForegroundColor Gray -NoNewline
        Write-Host "VÁLIDA ✓" -ForegroundColor Green
    }
    "NotSigned" {
        Write-Host " Status   : " -ForegroundColor Gray -NoNewline
        Write-Host "NÃO ASSINADO ✗" -ForegroundColor Yellow
        Write-Host ""
        Write-Host " O executável não possui assinatura Authenticode." -ForegroundColor Yellow
        Write-Host " Para assinar: .\scripts\sign.ps1" -ForegroundColor DarkYellow
        Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        exit 2
    }
    "HashMismatch" {
        Write-Host " Status   : " -ForegroundColor Gray -NoNewline
        Write-Host "HASH INVÁLIDO ✗ (arquivo modificado após assinatura)" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        exit 3
    }
    "NotTrusted" {
        Write-Host " Status   : " -ForegroundColor Gray -NoNewline
        Write-Host "NÃO CONFIÁVEL ⚠ (self-signed ou CA não raiz)" -ForegroundColor Yellow
        Write-Host " Nota: para distribuição comercial, use certificado de CA reconhecida (OV/EV)." -ForegroundColor DarkYellow
    }
    default {
        Write-Host " Status   : " -ForegroundColor Gray -NoNewline
        Write-Host "DESCONHECIDO — $($sig.Status)" -ForegroundColor Red
    }
}

# ── Certificate details ───────────────────────────────────────────────────────

if ($sig.SignerCertificate) {
    $cert = $sig.SignerCertificate
    Write-Host (" Sujeito  : " + $cert.Subject)  -ForegroundColor Gray
    Write-Host (" Emissor  : " + $cert.Issuer)   -ForegroundColor Gray
    Write-Host (" Thumb    : " + $cert.Thumbprint) -ForegroundColor Gray
    Write-Host (" Válido   : " + $cert.NotBefore.ToString("yyyy-MM-dd") + " → " + $cert.NotAfter.ToString("yyyy-MM-dd")) -ForegroundColor Gray

    # Self-signed detection
    if ($cert.Subject -eq $cert.Issuer) {
        Write-Host " Tipo     : " -ForegroundColor Gray -NoNewline
        Write-Host "SELF-SIGNED (QA apenas — não distribua comercialmente)" -ForegroundColor Yellow
    } else {
        Write-Host (" Tipo     : CA Comercial") -ForegroundColor Gray
    }
}

# ── Timestamp ─────────────────────────────────────────────────────────────────

if ($sig.TimeStamperCertificate) {
    $ts = $sig.TimeStamperCertificate
    Write-Host (" Timestamp: " + $ts.Subject) -ForegroundColor Gray
} else {
    Write-Host " Timestamp: " -ForegroundColor Gray -NoNewline
    Write-Host "AUSENTE ⚠ (sem timestamp, assinatura expira com o certificado)" -ForegroundColor Yellow
}

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Exit codes: 0=Valid, 1=Error, 2=NotSigned, 3=HashMismatch, 4=Other
if ($sig.Status -eq "Valid" -or $sig.Status -eq "NotTrusted") { exit 0 }
exit 4
