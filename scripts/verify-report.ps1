#Requires -Version 7.0
<#
.SYNOPSIS
    Verifica a integridade e a assinatura de um relatorio gerado pelo EchoNerfados.

.DESCRIPTION
    Checks:
      1. manifest.sha256 matches manifest.json
      2. manifest.sig validates against the embedded public key (if present)
      3. All file hashes listed in manifest.json match the actual files

    Exit codes:
      0 = VERIFIED (signed or unsigned -- all hashes intact)
      5 = FAIL     (tampered file, invalid signature, or missing file)

.PARAMETER ReportPath
    Path to the report folder (contains manifest.json, manifest.sha256, manifest.sig, etc.)

.PARAMETER PubKeyPath
    Optional. Path to echo_manifest_pub.pem. If omitted, the embedded public key is used.

.EXAMPLE
    .\scripts\verify-report.ps1 -ReportPath "C:\Reports\Echo_Nerfados_PC_20260516_120000"
    .\scripts\verify-report.ps1 -ReportPath "C:\Reports\Echo_..." -PubKeyPath echo_manifest_pub.pem
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ReportPath,

    [string] $PubKeyPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Embedded ECDSA P-256 public key for manifest verification.
# Must match ManifestSigner.EmbeddedPublicKeyPem in the scanner source.
$embeddedPubKeyPem = @"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5NATMD4Ogyg2aQQ+yv/P/Dsdvyc
ZiJqyHQn19tS8h6jslWfDIPXUdEguigs9X9207vlktpNepBwfKCXQgdGpQ==
-----END PUBLIC KEY-----
"@

# ---- Helpers ----------------------------------------------------------------

function Get-FileSHA256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try { return [System.BitConverter]::ToString($sha.ComputeHash($fs)).Replace("-","").ToLowerInvariant() }
        finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
}

function Fail {
    param([string]$Msg)
    Write-Host ""
    Write-Host " [FAIL] $Msg" -ForegroundColor Red
    Write-Host ""
    exit 5
}

function Pass {
    param([string]$Msg, [bool]$Signed, [string]$ManifestHash)
    Write-Host ""
    Write-Host " [OK] $Msg" -ForegroundColor Green
    if ($Signed) {
        Write-Host "      Manifest SHA256 : $ManifestHash" -ForegroundColor Gray
    }
    Write-Host ""
    exit 0
}

# ---- Main -------------------------------------------------------------------

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " Echo Nerfados -- Report Integrity Verification" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " Report : $ReportPath" -ForegroundColor Gray
Write-Host ""

$resolvedReport = $ReportPath
if (-not [System.IO.Path]::IsPathRooted($resolvedReport)) {
    $resolvedReport = Join-Path (Get-Location) $resolvedReport
}

$manifestPath = Join-Path $resolvedReport "manifest.json"
$sha256Path   = Join-Path $resolvedReport "manifest.sha256"
$sigPath      = Join-Path $resolvedReport "manifest.sig"

if (-not (Test-Path $manifestPath)) {
    Fail "manifest.json not found in: $resolvedReport"
}

# Step 1: manifest.sha256
Write-Host " Step 1 : Verifying manifest.sha256..." -ForegroundColor Gray
$actualHash = Get-FileSHA256 $manifestPath
if (Test-Path $sha256Path) {
    $sha256Content = (Get-Content $sha256Path -Raw -Encoding UTF8).Trim()
    $expectedHash  = ($sha256Content -split '\s+')[0]
    if ($actualHash -ne $expectedHash) {
        Fail "manifest.sha256 mismatch -- manifest.json was modified`n          Expected: $expectedHash`n          Actual  : $actualHash"
    }
    Write-Host "          OK ($actualHash)" -ForegroundColor Gray
} else {
    Write-Host "          manifest.sha256 absent -- skipping checksum" -ForegroundColor Yellow
}

# Step 2: ECDSA signature
$signed = $false
Write-Host " Step 2 : Verifying manifest.sig..." -ForegroundColor Gray
if (Test-Path $sigPath) {
    try {
        $pubKeyPem = if ($PubKeyPath -ne "" -and (Test-Path $PubKeyPath)) {
            Get-Content $PubKeyPath -Raw -Encoding ASCII
        } else {
            $embeddedPubKeyPem
        }

        $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
        $hash          = [System.Security.Cryptography.SHA256]::HashData($manifestBytes)
        $sigBytes      = [System.Convert]::FromBase64String(
                             (Get-Content $sigPath -Raw -Encoding ASCII).Trim())

        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportFromPem($pubKeyPem)
        $ok = $ecdsa.VerifyHash(
            $hash, $sigBytes,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        $ecdsa.Dispose()

        if (-not $ok) {
            Fail "manifest.sig is INVALID -- manifest was tampered or signed with a different key"
        }
        Write-Host "          Signature VALID" -ForegroundColor Green
        $signed = $true
    } catch {
        Fail "manifest.sig verification threw: $_"
    }
} else {
    Write-Host "          manifest.sig absent -- report is unsigned (not a failure)" -ForegroundColor Yellow
}

# Step 3: file hashes
Write-Host " Step 3 : Verifying file hashes..." -ForegroundColor Gray
$manifestJson = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$fileCount    = 0
foreach ($prop in $manifestJson.files.PSObject.Properties) {
    $name        = $prop.Name
    $expectedSha = $prop.Value.sha256
    if (-not $expectedSha) { continue }

    $filePath = Join-Path $resolvedReport $name
    if (-not (Test-Path $filePath)) {
        Fail "File listed in manifest is missing: $name"
    }
    $actualSha = Get-FileSHA256 $filePath
    if ($actualSha -ne $expectedSha) {
        Fail "Hash mismatch: $name -- file was modified after scan`n          Expected: $expectedSha`n          Actual  : $actualSha"
    }
    $fileCount++
}
Write-Host "          $fileCount files verified OK" -ForegroundColor Gray

Write-Host "=======================================================" -ForegroundColor Cyan

$msg = if ($signed) {
    "VERIFIED -- manifest and all report files are intact and cryptographically signed"
} else {
    "VERIFIED (unsigned) -- manifest and all report files are intact; no manifest.sig present"
}

Pass -Msg $msg -Signed $signed -ManifestHash $actualHash
