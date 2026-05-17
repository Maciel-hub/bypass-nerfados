#Requires -Version 7.0
<#
.SYNOPSIS
    Cria certificado self-signed de code signing para QA interno.

.DESCRIPTION
    - Instala o cert em CurrentUser\My (sem necessidade de admin)
    - Exporta para PFX (para uso com sign.ps1 via SIGN_PFX_PATH)
    - NÃO serve para distribuição comercial — apenas para testar o pipeline
    - Para distribuição real: use certificado OV ou EV de CA reconhecida (DigiCert, Sectigo, etc.)

.EXAMPLE
    .\scripts\create-selfsigned-cert.ps1
    .\scripts\create-selfsigned-cert.ps1 -Subject "CN=MyTool Dev" -OutputPfx "dev.pfx" -Password "mypass"
#>
[CmdletBinding()]
param(
    [string] $Subject    = "CN=Echo Nerfados Dev, O=Nerfados Dev, C=BR",
    [string] $OutputPfx  = "echo_dev_codesign.pfx",
    [string] $Password   = "dev123",
    [int]    $ValidYears = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Echo Nerfados — Criar Certificado Self-Signed (QA)" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host " [AVISO] Self-signed = QA INTERNO apenas." -ForegroundColor Yellow
Write-Host " SmartScreen não confia em self-signed. Para distribuição," -ForegroundColor Yellow
Write-Host " adquira um certificado OV ou EV de CA reconhecida." -ForegroundColor Yellow
Write-Host ""

# Create self-signed code signing cert
$notAfter = (Get-Date).AddYears($ValidYears)
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature `
    -HashAlgorithm SHA256 `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -NotAfter $notAfter `
    -ErrorAction Stop

Write-Host (" Sujeito  : " + $cert.Subject)     -ForegroundColor Gray
Write-Host (" Thumbprint: " + $cert.Thumbprint)  -ForegroundColor Gray
Write-Host (" Válido até: " + $notAfter.ToString("yyyy-MM-dd")) -ForegroundColor Gray
Write-Host ""

# Export to PFX
$securePass = ConvertTo-SecureString $Password -AsPlainText -Force
$resolvedPfx = $OutputPfx
if (-not [System.IO.Path]::IsPathRooted($resolvedPfx)) {
    $resolvedPfx = Join-Path (Get-Location) $resolvedPfx
}

Export-PfxCertificate -Cert $cert -FilePath $resolvedPfx -Password $securePass | Out-Null

Write-Host " PFX exportado : $resolvedPfx" -ForegroundColor Green

# Import to CurrentUser\Root so signing succeeds without signtool /ac workaround.
# No admin needed for CurrentUser store. Required for Set-AuthenticodeSignature to accept self-signed.
# Note: this only trusts the cert on THIS machine for THIS user.
try {
    $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $rootStore.Add($cert)
    $rootStore.Close()
    Write-Host " Confiança     : Importado em CurrentUser\Root (QA local)" -ForegroundColor Green
} catch {
    Write-Host " [WARN] Não foi possível importar ao CurrentUser\Root: $_" -ForegroundColor Yellow
    Write-Host "        A assinatura pode mostrar 'NotTrusted' — normal para self-signed." -ForegroundColor DarkYellow
}
Write-Host " Senha PFX     : $Password" -ForegroundColor Gray
Write-Host ""
Write-Host " Para assinar com este cert:" -ForegroundColor Gray
Write-Host '   $env:SIGN_PFX_PATH     = "' + $resolvedPfx + '"' -ForegroundColor DarkYellow
Write-Host '   $env:SIGN_PFX_PASSWORD = "' + $Password    + '"' -ForegroundColor DarkYellow
Write-Host '   .\scripts\sign.ps1' -ForegroundColor DarkYellow
Write-Host ""
Write-Host " Ou via thumbprint (cert já está no store):" -ForegroundColor Gray
Write-Host '   $env:SIGN_CERT_THUMBPRINT = "' + $cert.Thumbprint + '"' -ForegroundColor DarkYellow
Write-Host '   .\scripts\sign.ps1' -ForegroundColor DarkYellow
Write-Host ""

# ── Cert type notes ───────────────────────────────────────────────────────────
Write-Host "─── Referência: tipos de certificado ───────────────────" -ForegroundColor DarkGray
Write-Host " Self-signed : QA/dev apenas. SmartScreen bloqueia."      -ForegroundColor DarkGray
Write-Host " OV (Organization Validation) : SmartScreen avisa até"    -ForegroundColor DarkGray
Write-Host "   acumular reputação (~dias/semanas com volume de downloads)." -ForegroundColor DarkGray
Write-Host " EV (Extended Validation)     : Bypass imediato de SmartScreen." -ForegroundColor DarkGray
Write-Host "   Recomendado para distribuição comercial do EchoNerfados." -ForegroundColor DarkGray
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-Host (" THUMBPRINT: " + $cert.Thumbprint) -ForegroundColor White -BackgroundColor DarkGreen
Write-Host ""
