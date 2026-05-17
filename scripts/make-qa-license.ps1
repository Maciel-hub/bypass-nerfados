#Requires -Version 7.0
<#
.SYNOPSIS
    Emite uma licença QA/Teste Interno (wildcard, 15 dias, todos os features).

.DESCRIPTION
    Requer:
      - publish\tools\LicenseTool.exe (BUILD.bat --tools)
      - echo_priv.pem ao lado do script ou no diretório raiz do projeto

    Gera: publish\win-x64\license.nerf (pronto para empacotar junto do EXE)

.PARAMETER CustomerId
    Identificador do cliente/build QA. Padrão: QA-INTERNAL

.PARAMETER DaysValid
    Validade em dias a partir de hoje. Padrão: 15

.PARAMETER KeyPath
    Caminho para echo_priv.pem. Padrão: busca em . e scripts\

.PARAMETER OutputPath
    Destino do license.nerf gerado. Padrão: publish\win-x64\license.nerf

.EXAMPLE
    pwsh -File scripts\make-qa-license.ps1
    pwsh -File scripts\make-qa-license.ps1 -CustomerId "QA-2026-05" -DaysValid 7
#>
[CmdletBinding()]
param(
    [string] $CustomerId  = "QA-INTERNAL",
    [int]    $DaysValid   = 15,
    [string] $KeyPath     = "",
    [string] $OutputPath  = "publish\win-x64\license.nerf"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve key path
if ($KeyPath -eq "") {
    foreach ($candidate in @("echo_priv.pem", "scripts\echo_priv.pem")) {
        if (Test-Path $candidate) { $KeyPath = $candidate; break }
    }
}
if ($KeyPath -eq "" -or -not (Test-Path $KeyPath)) {
    Write-Error "echo_priv.pem não encontrado. Coloque ao lado do script ou passe -KeyPath <caminho>."
    exit 1
}

$toolPath = "publish\tools\LicenseTool.exe"
if (-not (Test-Path $toolPath)) {
    Write-Error "LicenseTool.exe não encontrado em '$toolPath'. Execute: BUILD.bat --tools"
    exit 1
}

$expires = (Get-Date).AddDays($DaysValid).ToString("yyyy-MM-dd")

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Echo Nerfados -- Gerando Licença QA" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Customer  : $CustomerId" -ForegroundColor Gray
Write-Host " Machine   : * (wildcard — sem binding)" -ForegroundColor Gray
Write-Host " Expira    : $expires ($DaysValid dias)" -ForegroundColor Gray
Write-Host " Features  : deep,memory,br_pack,forensic" -ForegroundColor Gray
Write-Host " Output    : $OutputPath" -ForegroundColor Gray
Write-Host ""

& $toolPath --issue `
    --customer  $CustomerId `
    --expires   $expires `
    --machine   "*" `
    --key       $KeyPath `
    --features  "deep,memory,br_pack,forensic" `
    --output    $OutputPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "LicenseTool falhou (exit $LASTEXITCODE)."
    exit 1
}

if (-not (Test-Path $OutputPath)) {
    Write-Error "license.nerf não foi gerado em: $OutputPath"
    exit 1
}

$sha = (Get-FileHash $OutputPath -Algorithm SHA256).Hash
Write-Host ""
Write-Host " Licença gerada com sucesso!" -ForegroundColor Green
Write-Host " Path   : $OutputPath" -ForegroundColor White
Write-Host " SHA256 : $sha" -ForegroundColor White
Write-Host ""
