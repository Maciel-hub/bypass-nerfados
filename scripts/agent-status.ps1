param(
    [switch]$Json
)

$ErrorActionPreference = "SilentlyContinue"

function Get-Sha256OrNull {
    param([string]$Path)
    if (Test-Path $Path) {
        return (Get-FileHash $Path -Algorithm SHA256).Hash
    }
    return $null
}

function Get-VersionOrNull {
    param([string]$Path)
    if (Test-Path $Path) {
        return (Get-Item $Path).VersionInfo.ProductVersion
    }
    return $null
}

function Get-FileInfoOrNull {
    param([string]$Path)
    if (Test-Path $Path) {
        $item = Get-Item $Path
        return [ordered]@{
            path = $item.FullName
            sizeBytes = $item.Length
            lastWriteTime = $item.LastWriteTime.ToString("s")
            productVersion = Get-VersionOrNull $item.FullName
            sha256 = Get-Sha256OrNull $item.FullName
        }
    }
    return $null
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $root

$gitStatus = git status --short 2>$null
$gitBranch = git rev-parse --abbrev-ref HEAD 2>$null
$gitCommit = git rev-parse --short HEAD 2>$null
$gitLast = git log -1 --pretty=format:"%h %s" 2>$null

$cli = Join-Path $root "publish\win-x64\EchoNerfados.exe"
$gui = Join-Path $root "publish\win-x64-gui\EchoNerfados.App.exe"
$latestInstaller = Get-ChildItem (Join-Path $root "dist") -Filter "EchoNerfadosSetup-*.exe" |
    Sort-Object LastWriteTime |
    Select-Object -Last 1

$handoffFiles = @(
    "handoff\CLAUDE_DONE.md",
    "handoff\CODEX_QA.md",
    "handoff\NEXT_SPRINT.md",
    "QA_RUNTIME_CHECKLIST.md",
    "AGENTS_PROTOCOL.md"
)

$handoff = foreach ($rel in $handoffFiles) {
    $p = Join-Path $root $rel
    if (Test-Path $p) {
        $item = Get-Item $p
        [ordered]@{
            file = $rel
            exists = $true
            lastWriteTime = $item.LastWriteTime.ToString("s")
            sizeBytes = $item.Length
        }
    } else {
        [ordered]@{
            file = $rel
            exists = $false
            lastWriteTime = $null
            sizeBytes = $null
        }
    }
}

$result = [ordered]@{
    generatedAt = (Get-Date).ToString("s")
    root = $root
    git = [ordered]@{
        branch = $gitBranch
        commit = $gitCommit
        last = $gitLast
        dirty = [bool]($gitStatus -and $gitStatus.Count -gt 0)
        status = @($gitStatus)
    }
    artifacts = [ordered]@{
        cli = Get-FileInfoOrNull $cli
        gui = Get-FileInfoOrNull $gui
        installer = if ($latestInstaller) { Get-FileInfoOrNull $latestInstaller.FullName } else { $null }
    }
    handoff = @($handoff)
}

if ($Json) {
    $result | ConvertTo-Json -Depth 8
    Pop-Location
    exit 0
}

Write-Host ""
Write-Host "Echo Nerfados - Agent Status" -ForegroundColor Cyan
Write-Host "Root: $root"
Write-Host ""

Write-Host "Git" -ForegroundColor Yellow
Write-Host "  Branch : $gitBranch"
Write-Host "  Commit : $gitCommit"
Write-Host "  Last   : $gitLast"
if ($result.git.dirty) {
    Write-Host "  Status : DIRTY" -ForegroundColor Red
    $gitStatus | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "  Status : clean" -ForegroundColor Green
}

Write-Host ""
Write-Host "Artifacts" -ForegroundColor Yellow
foreach ($name in @("cli","gui","installer")) {
    $a = $result.artifacts[$name]
    if ($null -eq $a) {
        Write-Host "  $name : missing" -ForegroundColor DarkYellow
        continue
    }
    Write-Host "  $name : $($a.path)"
    Write-Host "    Version : $($a.productVersion)"
    Write-Host "    SHA256  : $($a.sha256)"
    Write-Host "    Size    : $($a.sizeBytes)"
}

Write-Host ""
Write-Host "Handoff" -ForegroundColor Yellow
foreach ($h in $handoff) {
    if ($h.exists) {
        Write-Host "  OK      $($h.file)  $($h.lastWriteTime)"
    } else {
        Write-Host "  MISSING $($h.file)" -ForegroundColor DarkYellow
    }
}

Pop-Location
