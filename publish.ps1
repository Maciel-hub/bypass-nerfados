# Echo Nerfados Shield XDR — Build self-contained single-file executable
# Run from repo root: .\publish.ps1
# Output: publish\win-x64\EchoNerfados.exe  (no .NET runtime required)

$proj = "src\Scanner\Scanner.csproj"
$out  = "publish\win-x64"

Write-Host "Building Echo Nerfados Shield XDR..." -ForegroundColor Cyan

dotnet publish $proj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none `
    -p:DebugSymbols=false `
    -o $out

if ($LASTEXITCODE -eq 0) {
    $exe = Get-Item "$out\EchoNerfados.exe"
    $hash = (Get-FileHash $exe.FullName -Algorithm SHA256).Hash.ToLower()
    Write-Host ""
    Write-Host "Publicado: $($exe.FullName)" -ForegroundColor Green
    Write-Host "Tamanho  : $([math]::Round($exe.Length / 1MB, 1)) MB"
    Write-Host "SHA256   : $hash"
} else {
    Write-Host "Publish falhou." -ForegroundColor Red
    exit 1
}
