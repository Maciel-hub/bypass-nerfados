@echo off
setlocal EnableDelayedExpansion

:: ════════════════════════════════════════════════════════════
:: Echo Nerfados Shield XDR — Build + Publish + Optional Sign
:: ════════════════════════════════════════════════════════════
::
:: USO:
::   BUILD.bat                     publica sem assinar
::   BUILD.bat --sign               assina se cert configurado
::   BUILD.bat --tools              também publica LicenseTool
::   BUILD.bat --sign --tools       tudo
::
:: CERTIFICADO (defina antes de rodar com --sign):
::   set SIGN_PFX_PATH=echo_codesign.pfx
::   set SIGN_PFX_PASSWORD=sua_senha
::   -- OU --
::   set SIGN_CERT_THUMBPRINT=ABCDEF...
::
:: SELF-SIGNED (QA interno):
::   pwsh -File scripts\create-selfsigned-cert.ps1
::   set SIGN_PFX_PATH=echo_dev_codesign.pfx
::   set SIGN_PFX_PASSWORD=dev123
::   BUILD.bat --sign
:: ════════════════════════════════════════════════════════════

set "SIGN=0"
set "BUILD_TOOLS=0"

:parse_args
if "%~1"=="--sign"  set "SIGN=1"        & shift & goto parse_args
if "%~1"=="--tools" set "BUILD_TOOLS=1" & shift & goto parse_args
if "%~1" NEQ "" (
    echo Argumento desconhecido: %~1
    exit /b 1
)

:: ── Verify dotnet ─────────────────────────────────────────────────────────────
where dotnet >nul 2>&1
if errorlevel 1 (
    echo [ERRO] .NET SDK nao encontrado. Instale em: https://dotnet.microsoft.com/download
    exit /b 1
)

:: ── Step 1: Publish Scanner ───────────────────────────────────────────────────
echo.
echo [1/4] Publicando EchoNerfados...
dotnet publish src\Scanner\Scanner.csproj ^
    -c Release ^
    -r win-x64 ^
    --self-contained true ^
    -p:PublishSingleFile=true ^
    -p:PublishReadyToRun=true ^
    -o publish\win-x64
if errorlevel 1 (
    echo [ERRO] Publish do Scanner falhou.
    exit /b 1
)

:: ── Step 2: Publish LicenseTool (opcional) ───────────────────────────────────
if "%BUILD_TOOLS%"=="1" (
    echo.
    echo [2/4] Publicando LicenseTool...
    dotnet publish src\LicenseTool\LicenseTool.csproj ^
        -c Release ^
        -r win-x64 ^
        --self-contained true ^
        -p:PublishSingleFile=true ^
        -o publish\tools
    if errorlevel 1 (
        echo [ERRO] Publish do LicenseTool falhou.
        exit /b 1
    )
) else (
    echo [2/4] LicenseTool ignorado (use --tools para incluir)
)

:: ── Step 3: Sign ──────────────────────────────────────────────────────────────
if "%SIGN%"=="1" (
    echo.
    echo [3/4] Assinando EchoNerfados.exe...
    pwsh -NoProfile -NonInteractive -File scripts\sign.ps1 ^
        -TargetPath "publish\win-x64\EchoNerfados.exe"
    if errorlevel 1 (
        echo [ERRO] Assinatura do Scanner falhou.
        exit /b 1
    )
    if "%BUILD_TOOLS%"=="1" (
        echo.
        echo [3/4] Assinando LicenseTool.exe...
        pwsh -NoProfile -NonInteractive -File scripts\sign.ps1 ^
            -TargetPath "publish\tools\LicenseTool.exe"
        if errorlevel 1 (
            echo [ERRO] Assinatura do LicenseTool falhou.
            exit /b 1
        )
    )
) else (
    echo [3/4] Assinatura ignorada (use --sign para habilitar)
    echo       Configure: set SIGN_PFX_PATH=...  ^&  set SIGN_PFX_PASSWORD=...
)

:: ── Step 4: Verify signature ──────────────────────────────────────────────────
echo.
echo [4/4] Verificando assinatura...
pwsh -NoProfile -NonInteractive -File scripts\verify-signature.ps1 ^
    -TargetPath "publish\win-x64\EchoNerfados.exe"

:: ── Summary ───────────────────────────────────────────────────────────────────
echo.
echo ════════════════════════════════════════════
echo  BUILD CONCLUIDO
echo ════════════════════════════════════════════
for /f "delims=" %%v in ('publish\win-x64\EchoNerfados.exe --machine-id 2^>^&1') do (
    echo  Machine ID : %%v
)
echo  Artefatos  :
echo    publish\win-x64\EchoNerfados.exe
if "%BUILD_TOOLS%"=="1" echo    publish\tools\LicenseTool.exe
echo.
endlocal
