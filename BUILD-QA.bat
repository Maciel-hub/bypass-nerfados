@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM Echo Nerfados Shield XDR - Build QA/Teste Interno
REM ============================================================
REM
REM Gera um installer QA com licença wildcard embutida.
REM O tester recebe apenas EchoNerfadosSetup-QA-<ver>+<commit>.exe
REM e pode instalar + usar o scanner sem nenhuma configuração extra.
REM
REM USAGE:
REM   BUILD-QA.bat
REM   BUILD-QA.bat --sign                 assina o installer
REM   BUILD-QA.bat --key echo_priv.pem    chave de licença explícita
REM   BUILD-QA.bat --days 7               validade da licença (padrão: 15)
REM   BUILD-QA.bat --customer QA-2026-05  identificador do build
REM
REM REQUER:
REM   echo_priv.pem  (--key, ou ECHO_LICENSE_PRIV_KEY, ou ./echo_priv.pem)
REM   Inno Setup 6   (https://jrsoftware.org/isinfo.php)
REM
REM OUTPUT:
REM   dist\EchoNerfadosSetup-QA-<versão>+<commit>.exe
REM ============================================================

set "SIGN=0"
set "DAYS=15"
set "CUSTOMER=QA-INTERNAL"
set "KEY_PATH="

:parse_args
if "%~1"=="--sign"     ( set "SIGN=1"            & shift & goto parse_args )
if "%~1"=="--days"     ( set "DAYS=%~2"           & shift & shift & goto parse_args )
if "%~1"=="--customer" ( set "CUSTOMER=%~2"        & shift & shift & goto parse_args )
if "%~1"=="--key"      ( set "KEY_PATH=%~2"        & shift & shift & goto parse_args )
if "%~1" NEQ "" (
    echo [ERROR] Unknown argument: %~1
    exit /b 1
)

REM ---- Resolve chave de licença ----------------------------------------
if "!KEY_PATH!"=="" (
    if defined ECHO_LICENSE_PRIV_KEY set "KEY_PATH=!ECHO_LICENSE_PRIV_KEY!"
)
if "!KEY_PATH!"=="" (
    if exist "echo_priv.pem"         set "KEY_PATH=echo_priv.pem"
    if exist "scripts\echo_priv.pem" set "KEY_PATH=scripts\echo_priv.pem"
)
if "!KEY_PATH!"=="" (
    echo [ERROR] echo_priv.pem nao encontrado.
    echo         Opcoes:
    echo           BUILD-QA.bat --key ^<caminho^>
    echo           set ECHO_LICENSE_PRIV_KEY=^<caminho^>
    echo           Copie echo_priv.pem para a raiz do projeto
    exit /b 1
)
if not exist "!KEY_PATH!" (
    echo [ERROR] Chave nao encontrada: !KEY_PATH!
    exit /b 1
)

echo.
echo ============================================
echo  Echo Nerfados -- Build QA
echo  Key     : !KEY_PATH!
echo  Customer: !CUSTOMER!
echo  Days    : !DAYS!
echo  Sign    : !SIGN!
echo ============================================

REM ---- Step 1: Build Scanner + LicenseTool + GUI -----------------------
echo.
echo [1/4] Build ^(Scanner + LicenseTool + GUI^)...
call BUILD.bat --tools --gui
if errorlevel 1 (
    echo [ERROR] Build falhou.
    exit /b 1
)
echo [1/4] Build OK.

REM ---- Step 2: Gerar licença QA wildcard -------------------------------
echo.
echo [2/4] Gerando licenca QA wildcard ^(%DAYS% dias^)...
pwsh -NoProfile -NonInteractive -File scripts\make-qa-license.ps1 ^
    -CustomerId "!CUSTOMER!" ^
    -DaysValid !DAYS! ^
    -KeyPath "!KEY_PATH!" ^
    -OutputPath "publish\win-x64\license.nerf"
if errorlevel 1 (
    echo [ERROR] Geracao de licenca falhou.
    exit /b 1
)
echo [2/4] Licenca gerada: publish\win-x64\license.nerf

REM ---- Step 3: Criar installer (Inno Setup) ----------------------------
echo.
echo [3/4] Criando installer QA...
set "SIGN_FLAG="
if "!SIGN!"=="1" set "SIGN_FLAG=-Sign"
pwsh -NoProfile -NonInteractive -File scripts\package.ps1 -Variant QA !SIGN_FLAG!
if errorlevel 1 (
    echo [ERROR] Packaging falhou.
    exit /b 1
)
echo [3/4] Installer criado.

REM ---- Step 4: Verificar artefato --------------------------------------
echo.
echo [4/4] Verificando artefato em dist\...
for /f "delims=" %%f in ('dir /b "dist\EchoNerfadosSetup-QA-*.exe" 2^>nul') do set "ARTIFACT=dist\%%f"
if "!ARTIFACT!"=="" (
    echo [ERROR] Nenhum installer QA encontrado em dist\.
    exit /b 1
)

for /f "delims=" %%h in ('pwsh -NoProfile -NonInteractive -Command "(Get-FileHash '!ARTIFACT!' -Algorithm SHA256).Hash.ToLower()"') do set "SHA=%%h"

echo.
echo ============================================
echo  QA BUILD COMPLETO
echo ============================================
echo  Arquivo  : !ARTIFACT!
echo  SHA256   : !SHA!
echo  Licenca  : Wildcard QA, !DAYS! dias, customer=!CUSTOMER!
echo.
echo  Entregue apenas esse .exe para o tester.
echo  Ele instala e usa sem nenhuma configuracao extra.
echo.
endlocal
