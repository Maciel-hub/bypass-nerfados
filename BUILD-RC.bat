@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM Echo Nerfados Shield XDR - Build RC (Release Candidate)
REM ============================================================
REM
REM Gera um installer RC sem licença embutida.
REM O tester instala, vê o Machine ID, e depois recebe
REM license.nerf separado para copiar para ProgramData.
REM
REM USAGE:
REM   BUILD-RC.bat
REM   BUILD-RC.bat --sign     assina o installer
REM
REM OUTPUT:
REM   dist\EchoNerfadosSetup-RC-<versão>+<commit>.exe
REM ============================================================

set "SIGN=0"

:parse_args
if "%~1"=="--sign" ( set "SIGN=1" & shift & goto parse_args )
if "%~1" NEQ "" (
    echo [ERROR] Unknown argument: %~1
    exit /b 1
)

echo.
echo ============================================
echo  Echo Nerfados -- Build RC
echo  Sign: !SIGN!
echo ============================================

REM ---- Step 1: Build Scanner + GUI -------------------------------------
echo.
echo [1/3] Build ^(Scanner + GUI^)...
call BUILD.bat --gui
if errorlevel 1 (
    echo [ERROR] Build falhou.
    exit /b 1
)
echo [1/3] Build OK.

REM ---- Step 2: Criar installer RC (Inno Setup) -------------------------
echo.
echo [2/3] Criando installer RC...
set "SIGN_FLAG="
if "!SIGN!"=="1" set "SIGN_FLAG=-Sign"
pwsh -NoProfile -NonInteractive -File scripts\package.ps1 -Variant RC !SIGN_FLAG!
if errorlevel 1 (
    echo [ERROR] Packaging falhou.
    exit /b 1
)
echo [2/3] Installer criado.

REM ---- Step 3: Verificar artefato --------------------------------------
echo.
echo [3/3] Verificando artefato em dist\...
for /f "delims=" %%f in ('dir /b "dist\EchoNerfadosSetup-RC-*.exe" 2^>nul') do set "ARTIFACT=dist\%%f"
if "!ARTIFACT!"=="" (
    echo [ERROR] Nenhum installer RC encontrado em dist\.
    exit /b 1
)

for /f "delims=" %%h in ('pwsh -NoProfile -NonInteractive -Command "(Get-FileHash '!ARTIFACT!' -Algorithm SHA256).Hash.ToLower()"') do set "SHA=%%h"

echo.
echo ============================================
echo  RC BUILD COMPLETO
echo ============================================
echo  Arquivo  : !ARTIFACT!
echo  SHA256   : !SHA!
echo  Licenca  : NAO incluida ^(enviar license.nerf separadamente^)
echo.
echo  Fluxo do tester:
echo    1. Instalar o .exe
echo    2. GUI abre, mostra Machine ID
echo    3. Enviar Machine ID para o dev
echo    4. Dev gera license.nerf e envia de volta
echo    5. Tester clica "Atualizar licenca" na GUI
echo.
endlocal
