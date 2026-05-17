@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM Echo Nerfados Shield XDR - Build QA/Teste Interno
REM ============================================================
REM
REM Gera um pacote QA com licença wildcard de curta validade.
REM
REM USAGE:
REM   BUILD-QA.bat
REM   BUILD-QA.bat --sign          assina os EXEs antes de empacotar
REM   BUILD-QA.bat --days 7        validade da licença QA (padrão: 15)
REM   BUILD-QA.bat --customer QA-2026-05
REM
REM REQUER:
REM   echo_priv.pem  (ao lado deste script ou em scripts\)
REM
REM OUTPUT:
REM   dist\EchoNerfadosSetup-QA-<versão>+<commit>.zip
REM ============================================================

set "SIGN=0"
set "DAYS=15"
set "CUSTOMER=QA-INTERNAL"

:parse_args
if "%~1"=="--sign"     ( set "SIGN=1"    & shift & goto parse_args )
if "%~1"=="--days"     ( set "DAYS=%~2"  & shift & shift & goto parse_args )
if "%~1"=="--customer" ( set "CUSTOMER=%~2" & shift & shift & goto parse_args )
if "%~1" NEQ "" (
    echo [ERROR] Unknown argument: %~1
    exit /b 1
)

REM ---- Step 1: Build Scanner + LicenseTool -------------------------
echo.
echo [1/5] Building Scanner + LicenseTool...
call BUILD.bat --tools %SIGN_FLAG%
if errorlevel 1 (
    echo [ERROR] BUILD.bat failed.
    exit /b 1
)
echo [1/5] Build OK.

REM ---- Step 2: Generate QA license ---------------------------------
echo.
echo [2/5] Generating QA wildcard license...
pwsh -NoProfile -NonInteractive -File scripts\make-qa-license.ps1 ^
    -CustomerId "%CUSTOMER%" ^
    -DaysValid %DAYS% ^
    -OutputPath "publish\win-x64\license.nerf"
if errorlevel 1 (
    echo [ERROR] License generation failed.
    exit /b 1
)
echo [2/5] License generated: publish\win-x64\license.nerf

REM ---- Step 3: Extract version + commit ----------------------------
echo.
echo [3/5] Resolving version...
set "VERSION=1.0.0"
for /f "delims=" %%v in ('pwsh -NoProfile -NonInteractive -Command "[System.Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path 'publish\win-x64\EchoNerfados.exe').Path).ProductVersion"') do (
    set "FULL_VER=%%v"
)
for /f "tokens=1 delims=+" %%v in ("!FULL_VER!") do set "VERSION=%%v"
for /f "tokens=2 delims=+" %%v in ("!FULL_VER!") do set "COMMIT=%%v"
if "!COMMIT!"=="" (
    for /f "delims=" %%c in ('git rev-parse --short HEAD 2^>nul') do set "COMMIT=%%c"
)
set "PKG_NAME=EchoNerfadosSetup-QA-!VERSION!+!COMMIT!"
echo [3/5] Package: !PKG_NAME!

REM ---- Step 4: Assemble package folder -----------------------------
echo.
echo [4/5] Assembling package...
set "PKG_DIR=dist\!PKG_NAME!"
if exist "!PKG_DIR!" rmdir /s /q "!PKG_DIR!"
mkdir "!PKG_DIR!"

copy "publish\win-x64\EchoNerfados.exe"    "!PKG_DIR!\EchoNerfados.exe"    >nul
copy "publish\win-x64\license.nerf"        "!PKG_DIR!\license.nerf"        >nul

REM Copy rules if present
if exist "publish\win-x64\rules\" (
    xcopy /e /i /q "publish\win-x64\rules" "!PKG_DIR!\rules" >nul
)

REM README
echo Echo Nerfados Shield XDR - QA / Teste Interno > "!PKG_DIR!\LEIA-ME-QA.txt"
echo. >> "!PKG_DIR!\LEIA-ME-QA.txt"
echo Build   : !PKG_NAME! >> "!PKG_DIR!\LEIA-ME-QA.txt"
echo Licença : Wildcard QA ^(expira em %DAYS% dias^) >> "!PKG_DIR!\LEIA-ME-QA.txt"
echo Uso     : EchoNerfados.exe --help >> "!PKG_DIR!\LEIA-ME-QA.txt"
echo. >> "!PKG_DIR!\LEIA-ME-QA.txt"
echo NÃO DISTRIBUIR — uso interno de QA apenas. >> "!PKG_DIR!\LEIA-ME-QA.txt"

REM ---- Step 5: Zip -------------------------------------------------
echo.
echo [5/5] Creating ZIP...
if not exist dist mkdir dist
pwsh -NoProfile -NonInteractive -Command ^
    "Compress-Archive -Path '!PKG_DIR!\*' -DestinationPath 'dist\!PKG_NAME!.zip' -Force"
if errorlevel 1 (
    echo [ERROR] ZIP creation failed.
    exit /b 1
)

REM SHA256 of ZIP
for /f "delims=" %%h in ('pwsh -NoProfile -NonInteractive -Command "(Get-FileHash 'dist\!PKG_NAME!.zip' -Algorithm SHA256).Hash.ToLower()"') do set "ZIP_SHA=%%h"

REM Cleanup staging folder
rmdir /s /q "!PKG_DIR!"

REM ---- Summary -----------------------------------------------------
echo.
echo ============================================
echo  QA PACKAGE COMPLETE
echo ============================================
echo  File   : dist\!PKG_NAME!.zip
echo  SHA256 : !ZIP_SHA!
echo  License: Wildcard QA, %DAYS% dias, customer=%CUSTOMER%
echo  Signed : %SIGN%
echo.
endlocal
