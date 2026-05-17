@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM Echo Nerfados Shield XDR - Build RC (Release Candidate)
REM ============================================================
REM
REM Gera um pacote RC sem licença embutida.
REM O cliente precisa receber uma license.nerf separadamente.
REM
REM USAGE:
REM   BUILD-RC.bat
REM   BUILD-RC.bat --sign          assina os EXEs antes de empacotar
REM   BUILD-RC.bat --gui           inclui GUI (EchoNerfados.App.exe)
REM
REM OUTPUT:
REM   dist\EchoNerfadosSetup-RC-<versão>+<commit>.zip
REM ============================================================

set "SIGN=0"
set "BUILD_GUI=0"

:parse_args
if "%~1"=="--sign" ( set "SIGN=1"       & shift & goto parse_args )
if "%~1"=="--gui"  ( set "BUILD_GUI=1"  & shift & goto parse_args )
if "%~1" NEQ "" (
    echo [ERROR] Unknown argument: %~1
    exit /b 1
)

REM ---- Step 1: Build -------------------------------------------
echo.
set "GUI_FLAG="
if "%BUILD_GUI%"=="1" set "GUI_FLAG=--gui"
echo [1/4] Building Scanner%GUI_FLAG: %GUI_FLAG%...
call BUILD.bat %GUI_FLAG%
if errorlevel 1 (
    echo [ERROR] BUILD.bat failed.
    exit /b 1
)
echo [1/4] Build OK.

REM ---- Step 2: Extract version + commit ------------------------
echo.
echo [2/4] Resolving version...
set "VERSION=1.0.0"
for /f "delims=" %%v in ('pwsh -NoProfile -NonInteractive -Command "[System.Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path 'publish\win-x64\EchoNerfados.exe').Path).ProductVersion"') do (
    set "FULL_VER=%%v"
)
for /f "tokens=1 delims=+" %%v in ("!FULL_VER!") do set "VERSION=%%v"
for /f "tokens=2 delims=+" %%v in ("!FULL_VER!") do set "COMMIT=%%v"
if "!COMMIT!"=="" (
    for /f "delims=" %%c in ('git rev-parse --short HEAD 2^>nul') do set "COMMIT=%%c"
)
set "PKG_NAME=EchoNerfadosSetup-RC-!VERSION!+!COMMIT!"
echo [2/4] Package: !PKG_NAME!

REM ---- Step 3: Assemble package --------------------------------
echo.
echo [3/4] Assembling package...
set "PKG_DIR=dist\!PKG_NAME!"
if exist "!PKG_DIR!" rmdir /s /q "!PKG_DIR!"
mkdir "!PKG_DIR!"

copy "publish\win-x64\EchoNerfados.exe" "!PKG_DIR!\EchoNerfados.exe" >nul

if "%BUILD_GUI%"=="1" (
    if exist "publish\win-x64-gui\EchoNerfados.App.exe" (
        copy "publish\win-x64-gui\EchoNerfados.App.exe" "!PKG_DIR!\EchoNerfados.App.exe" >nul
    )
)

REM Copy rules if present
if exist "publish\win-x64\rules\" (
    xcopy /e /i /q "publish\win-x64\rules" "!PKG_DIR!\rules" >nul
)

REM README
echo Echo Nerfados Shield XDR - Release Candidate > "!PKG_DIR!\LEIA-ME.txt"
echo. >> "!PKG_DIR!\LEIA-ME.txt"
echo Build : !PKG_NAME! >> "!PKG_DIR!\LEIA-ME.txt"
echo Licença: não incluída — necessária para uso. >> "!PKG_DIR!\LEIA-ME.txt"
echo Coloque license.nerf ao lado de EchoNerfados.exe antes de executar. >> "!PKG_DIR!\LEIA-ME.txt"
echo. >> "!PKG_DIR!\LEIA-ME.txt"
echo Uso: EchoNerfados.exe --help >> "!PKG_DIR!\LEIA-ME.txt"

REM ---- Step 4: Zip ---------------------------------------------
echo.
echo [4/4] Creating ZIP...
if not exist dist mkdir dist
pwsh -NoProfile -NonInteractive -Command ^
    "Compress-Archive -Path '!PKG_DIR!\*' -DestinationPath 'dist\!PKG_NAME!.zip' -Force"
if errorlevel 1 (
    echo [ERROR] ZIP creation failed.
    exit /b 1
)

for /f "delims=" %%h in ('pwsh -NoProfile -NonInteractive -Command "(Get-FileHash 'dist\!PKG_NAME!.zip' -Algorithm SHA256).Hash.ToLower()"') do set "ZIP_SHA=%%h"

rmdir /s /q "!PKG_DIR!"

REM ---- Summary -------------------------------------------------
echo.
echo ============================================
echo  RC PACKAGE COMPLETE
echo ============================================
echo  File   : dist\!PKG_NAME!.zip
echo  SHA256 : !ZIP_SHA!
echo  License: NOT included (distribuir separadamente)
echo  GUI    : %BUILD_GUI%
echo.
endlocal
