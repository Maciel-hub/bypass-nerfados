@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM Echo Nerfados Shield XDR - Build + Publish + Sign
REM ============================================================
REM
REM USAGE:
REM   BUILD.bat                publish only (no signing)
REM   BUILD.bat --sign         sign after publish if cert configured
REM   BUILD.bat --tools        also publish LicenseTool
REM   BUILD.bat --gui          also publish EchoNerfados.App (WPF GUI)
REM   BUILD.bat --sign --tools --gui  all of the above
REM
REM CERTIFICATE (set before running with --sign):
REM   Via PFX:
REM     set SIGN_PFX_PATH=echo_codesign.pfx
REM     set SIGN_PFX_PASSWORD=your_password
REM   Via thumbprint (cert in Windows store):
REM     set SIGN_CERT_THUMBPRINT=ABCDEF...
REM
REM QA self-signed:
REM   pwsh -File scripts\create-selfsigned-cert.ps1
REM   set SIGN_PFX_PATH=echo_dev_codesign.pfx
REM   set SIGN_PFX_PASSWORD=dev123
REM   BUILD.bat --sign
REM ============================================================

set "SIGN=0"
set "BUILD_TOOLS=0"
set "BUILD_GUI=0"

:parse_args
if "%~1"=="--sign"  ( set "SIGN=1"        & shift & goto parse_args )
if "%~1"=="--tools" ( set "BUILD_TOOLS=1" & shift & goto parse_args )
if "%~1"=="--gui"   ( set "BUILD_GUI=1"   & shift & goto parse_args )
if "%~1" NEQ "" (
    echo [ERROR] Unknown argument: %~1
    exit /b 1
)

REM ---- Check dotnet -----------------------------------------------
where dotnet >nul 2>&1
if errorlevel 1 (
    echo [ERROR] .NET SDK not found. Install from: https://dotnet.microsoft.com/download
    exit /b 1
)

REM ---- Step 1: Publish Scanner ------------------------------------
echo.
echo [1/4] Publishing EchoNerfados...
dotnet publish src\Scanner\Scanner.csproj ^
    -c Release ^
    -r win-x64 ^
    --self-contained true ^
    -p:PublishSingleFile=true ^
    -p:PublishReadyToRun=true ^
    -o publish\win-x64
if errorlevel 1 (
    echo [ERROR] Scanner publish failed.
    exit /b 1
)
echo [1/4] Scanner published OK.

REM ---- Step 1b: Publish GUI (optional) ----------------------------
if "%BUILD_GUI%"=="1" (
    echo.
    echo [1b] Publishing EchoNerfados.App ^(WPF GUI^)...
    dotnet publish src\EchoNerfados.App\EchoNerfados.App.csproj ^
        -c Release ^
        -r win-x64 ^
        --self-contained true ^
        -p:PublishSingleFile=true ^
        -p:PublishReadyToRun=true ^
        -o publish\win-x64-gui
    if errorlevel 1 (
        echo [ERROR] GUI publish failed.
        exit /b 1
    )
    echo [1b] GUI published OK.
) else (
    echo [1b] GUI skipped ^(use --gui to include^).
)

REM ---- Step 2: Publish LicenseTool (optional) ---------------------
if "%BUILD_TOOLS%"=="1" (
    echo.
    echo [2/4] Publishing LicenseTool...
    dotnet publish src\LicenseTool\LicenseTool.csproj ^
        -c Release ^
        -r win-x64 ^
        --self-contained true ^
        -p:PublishSingleFile=true ^
        -o publish\tools
    if errorlevel 1 (
        echo [ERROR] LicenseTool publish failed.
        exit /b 1
    )
    echo [2/4] LicenseTool published OK.
) else (
    echo [2/4] LicenseTool skipped ^(use --tools to include^).
)

REM ---- Step 3: Sign -----------------------------------------------
if "%SIGN%"=="1" (
    echo.
    echo [3/4] Signing EchoNerfados.exe...
    pwsh -NoProfile -NonInteractive -File scripts\sign.ps1 ^
        -TargetPath "publish\win-x64\EchoNerfados.exe"
    if errorlevel 1 (
        echo [ERROR] Signing failed.
        exit /b 1
    )

    if "%BUILD_GUI%"=="1" (
        echo.
        echo [3/4] Signing EchoNerfados.App.exe...
        pwsh -NoProfile -NonInteractive -File scripts\sign.ps1 ^
            -TargetPath "publish\win-x64-gui\EchoNerfados.App.exe"
        if errorlevel 1 (
            echo [ERROR] GUI signing failed.
            exit /b 1
        )
    )

    if "%BUILD_TOOLS%"=="1" (
        echo.
        echo [3/4] Signing LicenseTool.exe...
        pwsh -NoProfile -NonInteractive -File scripts\sign.ps1 ^
            -TargetPath "publish\tools\LicenseTool.exe"
        if errorlevel 1 (
            echo [ERROR] LicenseTool signing failed.
            exit /b 1
        )
    )
) else (
    echo [3/4] Signing skipped ^(use --sign to enable^).
    echo        Configure: set SIGN_PFX_PATH=... and set SIGN_PFX_PASSWORD=...
)

REM ---- Step 4: Verify signature -----------------------------------
echo.
echo [4/4] Verifying signature on EchoNerfados.exe...
pwsh -NoProfile -NonInteractive -File scripts\verify-signature.ps1 ^
    -TargetPath "publish\win-x64\EchoNerfados.exe"
set VERIFY_EXIT=%ERRORLEVEL%

if "%SIGN%"=="1" (
    REM With --sign: any non-zero verify exit is a build failure
    if %VERIFY_EXIT% NEQ 0 (
        echo [ERROR] Signature verification failed ^(exit %VERIFY_EXIT%^). Build aborted.
        exit /b 1
    )
    echo [4/4] Signature verified OK.
) else (
    REM Without --sign: NotSigned exit=2 is a warning, not a failure.
    REM Exit 3+ means hash mismatch or error -- fails even without --sign.
    if %VERIFY_EXIT% GEQ 3 (
        echo [ERROR] Signature verification error ^(exit %VERIFY_EXIT%^). Investigate.
        exit /b 1
    )
    if %VERIFY_EXIT% EQU 2 (
        echo [WARN] EXE is unsigned. Run BUILD.bat --sign to sign.
    )
    if %VERIFY_EXIT% EQU 0 (
        echo [4/4] Signature verified OK.
    )
)

REM ---- Summary ----------------------------------------------------
echo.
echo ============================================
echo  BUILD COMPLETE
echo ============================================

for /f "delims=" %%v in ('publish\win-x64\EchoNerfados.exe --machine-id') do (
    echo  Machine ID : %%v
)

echo  Artifacts:
echo    publish\win-x64\EchoNerfados.exe

if "%BUILD_GUI%"=="1" (
    echo    publish\win-x64-gui\EchoNerfados.App.exe
)
if "%BUILD_TOOLS%"=="1" (
    echo    publish\tools\LicenseTool.exe
)

if "%SIGN%"=="1" (
    echo  Signed: YES
) else (
    echo  Signed: NO ^(unsigned artifact^)
)

echo.
endlocal
exit /b 0
