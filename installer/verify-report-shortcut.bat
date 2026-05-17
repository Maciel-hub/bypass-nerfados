@echo off
title Echo Nerfados - Verify Report
echo.
echo  Echo Nerfados Shield XDR - Report Verification
echo  ================================================
echo.
set /p "REPORT=Paste report folder path: "
if not defined REPORT (
    echo No path entered.
    pause
    exit /b 1
)
echo.
"%~dp0EchoNerfados.exe" --verify-report "%REPORT%"
echo.
pause
