@echo off
echo.
echo  ============================================================
echo   ECHO NERFADOS SHIELD XDR - Build Script
echo  ============================================================
echo.

where dotnet >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERRO] .NET SDK nao encontrado!
    echo  Instale o .NET 8 SDK em: https://dotnet.microsoft.com/download
    pause
    exit /b 1
)

echo  [INFO] .NET SDK encontrado:
dotnet --version

echo.
echo  [INFO] Publicando executavel self-contained...
dotnet publish "src\Scanner\Scanner.csproj" /p:PublishProfile=win-x64
if %errorlevel% neq 0 (
    echo  [ERRO] Falha ao publicar!
    pause
    exit /b 1
)

echo.
echo  ============================================================
echo   BUILD CONCLUIDO COM SUCESSO!
echo  ============================================================
echo.
echo  Executavel: publish\win-x64\EchoNerfados.exe
echo.
echo  USO (como Administrador):
echo    publish\win-x64\EchoNerfados.exe
echo    publish\win-x64\EchoNerfados.exe --investigator "Nome" --suspect "Suspeito"
echo.
pause
