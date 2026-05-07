@echo off
echo.
echo  ============================================================
echo   BYPASS NERFADOS SHIELD XDR - Build Script
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
echo  [INFO] Restaurando dependencias...
dotnet restore "src\Scanner\Scanner.csproj"
if %errorlevel% neq 0 (
    echo  [ERRO] Falha ao restaurar pacotes NuGet.
    pause
    exit /b 1
)

echo.
echo  [INFO] Compilando projeto...
dotnet build "src\Scanner\Scanner.csproj" -c Release -o "build\Release"
if %errorlevel% neq 0 (
    echo  [ERRO] Falha na compilacao!
    pause
    exit /b 1
)

echo.
echo  ============================================================
echo   BUILD CONCLUIDO COM SUCESSO!
echo  ============================================================
echo.
echo  Executavel: build\Release\BypassNerfados.exe
echo.
echo  USO (como Administrador):
echo    build\Release\BypassNerfados.exe
echo    build\Release\BypassNerfados.exe --investigator "Nome" --suspect "Suspeito"
echo.
pause
