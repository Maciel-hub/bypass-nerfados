# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | Fix installer — self-contained publish + arquivo completo (.iss wildcard) |
| Commit produto | `3d1d021` (installer .iss) / binários de `f4d5994` |
| Branch | `master` |
| ProductVersion CLI/GUI | `1.0.1+3d1d021` |
| CLI SHA256 (self-contained) | `82AFF7945880288747D928CAC0776C0069D7D63918A38EF992EE915FFF2A56BE` |
| GUI SHA256 (self-contained) | `80FB8686912EA3EA19F87E6E65517D976EB7D729CA33545ECE78A6D4C39FFECC` |
| Installer per-user | `dist/EchoNerfadosSetup-RC-User-1.0.1+3d1d021.exe` |
| Installer per-user SHA256 | `4502B66275E48F9B23E6365FB679C0D52980C6480668D29419B919483CDF4977` |
| Installer admin | `dist/EchoNerfadosSetup-RC-1.0.1+3d1d021.exe` |
| Installer admin SHA256 | `259BC1C8211C9B7AB1C25EFD5736987DD1220116BDBA40DD92EF75C3AD6D605A` |
| Tamanho esperado | ~74 MB cada installer (self-contained com runtime embutido) |
| Data/hora | 28/05/2026 |

## 2. Dois bugs corrigidos neste ciclo

### Bug 1 — Installer copiava bundle incompleto (P0)

`[Files]` listava arquivos explícitos: `App.exe`, `*.dll` da GUI, `EchoNerfados.exe`.
Faltavam: `EchoNerfados.dll`, `*.deps.json`, `*.runtimeconfig.json` e assemblies do CLI.
CLI falhava: "application does not exist: EchoNerfados.dll".
GUI falhava: "EchoNerfados.App.runtimeconfig.json was not found".

Corrigido em commit `3d1d021`: wildcards `Source: "..\publish\win-x64-gui\*"` e
`Source: "..\publish\win-x64\*"` com `recursesubdirs createallsubdirs`.

### Bug 2 — Publish era framework-dependent (~2.8 MB) em vez de self-contained (~74 MB)

Os últimos publishes foram feitos com `--self-contained false` (comandos manuais desta sessão).
O BUILD.bat correto usa `--self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true`.

Corrigido: publish dirs limpos e republicados com as flags corretas antes de gerar os installers.

## 3. Publish flags corretas (conforme BUILD.bat)

```
dotnet publish src/Scanner/Scanner.csproj
    -c Release -r win-x64
    --self-contained true
    -p:PublishSingleFile=true
    -p:PublishReadyToRun=true
    -o publish/win-x64

dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj
    -c Release -r win-x64
    --self-contained true
    -p:PublishSingleFile=true
    -p:PublishReadyToRun=true
    -o publish/win-x64-gui
```

Tamanhos corretos: CLI ~82 MB, GUI ~167 MB (runtime .NET embutido).
Installers LZMA2 comprimem para ~74 MB.

## 4. Criterios de aceite

- [x] Installers ~74 MB (self-contained, não depende de .NET instalado)
- [x] SHA256 documentados
- [ ] Instalar per-user em VM limpa (sem .NET SDK/runtime)
- [ ] EchoNerfados.App.exe abre sem erro
- [ ] EchoNerfados.exe --help executa sem erro
- [ ] Scan gera report.html, evidence.json, manifest.json
- [ ] Memory String Scan: sem self-hit em EchoNerfados

## 5. Smoke test recomendado

```powershell
# 1. Instalar em VM limpa (sem .NET runtime)
EchoNerfadosSetup-RC-User-1.0.1+f4d5994.exe /SILENT

# 2. Verificar CLI
& "$env:LOCALAPPDATA\Programs\EchoNerfados\EchoNerfados.exe" --help
# Deve mostrar usage sem erro de runtime

# 3. Verificar GUI (abrir e rodar scan)
& "$env:LOCALAPPDATA\Programs\EchoNerfados\EchoNerfados.App.exe"

# 4. Verificar relatório gerado
ls $env:LOCALAPPDATA\Programs\EchoNerfados\..\..\EchoNerfados\reports\*
# report.html, evidence.json, manifest.json, stan_90d.json, etc.

# 5. Confirmar SHA256 do installer
certutil -hashfile dist\EchoNerfadosSetup-RC-User-1.0.1+f4d5994.exe SHA256
# Esperado: 4502B66275E48F9B23E6365FB679C0D52980C6480668D29419B919483CDF4977
```

## 6. Observacoes para o Codex

- Para entregas futuras, SEMPRE usar BUILD.bat --gui (ou as flags self-contained acima).
  Nunca usar `dotnet publish --self-contained false` para installers de tester.
- O atalho de Desktop agora e marcado por padrao em ambos os installers
  (removido Flags: unchecked do [Tasks]).
- O installer admin exclui license.nerf do wildcard CLI (`Excludes: "license.nerf"`)
  porque o license.nerf e gerenciado pela secao #ifdef IncludeLicense separada.
- Commit de código: f4d5994 (self-scan FP fix).
  Commit de installer .iss: 3d1d021 (wildcard file copy + desktop icon default).
  Os binários publicados embedam 3d1d021 como ProductVersion porque o rebuild
  foi feito após o commit dos .iss.
