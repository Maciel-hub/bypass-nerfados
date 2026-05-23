# QA Runtime Checklist - Echo Nerfados

Checklist reutilizavel para validar builds e installers antes de envio externo.

## 1. Pre-flight

- [ ] `git status --short` revisado.
- [ ] `handoff/CLAUDE_DONE.md` preenchido pelo dev.
- [ ] ProductVersion informado.
- [ ] SHA256 do artefato informado.
- [ ] Build sem erros.
- [ ] Warnings conhecidos documentados.
- [ ] Artefatos antigos removidos de `dist/` ou claramente versionados.

## 2. Verificacao de artefato

```powershell
$exe = "D:\BypassNerfados\publish\win-x64\EchoNerfados.exe"
Get-Item $exe | Select FullName, Length, LastWriteTime
(Get-Item $exe).VersionInfo.ProductVersion
Get-FileHash $exe -Algorithm SHA256
```

Para GUI:

```powershell
$gui = "D:\BypassNerfados\publish\win-x64-gui\EchoNerfados.App.exe"
Get-Item $gui | Select FullName, Length, LastWriteTime
(Get-Item $gui).VersionInfo.ProductVersion
Get-FileHash $gui -Algorithm SHA256
```

## 3. CLI smoke test

Executar em PowerShell normal e admin quando aplicavel:

```powershell
cd D:\BypassNerfados\publish\win-x64
.\EchoNerfados.exe --profile fast --no-open-report --no-final-prompt
```

Validar:

- [ ] Processo conclui.
- [ ] Pasta `Echo_Nerfados_*` criada no Desktop.
- [ ] `report.html` existe.
- [ ] `report.txt` existe.
- [ ] `report_executive.html` existe.
- [ ] `evidence.json` existe.
- [ ] `manifest.json` existe.
- [ ] `manifest.sha256` existe.

Manifest:

```powershell
$folder = Get-ChildItem "$([Environment]::GetFolderPath('Desktop'))\Echo_Nerfados_*" |
  Sort-Object LastWriteTime | Select-Object -Last 1

cd $folder.FullName
$ref = (Get-Content manifest.sha256 -Raw).Split("  ")[0].Trim().ToLower()
$actual = (Get-FileHash manifest.json -Algorithm SHA256).Hash.ToLower()
if ($ref -eq $actual) { "MANIFESTO OK" } else { "MANIFESTO FALHOU: $ref vs $actual" }
```

## 4. GUI smoke test

- [ ] Janela abre.
- [ ] Botao iniciar habilitado em build de teste sem licenca.
- [ ] Machine ID aparece/foi registrado nos outputs.
- [ ] Clicar iniciar nao congela a GUI.
- [ ] Barra/log atualiza por modulo.
- [ ] Botao cancelar responde em ate 1 segundo.
- [ ] Ao concluir, navega para Resultado.
- [ ] Abre `report.html`.
- [ ] Abre `report_executive.html`.
- [ ] Abre pasta do relatorio.

## 5. Installer smoke test

- [ ] Installer abre sem erro.
- [ ] Instala em `C:\Program Files\EchoNerfados`.
- [ ] GUI abre apos install.
- [ ] CLI existe no Start Menu.
- [ ] `rules\` foi instalado.
- [ ] DLLs nativas WPF foram instaladas:
  - [ ] `wpfgfx_cor3.dll`
  - [ ] `PresentationNative_cor3.dll`
  - [ ] `D3DCompiler_47_cor3.dll`
  - [ ] `PenImc_cor3.dll`
  - [ ] `vcruntime140_cor3.dll`
- [ ] Uninstall remove app.
- [ ] ProgramData tratado conforme opcao do uninstall.

## 6. Regressao de deteccao

- [ ] USN Journal executa ou reporta skip/partial com motivo claro.
- [ ] Driver & Kernel sem falso positivo em drivers Microsoft/DriverStore.
- [ ] Memory DLL Trace sem High/Critical em FiveM limpo.
- [ ] Memory String Scan nao gera High/Critical com token generico isolado.
- [ ] AntiForensicScriptModule nao varre `node_modules`, caches de browser, pip/npm de forma ruidosa.
- [ ] RedENGINE export `redengine_{d}d.json` existe, mesmo vazio.

## 7. Criterio de envio externo

Liberar para tester externo somente se:

- [ ] Nao ha P0 aberto.
- [ ] Installer abre GUI.
- [ ] GUI conclui scan ou mostra erro claro recuperavel.
- [ ] Relatorio e manifest sao gerados.
- [ ] `agent-status.ps1` nao aponta artefato ausente.
- [ ] `handoff/CODEX_QA.md` esta aprovado ou aprovado com ressalvas explicitamente aceitas.

