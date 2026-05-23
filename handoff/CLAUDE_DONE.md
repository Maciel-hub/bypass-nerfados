# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | QA fixes - VM false positive + harness typo |
| Commit | `833e8a8` |
| Branch | `master` |
| Build/ProductVersion | `1.0.0+833e8a8` |
| GUI SHA256 | `33C7702E85EA0442B3787267B8A9DE910AF396156831EB08FB8BF68976B4D584` |
| CLI SHA256 | `4758079C61E0818E9DD4C902BD2DD57212A53156213484BEBB987020B577D68F` |
| Artefatos | `publish/win-x64-gui/EchoNerfados.App.exe`, `publish/win-x64/EchoNerfados.exe` |
| Data/hora | 23/05/2026 |

## 2. Objetivo da entrega

Corrigir P0-1 (falso positivo de VM em host fisico com Hyper-V instalado) e P1-1 (typo
`fvem_b_harness` -> `fivem_b_harness`) apontados em QA do commit `aa0f26f`.
Publicar artefato rastreavel alinhado ao commit corrigido.

## 3. Arquivos alterados

| Arquivo | Tipo | Descricao |
|---|---|---|
| `src/Scanner/Modules/SystemInfoModule.cs` | Modificado | Reescreve `CheckVirtualization` com scoring; Hyper-V host isolado vira Info |
| `src/Scanner/Data/CheatDatabase.cs` | Modificado | Corrige typo: `fvem_b_harness` -> `fivem_b_harness` |

## 4. Mudancas tecnicas

### CheckVirtualization — novo modelo de scoring

Substituiu a verificacao binaria por um sistema de pontuacao de 2 niveis:

**Sinais fortes (2 pts cada) — indicam guest real:**
- Disco com string de virtualizador (vmware, virtualbox, vbox, qemu, xen, parallels, innotek, bochs, "virtual disk", "virtual machine", "msft virtual")
- BIOS/produto com string de virtualizador (mesmo set acima)
- VMware Tools instalado (`SOFTWARE\VMware, Inc.\VMware Tools`)
- VirtualBox Guest Additions (`SOFTWARE\Oracle\VirtualBox Guest Additions`)
- Servico vmtoolsd (`SYSTEM\...\Services\vmtoolsd`)
- Servico VBoxService (`SYSTEM\...\Services\VBoxService`)

**Sinais fracos (1 pt) — existem em hosts fisicos com Hyper-V Feature:**
- Chaves de servico `vmbus`, `vmicheartbeat`, `vmicrdv`, `vid` com `Start=0/1/2 (automatico)`.
- Chaves com `Start=3/4 (Manual/Disabled)` sao **ignoradas** silenciosamente.

**Regras de classificacao:**
- Score >= 2 → `RiskLevel.High` "MAQUINA VIRTUAL DETECTADA"
- Score < 2, sinais fracos existem → `RiskLevel.Info` "Hyper-V recurso de host (nao guest)"
- Score = 0 → sem finding

**Por que isso resolve o FP:**  
Na maquina Gigabyte B450 com Hyper-V instalado: vmbus/vmicheartbeat existem com Start=3
(Manual). Esses nao sao sinais fracos (Start=Manual nao entra no calculo). Score = 0 → sem
finding. Mesmo se Start=Auto, seria 1pt fraco → Info, nao High.

### CheatDatabase — harness allowlist

- `fvem_b_harness` → `fivem_b_harness` (typo corrigido)

### ScanViewModel — Task.Run (P0-3 anterior, ja presente)

Confirmado: linha 55 ja contem `Task.Run(() => orchestrator.RunAsync(_cts.Token))`.
O P0-3 estava resolvido desde o commit `753ea1a` anterior. Nao havia regressao.

## 5. Riscos conhecidos

| Risco | Impacto | Mitigacao |
|---|---|---|
| Host com vmbus Start=Auto mas sem guest | Gera Info (nao High) | Aceitavel — Info nao bloqueia envio |
| Surface/Azure PC com BIOS Microsoft Corp | Pode gerar sinal de BIOS se "Virtual Machine" aparecer no prod name | VmGuestStrings exige substring especifica ("virtual machine", "virtual disk", "msft virtual"), nao apenas "microsoft" |
| Browser downloads perdeu path keyword (P1-2 herdado) | `setup.exe` em pasta local suspeita com URL neutra pode nao ser sinalizado | Registrado como P1-2 pendente — reintroduzir path scoring no proximo sprint |

## 6. Comandos executados pelo dev

```powershell
# Build Scanner
dotnet build src/Scanner/Scanner.csproj -c Release --no-restore

# Publicar GUI
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64-gui

# Publicar CLI
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64

# SHA256
Get-FileHash publish/win-x64-gui/EchoNerfados.App.exe -Algorithm SHA256
Get-FileHash publish/win-x64/EchoNerfados.exe -Algorithm SHA256
```

## 7. Comandos para QA

```powershell
# Status geral
pwsh -File scripts\agent-status.ps1

# Build
dotnet build .\EchoNerfados.sln -c Release --no-restore

# Validar artefato GUI
Get-FileHash publish/win-x64-gui/EchoNerfados.App.exe -Algorithm SHA256
(Get-Item publish/win-x64-gui/EchoNerfados.App.exe).VersionInfo.ProductVersion

# Validar SHA256 esperados
# GUI: 33C7702E85EA0442B3787267B8A9DE910AF396156831EB08FB8BF68976B4D584
# CLI: 4758079C61E0818E9DD4C902BD2DD57212A53156213484BEBB987020B577D68F

# Simular host Hyper-V (se Start=3 para vmbus/vmicheartbeat, espera-se 0 findings High)
# Verificar no registro:
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\vmbus -Name Start
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\vmicheartbeat -Name Start
# Se Start=3 (Manual): CheckVirtualization nao deve emitir nada.
# Se Start=2 (Auto) sem BIOS/disco virtual: CheckVirtualization emite Info, nao High.
```

## 8. Criterios de aceite

- [x] Build sem erros.
- [x] ProductVersion `1.0.0+833e8a8` nos artefatos.
- [x] SHA256 documentado e rastreavel ao commit.
- [ ] Host fisico com Hyper-V instalado (vmbus Start=3) nao gera `MAQUINA VIRTUAL DETECTADA` High.
- [ ] VM real (disco virtual + BIOS virtual) ainda gera High.
- [ ] `fivem_b_harness` allowlistado corretamente (verificar no codigo).
- [ ] GUI inicia scan sem congelar (Task.Run ja presente em ScanViewModel.cs:55).
- [ ] Pasta de relatorio criada ao concluir scan.

## 9. Observacoes para o Codex

- P1-2 (BrowserDownloads perdeu path keyword context) nao foi resolvido nesta entrega — registrado como risco e pendente para proxima revisao.
- O scoring de VM foi projetado para ser conservador: require 2+ pontos para High. Se o Codex validar que Surface/Azure gera FP por BIOS "microsoft" mesmo com VmGuestStrings atual, ajustar lista.
- artefatos em `publish/` sao ignorados pelo .gitignore; os SHA256 acima sao os binarios desta sessao de build.
