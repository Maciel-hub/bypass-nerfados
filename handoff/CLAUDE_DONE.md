# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | VM detection fix final — weak-only nunca gera High |
| Commit produto | `82ce5b0` |
| Branch | `master` |
| ProductVersion | `1.0.1+82ce5b0` |
| GUI SHA256 | `742F875C5C0BBB8FD34CD2BDE848A8D92411F92913081E6BCBA518E94CC45232` |
| CLI SHA256 | `60BBA123EF0D4E5A7F62060D6071051C29FB608CC4BDE2A20297CDBA31EA2728` |
| Installer | `dist/EchoNerfadosSetup-RC-1.0.1+82ce5b0.exe` |
| Installer SHA256 | `E1663EE6EB06CCE458582786C57137A679683B498D7B9DC09C6F9057F007B7CD` |
| Installer tamanho | 67.6 MB |
| Data/hora | 23/05/2026 |

## 2. Objetivo da entrega

Corrigir P0-1 definitivo: `weakSignals` de Hyper-V host nunca podem somar para High.
Corrigir P1-1: remover `"microsoft corporation"` de VmGuestStrings.
Alinhar installer com o commit do fix.

## 3. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `src/Scanner/Modules/SystemInfoModule.cs` | `82ce5b0` | Reescreve classificacao VM; High somente com strongSignals >= 1 |

## 4. Mudancas tecnicas

### Logica anterior (quebrada)

```csharp
var score = strongSignals.Count * 2 + weakSignals.Count;
if (score >= 2)  // FP: 2 sinais fracos = score 2 = High indevido
```

### Logica nova (correta)

```csharp
if (strongSignals.Count >= 1)  // High: exige pelo menos 1 sinal forte
    → RiskLevel.High "MÁQUINA VIRTUAL DETECTADA"
else if (weakSignals.Count > 0)  // Info: apenas contexto de host Hyper-V
    → RiskLevel.Info "Hyper-V recurso de host (nao guest)"
else
    return;                      // sem sinais = sem finding
```

### Removido de VmGuestStrings

- `"microsoft corporation"`: Surface e hardware fisico da Microsoft reportam este fabricante;
  nao pode ser sinal forte. Strings especificas `"virtual machine"`, `"virtual disk"` e
  `"msft virtual"` continuam presentes para detectar guest Hyper-V real.

### Verificacao do host Gigabyte B450 / Samsung

- vmbus Start=0 → weakSignal, nao strongSignal.
- vid Start=1 → weakSignal, nao strongSignal.
- BIOS "Gigabyte Technology Co., Ltd." → nao contem strings de VM guest.
- Disco "SAMSUNG HD161HJ" → nao contem strings de VM guest.
- Resultado: strongSignals=0, weakSignals=2 → Info, nao High. FP eliminado.

### Verificacao de VM real (guest Hyper-V esperado)

- BIOS SystemProductName = "Virtual Machine" → match em VmGuestStrings → strongSignal.
- Disco = "MSFT VIRTUAL DISK" → match → strongSignal.
- Resultado: strongSignals >= 1 → High. Deteccao preservada.

## 5. Riscos conhecidos

| Risco | Impacto | Mitigacao |
|---|---|---|
| VMware/VBox host com BIOS fisico mas sem GAs | Nao detectado se disco/BIOS fisico e GAs nao instaladas | Aceitavel: sem GAs e sem disco virtual, risco real de cheat via VM e reduzido |
| P1-2 herdado: BrowserDownloads path keyword | Backlog — nao tratado nesta entrega | Registrar para proximo sprint |

## 6. Comandos executados pelo dev

```powershell
# Build
dotnet build src/Scanner/Scanner.csproj -c Release --no-restore

# Publish GUI
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64-gui

# Publish CLI
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64

# Installer
& 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' /DAppVersion=1.0.1 /DAppVariant=RC /DBuildTag=+82ce5b0 installer\EchoNerfados.iss
```

## 7. Comandos para QA

```powershell
# Status geral
pwsh -File scripts\agent-status.ps1

# Verificar versao e SHA256
(Get-Item publish/win-x64-gui/EchoNerfados.App.exe).VersionInfo.ProductVersion
# Esperado: 1.0.1+82ce5b0

Get-FileHash publish/win-x64-gui/EchoNerfados.App.exe -Algorithm SHA256
# GUI: 742F875C5C0BBB8FD34CD2BDE848A8D92411F92913081E6BCBA518E94CC45232

Get-FileHash publish/win-x64/EchoNerfados.exe -Algorithm SHA256
# CLI: 60BBA123EF0D4E5A7F62060D6071051C29FB608CC4BDE2A20297CDBA31EA2728

Get-FileHash dist/EchoNerfadosSetup-RC-1.0.1+82ce5b0.exe -Algorithm SHA256
# Installer: E1663EE6EB06CCE458582786C57137A679683B498D7B9DC09C6F9057F007B7CD

# Verificar FP de VM no host fisico:
# vmbus/vid com Start=0/1 devem gerar Info, nunca High.
# Checar que BIOS Gigabyte + disco Samsung nao geram VM High.
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\vmbus -Name Start  # Start=0 esperado
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\vid  -Name Start  # Start=1 esperado
# Score esperado: strongSignals=0, weakSignals=2 -> Info, nao High.
```

## 8. Criterios de aceite

- [x] Build 0 erros.
- [x] ProductVersion 1.0.1+82ce5b0 em GUI e CLI.
- [x] SHA256 documentado e rastreavel.
- [x] Installer EchoNerfadosSetup-RC-1.0.1+82ce5b0.exe gerado e alinhado.
- [ ] Host fisico com Hyper-V (vmbus Start=0, vid Start=1) gera Info, nao High.
- [ ] VM real (BIOS "Virtual Machine" ou disco "MSFT VIRTUAL DISK") ainda gera High.
- [ ] GUI inicia scan sem congelar (Task.Run em ScanViewModel:55 confirmado).
- [ ] Pasta de relatorio criada ao concluir scan.

## 9. Observacoes para o Codex

A logica agora e binaria e clara: sem sinal forte = sem High. Nao ha mais scoring
numerico que permita acumulo de sinais fracos. O QA pode confirmar inspecionando
`strongSignals.Count >= 1` como unica porta de entrada para o finding High.

`"microsoft corporation"` foi removido de VmGuestStrings. Se um tester externo com
Surface fisico reportar FP, confirmar — a string nao deve estar la. Se for Hyper-V
guest real num Surface, o SystemProductName deve conter "Virtual Machine" e o disco
deve conter "MSFT VIRTUAL DISK" ou similar, que continuam mapeados.
