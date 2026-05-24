# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | FiveM Session Interaction QA fixes (P0+P1) |
| Commit produto | `f194191` |
| Branch | `master` |
| ProductVersion | `1.0.1+f194191` |
| GUI SHA256 | `9028F2A0DE1CC8FEC91D6FB94D2F8E8A38D14C21760C90F37E28B9506252D84D` |
| CLI SHA256 | `E1AAAD7F57A7053A6F451FCD2BE1BEFA51B3AE6D204A26D8C3457AF962013E4C` |
| Installer | `dist/EchoNerfadosSetup-RC-1.0.1+f194191.exe` |
| Installer SHA256 | `64FEE608562E3C3068BCDEEB4058D3A70993315CB82E9764C421F80130A2C1AE` |
| Data/hora | 23/05/2026 |

## 2. Objetivo da entrega

Fix P0/P1 do QA do sprint FiveM Session Interaction View (9f159f0).

P0: Rebuildar apos o commit da feature para alinhar ProductVersion ao commit final.
P1: Corrigir 3 issues de comportamento.

## 3. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `src/Scanner/Core/FiveMSessionAnalyzer.cs` | `f194191` | OutsideSession: ScoreEligible=false + Risk cap Medium; BAM sempre coletado |
| `src/Scanner/Core/Correlator.cs` | `f194191` | BAM sempre coletado; Critical exige Confidence>=High em 2+ fontes |
| `src/Scanner/Core/ConsoleUI.cs` | `f194191` | Top Findings: filtra por ScoreEligible |
| `src/EchoNerfados.App/ViewModels/ResultViewModel.cs` | `f194191` | TopFindings: filtra por ScoreEligible |
| `src/Scanner/Reports/HtmlTemplate.cs` | `f194191` | ProvasFortes: filtra por ScoreEligible |

## 4. Mudancas tecnicas

### P1-1 — OutsideSession nao polui Top Findings

`FiveMSessionAnalyzer`: OutsideSession com Confidence < High agora recebe:
- `ScoreEligible = false` — sai do score e do Top Findings
- `Risk` rebaixado para no maximo Medium se estava acima
- `ValidationHint` adicionado (ja estava, mantido)

`ConsoleUI` (top5 e top10), `ResultViewModel.TopFindings`, `HtmlTemplate.provasFortes`:
todos agora filtram `f.ScoreEligible == true` antes de listar High+.

### P1-2 — Sessoes FiveM agora juntam Prefetch + BAM

`FiveMSessionAnalyzer.CollectSessions` e `Correlator.CorrelateFiveMSession`:
removido `if (times.Count == 0)` antes do loop BAM. Prefetch e BAM sao
sempre coletados. `Distinct()` no final deduplica timestamps identicos.

### P1-3 — CORR_FIVEM_SESSION Critical exige qualidade de fonte

```csharp
// antes
bool hasMultipleSources = distinctModules >= 2;

// depois
bool hasMultipleSources = distinctModules >= 2 &&
    inWindow.Any(f => f.ScoreEligible && f.Confidence >= Confidence.High);
```

Dois Medium genericos de modulos distintos nao mais viram Critical.

## 5. Criterios de aceite

- [x] Build 0 erros.
- [x] ProductVersion CLI/GUI: `1.0.1+f194191`.
- [x] Installer: `EchoNerfadosSetup-RC-1.0.1+f194191.exe`.
- [x] OutsideSession generico: ScoreEligible=false, Risk<=Medium.
- [x] Top Findings (console/GUI/HTML ProvasFortes): filtra ScoreEligible.
- [x] Prefetch + BAM coletados sempre.
- [x] CORR_FIVEM_SESSION Critical: exige Confidence>=High em 2+ fontes.
- [x] Aba Sessao FiveM continua com 3 secoes.
- [x] evidence.json continua exportando fivemSessionContexts.
- [ ] Smoke test: instalar, abrir GUI, scan, verificar aba Sessao FiveM.

## 6. Riscos conhecidos

- Nenhum risco novo nesta entrega.
- Agrupamento por filename normalizado (P1-4 do QA) permanece como era:
  aceitavel no curto prazo conforme avaliado pelo Codex.

## 7. Comandos executados pelo dev

```powershell
# Build
dotnet build EchoNerfados.sln -c Release --no-restore

# Publish GUI
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64-gui

# Publish CLI
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64

# Installer
& 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' /DAppVersion=1.0.1 /DAppVariant=RC '/DBuildTag=+f194191' installer\EchoNerfados.iss
```

## 8. Comandos para QA

```powershell
# Status geral
pwsh -File scripts\agent-status.ps1

# ProductVersion — esperado: 1.0.1+f194191
(Get-Item publish/win-x64-gui/EchoNerfados.App.exe).VersionInfo.ProductVersion
(Get-Item publish/win-x64/EchoNerfados.exe).VersionInfo.ProductVersion

# SHA256
Get-FileHash publish/win-x64-gui/EchoNerfados.App.exe -Algorithm SHA256
# GUI: 9028F2A0DE1CC8FEC91D6FB94D2F8E8A38D14C21760C90F37E28B9506252D84D

Get-FileHash publish/win-x64/EchoNerfados.exe -Algorithm SHA256
# CLI: E1AAAD7F57A7053A6F451FCD2BE1BEFA51B3AE6D204A26D8C3457AF962013E4C

Get-FileHash dist/EchoNerfadosSetup-RC-1.0.1+f194191.exe -Algorithm SHA256
# Installer: 64FEE608562E3C3068BCDEEB4058D3A70993315CB82E9764C421F80130A2C1AE

# Verificar ScoreEligible + Risk cap em OutsideSession
rg -n "ScoreEligible = false|f.Risk = RiskLevel.Medium" src/Scanner/Core/FiveMSessionAnalyzer.cs

# Verificar filtro ScoreEligible em Top Findings
rg -n "ScoreEligible" src/Scanner/Core/ConsoleUI.cs
rg -n "ScoreEligible" src/EchoNerfados.App/ViewModels/ResultViewModel.cs

# Verificar coleta de sessoes (sem if(times.Count==0))
rg -n "if.*times.Count" src/Scanner/Core/FiveMSessionAnalyzer.cs
# Esperado: 0 matches

# Verificar Critical condition no correlator
rg -n "hasMultipleSources|Confidence.High" src/Scanner/Core/Correlator.cs
```

## 9. Observacoes para o Codex

Esta entrega fecha os P0/P1 do QA anterior.

Historial de commits para rastreabilidade:
- `9f159f0`: feat — FiveM Session Interaction View (feature base)
- `f194191`: fix — QA fixes P0/P1 (artefato alinhado + comportamento corrigido)

Installer anterior `+5940b08` e `+1a26eb5` ainda existem em dist\. Usar somente `+f194191`.
