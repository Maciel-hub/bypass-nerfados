# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | Release polish — version alignment + VM Info ScoreEligible |
| Commit produto | `1a26eb5` |
| Branch | `master` |
| ProductVersion | `1.0.1+1a26eb5` |
| GUI SHA256 | `AA790DE1C0B41444F4E09440C0706231458DCF921C50D5FC8DEA59AFD8CB98E2` |
| CLI SHA256 | `A17BD0921C6072EC7EC0FBF7BB26D1D7EB41A026D1656B915973FC91A98AA9B2` |
| Installer | `dist/EchoNerfadosSetup-RC-1.0.1+1a26eb5.exe` |
| Installer SHA256 | `C43CEBDCDA698A81338B985811AF6BCA58E2F5D5518FA1C1E2ED41E4DD4A725D` |
| Installer tamanho | 67.6 MB |
| Data/hora | 23/05/2026 |

## 2. Objetivo da entrega

Resolver P1 do QA aprovado 82ce5b0:
- Alinhar `<Version>` dos csproj para `1.0.1` (CLI, Core, GUI reportavam `1.0.0+82ce5b0`).
- Setar `ScoreEligible = false` no finding Info de Hyper-V weak-only.
- Republish CLI/GUI/installer com ProductVersion `1.0.1+1a26eb5`.

## 3. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `src/Scanner/Scanner.csproj` | `1a26eb5` | `<Version>1.0.0` → `1.0.1` |
| `src/Scanner.Core/Scanner.Core.csproj` | `1a26eb5` | `<Version>1.0.0` → `1.0.1` |
| `src/EchoNerfados.App/EchoNerfados.App.csproj` | `1a26eb5` | `<Version>1.0.0` → `1.0.1` |
| `src/Scanner/Modules/SystemInfoModule.cs` | `1a26eb5` | Finding Info Hyper-V: `{ ScoreEligible = false }` |

## 4. Mudancas tecnicas

### Version bump

```xml
<!-- antes -->
<Version>1.0.0</Version>

<!-- depois -->
<Version>1.0.1</Version>
```

O InformationalVersion continua sendo gerado pelo MSBuild target `SetGitVersion` como
`$(Version)+$(GitShortHash)`, portanto todos os binarios agora reportam `1.0.1+1a26eb5`.

### ScoreEligible = false

```csharp
// SystemInfoModule.cs — finding Info Hyper-V weak-only
findings.Add(new Finding(
    RiskLevel.Info,
    FindingCategory.SystemTampering,
    "System Info",
    "Hyper-V: recurso de host detectado (nao e VM guest)",
    ...
) { ScoreEligible = false });
```

`ScoreEligible` ja existe em `Finding.cs:49` com default `true`. Setar `false` explicitamente
garante que refactors futuros que iteram por findings com `ScoreEligible=true` nao incluam
este finding em calculos de risco/score.

## 5. Riscos conhecidos

Nenhum risco novo nesta entrega. Os riscos do sprint anterior (P1-2 BrowserDownloads path
context, deteccao de VM real sem GAs) continuam como backlog.

## 6. Comandos executados pelo dev

```powershell
# Build
dotnet build src/Scanner/Scanner.csproj -c Release --no-restore

# Publish GUI
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64-gui

# Publish CLI
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64

# Installer
& 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' /DAppVersion=1.0.1 /DAppVariant=RC /DBuildTag=+1a26eb5 installer\EchoNerfados.iss
```

## 7. Comandos para QA

```powershell
# Status geral
pwsh -File scripts\agent-status.ps1

# Verificar ProductVersion
(Get-Item publish/win-x64-gui/EchoNerfados.App.exe).VersionInfo.ProductVersion
# Esperado: 1.0.1+1a26eb5

(Get-Item publish/win-x64/EchoNerfados.exe).VersionInfo.ProductVersion
# Esperado: 1.0.1+1a26eb5

# SHA256
Get-FileHash publish/win-x64-gui/EchoNerfados.App.exe -Algorithm SHA256
# GUI: AA790DE1C0B41444F4E09440C0706231458DCF921C50D5FC8DEA59AFD8CB98E2

Get-FileHash publish/win-x64/EchoNerfados.exe -Algorithm SHA256
# CLI: A17BD0921C6072EC7EC0FBF7BB26D1D7EB41A026D1656B915973FC91A98AA9B2

Get-FileHash dist/EchoNerfadosSetup-RC-1.0.1+1a26eb5.exe -Algorithm SHA256
# Installer: C43CEBDCDA698A81338B985811AF6BCA58E2F5D5518FA1C1E2ED41E4DD4A725D

# Verificar ScoreEligible no fonte
Select-String -Path src/Scanner/Modules/SystemInfoModule.cs -Pattern 'ScoreEligible'
# Esperado: 1 match na linha do finding Info Hyper-V
```

## 8. Criterios de aceite

- [x] Build 0 erros.
- [x] CLI ProductVersion = 1.0.1+1a26eb5.
- [x] GUI ProductVersion = 1.0.1+1a26eb5.
- [x] Installer EchoNerfadosSetup-RC-1.0.1+1a26eb5.exe gerado.
- [x] SHA256 documentado e rastreavel.
- [x] Finding Info Hyper-V weak-only tem ScoreEligible = false.
- [ ] Installer instala e GUI abre sem crash (smoke test).
- [ ] Scan inicia, mostra progresso e cria pasta de relatorio.

## 9. Observacoes para o Codex

Entrega minima de polish. O NEXT_SPRINT.md estava correto — quatro arquivos, quatro mudancas
cirurgicas, sem logica nova. O installer antigo `EchoNerfadosSetup-RC-1.0.1+82ce5b0.exe` ainda
esta em dist\ — o novo e `1.0.1+1a26eb5.exe`. Para envio ao tester externo usar o novo.
