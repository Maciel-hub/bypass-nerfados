# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | Fix QA Sprint 6 — blockers P0-1, P0-2, P1-1, P1-2 |
| Commit produto | `98de112` |
| Branch | `master` |
| ProductVersion CLI/GUI | `1.0.1+98de112` |
| CLI SHA256 | `DFE8BE6C17E03BA08C670AC02D284C765D21F4C49CAF58DE1DF8F899015FB51B` |
| GUI SHA256 | `83F98ADA0432C8925DBBE4114B1602A024CFEDF883415F3F55A8D258079EA586` |
| Installer per-user | `dist/EchoNerfadosSetup-RC-User-1.0.1+98de112.exe` |
| Installer per-user SHA256 | `097B692E71FD1D8D64C1221BC89FB2B15818549D577F7089095092AF4EA087FA` |
| Installer admin | `dist/EchoNerfadosSetup-RC-1.0.1+98de112.exe` |
| Installer admin SHA256 | `83A34357335D215B1FE19CC46EFD5A9CA4F8784B7DC0FE92E37572566FB7806A` |
| Data/hora | 27/05/2026 |

## 2. Objetivo da entrega

Fix dos 4 blockers do QA Sprint 6 (bf3527b):
- P0-1: stan_90d.json nao era exportado
- P0-2: REDENGINE_RANDOM_LOADER_NET marcando OneDrive/FileCoAuth como High
- P1-1: loader.exe em CoProcessInteraction com delta -1585 min (timestamp errado)
- P1-2: BROWSER_DL_CHEAT_PORTAL_ARCHIVE nao aparecia para Loader-ffb16aac.zip

## 3. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `src/Scanner/Reports/EvidenceExporter.cs` | `98de112` | Adiciona astrix_90d.json e stan_90d.json; adiciona ao _fullCoverageModules |
| `src/Scanner/Core/SuspiciousCoProcessResolver.cs` | `98de112` | Allowlist filecoauth/onedrive/teams; excluir \microsoft\onedrive\ e \windowsapps\ |
| `src/Scanner/Core/FiveMSessionAnalyzer.cs` | `98de112` | CoProcess pivot: escolhe timestamp mais proximo da sessao FiveM |
| `src/Scanner/Modules/BrowserDownloadsModule.cs` | `98de112` | Remove guard portalFamily==null: CHEAT_PORTAL_ARCHIVE emite mesmo com portal match |

## 4. Mudancas tecnicas por blocker

### P0-1: stan_90d.json nao exportado

`EvidenceExporter.Export()`: adicionadas 2 linhas apos `redengine_{d}.json`:
```csharp
WriteModuleJson(result, runFolder, "Astrix Artifacts", $"astrix_{d}.json", lookback);
WriteModuleJson(result, runFolder, "Stan Artifacts",   $"stan_{d}.json",   lookback);
```

`_fullCoverageModules`: adicionados "Astrix Artifacts" e "Stan Artifacts" para relatar
coverageOk=true (modulos de filesystem-scan, nao event-log com janela limitada).

### P0-2: FP OneDrive/FileCoAuth

`IsUserWritablePath`: adicionados 2 novos exclusoes:
- `\microsoft\onedrive\` → exclui FileCoAuth.exe e outros binarios do OneDrive
- `\windowsapps\` → exclui Microsoft Store apps

`s_knownSafe`: adicionados ~14 processos Microsoft/sistema com nomes mixed-case que
trigavam a heuristica (filecoauth, onedrive, teams, outlook, microsoftedge, searchhost,
runtimebroker, sihost, textinputhost, startmenuexperiencehost, lockapp,
applicationframehost, shellexperiencehost, crashpad, crashpad_handler, msedgewebview2).

### P1-1: CoProcess delta incorreto

`FiveMSessionAnalyzer.DetermineRelation`: bloco `if (isCoProcess)` reescrito.
Antes: usava `findings.FirstOrDefault(f => f.Timestamp.HasValue)` — podia pegar
modificacao de arquivo antiga (ex: STAN_LOADER_WITH_CREDENTIAL com mtime de meses atras).

Agora: produto cartesiano findings × sessions → ordena por |delta| → pega o par com
menor distancia. Garante que o delta exibido no HTML reflete o timestamp de execucao
(Prefetch/BAM) mais proximo da sessao FiveM, nao um mtime aleatorio de arquivo.

### P1-2: BROWSER_DL_CHEAT_PORTAL_ARCHIVE ausente

Antes: `if (IsCheatPortalArchive(fileName) && portalFamily == null)` — o guard
impedia a emissao quando a URL ja havia gerado BROWSER_DL_REDENGINE_PORTAL.

Agora: `if (IsCheatPortalArchive(fileName))` — ambos os findings sao emitidos quando
um Loader-*.zip e baixado do portal. Os ruleIds sao distintos (REDENGINE_PORTAL vs
CHEAT_PORTAL_ARCHIVE) e sao sinais complementares: URL confirma portal; nome de arquivo
confirma padrao de entrega Stan/RedENGINE.

## 5. Criterios de aceite

- [x] Build 0 erros (9 avisos pre-existentes)
- [x] Commit `98de112` com ProductVersion `1.0.1+98de112`
- [x] Installers gerados e SHA256 documentados
- [ ] stan_90d.json exportado no runFolder apos varredura com Stan Artifacts
- [ ] astrix_90d.json exportado no runFolder apos varredura com Astrix Artifacts
- [ ] FileCoAuth.exe NAO gera REDENGINE_RANDOM_LOADER_NET
- [ ] OneDrive.exe NAO gera REDENGINE_RANDOM_LOADER_NET
- [ ] loader.exe com STAN_PREFETCH_EXECUTED: delta em CoProcessInteraction reflete
      timestamp do Prefetch (proximo da sessao FiveM), nao mtime do arquivo no disco
- [ ] Download Loader-ffb16aac.zip de redengine.net: AMBOS os findings emitidos
      (BROWSER_DL_REDENGINE_PORTAL e BROWSER_DL_CHEAT_PORTAL_ARCHIVE)

## 6. Comandos executados pelo dev

```powershell
# Build
dotnet build EchoNerfados.sln -c Release --nologo

# Commit
git add src/Scanner/Reports/EvidenceExporter.cs src/Scanner/Core/SuspiciousCoProcessResolver.cs src/Scanner/Core/FiveMSessionAnalyzer.cs src/Scanner/Modules/BrowserDownloadsModule.cs
git commit
# hash: 98de112

# Rebuild apos commit
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64-gui

# Installers
MSYS_NO_PATHCONV=1 "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" /DAppVersion=1.0.1 /DBuildTag=+98de112 installer/EchoNerfados-RC-User.iss
MSYS_NO_PATHCONV=1 "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" /DAppVersion=1.0.1 /DBuildTag=+98de112 installer/EchoNerfados.iss

# SHA256s
certutil -hashfile dist/EchoNerfadosSetup-RC-User-1.0.1+98de112.exe SHA256
# 097B692E71FD1D8D64C1221BC89FB2B15818549D577F7089095092AF4EA087FA
certutil -hashfile dist/EchoNerfadosSetup-RC-1.0.1+98de112.exe SHA256
# 83A34357335D215B1FE19CC46EFD5A9CA4F8784B7DC0FE92E37572566FB7806A
certutil -hashfile publish/win-x64/EchoNerfados.exe SHA256
# DFE8BE6C17E03BA08C670AC02D284C765D21F4C49CAF58DE1DF8F899015FB51B
certutil -hashfile publish/win-x64-gui/EchoNerfados.App.exe SHA256
# 83F98ADA0432C8925DBBE4114B1602A024CFEDF883415F3F55A8D258079EA586
```

## 7. Comandos para QA

```powershell
# 1. Verificar exports JSON das novas familias
# Executar varredura e confirmar arquivos no runFolder:
ls <runFolder>\stan_90d.json
ls <runFolder>\astrix_90d.json

# 2. Verificar allowlist OneDrive
Select-String "filecoauth|onedrive|windowsapps|microsoft.onedrive" src\Scanner\Core\SuspiciousCoProcessResolver.cs
# Esperado: ambos em s_knownSafe e em IsUserWritablePath

# 3. Teste FP OneDrive (maquina com OneDrive instalado):
# Executar varredura
# Verificar: FileCoAuth.exe NAO aparece em REDENGINE_RANDOM_LOADER_NET

# 4. Teste delta CoProcessInteraction:
# Colocar loader.exe em Downloads\ (mtime antigo)
# Ter PREFETCH LOADER.EXE*.PF recente (proximo da ultima sessao FiveM)
# Executar varredura
# Verificar: delta em "Sessao FiveM" reflete diferenca entre Prefetch e sessao, nao mtime do exe

# 5. Teste dual-finding portal+archive:
# Ter historico do Chrome com download de redengine.net/customer-area/orders/Loader-ffb16aac.zip
# Executar varredura
# Verificar: DOIS findings — BROWSER_DL_REDENGINE_PORTAL e BROWSER_DL_CHEAT_PORTAL_ARCHIVE

# 6. SHA256 installers
certutil -hashfile dist\EchoNerfadosSetup-RC-User-1.0.1+98de112.exe SHA256
# Esperado: 097B692E71FD1D8D64C1221BC89FB2B15818549D577F7089095092AF4EA087FA
```

## 8. Observacoes para o Codex

- Installer anterior (+bf3527b) invalido para este QA — usar +98de112.
- P0-2: a allowlist s_knownSafe usa o stem do executavel (sem extensao), lowercase.
  FileCoAuth.exe → stem "FileCoAuth" → lowercase "filecoauth" → match na allowlist.
  A exclusao de path \microsoft\onedrive\ e uma segunda linha de defesa para binarios
  do OneDrive em paths nao cobertos pela allowlist de nomes.
- P1-1: o algoritmo de pivot agora e O(N×M) onde N=findings, M=sessions. Para o
  cenario tipico (< 20 findings por grupo, < 10 sessoes FiveM) e negligenciavel.
- P1-2: o deduplicador (FindingDeduplicator) nao merge findings com ruleIds distintos,
  entao BROWSER_DL_REDENGINE_PORTAL e BROWSER_DL_CHEAT_PORTAL_ARCHIVE coexistem
  corretamente para o mesmo download.
