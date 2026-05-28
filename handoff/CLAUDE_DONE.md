# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | Sprint 6 — Stan Menu P0: loader.exe/.credentials/portal chain detection |
| Commit produto | `bf3527b` |
| Branch | `master` |
| ProductVersion CLI/GUI | `1.0.1+bf3527b` |
| CLI SHA256 | `BC824B26106F17B56E26BC9B598B62153AA9079DC65FDA44934D3C7E68A02790` |
| GUI SHA256 | `DB9508FFBA1827C7A257A51565BB66BD4941BCBCF0801579EFD4D0C45072235A` |
| Installer per-user | `dist/EchoNerfadosSetup-RC-User-1.0.1+bf3527b.exe` |
| Installer per-user SHA256 | `7D97B929FE688231EE810A130340D9575ED697F3488E499F4AABCFC467E291C5` |
| Installer admin | `dist/EchoNerfadosSetup-RC-1.0.1+bf3527b.exe` |
| Installer admin SHA256 | `5319D7E9DA5FEE0EABA37BAB1086DC526DEFC5E1C6957C270FF94138B874BDFA` |
| Data/hora | 27/05/2026 |

## 2. Objetivo da entrega

Sprint 6 P0: Cobertura completa Stan Menu antes do QA.

Problema: Stan foi testado em runtime mas o Echo documentava apenas Prefetch/BAM/UserAssist
soltos sem cadeia comportamental. RedENGINE e Astrix estavam fortes; Stan ficaria
subdetectado se liberarmos QA sem esta entrega.

Cadeia a detectar: download de redengine.net/customer-area/orders (Loader-ffb16aac.zip)
→ loader.exe + f0686phud.credentials no mesmo diretório
→ execução confirmada por Prefetch LOADER.EXE e BAM
→ correlação → CoProcessInteraction na aba Sessao FiveM.

## 3. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `src/Scanner/Modules/StanArtifactsModule.cs` | `bf3527b` | Novo — 5 ruleIds Stan (loader.exe, .credentials, arquivo, Prefetch, BAM) |
| `src/Scanner/Modules/BrowserDownloadsModule.cs` | `bf3527b` | BROWSER_DL_REDENGINE_PORTAL + BROWSER_DL_CHEAT_PORTAL_ARCHIVE |
| `src/Scanner/Core/FiveMSessionAnalyzer.cs` | `bf3527b` | STAN_ ruleIds em CoProcessInteraction + BuildSummary Stan + IsExecutableFinding |
| `src/Scanner/Core/Correlator.cs` | `bf3527b` | CorrelateCheatLoaderChain: CHEAT_GENERIC_LOADER_FROM_PORTAL_DOWNLOAD + CHEAT_GENERIC_LOADER_WITH_CREDENTIAL |
| `src/Scanner/Core/ScanOrchestrator.cs` | `bf3527b` | Queue(new StanArtifactsModule()) |
| `src/Scanner.Core/Scanner.Core.csproj` | `bf3527b` | Compile include para StanArtifactsModule.cs |

## 4. Mudancas tecnicas

### StanArtifactsModule (novo)

Detecta familia Stan Menu / loader generico com credencial:

**ScanLoaderExeOnDisk**: varredura de Downloads/Desktop/Documents/Temp por `loader.exe`.
- Co-localizado com .credentials → `STAN_LOADER_WITH_CREDENTIAL` (High/High)
- Sozinho → `STAN_LOADER_EXE` (Medium/Medium) — nao Critical, exige correlacao

**ScanCredentialsFiles**: varredura por `*.credentials`.
- SHA256 computado; conteudo NUNCA logado.
- loader.exe no mesmo dir → `STAN_CREDENTIALS_NEAR_LOADER` (High/High)
- Nome aleatorio isolado → `STAN_RANDOM_CREDENTIAL_FILE` (Medium/Medium)

**ScanLoaderArchives**: Loader-*.zip, Loader-*.rar, Executor*V*.zip, *spoofer*.zip
→ `STAN_LOADER_ARCHIVE` (High/Medium)

**ScanPrefetchBam**:
- Prefetch LOADER.EXE* → `STAN_PREFETCH_EXECUTED` (High/High)
- BAM loader.exe em user-writable path (via IsUserWritablePath) → `STAN_BAM_EXECUTED` (High/High)

### BrowserDownloadsModule (modificado)

Novos helpers:
- `MatchCheatPortalUrl(urlLower)`: true para redengine.net/customer-area, /orders, /download
- `IsCheatPortalArchive(fileNameLower)`: true para Loader-*.zip, Executor*.zip, *spoofer*.zip

Novos ruleIds emitidos (Chrome/Edge/Brave/Opera + Firefox):
- `BROWSER_DL_REDENGINE_PORTAL` (High/High): URL do portal redengine.net — supersede BROWSER_DL_SUSPICIOUS_URL generico
- `BROWSER_DL_CHEAT_PORTAL_ARCHIVE` (High/Medium): arquivo Loader-*.zip ou Executor*.zip (quando URL nao e portal)

### Correlator.CorrelateCheatLoaderChain (novo)

`CHEAT_GENERIC_LOADER_FROM_PORTAL_DOWNLOAD` (Critical/High):
- Exige: BROWSER_DL_REDENGINE_PORTAL ou BROWSER_DL_CHEAT_PORTAL_ARCHIVE
  AND STAN_LOADER_EXE ou STAN_LOADER_WITH_CREDENTIAL ou STAN_PREFETCH_EXECUTED ou STAN_BAM_EXECUTED

`CHEAT_GENERIC_LOADER_WITH_CREDENTIAL` (High/High):
- Exige: STAN_LOADER_WITH_CREDENTIAL ou STAN_CREDENTIALS_NEAR_LOADER
  AND qualquer evidencia de loader (STAN_LOADER_EXE / STAN_PREFETCH_EXECUTED / STAN_BAM_EXECUTED)

### FiveMSessionAnalyzer (modificado)

**DetermineRelation isCoProcess**: adicionados STAN_LOADER_WITH_CREDENTIAL, STAN_CREDENTIALS_NEAR_LOADER,
STAN_PREFETCH_EXECUTED, STAN_BAM_EXECUTED → classificam como FiveMRelation.CoProcessInteraction.
(STAN_LOADER_EXE isolado cai em NearSession/OutsideSession conforme timestamp — nao CoProcess.)

**BuildSummary**: novo caso `STAN_` → "Co-processo Stan loader ({modulo})".

**IsExecutableFinding**: STAN_ ruleIds incluidos → aparecem na aba Sessao FiveM.

## 5. Criterios de aceite

- [x] Build 0 erros (9 avisos pre-existentes de LicenseValidator/NU1701)
- [x] Commit `bf3527b` com ProductVersion `1.0.1+bf3527b` nos binarios
- [x] Installers gerados e SHA256 documentados
- [ ] BrowserDownloads: download de redengine.net/customer-area/orders emite BROWSER_DL_REDENGINE_PORTAL
- [ ] BrowserDownloads: Loader-ffb16aac.zip emite BROWSER_DL_CHEAT_PORTAL_ARCHIVE
- [ ] StanArtifacts: loader.exe + f0686phud.credentials no mesmo dir emite STAN_LOADER_WITH_CREDENTIAL
- [ ] StanArtifacts: .credentials isolado emite STAN_RANDOM_CREDENTIAL_FILE sem logar conteudo
- [ ] StanArtifacts: LOADER.EXE*.PF em Prefetch emite STAN_PREFETCH_EXECUTED
- [ ] StanArtifacts: BAM loader.exe em caminho de usuario emite STAN_BAM_EXECUTED
- [ ] Correlator: BROWSER_DL_REDENGINE_PORTAL + STAN_PREFETCH_EXECUTED → CHEAT_GENERIC_LOADER_FROM_PORTAL_DOWNLOAD (Critical)
- [ ] Correlator: STAN_LOADER_WITH_CREDENTIAL → CHEAT_GENERIC_LOADER_WITH_CREDENTIAL (High)
- [ ] HTML aba "Sessao FiveM": loader.exe com STAN_LOADER_WITH_CREDENTIAL aparece em Co-processos ativos
- [ ] loader.exe isolado fora da sessao FiveM NAO vira Critical

## 6. Comandos executados pelo dev

```powershell
# Build
dotnet build EchoNerfados.sln -c Release --nologo

# Commit
git add src/Scanner/Modules/StanArtifactsModule.cs src/Scanner/Modules/BrowserDownloadsModule.cs src/Scanner/Core/FiveMSessionAnalyzer.cs src/Scanner/Core/Correlator.cs src/Scanner/Core/ScanOrchestrator.cs src/Scanner.Core/Scanner.Core.csproj
git commit -m "feat: Stan Menu P0 — loader.exe/.credentials/portal chain detection"
# hash: bf3527b

# Rebuild apos commit (ProductVersion correto)
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64-gui

# Installers
MSYS_NO_PATHCONV=1 "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" /DAppVersion=1.0.1 /DBuildTag=+bf3527b installer/EchoNerfados-RC-User.iss
MSYS_NO_PATHCONV=1 "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" /DAppVersion=1.0.1 /DBuildTag=+bf3527b installer/EchoNerfados.iss

# SHA256s
certutil -hashfile dist/EchoNerfadosSetup-RC-User-1.0.1+bf3527b.exe SHA256
# 7D97B929FE688231EE810A130340D9575ED697F3488E499F4AABCFC467E291C5
certutil -hashfile dist/EchoNerfadosSetup-RC-1.0.1+bf3527b.exe SHA256
# 5319D7E9DA5FEE0EABA37BAB1086DC526DEFC5E1C6957C270FF94138B874BDFA
certutil -hashfile publish/win-x64/EchoNerfados.exe SHA256
# BC824B26106F17B56E26BC9B598B62153AA9079DC65FDA44934D3C7E68A02790
certutil -hashfile publish/win-x64-gui/EchoNerfados.App.exe SHA256
# DB9508FFBA1827C7A257A51565BB66BD4941BCBCF0801579EFD4D0C45072235A
```

## 7. Comandos para QA

```powershell
# 1. Verificar novo modulo no csproj
Select-String "StanArtifacts" src\Scanner.Core\Scanner.Core.csproj

# 2. Verificar privacidade .credentials — conteudo nunca logado
Select-String "ReadAllText|ReadAllLines|GetString|ReadToEnd" src\Scanner\Modules\StanArtifactsModule.cs
# Esperado: nenhum match (apenas ReadAllBytes para SHA256)

# 3. Verificar ruleIds BrowserDownloads
Select-String "BROWSER_DL_REDENGINE_PORTAL|BROWSER_DL_CHEAT_PORTAL_ARCHIVE" src\Scanner\Modules\BrowserDownloadsModule.cs
# Esperado: 2 matches (emissao dos findings)

# 4. Verificar correlacoes Stan no Correlator
Select-String "CHEAT_GENERIC_LOADER" src\Scanner\Core\Correlator.cs
# Esperado: CHEAT_GENERIC_LOADER_FROM_PORTAL_DOWNLOAD e CHEAT_GENERIC_LOADER_WITH_CREDENTIAL

# 5. Verificar CoProcessInteraction para Stan no FiveMSessionAnalyzer
Select-String "STAN_" src\Scanner\Core\FiveMSessionAnalyzer.cs
# Esperado: STAN_LOADER_WITH_CREDENTIAL, STAN_CREDENTIALS_NEAR_LOADER, STAN_PREFETCH_EXECUTED, STAN_BAM_EXECUTED, STAN_

# 6. Teste funcional (maquina com artefatos Stan):
# a. Colocar loader.exe + f0686phud.credentials em Downloads\
# b. Executar varredura
# c. Verificar: STAN_LOADER_WITH_CREDENTIAL + CHEAT_GENERIC_LOADER_WITH_CREDENTIAL

# 7. Teste BrowserDownloads (Chrome/Edge com historico de redengine.net):
# a. Verificar: BROWSER_DL_REDENGINE_PORTAL para URL redengine.net/customer-area/orders
# b. Verificar: BROWSER_DL_CHEAT_PORTAL_ARCHIVE para Loader-*.zip

# 8. SHA256 installers
certutil -hashfile dist\EchoNerfadosSetup-RC-User-1.0.1+bf3527b.exe SHA256
# Esperado: 7D97B929FE688231EE810A130340D9575ED697F3488E499F4AABCFC467E291C5

# 9. Verificar que loader.exe SOZINHO (sem .credentials/BAM/Prefetch) e apenas Medium
# e nao aparece em Co-processos ativos — deve ir para NearSession/OutsideSession
```

## 8. Restricao de privacidade (CRITICA)

StanArtifactsModule NUNCA registra conteudo do .credentials.
Registra apenas: SHA256 do arquivo, tamanho em bytes, timestamp, caminho, bool co-localizado com loader.exe.

Verificar: Select-String "ReadAllText|ReadAllLines|GetString|ReadToEnd" src\Scanner\Modules\StanArtifactsModule.cs
Resultado esperado: nenhum match.

## 9. Observacoes para o Codex

- Enviar installer per-user `EchoNerfadosSetup-RC-User-1.0.1+bf3527b.exe` para tester externo
- Installers anteriores (+5723c2c) sao invalidos para este sprint — nao enviar
- loader.exe isolado (STAN_LOADER_EXE) sozinho e apenas Medium/Medium — NAO Critical.
  Critical exige correlacao via Correlator (portal download + loader, ou loader + .credentials).
- STAN_LOADER_EXE sozinho NAO entra em CoProcessInteraction — cai em NearSession/OutsideSession
  conforme proximidade temporal com sessao FiveM. Apenas STAN_LOADER_WITH_CREDENTIAL,
  STAN_CREDENTIALS_NEAR_LOADER, STAN_PREFETCH_EXECUTED e STAN_BAM_EXECUTED classificam CoProcess.
- CorrelateCheatLoaderChain e chamado apos CorrelateFiveMSession — ordem importa pois
  os findings CORR_ gerados antes ficam visiveis para o EvidenceEnricher.
- Sprint anterior (5723c2c): RedENGINE + Astrix. Este sprint: Stan Menu chain. Ambos
  sao Pre-QA; o Codex deve testar as tres familias neste ciclo.
