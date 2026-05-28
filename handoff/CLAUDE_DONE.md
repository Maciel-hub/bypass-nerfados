# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | Fix QA Sprint 6 round 2 — P1-1, P1-2, P1-3 |
| Commit produto | `a17f02e` |
| Branch | `master` |
| ProductVersion CLI/GUI | `1.0.1+a17f02e` |
| CLI SHA256 | `24391D50B871DBE759F5B27A903F26B1EA517699C34EC4AFF9AFB4DA3489D588` |
| GUI SHA256 | `A0F551F3D48A9FE4FC0E8134287899B153DCA9506EECAD9585ACA0E21E520FB7` |
| Installer per-user | `dist/EchoNerfadosSetup-RC-User-1.0.1+a17f02e.exe` |
| Installer per-user SHA256 | `412FF10C17D18C121D1A23FB85671B7E630E345D78036AF0FFF9030CC94890F5` |
| Installer admin | `dist/EchoNerfadosSetup-RC-1.0.1+a17f02e.exe` |
| Installer admin SHA256 | `E6DEF7098113B3A05DDC9762C08057F25AD670A4680D9A97BA9760162E1084F5` |
| Data/hora | 27/05/2026 |

## 2. Objetivo da entrega

Fix dos 3 P1 pendentes do QA 98de112:
- P1-1: eventTime inconsistente com deltaMinutes
- P1-2: BROWSER_DL_CHEAT_PORTAL_ARCHIVE nao aparecia para Loader-ffb16aac.zip
- P1-3: AntiForensicScriptModule marcando CollectSyncLogs.bat (OneDrive)

## 3. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `src/Scanner/Core/FiveMSessionAnalyzer.cs` | `a17f02e` | EventTime reconstruido como sessionTime + deltaMinutes |
| `src/Scanner/Modules/BrowserDownloadsModule.cs` | `a17f02e` | REDENGINE_PORTAL enriquecido com nome de archive; CHEAT_PORTAL_ARCHIVE so se portal nao bateu |
| `src/Scanner/Modules/AntiForensicScriptModule.cs` | `a17f02e` | \AppData\Local\Microsoft\OneDrive\ adicionado ao SkippedPathSubstrings |

## 4. Mudancas tecnicas por blocker

### P1-1: eventTime inconsistente

`FiveMSessionAnalyzer.Analyze`: antes de criar `FiveMSessionContext`, calcula:
```csharp
var eventTime = (sessionTime.HasValue && deltaMinutes.HasValue)
    ? (DateTime?)sessionTime.Value.AddMinutes(deltaMinutes.Value)
    : representative.Timestamp;
```

Isso garante que `eventTime` e consistente com `deltaMinutes`: `deltaMinutes = eventTime - sessionTime`.
O pivot mais proximo escolhido em `DetermineRelation` determina tanto o delta quanto o eventTime.

### P1-2: CHEAT_PORTAL_ARCHIVE ausente para Loader-ffb16aac.zip

Causa raiz: `EvidenceKey = Category|entity|timebucket`. BROWSER_DL_REDENGINE_PORTAL e
BROWSER_DL_CHEAT_PORTAL_ARCHIVE para o mesmo download compartilham o mesmo EvidenceKey
(mesmo entity = targetPath, mesma categoria, mesmo bucket de hora). O deduplicador
mantinha apenas o de Confidence.High (REDENGINE_PORTAL) e descartava o CHEAT_PORTAL_ARCHIVE.

Solucao: quando `portalFamily != null` E `IsCheatPortalArchive(fileName)`:
- O finding BROWSER_DL_REDENGINE_PORTAL e emitido com Detail enriquecido:
  "Arquivo: loader-ffb16aac.zip (padrao Loader-*.zip — entrega Stan/RedENGINE)"
  e Evidence: "... | Loader: loader-ffb16aac.zip"
- BROWSER_DL_CHEAT_PORTAL_ARCHIVE NAO e emitido separadamente (mesmo EvidenceKey)

Quando so o filename bate (sem portal URL), BROWSER_DL_CHEAT_PORTAL_ARCHIVE continua
emitido normalmente (comportamento original mantido).

Aplicado identicamente em `AnalyzeDownloadRow` (Chromium) e `AnalyzeFirefoxEntry` (Firefox).

### P1-3: CollectSyncLogs.bat marcado como anti-forense

`AntiForensicScriptModule.SkippedPathSubstrings`: adicionado:
```csharp
@"\AppData\Local\Microsoft\OneDrive\",
```

Todos os scripts dentro do diretorio de instalacao do OneDrive sao agora ignorados.
Cobre CollectSyncLogs.bat, CollectSyncLogsLite.bat e quaisquer outros scripts
que o OneDrive instale em versoes futuras.

## 5. Criterios de aceite

- [x] Build 0 erros (9 avisos pre-existentes)
- [x] Commit `a17f02e` com ProductVersion `1.0.1+a17f02e`
- [x] Installers gerados e SHA256 documentados
- [ ] FiveMSessionContext do loader.exe: eventTime == sessionTime + deltaMinutes (consistentes)
      Exemplo esperado: se delta=-21.93, sessionTime=18:54, eventTime=18:32
- [ ] Download Loader-ffb16aac.zip de redengine.net: finding BROWSER_DL_REDENGINE_PORTAL
      com Detail contendo "loader-ffb16aac.zip (padrao Loader-*.zip)"
- [ ] CollectSyncLogs.bat e CollectSyncLogsLite.bat NAO aparecem como Anti-Forensic Scripts

## 6. Comandos executados pelo dev

```powershell
# Commit
git add src/Scanner/Core/FiveMSessionAnalyzer.cs src/Scanner/Modules/BrowserDownloadsModule.cs src/Scanner/Modules/AntiForensicScriptModule.cs
# hash: a17f02e

# Rebuild
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64-gui

# Installers
MSYS_NO_PATHCONV=1 "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" /DAppVersion=1.0.1 /DBuildTag=+a17f02e installer/EchoNerfados-RC-User.iss
MSYS_NO_PATHCONV=1 "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" /DAppVersion=1.0.1 /DBuildTag=+a17f02e installer/EchoNerfados.iss

# SHA256s
certutil -hashfile dist/EchoNerfadosSetup-RC-User-1.0.1+a17f02e.exe SHA256
# 412FF10C17D18C121D1A23FB85671B7E630E345D78036AF0FFF9030CC94890F5
certutil -hashfile dist/EchoNerfadosSetup-RC-1.0.1+a17f02e.exe SHA256
# E6DEF7098113B3A05DDC9762C08057F25AD670A4680D9A97BA9760162E1084F5
certutil -hashfile publish/win-x64/EchoNerfados.exe SHA256
# 24391D50B871DBE759F5B27A903F26B1EA517699C34EC4AFF9AFB4DA3489D588
certutil -hashfile publish/win-x64-gui/EchoNerfados.App.exe SHA256
# A0F551F3D48A9FE4FC0E8134287899B153DCA9506EECAD9585ACA0E21E520FB7
```

## 7. Comandos para QA

```powershell
# 1. Verificar enrichment do portal finding
Select-String "isArchiveFile|isArchive|Loader:" src\Scanner\Modules\BrowserDownloadsModule.cs
# Esperado: condicoes de enrichment e "Loader: {fileName}" no Evidence

# 2. Verificar que guard portalFamily==null foi restaurado para CHEAT_PORTAL_ARCHIVE
Select-String "portalFamily == null" src\Scanner\Modules\BrowserDownloadsModule.cs
# Esperado: 2 matches (AnalyzeDownloadRow e AnalyzeFirefoxEntry)

# 3. Verificar exclusao OneDrive
Select-String "OneDrive" src\Scanner\Modules\AntiForensicScriptModule.cs
# Esperado: 1 match em SkippedPathSubstrings

# 4. Verificar eventTime no FiveMSessionAnalyzer
Select-String "sessionTime.Value.AddMinutes" src\Scanner\Core\FiveMSessionAnalyzer.cs
# Esperado: 1 match (calculo do eventTime)

# 5. Teste funcional — portal + archive:
# Ter Chrome com download de redengine.net/customer-area/orders de Loader-ffb16aac.zip
# Executar varredura
# Verificar: 1 finding BROWSER_DL_REDENGINE_PORTAL com Detail contendo
# "loader-ffb16aac.zip (padrao Loader-*.zip — entrega Stan/RedENGINE)"

# 6. Teste eventTime:
# Loader.exe com Prefetch recente (ex: 18:32) e sessao FiveM (ex: 18:54)
# Verificar: FiveMSessionContext.eventTime = 18:32, deltaMinutes = -21.93

# 7. Teste OneDrive:
# Maquina com OneDrive instalado (CollectSyncLogs.bat presente)
# Verificar: nenhum finding Anti-Forensic para esses scripts

# 8. SHA256 installers
certutil -hashfile dist\EchoNerfadosSetup-RC-User-1.0.1+a17f02e.exe SHA256
# Esperado: 412FF10C17D18C121D1A23FB85671B7E630E345D78036AF0FFF9030CC94890F5
```

## 8. Observacoes para o Codex

- Installer anterior (+98de112) invalido — usar +a17f02e.
- P1-2: a causa raiz era o EvidenceKey de Finding ser Category|entity|timebucket.
  Dois findings para o mesmo download (mesmo entity, mesma hora) com categorias iguais
  colidem e o deduplicador mantém o de maior Confidence. A solucao de enrichment
  e mais robusta que tentar emitir dois findings com a mesma chave.
- P1-1: a reconstrucao eventTime = sessionTime + deltaMinutes e matematicamente correta
  porque deltaMinutes = (pivotTimestamp - sessionTime).TotalMinutes.
- P1-3: \AppData\Local\Microsoft\OneDrive\ cobre todas as versoes futuras do OneDrive
  sem necessidade de allowlist por nome de arquivo.
