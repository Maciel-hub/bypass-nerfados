# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | Sprint 5 — Runtime co-process detection + familias RedENGINE/Astrix |
| Commit produto | `5723c2c` |
| Branch | `master` |
| ProductVersion CLI/GUI | `1.0.1+5723c2c` |
| GUI SHA256 | `003BCB1EDF8560B41D52C3466F942715319B5CBEC7701E1A3310DB4F2FFD345D` |
| CLI SHA256 | `3526BF2EC224B5E678FFB8A41181FC225953343693CFABCAD4C13120CDACCE53` |
| Installer per-user | `dist/EchoNerfadosSetup-RC-User-1.0.1+5723c2c.exe` |
| Installer per-user SHA256 | `DFBE35DC2082D90261A4077DCB6B5C3EA0C1EAB03DA218FBD28891FDB0E2CB38` |
| Installer admin | `dist/EchoNerfadosSetup-RC-1.0.1+5723c2c.exe` |
| Installer admin SHA256 | `9B7B7631AEF17F7F9E6A90304C41B12F325122B45E264D718CACDB62C557389E` |
| Data/hora | 27/05/2026 |

## 2. Objetivo da entrega

Sprint 5 P0: Detectar co-processos suspeitos em execucao junto ao FiveM.
Base obrigatoria: handoff/RUNTIME_STAN_REDENGINE_DOSSIE_DEV.md.

Problema central: redengine_90d.json vazio em runtime real porque:
- Loader usa nome aleatorio (ex: nkhDWzGn.exe), nao "redengine.exe"
- Modulos de memoria so varriam processos FiveM/GTA5 por nome hardcoded
- Sem deteccao de -cf <payload>.exe nem porta 10001

## 3. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `src/Scanner/Core/SuspiciousCoProcessResolver.cs` | `5723c2c` | Novo — resolver compartilhado de co-processos suspeitos |
| `src/Scanner/Modules/AstrixArtifactsModule.cs` | `5723c2c` | Novo — deteccao da familia Astrix External |
| `src/Scanner/Models/FiveMSessionContext.cs` | `5723c2c` | Adicionado `FiveMRelation.CoProcessInteraction` |
| `src/Scanner/Modules/RedEngineArtifactsModule.cs` | `5723c2c` | v2: cfg.dat near loader, -cf payload, porta 10001 |
| `src/Scanner/Modules/MemoryDllTraceModule.cs` | `5723c2c` | CollectTargetProcesses expande para co-processos |
| `src/Scanner/Modules/MemoryStringScanModule.cs` | `5723c2c` | CollectTargetProcesses expande para co-processos |
| `src/Scanner/Core/FiveMSessionAnalyzer.cs` | `5723c2c` | Classificacao CoProcessInteraction + BuildSummary |
| `src/Scanner/Modules/NetworkModule.cs` | `5723c2c` | ruleId + entity em todas findings de conexao |
| `src/Scanner/Reports/HtmlTemplate.cs` | `5723c2c` | 4a secao "Co-processos ativos" na aba Sessao FiveM |
| `src/Scanner/Core/ScanOrchestrator.cs` | `5723c2c` | Queue(new AstrixArtifactsModule()) |
| `src/Scanner.Core/Scanner.Core.csproj` | `5723c2c` | Compile includes para 2 novos arquivos |

## 4. Mudancas tecnicas

### SuspiciousCoProcessResolver (novo)

Detecta processos em execucao em paths de usuario com nome aleatorio:
- `IsRandomName(name)`: ratio de vogais < 15% OU mixed case com 2+ uppercase + 2+ lowercase
- `IsUserWritablePath(path)`: exclui Windows/, Program Files/, steamapps/, Epic Games/, Rockstar Games/
- `ExtractCfPayload(cmdLine)`: extrai argumento `-cf <path>` da linha de comando
- WMI (`Win32_Process`) para obter `ExecutablePath` e `CommandLine` sem admin
- TCP P/Invoke para mapear PID → conexoes externas
- Cache de 60s para evitar multiplas queries WMI entre modulos sequenciais

### RedEngineArtifactsModule v2

Novos scans:
- `ScanRandomLoaderWithCfgDat`: varre Downloads/Temp por `cfg.dat`; se EXE aleatorio co-localizado → `REDENGINE_CFG_DAT_NEAR_LOADER` (Critical/High); cfg.dat isolado → `REDENGINE_CFG_DAT_STANDALONE` (Medium/Low)
- `ScanActiveLoaderProcess`: via SuspiciousCoProcessResolver:
  - PayloadPath != null → `REDENGINE_CMDLINE_CF_PAYLOAD` (High) ou `REDENGINE_NUMERIC_PAYLOAD_EXECUTED` (Critical se payload numerico)
  - Conexao em :10001 → `REDENGINE_ACTIVE_C2_PORT` (Critical)
  - EXE aleatorio com conexao externa sem -cf → `REDENGINE_RANDOM_LOADER_NET` (High)

### AstrixArtifactsModule (novo)

- `ASTRIX_EXE_USERPATH`: "Astrix External.exe" no disco em Downloads/Desktop/Documents/Temp (Critical/Confirmed)
- `ASTRIX_CONFIG_FILE`: config.astrix com SHA256 + tamanho + campos presentes (Critical se username/password presentes — **NUNCA os valores**)
- `ASTRIX_PREFETCH_EXECUTED`: Prefetch ASTRIX*.PF (High/High)
- `ASTRIX_BAM_EXECUTED`: BAM/DAM com path contendo "astrix" (High/High)
- `ASTRIX_ACTIVE_PROCESS`: Astrix External.exe em execucao via SuspiciousCoProcessResolver (Critical/Confirmed)

### FiveMRelation.CoProcessInteraction

Novo valor de enum — 4a secao na aba Sessao FiveM (cor violeta `#c026d3`).
Classificado quando qualquer finding tem ruleId: REDENGINE_CFG_DAT_NEAR_LOADER, REDENGINE_CMDLINE_CF_PAYLOAD, REDENGINE_NUMERIC_PAYLOAD_EXECUTED, REDENGINE_ACTIVE_C2_PORT, REDENGINE_RANDOM_LOADER_NET, ASTRIX_ACTIVE_PROCESS, ASTRIX_EXE_USERPATH, ASTRIX_CONFIG_FILE, ASTRIX_PREFETCH_EXECUTED, ASTRIX_BAM_EXECUTED.

### Expansao dos modulos de memoria

MemoryDllTraceModule e MemoryStringScanModule agora chamam `SuspiciousCoProcessResolver.Resolve()` em `CollectTargetProcesses()` para incluir co-processos suspeitos alem dos alvos hardcoded FiveM/GTA5/redengine.

### NetworkModule

Todos os findings de conexao agora tem `ruleId` e `entity`:
- `NET_KNOWN_CHEAT_ACTIVE`: cheat confirmado com conexao
- `NET_SUSPICIOUS_GENERIC_PROCESS`: nome generico de loader com conexao
- `NET_SUSPICIOUS_USERPATH_PROCESS`: EXE em path de usuario com conexao
- `NET_COPROC_NEAR_FIVEM`: conexao na porta 10001 (C2 RedENGINE)
- `NET_NONSTANDARD_PORT`: portas 4444-9999 (antes era sem ruleId)

## 5. Criterios de aceite

- [x] Build 0 erros (9 avisos pre-existentes de LicenseValidator/NU1701)
- [x] Commit `5723c2c` com ProductVersion `1.0.1+5723c2c` nos binarios
- [x] Installers gerados e SHA256 documentados
- [ ] ScanRandomLoaderWithCfgDat detecta cfg.dat + nkhDWzGn.exe no mesmo diretorio
- [ ] ScanActiveLoaderProcess detecta nkhDWzGn.exe com -cf 1234.exe em execucao
- [ ] REDENGINE_ACTIVE_C2_PORT dispara para conexao :10001 com processo aleatorio
- [ ] ASTRIX_CONFIG_FILE registra campos presentes (username, password) e SHA256 — SEM valores
- [ ] ASTRIX_ACTIVE_PROCESS dispara se "Astrix External.exe" esta em execucao
- [ ] HTML: aba "Sessao FiveM" mostra 4 secoes (Interagiram / Co-processos / Proximos / Fora)
- [ ] FiveMRelation.CoProcessInteraction aparece em evidencia de co-processo
- [ ] Modulos de memoria vasculham co-processos (nkhDWzGn.exe) se em execucao

## 6. Comandos executados pelo dev

```powershell
# Build e publish
dotnet build EchoNerfados.sln -c Release --nologo
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64-gui

# Commit (hash embebido no build seguinte)
git commit -m "feat: Sprint 5 — Runtime co-process detection + RedENGINE/Astrix families"
# hash: 5723c2c

# Rebuild apos commit (ProductVersion correto)
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64
dotnet publish src/EchoNerfados.App/EchoNerfados.App.csproj -c Release -r win-x64 --self-contained false -o publish/win-x64-gui

# Installers
& 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' /DAppVersion=1.0.1 /DBuildTag=+5723c2c installer\EchoNerfados-RC-User.iss
& 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' /DAppVersion=1.0.1 /DBuildTag=+5723c2c installer\EchoNerfados.iss

# SHA256s
Get-FileHash dist\EchoNerfadosSetup-RC-User-1.0.1+5723c2c.exe -Algorithm SHA256
# DFBE35DC2082D90261A4077DCB6B5C3EA0C1EAB03DA218FBD28891FDB0E2CB38
Get-FileHash dist\EchoNerfadosSetup-RC-1.0.1+5723c2c.exe -Algorithm SHA256
# 9B7B7631AEF17F7F9E6A90304C41B12F325122B45E264D718CACDB62C557389E
Get-FileHash publish\win-x64\EchoNerfados.exe -Algorithm SHA256
# 3526BF2EC224B5E678FFB8A41181FC225953343693CFABCAD4C13120CDACCE53
Get-FileHash publish\win-x64-gui\EchoNerfados.App.exe -Algorithm SHA256
# 003BCB1EDF8560B41D52C3466F942715319B5CBEC7701E1A3310DB4F2FFD345D
```

## 7. Comandos para QA

```powershell
# 1. Verificar estrutura dos novos arquivos
rg "SuspiciousCoProcessResolver|AstrixArtifactsModule" src\Scanner.Core\Scanner.Core.csproj

# 2. Verificar IsRandomName (heuristica de nome aleatorio)
# Testar: nkhDWzGn (deve ser true), launcher (deve ser false), 1234 (deve ser true)

# 3. Verificar privacidade config.astrix — nunca deve aparecer valores
rg "username|password" src\Scanner\Modules\AstrixArtifactsModule.cs
# Esperado: so aparece como campo para verificar existencia (hasUsername, hasPassword)
# Nunca deve aparecer prop.Value nem obj["username"].GetString()

# 4. SHA256 dos installers
Get-FileHash dist\EchoNerfadosSetup-RC-User-1.0.1+5723c2c.exe -Algorithm SHA256
# Esperado: DFBE35DC2082D90261A4077DCB6B5C3EA0C1EAB03DA218FBD28891FDB0E2CB38

# 5. Teste funcional (requer maquina com nkhDWzGn.exe + cfg.dat em Downloads):
# - Colocar nkhDWzGn.exe e cfg.dat em C:\Users\<user>\Downloads\
# - Executar varredura com admin
# - Verificar findings: REDENGINE_CFG_DAT_NEAR_LOADER deve aparecer

# 6. Teste privacidade Astrix (requer config.astrix com campos username/password):
# - Colocar config.astrix em Downloads
# - Executar varredura
# - Verificar: finding ASTRIX_CONFIG_FILE nao contem valores de username/password

# 7. HTML tab 4 secoes
# - Abrir report.html e navegar para aba "Sessao FiveM"
# - Verificar: 4 secoes (Interagiram / Co-processos ativos / Proximos / Fora de contexto)
```

## 8. Restricao de privacidade (CRITICA)

AstrixArtifactsModule NUNCA registra valores de username/password do config.astrix.
Registra apenas: campo "username" presente (bool), campo "password" presente (bool),
quantidade de campos, SHA256 do arquivo, tamanho em bytes, timestamp.

Verificar: rg "\.GetString\(\)|prop\.Value|GetRawText" src\Scanner\Modules\AstrixArtifactsModule.cs
Resultado esperado: nenhum match.

## 9. Observacoes para o Codex

- Enviar installer per-user `EchoNerfadosSetup-RC-User-1.0.1+5723c2c.exe` para tester externo
- Installers anteriores (+f194191) sao invalidos — nao enviar
- ProcessMemoryModule NAO foi expandido para co-processos (scanner via ScanRunningProcesses
  ja cobre processos em execucao; a expansao de alvos de memoria e via MemoryDllTrace e MemoryStringScan)
- Cross-family CORR_ rules (CHEAT_RANDOM_LOADER_NEAR_FIVEM etc.) ficaram para proximo sprint
  para manter o escopo gerenciavel
- SuspiciousCoProcessResolver.Resolve() tem cache de 60s — chamadas multiplas entre
  modulos nao duplicam a query WMI
