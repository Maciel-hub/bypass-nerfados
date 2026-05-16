# Echo Nerfados Shield XDR — Relatório de QA
**Versão:** 1.0.0+1d0f2cd  
**Build:** 5622fc2 `E66B799D63DACBEDFE7C1C94ACE4A6A0F5253B8CD1A7E37646FF5E963D049AE2` — release v1.0.0 (fonte + QA_REPORT + artefato casados); bdf89c9 — fix: SRUM bytes ausentes = degradação informativa; 1d0f2cd — feat: SRUM IdBlob parser Win11+; 8f0bf22 — feat: RedENGINE  
**Arquivo:** `publish\win-x64\EchoNerfados.exe`  
**SHA256:** `8E7D7E8F03BE98DF59DA629C00FE23AC3644E0D857C31396CEF777F7AAF056C6`  
**Tamanho:** ~67 MB (self-contained, sem dependência de .NET no host)  
**Lookback:** 90 dias (`EventWindowLookback = TimeSpan.FromDays(90)`) — JSONs exportados como `*_90d.json`

---

## 1. Visão Geral

O **Echo Nerfados Shield XDR** é um scanner forense Windows para investigações anti-cheat em FiveM/GTA V.  
Ele coleta evidências de múltiplas fontes de artefatos do sistema (registry, event logs, prefetch, amcache, shimcache, etc.), correlaciona sinais entre módulos, gera relatório HTML + TXT + JSON e produz um manifesto criptograficamente verificável.

**Plataforma alvo:** Windows 10/11 x64  
**Privilégios:** Administrador recomendado (módulos offline exigem; ShimCache + LNK + RegistryPersistence funcionam sem admin)  
**Runtime:** Nenhum — executável self-contained

---

## 2. Pré-requisitos de Execução

- **Terminal interativo obrigatório** — o app detecta `Console.IsInputRedirected` / `IsOutputRedirected` e encerra com exit code 1 e mensagem de erro se não houver console interativo. Nunca crasha.
- `--help` / `-h` funciona **sem login**, sem console interativo, exit code 0.
- **Admin é recomendado, não forçado** — `app.manifest` usa `asInvoker`. O EXE não dispara UAC automaticamente. Execute via "Executar como administrador" para habilitar todos os módulos.
- **Diretório `rules/`** deve estar ao lado do EXE (copiado automaticamente no publish via `PreserveNewest`). Se ausente, o scanner funciona normalmente com regras embutidas — sem crash.

## 3. Credenciais de Acesso

O executável exige login antes de qualquer varredura.

| Campo  | Valor     |
|--------|-----------|
| Usuário | `nerfados` (case-insensitive) |
| Senha   | `admin`   |

**Comportamento:**
- 3 tentativas máximas — após 3 falhas, o processo encerra com exit code 2
- Senha comparada via `CryptographicOperations.FixedTimeEquals` (sem timing attack)
- Comparação do usuário é case-insensitive (`NERFADOS`, `Nerfados` → aceitos)

**Casos de teste:**
- [ ] Login correto → varredura inicia normalmente
- [ ] Senha errada 1x → aviso "Credenciais inválidas" + nova tentativa
- [ ] Senha errada 3x → mensagem "Acesso negado" + processo encerra (exit code 2)
- [ ] Usuário errado (qualquer senha) → falha da mesma forma

---

## 4. Módulos de Varredura

**Default/Deep profile: 28 módulos** | **Fast profile: 17 módulos** (ShimCache, ShellBags, JumpLists, SRUM, NvidiaArtifacts, ExternalToolResidue, RecycleBin, Amcache, UserAssist, USN Journal e ProcessMemory são pulados)

### Módulos sem requisito de admin (funcionam com asInvoker)

| Módulo | Artefato | O que detecta |
|--------|----------|---------------|
| **System Info** | WMI | Nome da máquina, usuário, OS, BIOS |
| **BAM/DAM** | HKLM\SYSTEM\...\BAM | Histórico de execução (Background Activity Monitor) — últimos ~7 dias. **Nota:** o registro BAM tem ACL restrita em algumas builds do Windows; sem admin pode resultar em PARCIAL (SecurityException capturada, motivo exibido). |
| **Prefetch** | C:\Windows\Prefetch\*.pf | Histórico de execução por nome de arquivo; nome da entry = nome do processo. **Nota:** `C:\Windows\Prefetch` exige admin em algumas configurações; sem admin pode resultar em PARCIAL. |
| **Registry Artifacts** | HKLM run keys + MRU | Execuções recentes, autoruns em registry |
| **Event Viewer** | Security/System/Application logs | Logons (4624), falhas (4625), serviços instalados (7045), Defender alerts, cobertura de log |
| **Windows Defender** | Event log + MPLog | Detecções, exclusões, deleções de definição, reconfiguração |
| **Known Cheats** | File system scan | Varredura de nomes conhecidos de cheat nos drives especificados; lista extensível via `rules/cheat_names.json` |
| **File System** | Paths suspeitos | Arquivos em AppData\Roaming, Temp, Downloads com nomes/extensões suspeitos |
| **Network Usage** | iphlpapi P/Invoke + netstat | Conexões TCP ativas por processo; cheat com tráfego ativo = Critical |
| **Services** | SCM + Event 7045 | Serviços instalados com nomes suspeitos ou por publishers não-Microsoft |
| **LNK Recent** | %APPDATA%\...\Recent + AutomaticDestinations | Atalhos de arquivos recentemente acessados → evidência de abertura de arquivos |
| **RegistryPersistence** | IFEO, AppInit_DLLs, AppCertDlls, Winlogon, BootExecute, Run keys | Técnicas de persistência e hijack de processo |
| **SystemResetRestore** | InstallDate, Windows.old, Panther logs, PendingRename | Reinstalação/reset recente do Windows — perda de cobertura forense |
| **SystemTampering** | LabConfig/MoSetup keys, getadmin.vbs, scripts bat/ps1 | Bypass de requisitos Windows 11, BatchGotAdmin, scripts de elevação UAC |
| **BrowserDownloads** | Chrome/Edge/Brave/Opera/Firefox History SQLite | Downloads de executáveis suspeitos + URLs de C2 conhecidos; domínios extensíveis via `rules/suspicious_domains.json` |
| **Timeline** | Prefetch + BAM + LNK + Downloads + Temp | Linha do tempo unificada — sequência de eventos dentro da janela de lookback (padrão: 90 dias) |
| **RedENGINE Artifacts** | File system scan | `settings.cock`, menus `.lua` (absolute/lumia/phaze/nexus/strata/insec/hoax/etc.), `imgui.ini` no dir GTA V, diretórios WinRAR `Rar$*` com artefatos RedENGINE |

### Módulos pulados no perfil Fast (16 módulos essenciais)

| Módulo | Artefato | O que detecta |
|--------|----------|---------------|
| **ShimCache** | HKLM AppCompatCache | Histórico de carregamento de executáveis pelo kernel — sobrevive a reboots |
| **ShellBags** | HKCU BagMRU | Navegação em pastas suspeitas — persiste após deleção dos arquivos |
| **JumpLists** | AutomaticDestinations + CustomDestinations | Histórico de arquivos abertos por aplicação — executáveis e caminhos suspeitos |
| **NvidiaArtifacts** | nvAppTimestamps + nvdrsdb | Timestamps de uso de GPU — confirma sessão FiveM com dados de hardware |
| **ExternalToolResidue** | Prefetch + paths + registry | 28 ferramentas de análise/tampering: Process Hacker, CheatEngine, x64dbg, Everything, etc. |
| **RecycleBin** | C:\$RECYCLE.BIN\{SID}\$I* | Caminho original + data de deleção de arquivos suspeitos — evidência pós-deleção |
| **SRUM** | SRUDB.dat (ESE) | Uso de rede por processo (~30-60 dias) — fonte mais confiável que o painel Windows |

### Módulos que exigem Administrador

| Módulo | Artefato | O que detecta |
|--------|----------|---------------|
| **Amcache** | C:\Windows\appcompat\Programs\Amcache.hve | SHA1 + caminho de todo executável que já existiu — persiste após deleção do arquivo |
| **UserAssist** | HKCU\...\UserAssist (NTUSER.DAT) | Histórico de execução via Explorer (ROT-13); count + FILETIME de cada exe |

### Módulos opcionais (exigem admin + config)

| Módulo | Trigger | O que detecta |
|--------|---------|---------------|
| **USN Journal** | `RunUsnJournal=true` + admin (ou `--profile deep`) | Operações de arquivo de baixo nível (criação, deleção, renomeação) |
| **Process Memory** | `DeepMemoryScan=true` + admin (ou `--profile deep`) | Strings suspeitas em memória de processos em execução |

---

## 4a. Módulo RedENGINE Artifacts — Critérios e Teste Sintético

### Sinais e níveis de risco esperados

| Artefato | Condição | Risk | Confidence | RuleId |
|----------|----------|------|------------|--------|
| `settings.cock` encontrado sozinho | Qualquer path em user-writable | **High** | Medium | `REDENGINE_SETTINGS_COCK` |
| `settings.cock` + `redengine.exe` no mesmo dir | Co-localização de loader e config | **Critical** | High | `REDENGINE_SETTINGS_COCK_WITH_LOADER` |
| `absolute.lua`, `lumia.lua`, `phaze.lua`, etc. em Downloads/Desktop/Temp | Nome de menu RedENGINE conhecido | **High** | Medium | `REDENGINE_MENU_LUA_*` |
| `imgui.ini` no diretório GTA V | GTA V não usa ImGui — sozinho | **Medium** | Low | `REDENGINE_IMGUI_INI` |
| WinRAR temp com `redengine.exe` ou `settings.cock` | Extração recente do RAR | **Critical** | High | `REDENGINE_WINRAR_TEMP` |
| WinRAR temp com menus `.lua` | Artefatos RedENGINE em extração | **High** | Medium | `REDENGINE_WINRAR_TEMP` |

**Nota:** `imgui.ini` sozinho permanece Medium/Low — overlays legítimos (ReShade, GTA mod tools) também escrevem este arquivo. Escalação para High requer correlação com `settings.cock`, menu `.lua` ou Prefetch de `redengine.exe`.

### JSON esperado

`redengine_90d.json` deve sempre ser gerado no run folder, mesmo quando vazio (FindingCount=0).

### Teste sintético (criar artefatos antes do scan)

```powershell
# Criar diretório WinRAR fake com artefatos
$test = "$env:TEMP\Rar`$EXa_QA_redengine"
New-Item -ItemType Directory -Force $test | Out-Null
New-Item -ItemType File -Force "$test\redEngine.exe" | Out-Null
New-Item -ItemType File -Force "$test\settings.cock" | Out-Null
New-Item -ItemType File -Force "$test\absolute.lua" | Out-Null

# Também criar settings.cock solto em Downloads para testar High sem loader
New-Item -ItemType File -Force "$env:USERPROFILE\Downloads\settings.cock" | Out-Null
```

### Validação pós-scan

```powershell
cd D:\BypassNerfados\publish\win-x64
.\EchoNerfados.exe --profile deep --no-open-report --no-final-prompt

$desktop = [Environment]::GetFolderPath("Desktop")
$folder  = Get-ChildItem "$desktop\Echo_Nerfados_*" | Sort-Object LastWriteTime | Select-Object -Last 1

# P0: JSON exportado
Test-Path "$($folder.FullName)\redengine_90d.json"  # deve ser True

# Cobertura do módulo
$e = Get-Content "$($folder.FullName)\evidence.json" -Raw | ConvertFrom-Json
$e.moduleCoverage | Where-Object name -eq "RedENGINE Artifacts"  # status = "Executed"

# Findings esperados
$rf = $e.findings | Where-Object module -eq "RedENGINE Artifacts"
$rf | Select-Object risk, confidence, ruleId, title

# Critérios de aceite:
# - WinRAR temp com co-localização: risk=Critical, confidence=High, ruleId=REDENGINE_WINRAR_TEMP
# - settings.cock em Downloads: risk=High, confidence=Medium, ruleId=REDENGINE_SETTINGS_COCK
# - NÃO deve haver Critical sem loader co-localizado para settings.cock sozinho
```

### Limpeza após teste

```powershell
Remove-Item -Recurse -Force "$env:TEMP\Rar`$EXa_QA_redengine" -ErrorAction SilentlyContinue
Remove-Item -Force "$env:USERPROFILE\Downloads\settings.cock" -ErrorAction SilentlyContinue
```

---

## 5. Motor de Correlação

Após todos os módulos, o **Correlator** analisa padrões cruzados:

- **Serviço 7045 + Prefetch**: Mesmo nome → sinal de instalação + execução correlacionados
- **Amcache + ShimCache**: Mesmo executável em ambos → alta confiança de execução real
- **Defacement de IFEO + processo ativo**: Possível hijack em andamento
- **Múltiplos sinais em janela de 1h**: Agrupados em evento de instalação/uso

Saídas do correlator aparecem com prefixo `CORR_` nas `RuleId`.

**Score Noise Reduction (pós-correlação):**  
Findings `Risk ≤ Medium` e `Confidence ≤ Low` sem correlação (`RuleId` sem prefixo `CORR_`) têm `ScoreEligible = false` — não contribuem para o score numérico, mas permanecem visíveis no relatório. O threshold é configurável via `rules/score_weights.json` (`noiseMinRisk`, `noiseMaxConfidence`).

**External Rules (pós-correlação):**  
- Hash match (`rules/cheat_hashes.json`) → eleva para Critical, `ScoreEligible = true`
- Nome match (`rules/cheat_names.json`) → garante mínimo High, `ScoreEligible = true`

**Perfil Florence (pós-correlação):**  
Findings High/Critical com apenas um módulo referenciando a mesma entidade são rebaixados para Medium + `ValidationHint` orientando correlação adicional. Requer ≥2 módulos para manter High/Critical.

---

## 6. EvidenceEnricher — Artifact Dossiers

Após correlação, o **EvidenceEnricher** agrupa sinais em dossiers por artefato (executável/DLL):

**Chave de agrupamento (prioridade):**
1. SHA256 do arquivo (quando disponível)
2. Path completo normalizado
3. Nome do arquivo

**Bypass temporal window:**  
Cada sinal de bypass é comparado individualmente: `bypass.Timestamp` deve estar dentro de ±1h de **qualquer** timestamp do artefato (não do intervalo min/max). Isso evita que um sinal de abril apareça em todos os dossiers porque outro sinal foi em março.

**Campos do dossier:**
- `ArtifactName`, `FullPath`, `SHA256`, `SHA1`
- `Verdict` (ex: "Cheat detectado", "Suspeito", "Bypass")
- `Risk`, `Confidence`
- `BypassIndicators[]` — lista de evidências de adulteração de log
- `ValidationSteps[]` — sugestões de próximos passos para o investigador

---

## 7. Estrutura de Saída (Run Folder)

Todo scan gera uma pasta timestamped na área de trabalho:

```
Desktop\
└── Echo_Nerfados_HOSTNAME_20260509_180900\
    ├── report.html              ← Relatório visual completo (abas diagnósticas)
    ├── report_executive.html    ← Relatório executivo compacto (1 página, imprimível)
    ├── report.txt               ← Relatório texto (compartilhável)
    ├── evidence.json                  ← Todos os findings + dossiers em JSON
    ├── bamdam_90d.json                ← BAM/DAM — timestamps de execução (core)
    ├── prefetch_90d.json              ← Prefetch — evidência de execução (core)
    ├── knowncheats_90d.json           ← Known Cheats — hits diretos confirmados
    ├── registryartifacts_90d.json     ← Store, MuiCache, RecentDocs, 7-Zip, WinRAR
    ├── eventviewer_90d.json           ← Findings do Event Viewer (cobertura real)
    ├── defender_90d.json              ← Findings do Windows Defender
    ├── services_90d.json              ← Findings de Serviços
    ├── amcache_90d.json               ← Findings do Amcache
    ├── userassist_90d.json            ← Findings do UserAssist
    ├── shimcache_90d.json             ← Findings do ShimCache
    ├── lnk_90d.json                   ← Findings de LNK Recent
    ├── registrypersistence_90d.json   ← Findings de RegistryPersistence
    ├── ... (27 JSONs por módulo no total — Default/Deep; 16 no Fast profile)
    ├── manifest.json                  ← Metadados completos + SHA256 de todos os arquivos
    └── manifest.sha256                ← Hash do manifest.json (verificável com sha256sum)
```

**Nota (Fast profile):** 11 módulos são pulados; os JSONs correspondentes não são gerados. Apenas os 16 módulos executados produzem `*_90d.json`.

**Cobertura de log por arquivo `*_90d.json`:**

Cada arquivo tem campos:
```json
{
  "module": "Event Viewer",
  "lookbackDays": 90,
  "coverageDays": 45,
  "coverageOk": false,
  "oldestEvent": "2026-03-25T...",
  "newestEvent": "2026-05-09T...",
  "findingCount": 12,
  "findings": [...]
}
```

Se `coverageOk = false`, o Windows não tem 90 dias de log — o relatório avisa explicitamente.

---

## 8. manifest.json — Verificação Forense

O `manifest.json` contém:

```json
{
  "scannerName": "Echo Nerfados Shield XDR",
  "scannerVersion": "1.0.0+e4efd75",
  "scanStarted": "2026-05-09T18:09:00",
  "scanCompleted": "2026-05-09T18:12:30",
  "machine": "HOSTNAME",
  "user": "username",
  "isElevated": true,
  "processId": 1234,
  "commandLine": "...",
  "arguments": [...],
  "workingDirectory": "C:\\...",
  "osVersion": "Microsoft Windows NT 10.0.26200.0",
  "timezone": "E. South America Standard Time",
  "lookbackDays": 90,
  "totalScore": 185,
  "overallRisk": "CRÍTICO",
  "files": {
    "report.html":            { "sha256": "...", "size": 123456 },
    "report_executive.html":  { "sha256": "...", "size": 45678 },
    "report.txt":             { "sha256": "...", "size": 34567 },
    "evidence.json":          { "sha256": "...", "size": 234567 },
    ...
  },
  "scannerExecutable": {
    "processPath":      "C:\\..\\EchoNerfados.exe",
    "processPathHash":  "...",
    "assemblyLocation": "",
    "assemblyLocationNote": "Assembly embedded in single-file app"
  }
}
```

**Verificação por terceiro:**
```bash
# Linux/Mac
sha256sum -c manifest.sha256

# Windows PowerShell
$ref = (Get-Content manifest.sha256 -Raw).Split("  ")[0]
$actual = (Get-FileHash manifest.json -Algorithm SHA256).Hash.ToLower()
if ($ref -eq $actual) { "OK" } else { "FALHOU" }
```

---

## 9. Como Executar

### Execução padrão
1. Copiar `EchoNerfados.exe` **e o diretório `rules/`** para a máquina alvo
2. Para acesso completo (todos os módulos): clicar com botão direito → "Executar como administrador"
3. Sem elevação: módulos ShimCache, LNK Recent, RegistryPersistence, BAM/DAM, Prefetch etc. funcionam; Amcache e UserAssist são pulados (exigem acesso a hives offline)
4. Fazer login: `nerfados` / `admin`
5. Aguardar conclusão (2–10 min dependendo do hardware; ~30s no perfil Fast)
6. Pasta de resultados criada na área de trabalho

### Flags de linha de comando
```
EchoNerfados.exe [opções]
  --investigator <nome>   Nome do investigador (para o relatório)
  --suspect <nome>        Nome do suspeito (para o relatório)
  --case-id <id>          ID do caso/investigação
  --drive <letra>         Drive a ser analisado (padrão: C:)
  --output <caminho>      Pasta de saída do relatório
  --lookback <dias>       Janela de análise em dias (padrão: 90)
  --profile default       Todos os módulos (padrão)
  --profile fast          16 módulos essenciais — scan rápido (~30s)
  --profile deep          Todos os módulos + USN + Memory (ignora --no-usn/--no-memory)
  --profile fivem         Foco FiveM — todos os módulos + timeline por sessão
  --profile florence      Todos os módulos + downgrade single-source High/Critical
  --ui minimal            Console limpo: score + top 5 + caminhos (padrão)
  --ui detailed           Console detalhado: tabelas + dossiês + cobertura
  --open-report           Abrir HTML automaticamente ao finalizar
  --no-open-report        Não abrir HTML nem exibir menu (apenas caminho)
  --no-usn                Pular análise do USN Journal
  --no-memory             Pular análise de memória de processos
  --no-report             Não gerar relatório em arquivo
  --no-final-prompt       Não exibir menu após conclusão (automação)
  --verbose               Mostrar todos os findings (incluindo INFO)
  --help                  Exibir esta ajuda
```

---

## 10. Cenários de Teste para QA

### 10.1 Execução sem console interativo
- [ ] `EchoNerfados.exe --help | more` → exit code 0, ajuda exibida, sem crash
- [ ] `EchoNerfados.exe 2>&1 | more` (stdout redirecionado) → exit code 1 + mensagem de erro no stderr, sem crash
- [ ] `dotnet exec EchoNerfados.dll --help` → exit code 0, sem crash

### 10.2 --help
- [ ] `EchoNerfados.exe --help` → exibe ajuda sem pedir login, exit code 0
- [ ] `EchoNerfados.exe -h` → idem
- [ ] Ajuda lista `--profile`, `--ui`, `--open-report`, `--no-open-report`

### 10.3 Login
- [ ] Login correto → scan inicia
- [ ] Senha errada 3x → exit code 2
- [ ] Ctrl+C durante login → scan não inicia

### 10.4 Execução Sem Admin (asInvoker — sem UAC)
- [ ] EXE abre sem prompt de UAC
- [ ] Módulos ShimCache, LNK Recent, RegistryPersistence, Prefetch, BAM/DAM executam
- [ ] Módulos Amcache, UserAssist são pulados (reportado no console)
- [ ] Aviso "Executando sem privilégios" exibido

### 10.5 Execução Com Admin ("Executar como administrador")
- [ ] Todos os módulos do perfil executam
- [ ] Amcache.hve carregado sem erro
- [ ] NTUSER.DAT de todos os perfis lidos

### 10.6 Saída de Arquivos
- [ ] Pasta timestamped criada na área de trabalho
- [ ] `report.html` abre no browser corretamente
- [ ] `report_executive.html` presente — abre no browser, exibe score, top-5 provas, timeline, bypass e cobertura
- [ ] `report.txt` legível em qualquer editor
- [ ] `evidence.json` JSON válido
- [ ] `*_90d.json` presentes para os módulos executados (27 no Default/Deep; 16 no Fast) + `evidence.json`
- [ ] `manifest.json` presente e campos preenchidos (inclui `report_executive.html` na seção `files`)
- [ ] `manifest.sha256` verificável com sha256sum
- [ ] Diretório `rules/` presente ao lado do EXE com 5 arquivos JSON

### 10.7 Cobertura de Log
- [ ] Em máquina com logs < 90 dias: `coverageOk: false` nos JSONs relevantes
- [ ] Aviso de cobertura aparece no HTML e TXT
- [ ] Em máquina com logs >= 90 dias: `coverageOk: true`

### 10.8 Correlação e Dossiers
- [ ] Findings do mesmo executável agrupados em um único dossier
- [ ] `BypassIndicators` só aparecem em dossiers com sinais temporalmente próximos (±1h)
- [ ] Findings CORR_ presentes quando módulos cruzam sinais

### 10.9 Cancelamento
- [ ] Ctrl+C durante scan: encerra limpo sem pasta corrompida
- [ ] Ctrl+C durante geração de relatório: manifesto não gerado (parcial OK)

### 10.10 Módulos Específicos
- [ ] **Amcache**: Detecta exe deletado com flag `[ARQUIVO DELETADO]` + SHA1 presente; texto diz "presença/registro", não "execução confirmada"
- [ ] **ShimCache**: Lista executáveis com timestamp; texto diz "indício de carregamento/presença"; instrui correlacionar com Prefetch/BAM
- [ ] **UserAssist**: Count e timestamp de execuções via Explorer
- [ ] **LNK Recent**: Detecta .lnk com alvo Unicode (caminhos com caracteres não-ASCII)
- [ ] **RegistryPersistence**: AppInit_DLLs com LoadAppInit_DLLs=0 → Medium/Low (não High); AppInit_DLLs com LoadAppInit_DLLs=1 → High

### 10.11 Perfis de Varredura
- [ ] `--profile fast` executa exatamente 16 módulos; SRUM, ShimCache, ShellBags, JumpLists, NvidiaArtifacts, ExternalToolResidue, RecycleBin, Amcache, UserAssist, USN Journal, ProcessMemory aparecem como PULADO na tabela de cobertura
- [ ] `--profile deep` força USN Journal e ProcessMemory mesmo sem `--no-usn`/`--no-memory`
- [ ] `--profile fivem` produz timeline agrupada por sessão FiveM (janela -30min/+2h ao redor de evento âncora)
- [ ] `--profile florence` rebaixa High/Critical single-source para Medium; Finding inclui `ValidationHint` com orientação de correlação
- [ ] `--profile default` (sem flag) executa todos os 27 módulos sem USN/Memory por padrão

### 10.12 Score e Ruído
- [ ] Score (0-100) não inflaciona por findings Medium+LowConfidence sem correlação (`ScoreEligible = false`)
- [ ] Resumo HTML exibe seção "Por que X/100?" com breakdown por categoria e count de findings filtrados
- [ ] Aba "Provas Fortes" no HTML lista findings Confirmed ou High+HighConf ou CORR_
- [ ] `FilteredCount` no score card indica quantos findings foram excluídos do cálculo

### 10.13 Regras Externas
- [ ] Adicionar hash em `rules/cheat_hashes.json` → finding elevado para Critical no próximo scan sem recompilar
- [ ] Adicionar nome em `rules/cheat_names.json` → finding elevado para High no próximo scan
- [ ] Remover `rules/` → scanner funciona normalmente com comportamento padrão (sem crash, sem aviso fatal)

### 10.14 Relatório Executivo
- [ ] `report_executive.html` abre sem JS; imprimível via Ctrl+P (CSS `@media print`)
- [ ] Exibe: score numérico, label de risco, top-5 provas fortes, timeline de eventos High+, tentativas de ocultação, contadores de cobertura
- [ ] Hash do manifesto exibido no rodapé do executivo quando `manifest.sha256` existe

---

## 11. Limitações Conhecidas

| Limitação | Impacto | Status |
|-----------|---------|--------|
| **SRUM: dirty shutdown** | SRUDB.dat pode exigir recovery — tentadas 3 page sizes (32768/16384/8192); se todas falharem → PARCIAL | Comportamento esperado em máquinas com shutdown abrupto |
| **ManagedEsent NU1701** | ManagedEsent 1.9.4 é .NET Framework — compatível com net8.0 via shim, mas gera warning NU1701 | Funcional; migrar para parser ESE nativo .NET 8 em futura iteração |
| **ShimCache: formato Windows 7/8** | Parser fallback por UTF-16 — timestamps ausentes | Aceitável para Win10/11 |
| **UserAssist: somente HKCU do usuário atual** | Outros perfis lidos via offline hive (admin only) | Funcional |
| **Log < 90 dias** | `coverageOk: false` reportado mas scan continua | Investigador deve notar o aviso |
| **assemblyLocation vazio** | Em single-file app, `Assembly.Location` é sempre empty | `manifest.json` contém nota explicativa |
| **Assinatura digital** | manifest.sha256 não assinado por PKI | Requer setup de certificado (futuro) |
| **License key** | Login fixo (nerfados/admin) | Substituir por sistema de keys para comercialização |
| **ProcessMemoryModule** | Pode causar lentidão em máquinas com muitos processos | Desativar com `--no-memory` se necessário |
| **UserAssist PARCIAL para perfis de sistema** | NTUSER.DAT de "Usuário Padrão", "WsiAccount" e perfis similares é inacessível mesmo com admin | Comportamento esperado — perfis de sistema não têm NTUSER.DAT padrão. O finding PARCIAL é correto; confirmar que o perfil do usuário real foi lido. |
| **BAM/DAM PARCIAL sem admin** | ACL restrita em HKLM\SYSTEM\...\BAM em algumas configurações | SecurityException capturada → PARCIAL com motivo. Para cobertura completa, usar com admin. |
| **Fast profile reduz cobertura forense** | 11 módulos pulados — ShimCache, ShellBags, SRUM, etc. não geram artefatos | Usar Default ou Deep para investigação completa; Fast apenas para triagem rápida |
| **Florence pode mascarar provas reais** | Single-source High/Critical rebaixado para Medium pode ser legítimo em máquinas com poucos artefatos | Confirmar com perfil Default antes de usar Florence como definitivo |
| **rules/ ausente no publish** | Se o diretório `rules/` não for copiado junto ao EXE, as regras externas não são carregadas | Scanner funciona sem crash — usa defaults embutidos. Garantir que `rules/` acompanha o artefato. |
| **report_executive.html sem JS** | Sem busca, filtro ou zoom interativo | Impresso via Ctrl+P supre o caso de uso principal |

---

## 12. Smoke Test Interativo — Procedimento Obrigatório

O smoke test requer execução manual com console interativo real (admin). Executar as condições A/B e depois o bloco de perfis.

### Script de verificação operacional (executar após cada perfil)

Copiar para um terminal PowerShell na mesma pasta do EXE. Substituir `--profile fast` pelo perfil sendo testado.

```powershell
# 1. Executar (aguarda conclusão)
.\EchoNerfados.exe --profile fast --no-open-report
$LASTEXITCODE   # esperado: 0 (Clean) a 4 (Critical) — nunca 98/99

# 2. Localizar pasta gerada
$folder = Get-ChildItem "$([Environment]::GetFolderPath('Desktop'))\Echo_Nerfados_*" |
  Sort-Object LastWriteTime | Select-Object -Last 1

# 3. Artefatos obrigatórios (todos devem ser True)
Test-Path "$($folder.FullName)\report.html"
Test-Path "$($folder.FullName)\report_executive.html"
Test-Path "$($folder.FullName)\evidence.json"
Test-Path "$($folder.FullName)\manifest.json"
Test-Path "$($folder.FullName)\manifest.sha256"

# 4. Verificar integridade do manifesto
Set-Location $folder.FullName
$ref    = (Get-Content manifest.sha256 -Raw).Split("  ")[0].Trim()
$actual = (Get-FileHash manifest.json -Algorithm SHA256).Hash.ToLower()
if ($ref -eq $actual) { "MANIFESTO OK" } else { "MANIFESTO FALHOU: $ref vs $actual" }
```

**Critério por perfil:**

| Perfil | Exit code | JSONs esperados | Verificação adicional |
|--------|-----------|-----------------|----------------------|
| `default` | 0–4 | 27 `*_90d.json` + evidence.json | Todos os 27 módulos = EXECUTADO ou PARCIAL na cobertura |
| `fast` | 0–4 | 16 `*_90d.json` + evidence.json | 11 módulos (ShimCache, SRUM, ShellBags, JumpLists, Nvidia, ExternalTool, RecycleBin, Amcache, UserAssist, USN, ProcessMemory) = PULADO |
| `deep` | 0–4 | 27+ `*_90d.json` + evidence.json | USN Journal e ProcessMemory = EXECUTADO mesmo sem flags |
| `fivem` | 0–4 | 27 `*_90d.json` + evidence.json | Timeline HTML exibe blocos "Antes / Durante / Após sessão FiveM" |
| `florence` | 0–4 | 27 `*_90d.json` + evidence.json | Findings High single-source → Medium com ValidationHint no HTML |

---

### CONDIÇÃO A — Sem elevação (duplo clique / terminal normal)

```
1. Copiar EchoNerfados.exe e o diretório rules/ para a máquina alvo
2. Abrir terminal normal (sem "Executar como administrador")
3. Executar: .\EchoNerfados.exe
4. Login: nerfados / admin
5. Aguardar conclusão
```

**Verificar:**
- [ ] Nenhum UAC prompt aparece (app.manifest = asInvoker)
- [ ] Console exibe "Executando sem privilégios de Administrador"
- [ ] Módulos ShimCache, LNK Recent, RegistryPersistence, KnownCheats, FileSystem, Network, Services executam normalmente
- [ ] BAM/DAM e Prefetch podem aparecer como PARCIAL se o sistema tiver ACL restrita; confirmar que o status é PARCIAL (não FALHOU) e que o motivo está visível na tabela
- [ ] EventViewer e Defender podem aparecer como PARCIAL (Security log pode ser inacessível sem admin); qualquer limitação aparece como PARCIAL — não FALHOU — na tabela de cobertura
- [ ] Tabela "COBERTURA DA VARREDURA" no console mostra Amcache = PULADO, UserAssist = PULADO (com motivo)
- [ ] Pasta timestamped criada na área de trabalho
- [ ] `report.html` abre no browser — seção "COBERTURA DA VARREDURA" visível; aba "Provas Fortes" presente
- [ ] `report_executive.html` presente na pasta — abre no browser; exibe score, top-5, timeline
- [ ] `report.txt` — seção "COBERTURA DA VARREDURA" visível com status PULADO para Amcache/UserAssist
- [ ] `evidence.json` — JSON válido, parseable
- [ ] `*_90d.json` presentes para os módulos executados + `evidence.json`
- [ ] `manifest.json` — campo `"isElevated": false`; `report_executive.html` listado na seção `files`
- [ ] `manifest.sha256` verifica: `sha256sum -c manifest.sha256` → OK
- [ ] Diretório `rules/` presente ao lado do EXE com `cheat_names.json`, `cheat_hashes.json`, `suspicious_domains.json`, `known_legit_publishers.json`, `score_weights.json`

**Se algum módulo tiver erro parcial:**
- [ ] Status aparece como PARCIAL (não FALHOU nem EXECUTADO) na tabela
- [ ] Motivo específico está visível ("X itens inacessíveis" ou mensagem de contexto)

---

### CONDIÇÃO B — Com elevação ("Executar como administrador")

```
1. Clicar com botão direito em EchoNerfados.exe → "Executar como administrador"
2. Login: nerfados / admin
3. Aguardar conclusão
```

**Verificar:**
- [ ] Console NÃO exibe aviso de privilégios
- [ ] Tabela "COBERTURA DA VARREDURA" mostra Amcache = EXECUTADO, UserAssist = EXECUTADO
- [ ] `manifest.json` — campo `"isElevated": true`
- [ ] `amcache_90d.json` — `findingCount > 0` (ou `findingCount: 0` + `coverageDays` preenchido)
- [ ] `userassist_90d.json` — idem
- [ ] `registrypersistence_90d.json` — presente
- [ ] `evidence.json` — campo `EvidenceBundles` não vazio se houver cheats
- [ ] `manifest.sha256` verifica

**Verificação do manifesto (Windows PowerShell):**
```powershell
$desktop = [Environment]::GetFolderPath("Desktop")
$folder = Get-ChildItem "$desktop\Echo_Nerfados_*" | Sort LastWriteTime | Select -Last 1
cd $folder.FullName
$ref = (Get-Content manifest.sha256 -Raw).Split("  ")[0].Trim()
$actual = (Get-FileHash manifest.json -Algorithm SHA256).Hash.ToLower()
if ($ref -eq $actual) { "MANIFESTO OK" } else { "FALHOU: $ref vs $actual" }
```

**Verificar `report_executive.html` imprimível:**
- [ ] Abrir `report_executive.html` no browser → Ctrl+P → "Salvar como PDF" → verificar que score, top-5 e timeline aparecem na impressão
- [ ] Seção de hash do manifesto exibida no rodapé do executivo

---

## 13. Build Reproducível

```bash
# Clonar e publicar
git clone <repo>
cd BypassNerfados
git checkout 09613d3   # HEAD do artefato entregue (inclui Sprint 1/2/3, QA_REPORT e .gitignore limpo)
dotnet publish src/Scanner/Scanner.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64
```

**Nota:** Uma nova compilação a partir do mesmo commit **não produz o mesmo hash**: metadados de timestamp e GUID do PE variam por compilação. Para build realmente reproduzível é necessário configurar `<Deterministic>true</Deterministic>` no `.csproj` (fora do escopo desta release).

**Nota publicação:** Antes de republicar, verificar que nenhuma instância de `EchoNerfados.exe` está em execução — o bundler não consegue sobrescrever o executável em uso. Encerrar o processo antes de rodar `dotnet publish`.

---

## 14. Sumário para QA

**O que está pronto e testável (build 38907aa — apto para smoke test interativo):**
- `--help` funciona sem login e sem console interativo (exit 0, seguro para pipe)
- Execução sem console retorna exit 1 com mensagem clara, nunca crasha
- `app.manifest asInvoker` — sem UAC forçado; admin por escolha do operador
- Login gate funcional com bloqueio após 3 tentativas (exit code 2)
- **27 módulos** cobrindo todos os principais artefatos forenses Windows (Default/Deep profile)
- **Fast profile** (16 módulos essenciais) para triagem em ~30s
- **FiveM profile** — timeline agrupada por sessão detectada via eventos âncora (fivem/gta5/citizenfx), janela -30min/+2h, clustering de 3h
- **Florence profile** — downgrade de single-source High/Critical para Medium; ValidationHint orienta correlação adicional
- **Score noise reduction** — `ScoreEligible = false` para Medium+LowConf sem correlação; score 0-100 reflete apenas sinais confiantes
- **Score breakdown explicável** — aba Resumo HTML exibe "Por que X/100?" com 5 categorias e count de filtrados
- **Aba "Provas Fortes"** — agrupa Confirmed/HighConf/CORR_ com cross-ref de dossiês bypass
- **Regras externas JSON** — 5 arquivos em `rules/`: cheat_names, cheat_hashes, suspicious_domains, known_legit_publishers, score_weights; extensíveis sem recompilar
- **`report_executive.html`** — relatório compacto 1-página, imprimível via Ctrl+P (sem JS, sem deps externas); inclui score, top-5 provas, timeline, bypass, cobertura e hash do manifesto
- **Bypass alert banner** no HTML com detecção de IDs 1102, 104, 3079, 5007, 1116, 1117, 7045
- Correlação cruzada entre módulos + artifact dossiers com bypass ±1h por sinal + correlação FiveM session
- Exportação: HTML, HTML executivo, TXT, **28 JSONs dedicados** (27 módulos + evidence.json — Default profile)
- Manifesto criptograficamente verificável (`manifest.sha256`)
- Tabela "COBERTURA DA VARREDURA" no terminal, TXT e HTML com status Executed/Partial/Skipped/Failed
- Todos os catches críticos logam `LogPartialError` com contexto específico; inaccessible contados, não silenciados
- Executável self-contained (~67 MB), sem .NET no host
- AppInit_DLLs distingue ativo vs. inativo via `LoadAppInit_DLLs`
- LNK parser suporta `LocalBasePathUnicode` (caminhos Unicode)
- Amcache/ShimCache com linguagem forense calibrada ("presença/indício", não "execução confirmada")
- BAM/DAM sem admin → PARCIAL com motivo (SecurityException capturada), nunca FALHOU
- Amcache com admin → SeBackupPrivilege + cópia de .LOG1/.LOG2 + fallback VSS via WMI `Win32_ShadowCopy.Create`
- `evidence.json` inclui `ModuleCoverage` (status, motivo, impacto forense de cada módulo)
- Auto-exclusão robusta: `IsOwnProcess` cobre nomes históricos e caminhos de build
- **NVIDIA**: só High se strings suspeitas encontradas no binário nvAppTimestamps — sem false positive em PC limpo
- **SRUM**: CopyLockedFile para SRUDB.dat + fallback FileStream; 3 page sizes (32768/16384/8192)
- **BrowserDownloads**: suporte Chrome/Edge/Brave/Opera/Firefox; GitHub apenas via allowlist de orgs; Uri.Host para domain check
- **BatchGotAdmin**: `SCRIPT_BATCHGOTADMIN_PRESENT`; linguagem calibrada ("autoelevação via UAC")
- **ShellBags**: Medium sem timestamp (High requer correlação); inaccessible logados
- **RecycleBin**: usa `config.EventWindowLookback` (não hardcoded)
- **`--ui minimal`** (padrão): score + contagem por severidade + top 5 High/Critical — saída limpa para operadores
- **`--ui detailed`**: tabelas completas + top 10 findings + top 10 dossiês + cobertura + bypass no terminal — para analistas
- **`--open-report`**: abre o HTML no browser padrão automaticamente ao terminar, sem menu
- **`--no-open-report`**: suprime menu pós-scan inteiramente — apenas exibe o caminho do relatório (modo automação)
- **HTML CSS custom properties**: `--bg`, `--panel`, `--critical`, `--high`, `--medium`, `--low`, `--accent`, etc. — tema consistente sem valores hexadecimais duplicados
- **Relatório HTML com abas diagnósticas**: Resumo, Cheats, Provas Fortes, Diagnóstico, Execuções, Downloads, Deleções/USN, Pastas, Memória, Bypass, Outros, Timeline, Cobertura — filtro por severidade por aba, agrupamento por módulo
- **`--lookback <dias>`**: flag implementada — substitui padrão de 90 dias por valor customizado
- **Nomes genéricos neutros**: `launcher.exe` e `spotify.exe` deixam de rotular diretamente "GOSTH" — usam "Loader FiveM Suspeito (padrão GOSTH)"
- **EventViewer**: todos os findings usam `"Event Viewer"` (com espaço) — eventviewer_90d.json preenchido corretamente
- **Defender**: todos os findings usam `Name` = `"Windows Defender"` — defender_90d.json preenchido corretamente
- **filesystem_90d.json** + **network_90d.json** adicionados ao EvidenceExporter
- **4688**: query XPath inclui janela temporal `EventWindowLookback` — sem scan ilimitado
- **QueryDb**: falhas de sqlite3_open/prepare logadas via LogPartialError
- **IgnoreInaccessible**: KnownCheats e FileSystem usam EnumerationOptions ao invés de GetFiles+SearchOption

**Prioridade de teste:** Focar nos cenários 10.1, 10.2, 10.3, 10.4, 10.11, 10.12 — são os mais críticos para validar o produto. Os outros podem ser smoke test.

---

## Critérios de Aceite (próximo QA)

- [x] PC com NVIDIA limpo **não** gera Medium/High por nvAppTimestamps
- [x] `bypassstoragecheck` (correto) dispara no scan de scripts de LabConfig
- [x] Todos os 27 módulos aparecem em evidence.json + arquivos `*_90d.json` dedicados (Default profile)
- [x] Browser aberto durante o scan **não** quebra coleta (CopyLockedFile)
- [x] Nenhum ruleId com `GOSTH` fora de: `CHEAT_HASH_GOSTH_WHATSAPP`, `CHEAT_PATH_GOSTH_DXSETUP`, `GOSTH_PATTERN_SYSTEM32`
- [x] `SCRIPT_BATCHGOTADMIN_PRESENT` substitui `_EXECUTED` no ruleId
- [x] `manifest.sha256` verificável após scan completo
- [x] `eventviewer_90d.json` não vazio quando há eventos no período
- [x] `defender_90d.json` não vazio quando há eventos no período
- [x] `filesystem_90d.json` e `network_90d.json` exportados em todo scan
- [x] `bamdam_90d.json` e `prefetch_90d.json` exportados (core forense — sempre presentes)
- [x] `knowncheats_90d.json` e `registryartifacts_90d.json` exportados em todo scan
- [x] `--ui minimal` exibe score + contagem por severidade + top 5 (padrão — sem arg)
- [x] `--ui detailed` exibe tabelas completas, dossiês e cobertura no terminal
- [x] `--open-report` abre HTML no browser padrão sem exibir menu interativo
- [x] `--no-open-report` não exibe menu nem abre browser; apenas imprime caminho do relatório
- [x] `EchoNerfados.exe --help` lista `--profile`, `--ui`, `--open-report`, `--no-open-report`
- [x] HTML report renderiza com CSS custom properties (sem fallback de cor hardcoded)
- [ ] `--profile fast` executa 16 módulos; 11 aparecem como PULADO na cobertura
- [ ] `--profile deep` força USN Journal + ProcessMemory
- [ ] `--profile fivem` agrupa timeline por sessão FiveM detectada
- [ ] `--profile florence` rebaixa single-source High/Critical para Medium com ValidationHint
- [ ] Score (0-100) não inflaciona por Medium+LowConf sem correlação; `FilteredCount` > 0 em scan típico
- [ ] Aba "Provas Fortes" presente no HTML e lista findings Confirmed/HighConf/CORR_
- [ ] Seção "Por que X/100?" no Resumo HTML descreve breakdown por categoria
- [ ] `report_executive.html` gerado em todo scan; listado em `manifest.json` seção `files`
- [ ] `report_executive.html` imprimível via Ctrl+P sem JS
- [ ] Bypass alert banner aparece no HTML quando eventos 1102/104/3079/5007/1116/1117/7045 detectados
- [ ] `rules/cheat_names.json` carregado — nomes do arquivo elevam findings para mínimo High
- [ ] `rules/cheat_hashes.json` carregado — hash match eleva finding para Critical
- [ ] Scanner não crasha quando `rules/` ausente (graceful fallback)
- [ ] `rules/score_weights.json` controla threshold de noise reduction (noiseMinRisk / noiseMaxConfidence)

### RedENGINE Artifacts

- [ ] `redengine_90d.json` gerado em todo scan (mesmo quando vazio)
- [ ] `settings.cock` sozinho → **High/Medium** — NÃO Critical
- [ ] `settings.cock` + `redengine.exe` no mesmo dir → **Critical/High** — ruleId `REDENGINE_SETTINGS_COCK_WITH_LOADER`
- [ ] Menu `.lua` conhecido (absolute/lumia/phaze/nexus) em Downloads/Desktop/Temp → **High/Medium**
- [ ] `imgui.ini` no dir GTA V sozinho → **Medium/Low** — NÃO escala sem correlação
- [ ] WinRAR temp com loader co-localizado → **Critical/High** — ruleId `REDENGINE_WINRAR_TEMP`
- [ ] Módulo aparece como `Executed` em `moduleCoverage` do `evidence.json`
- [ ] Teste sintético: findings presentes para artefatos criados em `$TEMP\Rar$EXa_QA_redengine`

---

---

## 13. SRUM — Resiliência de Schema

SRUDB.dat usa ESE e os nomes de coluna variam entre builds do Windows.

| Coluna primária | Fallbacks testados |
|---|---|
| `AppId` | `AppID`, `AppIndex` |
| `BytesSent` | — |
| `BytesRecvd` | `BytesRecv`, `BytesReceived` |
| `TimeStamp` | `Timestamp`, `timestamp` |
| `IdIndex` (IdTable) | `IdIdx`, `Id` |
| `App` (IdTable) | `ExeInfo`, `AppName` |

`TryGetColumn()` tenta cada candidato em ordem; lança `InvalidOperationException` apenas se todos falharem, e o erro é capturado e logado como `PartialError`.

**Critério de aceite:** SRUM não deve emitir `No such column` nem `Not a valid Win32 FileTime` em nenhuma build do Windows.

**Detecção de tipo de TimeStamp:**
- `tsColtyp == "DateTime"` → `RetrieveColumnAsDateTime` (OLE Automation date, UTC → local)
- Outro (Long/LongLong/Currency) → `RetrieveColumnAsInt64` + `FileTimeToDateTime` (FILETIME)
- Linha com timestamp nulo ou inválido → `malformedRows++; continue` (não derruba o módulo)
- Após loop: `LogPartialError` se `malformedRows > 0`

**Critério de aceite — degradação graciosa:**
- Se colunas de bytes não forem encontradas: `SRUM_SCHEMA_INCOMPATIBLE` presente em `srum_90d.json` com lista de colunas disponíveis
- Finding com `ruleId = "SRUM_SCHEMA_INCOMPATIBLE"`, `risk = "info"`, `scoreEligible = false`
- Módulo **não chama `LogPartialError`** — bytes ausentes são degradação informativa
- `moduleCoverage` SRUM = `Executed` (não `Partial`) quando `AppId`, `TimeStamp` e `IdMap` foram lidos com sucesso
- `Partial` só ocorre se: `AppId` ausente, `TimeStamp` ausente, tabela de rede não encontrada, ou `IdMap` impossível
- Cheats conhecidos ainda detectados por app path e timeline — detecção por bytes não é bloqueante

**IdMap — dual-schema (BuildAppMap):**

`SruDbIdMapTable` sofreu mudança de schema no Windows 11 (build 22000+):

| Campo | Schema antigo (Win10) | Schema novo (Win11+) |
|---|---|---|
| Índice | `IdIndex (Long)` | `IdIndex (Long)` |
| App path | `App (Text / Unicode)` | `IdBlob (LongBinary)` — UTF-16LE |
| Tipo de entrada | *(implícito — apenas paths)* | `IdType (UnsignedByte)`: 1=exe, 2=SID, 3=serviço |

Parser tenta schema antigo primeiro (`App`/`ExeInfo`/`AppName`). Se nenhuma dessas colunas existir, tenta `IdBlob` (schema novo). Entradas com `IdType ≠ 1` e paths que começam com `S-1-` são ignoradas.

**Critério de aceite — IdMap (BuildAppMap):**
- Se `SruDbIdMapTable` não existir: `LogPartialError` `"SruDbIdMapTable não encontrada"` — sem crash
- Schema antigo detectado → app path lido via `RetrieveColumnAsString(Unicode)`
- Schema novo detectado → `IdBlob` decodificado como UTF-16LE; entradas `IdType ≠ 1` descartadas
- Se nem `App/*` nem `IdBlob` encontrados: finding `SRUM_IDMAP_SCHEMA_INCOMPATIBLE` (info/LogCoverage/scoreEligible=false) com schema dump
- Se tabela existe mas `appMap.Count == 0` após parsing: finding `SRUM_IDMAP_EMPTY` (info/LogCoverage/scoreEligible=false)
- Em nenhum caso o módulo encerra silenciosamente sem diagnóstico
- **Schema novo resolvido com sucesso → SRUM status = `Executed` (não `Partial`)**

---

## 14. Cobertura de Módulos Filesystem/Registry

Para módulos baseados em varredura de disco ou registry (`Known Cheats`, `File System`, `RedENGINE Artifacts`, `Registry Artifacts`, `RegistryPersistence`, `SystemTampering`, `System Reset/Restore`, `System Info`, `Services`, `Process Memory`, `Network Usage`):

- `coverageOk` deve ser **sempre `true`**
- `coverageDays` deve ser igual a `lookbackDays` (ex: 90)
- Timestamps de findings refletem idade do artefato, **não** profundidade da cobertura do módulo

Módulos baseados em log de eventos (`Event Viewer`, `Windows Defender`) continuam usando a lógica de cobertura real via `LOG_COVERAGE_*`.

---

*Relatório gerado em: 2026-05-16 | Build: 5622fc2 | Echo Nerfados Shield XDR v1.0.0*
