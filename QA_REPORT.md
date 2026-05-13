# Echo Nerfados Shield XDR — Relatório de QA
**Versão:** 1.0.0+7382cf9  
**Build:** 7382cf9 (2026-05-11) — feat: live dashboard, DMA detection, behavioral correlation, QA fixes  
**Arquivo:** `publish\win-x64\EchoNerfados.exe`  
**SHA256:** `a7f99999571981e151d9009a1a33ce41d683cb80d8cf81c7f6c625d87754327b`  
**Tamanho:** ~34 MB (self-contained, sem dependência de .NET no host)  
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

## 4. Módulos de Varredura (23 módulos base + 2 requerem Admin + 2 opcionais por flag)

### Módulos sem requisito de admin (funcionam com asInvoker)

| Módulo | Artefato | O que detecta |
|--------|----------|---------------|
| **System Info** | WMI | Nome da máquina, usuário, OS, BIOS |
| **BAM/DAM** | HKLM\SYSTEM\...\BAM | Histórico de execução (Background Activity Monitor) — últimos ~7 dias. **Nota:** o registro BAM tem ACL restrita em algumas builds do Windows; sem admin pode resultar em PARCIAL (SecurityException capturada, motivo exibido). |
| **Prefetch** | C:\Windows\Prefetch\*.pf | Histórico de execução por nome de arquivo; nome da entry = nome do processo. **Nota:** `C:\Windows\Prefetch` exige admin em algumas configurações; sem admin pode resultar em PARCIAL. |
| **Registry Artifacts** | HKLM run keys + MRU | Execuções recentes, autoruns em registry |
| **Event Viewer** | Security/System/Application logs | Logons (4624), falhas (4625), serviços instalados (7045), Defender alerts, cobertura de log |
| **Windows Defender** | Event log + MPLog | Detecções, exclusões, deleções de definição, reconfiguração |
| **Known Cheats** | File system scan | Varredura de nomes conhecidos de cheat nos drives especificados |
| **File System** | Paths suspeitos | Arquivos em AppData\Roaming, Temp, Downloads com nomes/extensões suspeitos |
| **Network Usage** | iphlpapi P/Invoke + netstat | Conexões TCP ativas por processo; cheat com tráfego ativo = Critical |
| **Services** | SCM + Event 7045 | Serviços instalados com nomes suspeitos ou por publishers não-Microsoft |
| **ShimCache** | HKLM AppCompatCache | Histórico de carregamento de executáveis pelo kernel — sobrevive a reboots |
| **LNK Recent** | %APPDATA%\...\Recent + AutomaticDestinations | Atalhos de arquivos recentemente acessados → evidência de abertura de arquivos |
| **RegistryPersistence** | IFEO, AppInit_DLLs, AppCertDlls, Winlogon, BootExecute, Run keys | Técnicas de persistência e hijack de processo |
| **SystemResetRestore** | InstallDate, Windows.old, Panther logs, PendingRename | Reinstalação/reset recente do Windows — perda de cobertura forense |
| **SystemTampering** | LabConfig/MoSetup keys, getadmin.vbs, scripts bat/ps1 | Bypass de requisitos Windows 11, BatchGotAdmin, scripts de elevação UAC |
| **BrowserDownloads** | Chrome/Edge/Brave/Opera/Firefox History SQLite | Downloads de executáveis suspeitos + URLs de C2 conhecidos |
| **ShellBags** | HKCU BagMRU | Navegação em pastas suspeitas — persiste após deleção dos arquivos |
| **JumpLists** | AutomaticDestinations + CustomDestinations | Histórico de arquivos abertos por aplicação — executáveis e caminhos suspeitos |
| **NvidiaArtifacts** | nvAppTimestamps + nvdrsdb | Timestamps de uso de GPU — confirma sessão FiveM com dados de hardware |
| **ExternalToolResidue** | Prefetch + paths + registry | 28 ferramentas de análise/tampering: Process Hacker, CheatEngine, x64dbg, Everything, etc. |
| **RecycleBin** | C:\$RECYCLE.BIN\{SID}\$I* | Caminho original + data de deleção de arquivos suspeitos — evidência pós-deleção |
| **Timeline** | Prefetch + BAM + LNK + Downloads + Temp | Linha do tempo unificada — sequência de eventos dos últimos 60 dias |
| **SRUM** | SRUDB.dat (ESE) | Uso de rede/CPU por processo (~30-60 dias) — fonte mais confiável que o painel Windows |

### Módulos que exigem Administrador

| Módulo | Artefato | O que detecta |
|--------|----------|---------------|
| **Amcache** | C:\Windows\appcompat\Programs\Amcache.hve | SHA1 + caminho de todo executável que já existiu — persiste após deleção do arquivo |
| **UserAssist** | HKCU\...\UserAssist (NTUSER.DAT) | Histórico de execução via Explorer (ROT-13); count + FILETIME de cada exe |

### Módulos opcionais (exigem admin + config)

| Módulo | Trigger | O que detecta |
|--------|---------|---------------|
| **USN Journal** | `RunUsnJournal=true` + admin | Operações de arquivo de baixo nível (criação, deleção, renomeação) |
| **Process Memory** | `DeepMemoryScan=true` + admin | Strings suspeitas em memória de processos em execução |

---

## 5. Motor de Correlação

Após todos os módulos, o **Correlator** analisa padrões cruzados:

- **Serviço 7045 + Prefetch**: Mesmo nome → sinal de instalação + execução correlacionados
- **Amcache + ShimCache**: Mesmo executável em ambos → alta confiança de execução real
- **Defacement de IFEO + processo ativo**: Possível hijack em andamento
- **Múltiplos sinais em janela de 1h**: Agrupados em evento de instalação/uso

Saídas do correlator aparecem com prefixo `CORR_` nas `RuleId`.

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
    ├── report.html              ← Relatório visual completo
    ├── report.txt               ← Relatório texto (compartilhável)
    ├── evidence.json                  ← Todos os findings + dossiers em JSON
    ├── bamdam_60d.json                ← BAM/DAM — timestamps de execução (core)
    ├── prefetch_60d.json              ← Prefetch — evidência de execução (core)
    ├── knowncheats_60d.json           ← Known Cheats — hits diretos confirmados
    ├── registryartifacts_60d.json     ← Store, MuiCache, RecentDocs, 7-Zip, WinRAR
    ├── eventviewer_60d.json           ← Findings do Event Viewer (cobertura real)
    ├── defender_60d.json              ← Findings do Windows Defender
    ├── services_60d.json              ← Findings de Serviços
    ├── amcache_60d.json               ← Findings do Amcache
    ├── userassist_60d.json            ← Findings do UserAssist
    ├── shimcache_60d.json             ← Findings do ShimCache
    ├── lnk_60d.json                   ← Findings de LNK Recent
    ├── registrypersistence_60d.json   ← Findings de RegistryPersistence
    ├── ... (25 JSONs por módulo no total)
    ├── manifest.json                  ← Metadados completos + SHA256 de todos os arquivos
    └── manifest.sha256                ← Hash do manifest.json (verificável com sha256sum)
```

**Cobertura de log por arquivo `*_60d.json`:**

Cada arquivo tem campos:
```json
{
  "module": "Event Viewer",
  "lookbackDays": 60,
  "coverageDays": 45,
  "coverageOk": false,
  "oldestEvent": "2026-03-25T...",
  "newestEvent": "2026-05-09T...",
  "findingCount": 12,
  "findings": [...]
}
```

Se `coverageOk = false`, o Windows não tem 60 dias de log — o relatório avisa explicitamente.

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
  "lookbackDays": 60,
  "totalScore": 185,
  "overallRisk": "CRÍTICO",
  "files": {
    "report.html":    { "sha256": "...", "size": 123456 },
    "report.txt":     { "sha256": "...", "size": 45678 },
    "evidence.json":  { "sha256": "...", "size": 234567 },
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
1. Copiar `EchoNerfados.exe` para a máquina alvo
2. Para acesso completo (todos os módulos): clicar com botão direito → "Executar como administrador"
3. Sem elevação: módulos ShimCache, LNK Recent, RegistryPersistence, BAM/DAM, Prefetch etc. funcionam; Amcache e UserAssist são pulados (exigem acesso a hives offline)
4. Fazer login: `nerfados` / `admin`
5. Aguardar conclusão (2–10 min dependendo do hardware)
6. Pasta de resultados criada na área de trabalho

### Flags de linha de comando
```
EchoNerfados.exe [opções]
  -d, --drive <letra>     Drive a varrer (padrão: C:)
  -v, --verbose           Output detalhado
  --no-report             Não salva arquivos (apenas console)
  --no-memory             Desativa varredura de memória de processo
  --no-usn               Desativa USN Journal
  --lookback <dias>       Janela de análise em dias (padrão: 60)
  --investigator <nome>   Nome do investigador (aparece no relatório)
  --suspect <nome>        Nome do suspeito
  --case <id>             ID do caso
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
- [ ] Todos os 15+ módulos executam
- [ ] Amcache.hve carregado sem erro
- [ ] NTUSER.DAT de todos os perfis lidos

### 10.6 Saída de Arquivos
- [ ] Pasta timestamped criada na área de trabalho
- [ ] `report.html` abre no browser corretamente
- [ ] `report.txt` legível em qualquer editor
- [ ] `evidence.json` JSON válido
- [ ] Todos os 25 `*_60d.json` presentes + `evidence.json`, mesmo que vazios
- [ ] `manifest.json` presente e campos preenchidos
- [ ] `manifest.sha256` verificável com sha256sum

### 10.7 Cobertura de Log
- [ ] Em máquina com logs < 60 dias: `coverageOk: false` nos JSONs relevantes
- [ ] Aviso de cobertura aparece no HTML e TXT
- [ ] Em máquina com logs >= 60 dias: `coverageOk: true`

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

---

## 11. Limitações Conhecidas

| Limitação | Impacto | Status |
|-----------|---------|--------|
| **SRUM: dirty shutdown** | SRUDB.dat pode exigir recovery — tentadas 3 page sizes (32768/16384/8192); se todas falharem → PARCIAL | Comportamento esperado em máquinas com shutdown abrupto |
| **ManagedEsent NU1701** | ManagedEsent 1.9.4 é .NET Framework — compatível com net8.0 via shim, mas gera warning NU1701 | Funcional; migrar para parser ESE nativo .NET 8 em futura iteração |
| **ShimCache: formato Windows 7/8** | Parser fallback por UTF-16 — timestamps ausentes | Aceitável para Win10/11 |
| **UserAssist: somente HKCU do usuário atual** | Outros perfis lidos via offline hive (admin only) | Funcional |
| **Log < 60 dias** | `coverageOk: false` reportado mas scan continua | Investigador deve notar o aviso |
| **assemblyLocation vazio** | Em single-file app, `Assembly.Location` é sempre empty | `manifest.json` contém nota explicativa |
| **Assinatura digital** | manifest.sha256 não assinado por PKI | Requer setup de certificado (futuro) |
| **License key** | Login fixo (nerfados/admin) | Substituir por sistema de keys para comercialização |
| **ProcessMemoryModule** | Pode causar lentidão em máquinas com muitos processos | Desativar com `--no-memory` se necessário |
| **UserAssist PARCIAL para perfis de sistema** | NTUSER.DAT de "Usuário Padrão", "WsiAccount" e perfis similares é inacessível mesmo com admin | Comportamento esperado — perfis de sistema não têm NTUSER.DAT padrão. O finding PARCIAL é correto; confirmar que o perfil do usuário real foi lido. |
| **BAM/DAM PARCIAL sem admin** | ACL restrita em HKLM\SYSTEM\...\BAM em algumas configurações | SecurityException capturada → PARCIAL com motivo. Para cobertura completa, usar com admin. |

---

## 12. Smoke Test Interativo — Procedimento Obrigatório

O smoke test requer execução manual com console interativo real. Executar nas duas condições abaixo.

### CONDIÇÃO A — Sem elevação (duplo clique / terminal normal)

```
1. Copiar EchoNerfados.exe para a máquina alvo
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
- [ ] `report.html` abre no browser — seção "COBERTURA DA VARREDURA" visível
- [ ] `report.txt` — seção "COBERTURA DA VARREDURA" visível com status PULADO para Amcache/UserAssist
- [ ] `evidence.json` — JSON válido, parseable
- [ ] Todos os 25 `*_60d.json` presentes + `evidence.json` (26 arquivos no total)
- [ ] `manifest.json` — campo `"isElevated": false`
- [ ] `manifest.sha256` verifica: `sha256sum -c manifest.sha256` → OK

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
- [ ] `amcache_60d.json` — `findingCount > 0` (ou `findingCount: 0` + `coverageDays` preenchido)
- [ ] `userassist_60d.json` — idem
- [ ] `registrypersistence_60d.json` — presente
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

---

## 13. Build Reproducível

```bash
# Clonar e publicar
git clone <repo>
cd BypassNerfados
git checkout ddf0a09
dotnet publish src/Scanner/Scanner.csproj -p:PublishProfile=win-x64
```

**SHA256 do artefato entregue para QA (build ddf0a09 — 2026-05-10):**
```
293e44f493d135107ec67681593bcbb47074e5abc994e67211106d5f930bd72a
```

**Nota:** Este hash identifica o artefato `EchoNerfados.exe` gerado nesta sessão. Uma nova compilação a partir do mesmo commit **não produz o mesmo hash**: metadados de timestamp e GUID do PE variam por compilação. Para build realmente reproduzível é necessário configurar `<Deterministic>true</Deterministic>` no `.csproj` (fora do escopo desta release).

---

## 14. Sumário para QA

**O que está pronto e testável (build ddf0a09 — apto para smoke test interativo):**
- `--help` funciona sem login e sem console interativo (exit 0, seguro para pipe)
- Execução sem console retorna exit 1 com mensagem clara, nunca crasha
- `app.manifest asInvoker` — sem UAC forçado; admin por escolha do operador
- Login gate funcional com bloqueio após 3 tentativas (exit code 2)
- **22 módulos** cobrindo todos os principais artefatos forenses Windows
- Correlação cruzada entre módulos + artifact dossiers com bypass ±1h por sinal + correlação FiveM session (-30min/+2h)
- Exportação: HTML, TXT, **26 JSONs dedicados** (25 módulos + evidence.json)
- Manifesto criptograficamente verificável (`manifest.sha256`)
- Tabela "COBERTURA DA VARREDURA" no terminal, TXT e HTML com status Executed/Partial/Skipped/Failed
- Todos os catches críticos logam `LogPartialError` com contexto específico; inaccessible contados, não silenciados
- Executável self-contained (~34 MB), sem .NET no host
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
- **RecycleBin**: usa `config.EventWindowLookback` (não hardcoded 60 dias)
- **Timeline** — linha do tempo unificada Prefetch/BAM/LNK/Downloads/Temp
- **NvidiaArtifacts** — timestamps GPU de sessão FiveM via nvAppTimestamps
- **EventViewer**: todos os findings usam `"Event Viewer"` (com espaço) — eventviewer_60d.json preenchido corretamente
- **Defender**: todos os findings usam `Name` = `"Windows Defender"` — defender_60d.json preenchido corretamente
- **filesystem_60d.json** + **network_60d.json** adicionados ao EvidenceExporter
- **bamdam_60d.json**, **prefetch_60d.json**, **knowncheats_60d.json**, **registryartifacts_60d.json**, **usnjournal_60d.json**, **processmemory_60d.json** adicionados (26 JSONs no total)
- **4688**: query XPath inclui janela temporal `EventWindowLookback` — sem scan ilimitado
- **QueryDb**: falhas de sqlite3_open/prepare logadas via LogPartialError
- **IgnoreInaccessible**: KnownCheats e FileSystem usam EnumerationOptions ao invés de GetFiles+SearchOption

**Prioridade de teste:** Focar nos cenários 10.1, 10.2, 10.3, 10.4 — são os mais críticos para validar o produto. Os outros podem ser smoke test.

---

## Critérios de Aceite (próximo QA)

- [x] PC com NVIDIA limpo **não** gera Medium/High por nvAppTimestamps
- [x] `bypassstoragecheck` (correto) dispara no scan de scripts de LabConfig
- [x] Todos os 25 módulos aparecem em evidence.json + arquivos `*_60d.json` dedicados
- [x] Browser aberto durante o scan **não** quebra coleta (CopyLockedFile)
- [x] Nenhum ruleId com `GOSTH` fora de: `CHEAT_HASH_GOSTH_WHATSAPP`, `CHEAT_PATH_GOSTH_DXSETUP`, `GOSTH_PATTERN_SYSTEM32`
- [x] `SCRIPT_BATCHGOTADMIN_PRESENT` substitui `_EXECUTED` no ruleId
- [x] `manifest.sha256` verificável após scan completo
- [x] `eventviewer_60d.json` não vazio quando há eventos no período
- [x] `defender_60d.json` não vazio quando há eventos no período
- [x] `filesystem_60d.json` e `network_60d.json` exportados em todo scan
- [x] `bamdam_60d.json` e `prefetch_60d.json` exportados (core forense — sempre presentes)
- [x] `knowncheats_60d.json` e `registryartifacts_60d.json` exportados em todo scan
- [x] README reflete EchoNerfados.exe, publish\win-x64\, 22 módulos, multi-família

---

*Relatório gerado em: 2026-05-10 | Build: ddf0a09 | Echo Nerfados Shield XDR v1.0.0*
