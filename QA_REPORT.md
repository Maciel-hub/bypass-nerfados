# Echo Nerfados Shield XDR — Relatório de QA
**Versão:** 1.0.0+e4efd75  
**Build:** e4efd75 → pós-QA (2026-05-09)  
**Arquivo:** `publish\win-x64\EchoNerfados.exe`  
**SHA256:** `f4228ff50fd1480667ffa3db0dd5aeb8def246da23cc0687ab1bd826c846a76e`  
**Tamanho:** ~34 MB (self-contained, sem dependência de .NET no host)

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

## 4. Módulos de Varredura (15 módulos)

### Módulos sem requisito de admin (funcionam com asInvoker)

| Módulo | Artefato | O que detecta |
|--------|----------|---------------|
| **System Info** | WMI | Nome da máquina, usuário, OS, BIOS |
| **BAM/DAM** | HKLM\SYSTEM\...\BAM | Histórico de execução (Background Activity Monitor) — últimos ~7 dias |
| **Prefetch** | C:\Windows\Prefetch\*.pf | Histórico de execução por nome de arquivo; nome da entry = nome do processo |
| **Registry Artifacts** | HKLM run keys + MRU | Execuções recentes, autoruns em registry |
| **Event Viewer** | Security/System/Application logs | Logons (4624), falhas (4625), serviços instalados (7045), Defender alerts, cobertura de log |
| **Windows Defender** | Event log + MPLog | Detecções, exclusões, deleções de definição, reconfiguração |
| **Known Cheats** | File system scan | Varredura de nomes conhecidos de cheat nos drives especificados |
| **File System** | Paths suspeitos | Arquivos em AppData\Roaming, Temp, Downloads com nomes/extensões suspeitos |
| **Network Usage** | HKCU\...\NetworkList | Redes Wi-Fi conectadas; rede com nome de cheat = High |
| **Services** | SCM + Event 7045 | Serviços instalados com nomes suspeitos ou por publishers não-Microsoft |
| **ShimCache** | HKLM AppCompatCache | Histórico de carregamento de executáveis pelo kernel — sobrevive a reboots |
| **LNK Recent** | %APPDATA%\...\Recent + AutomaticDestinations | Atalhos de arquivos recentemente acessados → evidência de abertura de arquivos |
| **RegistryPersistence** | IFEO, AppInit_DLLs, AppCertDlls, Winlogon, BootExecute, Run keys | Técnicas de persistência e hijack de processo |

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
    ├── evidence.json            ← Todos os findings + dossiers em JSON
    ├── eventviewer_60d.json     ← Findings do Event Viewer (cobertura real)
    ├── defender_60d.json        ← Findings do Windows Defender
    ├── services_60d.json        ← Findings de Serviços
    ├── amcache_60d.json         ← Findings do Amcache
    ├── userassist_60d.json      ← Findings do UserAssist
    ├── shimcache_60d.json       ← Findings do ShimCache
    ├── lnk_60d.json             ← Findings de LNK Recent
    ├── registrypersistence_60d.json ← Findings de RegistryPersistence
    ├── manifest.json            ← Metadados completos + SHA256 de todos os arquivos
    └── manifest.sha256          ← Hash do manifest.json (verificável com sha256sum)
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
- [ ] Todos os `*_60d.json` presentes (incluindo `registrypersistence_60d.json`), mesmo que vazios
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
| **SRUM não implementado** | Histórico de uso de rede/CPU por processo (~30 dias) não coletado | Previsto para sprint futuro |
| **ShimCache: formato Windows 7/8** | Parser fallback por UTF-16 — timestamps ausentes | Aceitável para Win10/11 |
| **UserAssist: somente HKCU do usuário atual** | Outros perfis lidos via offline hive (admin only) | Funcional |
| **Log < 60 dias** | `coverageOk: false` reportado mas scan continua | Investigador deve notar o aviso |
| **assemblyLocation vazio** | Em single-file app, `Assembly.Location` é sempre empty | `manifest.json` contém nota explicativa |
| **Assinatura digital** | manifest.sha256 não assinado por PKI | Requer setup de certificado (futuro) |
| **License key** | Login fixo (nerfados/admin) | Substituir por sistema de keys para comercialização |
| **ProcessMemoryModule** | Pode causar lentidão em máquinas com muitos processos | Desativar com `--no-memory` se necessário |

---

## 12. Build Reproducível

```bash
# Clonar e publicar
git clone <repo>
cd BypassNerfados
git checkout e4efd75
.\publish.ps1

# Verificar hash do resultado
# SHA256 esperado: f835ee2f9806dc14c684ac2e745b6e7a0e75bde932500f920cdd4feb6082e796
```

**Nota:** O hash do EXE varia com cada build (metadados de timestamp no PE). O hash acima é da build de referência `e4efd75` gerada em 2026-05-09.

---

## 13. Sumário para QA

**O que está pronto e testável:**
- `--help` funciona sem login e sem console interativo (exit 0)
- Execução sem console retorna exit 1 com mensagem clara, nunca crasha
- `app.manifest asInvoker` — sem UAC forçado; admin por escolha do operador
- Login gate funcional com bloqueio por tentativas
- 15 módulos de varredura cobrindo todos os principais artefatos forenses Windows
- Correlação cruzada entre módulos
- Artifact dossiers com bypass temporal window corrigido (±1h por sinal)
- Exportação completa: HTML, TXT, **8 JSONs de cobertura** (incluindo `registrypersistence_60d.json`), evidence.json
- Manifesto criptograficamente verificável (SHA256)
- Executável self-contained (~34 MB), sem .NET no host
- AppInit_DLLs distingue ativo vs. inativo via `LoadAppInit_DLLs`
- LNK parser suporta `LocalBasePathUnicode` (caminhos Unicode)
- Amcache/ShimCache com linguagem forense calibrada ("presença/indício", não "execução confirmada")

**Prioridade de teste:** Focar nos cenários 9.1, 9.2, 9.3, 9.4 — são os mais críticos para validar o produto. Os outros podem ser smoke test.

---

*Relatório gerado em: 2026-05-09 | Build: e4efd75 | Echo Nerfados Shield XDR v1.0.0*
