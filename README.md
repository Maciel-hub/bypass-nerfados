# Bypass Nerfados Shield XDR

**Plataforma forense anti-cheat para investigação de screen-share em gaming.**

Scanner Windows local que automatiza a investigação de evidências de cheats (FiveM, GTA V, Minecraft e similares), gerando um relatório HTML + TXT com score de risco, timeline e cadeia de custódia básica.

> **Uso autorizado apenas.** Esta ferramenta é para uso defensivo em ambientes próprios ou com permissão formal. Não deve ser usada para evasão, limpeza de rastros ou qualquer finalidade ofensiva.

---

## Requisitos

| Requisito | Versão mínima |
|---|---|
| Windows | 10 / 11 (64-bit) |
| .NET SDK | 8.0 LTS |
| Permissão | Administrador local |

Instale o .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0

---

## Build

```bat
BUILD.bat
```

Ou manualmente:

```powershell
dotnet restore BypassNerfados.sln
dotnet build BypassNerfados.sln -c Release -o build\Release
```

O executável gerado fica em `build\Release\BypassNerfados.exe`.

---

## Uso

Execute **como Administrador**:

```
BypassNerfados.exe [opções]
```

### Opções

| Opção | Descrição | Padrão |
|---|---|---|
| `--investigator <nome>` | Nome do investigador (para o relatório) | — |
| `--suspect <nome>` | Nome do suspeito (para o relatório) | — |
| `--case-id <id>` | ID do caso/investigação | — |
| `--drive <letra>` | Drive a analisar | `C:` |
| `--output <caminho>` | Pasta de saída do relatório | Desktop |
| `--no-usn` | Pular análise do USN Journal | — |
| `--no-memory` | Pular análise de memória | — |
| `--no-report` | Não gerar arquivo de relatório | — |
| `--verbose` | Mostrar findings INFO também | — |
| `--help` | Exibir ajuda | — |

### Exemplos

```bat
:: Scan básico (relatório no Desktop)
BypassNerfados.exe

:: Com contexto de investigação
BypassNerfados.exe --investigator "Fulano" --suspect "Ciclano" --case-id "CASO-001"

:: Scan rápido sem análise de memória
BypassNerfados.exe --no-memory --no-usn

:: Salvar relatório em pasta específica
BypassNerfados.exe --output "C:\Investigacoes\2026"
```

---

## Módulos de detecção

| Módulo | O que verifica |
|---|---|
| **BAM/DAM** | Histórico de execução via registry (timestamp `!YYYY/MM/DD`) |
| **Prefetch** | Programas executados (pasta `C:\Windows\Prefetch`) |
| **USN Journal** | Arquivos `.exe` criados, deletados e renomeados no NTFS |
| **Windows Defender** | Detecções (IDs 1116, 1117) e config alterada (ID 5007) |
| **Registry Artifacts** | Store (PCA), MuiCache, RecentDocs, 7-Zip, WinRAR, MountedDevices |
| **Event Viewer** | IDs: 1102, 104, 3079, 4616, 4688, 4698, 7045 |
| **Known Cheats** | GOSTH, FarinhaFree, d3d10.dll, WhatsApp Installer falso, PSReadLine |
| **Process Memory** | Hollowing, shellcode, APC — regiões PAGE_EXECUTE_READWRITE privadas |
| **Network** | Conexões TCP ativas por processo; cheats com tráfego ativo |
| **File System** | Lixeira, Temp, Downloads, CrashDumps, AppData, FiveM Plugins |
| **System Info** | Data de instalação, DMA Protection, VM detection, dispositivos PCIe |
| **Services** | BAM, EventLog, Defender, PCA, DPS, WinFirewall, WSC |
| **Correlação** | Padrões cross-módulo: anti-forense, burst temporal, cheat+ocultação |

---

## Cheats conhecidos (banco de dados embutido)

| Cheat | Executável | Indicadores |
|---|---|---|
| **GOSTH** | `launcher.exe` | BAM, Defender, Store (PCA), Nvidia Panel; gera arquivo de 8-10 chars na System32 |
| **FarinhaFree** | `farinhafree.exe` | SHA1: `53f9c024f03c007ce1db49a02b2db39d35e340b2` |
| **GOSTH Loader** | `WhatsApp Installer.exe` | Em `System32\WinBioDatabase`; SHA1: `a7d04fdbc41fe2165a4cbc8e0657052ec3fb334f` |
| **GOSTH dxsetup** | `dxsetup.exe` | Em `AppData\Local\Programs\Common` |
| **d3d10.dll** | `d3d10.dll` | FiveM Plugins, ~1MB |

---

## Score de risco

| Score | Nível | Significado |
|---|---|---|
| 0 | Limpo | Sem indicadores |
| 1–25 | Baixo | Registrar e monitorar |
| 26–50 | Médio | Revisar com contexto |
| 51–75 | Alto | Investigar, coletar evidências |
| 76–100 | Crítico | Prioridade máxima |

---

## Saída

O scanner gera dois arquivos no Desktop (ou `--output`):

- `Bypass_Nerfados_MAQUINA_YYYYMMDD_HHMMSS.html` — relatório visual dark theme
- `Bypass_Nerfados_MAQUINA_YYYYMMDD_HHMMSS.txt` — texto para documentação

O código de saída do processo reflete o risco: `0` (limpo) → `4` (crítico).

---

## Roadmap

- [x] Sprint 0 — Scanner CLI local, módulos core, relatório HTML
- [x] Sprint 1 — Correções P0 de build e bugs críticos
- [ ] Sprint 2 — Janela temporal, confidence score, deduplicação de findings
- [ ] Sprint 3 — `evidence-manifest.json`, SHA256 em evidências, `CaseId`
- [ ] Sprint 4 — Agente Windows como serviço + API de ingestão
- [ ] Sprint 5 — Dashboard (Next.js), timeline unificada, tela de alertas

---

## Licença e ética

- Uso exclusivamente defensivo e em ambientes autorizados.
- A ferramenta não executa evasão, bypass, limpeza de rastros ou ações ofensivas.
- Todo acesso a artefatos deve ser auditável e vinculado a um responsável.
