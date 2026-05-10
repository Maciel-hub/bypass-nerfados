# Echo Nerfados Shield XDR

**Plataforma forense anti-cheat para investigação de screen-share em gaming.**

Scanner Windows local que automatiza a coleta e análise de artefatos forenses de cheats (FiveM, GTA V e similares), gerando relatório HTML + TXT com score de risco, timeline unificada, 21 JSONs por módulo e manifesto criptográfico de cadeia de custódia.

> **Uso autorizado apenas.** Esta ferramenta é para uso exclusivamente defensivo, em ambientes próprios ou com permissão formal documentada. Não deve ser usada para evasão, limpeza de rastros ou qualquer finalidade ofensiva.

---

## Requisitos

| Requisito | Versão mínima |
|---|---|
| Windows | 10 / 11 (64-bit) |
| .NET SDK | 8.0 LTS (apenas para build; o executável publicado é self-contained) |
| Permissão | Administrador local recomendado |

---

## Build

```powershell
dotnet publish src\Scanner\Scanner.csproj /p:PublishProfile=win-x64
```

O executável self-contained (~34 MB, sem .NET instalado no host) fica em:

```
publish\win-x64\EchoNerfados.exe
```

---

## Uso

Execute **como Administrador**:

```
EchoNerfados.exe [opções]
```

### Opções

| Opção | Descrição | Padrão |
|---|---|---|
| `--investigator <nome>` | Nome do investigador (para o relatório) | — |
| `--suspect <nome>` | Nome do suspeito (para o relatório) | — |
| `--case-id <id>` | ID do caso/investigação | — |
| `--drive <letra>` | Drive alvo para o USN Journal | `C:` |
| `--output <caminho>` | Pasta de saída do relatório | Desktop |
| `--no-usn` | Pular análise do USN Journal | — |
| `--no-memory` | Pular análise de memória de processos | — |
| `--no-report` | Não gravar arquivos de relatório | — |
| `--verbose` | Exibir também findings de nível INFO | — |
| `--help` | Exibir ajuda | — |

> **Nota sobre `--drive`:** afeta apenas o módulo USN Journal. Os demais módulos analisam o sistema a partir do caminho padrão do Windows (variáveis de ambiente, registry, AppData, etc.).

### Exemplos

```bat
:: Scan básico (relatório gerado no Desktop)
EchoNerfados.exe

:: Com contexto de investigação
EchoNerfados.exe --investigator "Fulano" --suspect "Ciclano" --case-id "CASO-001"

:: Scan rápido sem módulos opcionais
EchoNerfados.exe --no-memory --no-usn

:: Salvar relatório em pasta específica
EchoNerfados.exe --output "C:\Investigacoes\2026"
```

---

## Módulos de detecção

22 módulos core + 2 opcionais (requerem Administrador) + 2 opcionais por flag:

| Módulo | O que verifica |
|---|---|
| **System Info** | Instalação do Windows, DMA Protection, VM detection, dispositivos PCIe |
| **BAM/DAM** | Histórico de atividade de processos em background (timestamps de execução) |
| **Prefetch** | Execução de processos via `.pf` (últimas 128 entradas, include run count) |
| **Registry Artifacts** | Store (PCA), MuiCache, RecentDocs, 7-Zip/WinRAR, MountedDevices |
| **Event Viewer** | IDs críticos: 1102, 104, 3079, 4616, 4688, 4698, 4699, 7045 + cobertura de logs |
| **Windows Defender** | Detecções (1116–1119), config alterada (5007), status via registry |
| **Known Cheats** | Hashes SHA1/SHA256, caminhos e padrões de famílias conhecidas de cheats |
| **File System** | Temp, Downloads, CrashDumps, AppData, FiveM Plugins — arquivos suspeitos |
| **Network Usage** | Histórico de redes Wi-Fi conectadas |
| **Services** | Serviços com nomes suspeitos instalados via SCM |
| **ShimCache** | AppCompatCache — indício de carregamento de executáveis (inclusive deletados) |
| **LNK Recent** | Atalhos recentes — acesso a arquivos e pastas com timestamp |
| **Registry Persistence** | IFEO, AppInit_DLLs, Winlogon, BootExecute — persistência sem instalador |
| **System Reset/Restore** | Reinstalação, reset e restauração do Windows — perda de cobertura forense |
| **System Tampering** | LabConfig/MoSetup bypass (Win11), BatchGotAdmin, scripts de elevação UAC |
| **Browser Downloads** | Downloads Chrome/Edge/Brave/Opera/Firefox — executáveis e URLs suspeitos |
| **ShellBags** | Histórico de navegação de pastas (acesso a diretórios mesmo após deleção) |
| **Jump Lists** | Histórico de acesso recente por aplicação — executáveis e caminhos suspeitos |
| **NVIDIA Artifacts** | Strings suspeitas em artefatos do driver NVIDIA (detecção por conteúdo) |
| **External Tool Residue** | Prefetch de ferramentas de análise/tampering: Process Hacker, x64dbg, CheatEngine, etc. |
| **Recycle Bin** | Lixeira — caminho original e data de deleção de arquivos suspeitos |
| **Timeline** | Linha do tempo unificada: Prefetch, BAM, LNK, Downloads, Temp |
| **SRUM** | Uso de rede por processo via SRUDB.dat (~30–60 dias) |
| **Amcache** *(Admin)* | SHA1 de executáveis e detecção de execução pós-deleção |
| **UserAssist** *(Admin)* | Histórico de execuções via Explorer (NTUSER.DAT) |
| **USN Journal** *(Admin + flag)* | Operações NTFS de baixo nível: criação, deleção, renomeação |
| **Process Memory** *(Admin + flag)* | Strings suspeitas em memória de processos ativos |

---

## Famílias de cheats detectadas

O banco de dados embutido cobre múltiplas famílias com combinações de hash SHA1/SHA256, nome de arquivo, caminho e padrões de string:

| Família | Indicadores principais |
|---|---|
| **GOSTH** | `launcher.exe`, hash WhatsApp Installer falso, `dxsetup.exe` em AppData, padrão System32 (8–10 chars) |
| **Foxee / Echo Bypass** | `foxee69`, `echo-bypass-fivem` em downloads e paths |
| **RedEngine / Cherax / Susano** | Nomes de executável, URLs de download, keywords em memória |
| **CheatEngine / x64dbg** | Prefetch e registry residues de ferramentas de reverse engineering |
| **Genérico** | `spoofer`, `hwid`, `injector`, `loader`, `bypass`, `trainer` em paths suspeitos |

---

## Score de risco

| Score | Nível | Significado |
|---|---|---|
| 0 | Limpo | Sem indicadores detectados |
| 1–25 | Baixo | Registrar e monitorar |
| 26–50 | Médio | Revisar com contexto |
| 51–75 | Alto | Investigar e coletar evidências |
| 76–100 | Crítico | Prioridade máxima de escalação |

---

## Saída

Cada execução cria uma pasta timestamped no Desktop (ou `--output`):

```
Echo_Nerfados_{MAQUINA}_{YYYYMMDD_HHMMSS}/
├── report.html          # Relatório visual (dark theme, score, timeline, artifact dossiers)
├── report.txt           # Texto para documentação e e-mail
├── evidence.json        # Todos os findings + módulos + bundles (JSON estruturado)
├── eventviewer_60d.json
├── defender_60d.json
├── amcache_60d.json
├── ... (21 JSONs por módulo, sempre gerados mesmo quando vazios)
└── manifest.sha256      # Hash SHA256 de todos os arquivos — cadeia de custódia
```

O código de saída reflete o risco: `0` (limpo/baixo) → `3` (crítico).

---

## Roadmap

- [x] Core: 22 módulos forenses + 4 opcionais, score de risco, deduplicação, correlação cross-módulo
- [x] Relatório: HTML dark theme, TXT, 21 JSONs por módulo, manifesto SHA256
- [x] Artifact dossiers: bypass window ±1h por sinal + correlação FiveM session (-30min/+2h)
- [x] Cobertura: tabela Executed/Partial/Skipped/Failed no terminal, TXT e HTML
- [x] SRUM: uso de rede por processo via SRUDB.dat (ManagedEsent)
- [x] Firefox: downloads via `places.sqlite` sem dependências externas
- [ ] Sprint próxima: servidor de API de ingestão + dashboard (Next.js) + alertas em tempo real
- [ ] Assinatura digital do manifesto (Ed25519)
- [ ] Integração com MITRE ATT&CK (mapeamento de findings para técnicas)

---

## Licença e ética

- Uso exclusivamente defensivo e em ambientes autorizados.
- A ferramenta não executa evasão, bypass, limpeza de rastros ou ações ofensivas.
- Todo acesso a artefatos deve ser auditável e vinculado a um responsável identificado.
