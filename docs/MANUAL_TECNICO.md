# Echo Nerfados Shield XDR — Manual Técnico Interno

**Versão:** 1.0.0  
**Classificação:** Uso interno — equipe de investigação  
**Plataforma:** Windows 10/11 x64  

---

## 1. O que é o Echo Nerfados Shield XDR

Echo Nerfados Shield XDR é um scanner forense anti-cheat para servidores FiveM (GTA V Multiplayer). Ele coleta e correlaciona evidências digitais de uma máquina Windows para determinar se há indicadores de uso de cheat, ferramentas de bypass e tentativas de apagar rastros.

O programa **não é invasivo nem destrutivo**: apenas lê artefatos do sistema (registros, logs, arquivos de histórico) que o Windows mantém normalmente. Não instala drivers, não injeta em processos e não modifica o sistema.

---

## 2. Componentes

| Arquivo | Função |
|---|---|
| `EchoNerfados.exe` | CLI — varredura headless, linha de comando |
| `EchoNerfados.App.exe` | GUI — interface gráfica para uso em campo |
| `EchoNerfadosSetup-RC-*.exe` | Installer para distribuição interna |

O installer coloca ambos os executáveis em `%ProgramFiles%\Echo Nerfados`. A GUI é o ponto de entrada recomendado para uso em campo.

---

## 3. Requisitos

- Windows 10 ou Windows 11 (x64)
- **Conta Administrador recomendada** — vários módulos precisam de privilégio elevado para acessar Prefetch, USN Journal, Security Event Log e memória de processos
- Sem dependência de .NET externo — o runtime está embutido (self-contained)
- Sem licença para esta build — modo teste ativo (`EnforceLicense = false`)

---

## 4. Instalação

1. Executar `EchoNerfadosSetup-RC-*.exe` como Administrador
2. Seguir o assistente (instalação padrão em `C:\Program Files\Echo Nerfados`)
3. O atalho "Echo Nerfados Shield XDR" na área de trabalho abre a GUI
4. Para uso em linha de comando: abrir terminal como Administrador e chamar `EchoNerfados.exe`

---

## 5. Modos de Varredura

| Modo | Flag CLI | Descrição |
|---|---|---|
| **Completo** | *(padrão)* | Todos os módulos, janela de 30 dias |
| **Rápido** | `--profile fast` | Módulos core sem memória/USN/drivers — usado para triagem |
| **Profundo** | `--profile deep` | Igual ao FiveM + memória de processo completa |
| **FiveM** | `--profile fivem` | Otimizado para investigação FiveM — todos os módulos forenses + memória |
| **Florence** | `--profile florence` | Modo conservador — exige ≥2 módulos confirmando a mesma entidade antes de elevar risco |

> **Recomendação de campo:** usar **FiveM** com Administrador para investigações completas.

---

## 6. Módulos de Detecção

### 6.1 Evidência de Execução

| Módulo | O que detecta |
|---|---|
| **BAM/DAM** | Background Activity Monitor — histórico de execução de processos dos últimos 30 dias no registro |
| **Prefetch** | Arquivos `.pf` em `C:\Windows\Prefetch` — confirma execução de programas mesmo após deleção |
| **ShimCache** | AppCompatCache — registro de executáveis carregados (inclui pós-deleção) |
| **Amcache** | SHA1 de executáveis — detecta arquivos que não existem mais no disco |
| **UserAssist** | Contadores de execução via Explorer (NTUSER.DAT) |
| **LNK Recent** | Atalhos `.lnk` de arquivos abertos recentemente |
| **Jump Lists** | Histórico por aplicação — arquivos recentemente abertos por programa |
| **Timeline** | Linha do tempo unificada cruzando Prefetch, BAM, LNK, Downloads e Temp |

### 6.2 Cheats Conhecidos

| Módulo | O que detecta |
|---|---|
| **Known Cheats** | Arquivos de cheat por nome exato (`farinhafree.exe`, `eulen.exe`, `redengine.exe`, etc.) e hash SHA1 em disco |
| **File System** | Executáveis suspeitos em Desktop, Downloads, AppData, Temp por nome e palavra-chave |
| **RedENGINE Artifacts** | Configurações específicas do executor redENGINE (FiveM) — `settings.cock`, menus `.lua`, `imgui.ini` |

### 6.3 Anti-Forense

| Módulo | O que detecta |
|---|---|
| **USN Journal** | Diário NTFS — cheats criados/deletados/renomeados; deleção de `.evtx`, `.lnk`, JumpLists; limpeza em massa de arquivos |
| **Anti-Forensic Scripts** | Scripts `.py/.bat/.cmd/.ps1/.vbs` com padrões de limpeza (wevtutil, reg delete, ClearMyTracks, prefetch wipe); domínios C2 conhecidos (`api.tzproject.com`, `lmarket.fr`, `ovix.one`) |
| **Event Viewer** | Log Security limpo (1102), Log System limpo (104), wevtutil cl (4688), fsutil usn delete (4688), rundll32 ClearMyTracks (4688), reg delete em chaves forenses (4688), script python anti-echo (4688) |

### 6.4 Tampering de Sistema

| Módulo | O que detecta |
|---|---|
| **System Tampering** | Bypass Windows 11 (LabConfig/MoSetup), BatchGotAdmin, VulnerableDriverBlocklistEnable=0 |
| **System Reset/Restore** | Reset do Windows, restauração, reinstalação — perda de cobertura forense |
| **Registry Artifacts** | Autoruns, Run keys, serviços suspeitos |
| **Registry Persistence** | IFEO, AppInit DLLs, Winlogon, BootExecute |
| **Services** | Serviços instalados com nomes suspeitos |
| **Driver & Kernel** | Drivers não assinados, caminhos suspeitos, instalados recentemente |

### 6.5 Memória (requer Administrador + perfil Deep/FiveM)

| Módulo | O que detecta |
|---|---|
| **Process Memory** | Strings suspeitas em memória de processos em execução |
| **Memory DLL Trace** | DLLs carregadas, manual map, módulos ocultos, regiões executáveis sem backing em processos FiveM/GTA |
| **Memory String Scan** | Strings de famílias de cheat conhecidas em memória de FiveM/GTA V |

### 6.6 Rede e Ambiente

| Módulo | O que detecta |
|---|---|
| **Network** | Histórico de redes Wi-Fi conectadas — correlação com locais de uso |
| **SRUM** | Uso de rede por processo (SRUDB.dat, ~30–60 dias) |
| **Windows Defender** | Alertas de ameaça, exclusões suspeitas, Defender desabilitado |
| **System Info** | Informações da máquina — base para Machine ID e contexto do laudo |
| **NVIDIA Artifacts** | Timestamps de sessão GPU — confirma execução de jogo na sessão investigada |

### 6.7 Artefatos Adicionais

| Módulo | O que detecta |
|---|---|
| **Browser Downloads** | Downloads do Chrome/Edge/Brave/Opera/Firefox — executáveis e URLs suspeitos |
| **ShellBags** | Histórico de navegação de pastas — pastas suspeitas visitadas mesmo após deleção |
| **Recycle Bin** | Caminho original e data de deleção de arquivos na lixeira |
| **External Tool Residue** | Process Hacker, CheatEngine, x64dbg, Everything, Wireshark e similares no Prefetch |

---

## 7. Sistema de Score

Cada finding tem um nível de risco:

| Nível | Descrição |
|---|---|
| **Critical** | Evidência direta e forte de cheat ou anti-forense agressivo |
| **High** | Indicador forte — exige correlação para conclusão |
| **Medium** | Indício — sozinho não é suficiente |
| **Low** | Nota para investigador |
| **Info** | Registro informativo (ex: ferramenta de auditoria externa) |

O score final (0–100) pondera os findings por categoria e nível, com cap por categoria para evitar inflação. O rótulo de risco geral é:

| Score | Rótulo |
|---|---|
| 0 | Limpo |
| 1–15 | Baixo Risco |
| 16–35 | Risco Moderado |
| 36–60 | Risco Elevado |
| 61–80 | Alto Risco |
| 81–100 | Crítico |

---

## 8. Saídas do Scan

Todos os artefatos são salvos em `%ProgramData%\EchoNerfados\Reports\<timestamp>\`:

| Arquivo | Conteúdo |
|---|---|
| `report.html` | Relatório principal — todos os findings, score, cobertura por módulo |
| `report_executive.html` | Sumário executivo — conclusão, score, Machine ID |
| `report.txt` | Versão texto do relatório (para cópia e envio por mensagem) |
| `evidence.json` | Todos os findings em JSON estruturado (para análise programática) |
| `manifest.json` | Metadados de cadeia de custódia — versão, machine ID, hash de todos os arquivos |
| `manifest.sha256` | Hash do manifest para verificação de integridade |
| `machine_id.txt` | Machine ID + metadados da máquina |
| `bamdam_30d.json` | Findings do módulo BAM/DAM |
| `prefetch_30d.json` | Findings do módulo Prefetch |
| `eventviewer_30d.json` | Findings do Event Viewer |
| `antiforensicscripts_30d.json` | Findings de scripts anti-forense |
| *(demais módulos)* | Um arquivo JSON por módulo |

> A pasta de relatório completa deve ser enviada para o investigador — não apenas o `report.html`.

---

## 9. Uso em Campo (Passo a Passo)

1. **Instalar** o `EchoNerfadosSetup-RC-*.exe` na máquina investigada como Administrador
2. **Abrir** o "Echo Nerfados Shield XDR" pela área de trabalho
3. Preencher **Suspeito**, **Investigador** e **Caso** (opcional, aparecem no relatório)
4. Selecionar perfil **FiveM** e clicar **Iniciar Varredura**
5. Aguardar a varredura (3–8 minutos dependendo do hardware e perfil)
6. Ao concluir, clicar **Abrir Pasta do Relatório**
7. Compactar a pasta completa e enviar para análise

### Dica para máquinas sem internet
O installer é auto-suficiente — não precisa de conexão para instalar nem para escanear.

### Dica para cobertura máxima
Executar **com conta Administrador** garante acesso a Prefetch, USN Journal, Security Event Log e módulos de memória. Sem Admin, esses módulos são ignorados e a cobertura cai significativamente.

---

## 10. Interpretação de Resultados

### Score ≥ 61 (Alto Risco / Crítico)
Múltiplas fontes independentes confirmando a mesma entidade. Cheat ou anti-forense coordenado.  
**Ação:** Banir com laudo — encaminhar a pasta de relatório completa.

### Score 36–60 (Risco Elevado)
Indicadores significativos mas ainda requerendo correlação manual.  
**Ação:** Revisão pelo investigador antes de decisão. Verificar os findings High/Critical individualmente.

### Score 16–35 (Risco Moderado)
Indícios presentes mas fracos. Pode ser comportamento legítimo (ferramentas de dev, bypass Windows 11 para hardware antigo).  
**Ação:** Contexto da conta do jogador + revisão dos findings específicos.

### Score 0–15 (Baixo / Limpo)
Sem evidência material de cheat. Máquina provavelmente limpa.  
**Ação:** Nenhuma.

---

## 11. Limitações Conhecidas

| Limitação | Impacto |
|---|---|
| Sem licença por Machine ID (modo teste) | Build liberada — qualquer máquina roda sem licença. Licenciamento por machine será ativado na versão comercial. |
| Sem obfuscação de código | Assemblies podem ser inspecionados por engenharia reversa. Obfuscação programada para sprint seguinte. |
| Regras não encriptadas | `rules/` pode ser lida por terceiros. Encriptação AES-GCM programada para sprint seguinte. |
| Módulos de memória bloqueados sem Admin | Processo FiveM em memória não é varrido se a conta não for Administrador. |
| CLI não executa com stdout/stderr redirecionado | Impede automação direta via script — use a pasta de relatório como saída. |

---

## 12. Suporte Interno

Para dúvidas sobre findings específicos, encaminhar a pasta de relatório completa (incluindo todos os `.json`) para o responsável técnico. Não enviar apenas o `report.html` — os arquivos JSON contêm evidências que o HTML não exibe na íntegra.
