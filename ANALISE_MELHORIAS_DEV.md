# Analise tecnica e plano de melhorias - Bypass/Nerfados Shield XDR

## Resumo executivo

O projeto atual e um scanner local em C#/.NET para Windows, com interface CLI via Spectre.Console e modulos para Event Viewer, Defender, BAM/DAM, Prefetch, USN Journal, arquivos, processos, memoria, rede e relatorios HTML/TXT.

O documento tecnico incluido no projeto descreve um produto defensivo maior, "Nerfados Shield XDR", com agente Windows, backend, dashboard, API de ingestao, timeline unificada, cadeia de custodia e armazenamento de evidencias. O codigo atual ainda esta no nivel de MVP/PoC local: nao ha backend, agente como servico, testes, CI/CD, lockfile, README operacional, cadeia de custodia ou validacao forense forte.

Prioridade para o dev: primeiro fazer o projeto compilar de forma reproduzivel, corrigir falsos negativos/positivos obvios nos coletores, reduzir riscos de execucao como administrador, e depois evoluir a arquitetura para evidencias auditaveis.

## Escopo analisado

- Solucao: `BypassNerfados.sln`
- Projeto principal: `src/Scanner/Scanner.csproj`
- Codigo C#: 18 arquivos, cerca de 3164 linhas
- Documento tecnico: `Nerfados_Shield_XDR_Documento_Tecnico_Completo.docx`
- Ambiente local: sem Git inicializado; `dotnet` e `msbuild` nao encontrados no PATH; `rg` do ambiente falhou por acesso negado.

## Validacao executada

- Mapeamento de estrutura e arquivos.
- Leitura do `.sln`, `.csproj`, `BUILD.bat`, documento tecnico e todos os modulos C#.
- Revisao estatica de erros de compilacao provaveis, bugs de logica, riscos de seguranca, falsos positivos, lacunas de arquitetura e lacunas frente ao documento tecnico.
- Pesquisa externa em fontes oficiais/Microsoft/NuGet sobre .NET, NuGet Audit, lockfile, ServiceController e Spectre.Console.

Nao foi possivel executar `dotnet restore`, `dotnet build` ou `dotnet test` porque o SDK .NET nao esta instalado ou nao esta no PATH da maquina.

## Achados P0 - bloqueiam build, confiabilidade ou seguranca

### P0.1 - `ServiceControllerStatus.Disabled` nao existe

**Arquivo:** `src/Scanner/Modules/ServiceCheckModule.cs:42`

O codigo compara:

```csharp
status == ServiceControllerStatus.Disabled;
```

Porem o enum `ServiceControllerStatus` contem estados como `Stopped`, `StartPending`, `StopPending`, `Running`, `ContinuePending`, `PausePending` e `Paused`; nao existe `Disabled`. Isso tende a quebrar a compilacao.

**Impacto:** build falha ou, se corrigido parcialmente, o modulo de servicos pode continuar sem detectar servicos desabilitados.

**Correcao sugerida:**

- Usar `sc.Status` para estado atual (`Stopped`, `Running`, etc.).
- Usar `sc.StartType` para tipo de inicializacao e comparar com `ServiceStartMode.Disabled`.
- Garantir referencia explicita ao pacote `System.ServiceProcess.ServiceController`.

Exemplo conceitual:

```csharp
bool isStopped = sc.Status == ServiceControllerStatus.Stopped;
bool isDisabled = sc.StartType == ServiceStartMode.Disabled;
```

### P0.2 - Dependencia de `System.ServiceProcess.ServiceController` nao declarada

**Arquivo:** `src/Scanner/Scanner.csproj`

O projeto usa `System.ServiceProcess.ServiceController`, mas o `.csproj` so declara `Spectre.Console`. Em .NET moderno, o `ServiceController` fica no assembly/pacote `System.ServiceProcess.ServiceController`.

**Impacto:** erro de compilacao provavel em ambiente limpo.

**Correcao sugerida:**

Adicionar ao `.csproj`:

```xml
<PackageReference Include="System.ServiceProcess.ServiceController" Version="10.0.7" />
```

Se o projeto permanecer em `net8.0-windows`, tambem e aceitavel fixar uma linha 8.x, mas a equipe deve padronizar a estrategia de versao.

### P0.3 - Execucao via `cmd.exe /c` com argumento de drive sem validacao

**Arquivos:** `src/Scanner/Modules/UsnJournalModule.cs:130`, `src/Scanner/Core/ScanConfig.cs`, `src/Scanner/Program.cs`

`--drive` vem do usuario e e interpolado em comando shell:

```csharp
fsutil usn readjournal {drive} csv | findstr ...
```

Como o processo roda elevado, qualquer argumento de entrada usado em `cmd.exe /c` precisa ser tratado como perigoso.

**Impacto:** risco de execucao indevida de comandos caso a entrada seja malformada, alem de fragilidade operacional.

**Correcao sugerida:**

- Validar `TargetDrive` com allowlist estrita: `^[A-Za-z]:$`.
- Evitar pipeline em `cmd.exe`; chamar `fsutil.exe` diretamente com `ProcessStartInfo.ArgumentList`.
- Fazer o filtro de saida em C# em vez de `findstr`.
- Registrar erro claro quando o drive for invalido.

### P0.4 - `RunCmd` tem timeout inefetivo e pode travar

**Arquivo:** `src/Scanner/Modules/BaseModule.cs:54-73`

O metodo chama `ReadToEnd()` antes de `WaitForExit(timeoutMs)`. Se o processo nao encerrar, `ReadToEnd()` bloqueia indefinidamente. Alem disso, `stderr` e redirecionado mas nunca lido, o que pode bloquear se o buffer encher.

**Impacto:** scanner pode travar em `fsutil`, `netstat`, `pnputil` ou qualquer comando externo; timeout nao protege o usuario.

**Correcao sugerida:**

- Usar leitura assincrona de stdout/stderr.
- Aplicar `CancellationTokenSource`.
- Matar o processo em timeout.
- Retornar objeto estruturado com `ExitCode`, `Stdout`, `Stderr`, `TimedOut`, duracao e comando sanitizado.

### P0.5 - Parser de Prefetch adiciona `.exe` duas vezes e perde deteccoes

**Arquivo:** `src/Scanner/Modules/PrefetchModule.cs:39-51`

Arquivos Prefetch normalmente seguem formato como `APP.EXE-HASH.pf`. O codigo extrai `launcher.exe` e depois consulta `launcher.exe.exe`:

```csharp
if (CheatDatabase.KnownExecutables.TryGetValue(exeName + ".exe", out var cheatInfo))
```

**Impacto:** falsos negativos em um dos artefatos mais importantes para confirmar execucao.

**Correcao sugerida:**

- Normalizar nome uma unica vez.
- Se o nome ja termina com `.exe`, nao concatenar.
- Reutilizar uma funcao central `NormalizeExecutableName`.
- Ajustar tambem `IsKnownHackTool`, que recebe nomes com extensao mas compara com lista sem extensao.

### P0.6 - Hash forense usa SHA1, enquanto a especificacao pede SHA256

**Arquivo:** `src/Scanner/Modules/BaseModule.cs:81-84`

O documento tecnico exige SHA256 para cadeia de custodia, mas o codigo calcula SHA1.

**Impacto:** evidencias ficam abaixo do padrao esperado; SHA1 nao deve ser o hash primario para integridade de evidencia.

**Correcao sugerida:**

- Substituir por SHA256 como hash padrao.
- Se houver necessidade historica, manter SHA1 apenas como campo adicional.
- Nomear claramente `GetFileSha256`.

## Achados P1 - bugs funcionais e falsos positivos relevantes

### P1.1 - Event Viewer consulta eventos antigos e pode perder eventos recentes

**Arquivos:** `src/Scanner/Modules/EventViewerModule.cs`, `src/Scanner/Modules/DefenderModule.cs`

As consultas de EventLog nao definem janela temporal nem direcao reversa. Em alguns pontos o modulo limita `count < 20`, mas tende a pegar os primeiros eventos retornados, nao necessariamente os mais recentes. Em Defender, a leitura pode varrer historico inteiro sem limite.

**Impacto:** relatorio pode destacar eventos antigos fora de contexto e deixar de mostrar eventos recentes importantes.

**Correcao sugerida:**

- Definir janela de varredura configuravel: ultimas 24h, 7 dias, 30 dias ou intervalo de investigacao.
- Usar `EventLogQuery.ReverseDirection = true` para priorizar recentes.
- Registrar no relatorio o intervalo analisado.
- Adicionar filtros XPath por `TimeCreated`.

### P1.2 - `RegistryArtifactsModule` pode abortar PCA Store por conversao invalida

**Arquivo:** `src/Scanner/Modules/RegistryArtifactsModule.cs:42`

`Compatibility Assistant\Store` pode conter dados em formatos que nao convertem diretamente com `Convert.ToInt32(data)`. Se a conversao falhar, o `catch` externo encerra a varredura daquela chave inteira.

**Impacto:** falso negativo silencioso no modulo de registro.

**Correcao sugerida:**

- Tratar tipo antes de converter (`int`, `byte[]`, `string`, etc.).
- Colocar `try/catch` por valor individual, nao em torno do loop inteiro.
- Registrar erro parcial como finding informativo/diagnostico.

### P1.3 - Muitos `catch { }` silenciosos escondem falhas

**Evidencia:** 36 ocorrencias de `catch { }` exato e mais ocorrencias com comentarios.

**Impacto:** o scanner pode falhar em modulos importantes e ainda gerar relatorio com aparencia de sucesso.

**Correcao sugerida:**

- Padronizar um `ModuleError` com excecao, local e severidade.
- Para erro esperado de permissao, gerar finding `Info` com acao recomendada.
- Para erro de parser/coleta, incluir contagem de itens ignorados.
- Nunca engolir erro de modulo inteiro sem registrar.

### P1.4 - Recursao de Temp e Downloads nao acontece como esperado

**Arquivo:** `src/Scanner/Modules/FileSystemModule.cs:96-140`

`MaxRecursionDepth` foi configurado, mas `RecurseSubdirectories = true` nao foi definido nas buscas de Temp e Downloads.

**Impacto:** scanner passa por menos arquivos do que o relatorio sugere, causando falso negativo.

**Correcao sugerida:**

Adicionar `RecurseSubdirectories = true` quando a intencao for recursiva, e usar limites de quantidade/tempo para nao travar.

### P1.5 - Caminhos fixos ignoram `TargetDrive` e "all users"

**Arquivos:** `FileSystemModule.cs`, `KnownCheatsModule.cs`, `PrefetchModule.cs`, `ScanConfig.cs`

Varias buscas estao hardcoded em `C:\`, usuario atual, `Environment.SpecialFolder.UserProfile` ou `Windows`, apesar de existir `TargetDrive` e `ScanAllUsers`.

**Impacto:** em maquinas com Windows em outro drive, multiplos usuarios, perfis redirecionados ou coleta offline, o scanner perde evidencia.

**Correcao sugerida:**

- Centralizar resolucao de caminhos em um `IArtifactPathProvider`.
- Enumerar perfis em `C:\Users` quando `ScanAllUsers=true`.
- Usar `TargetDrive` para artefatos de disco.
- Permitir modo offline apontando para raiz montada.

### P1.6 - Heuristicas de "caminho suspeito" sao agressivas

**Arquivo:** `src/Scanner/Data/CheatDatabase.cs`

`Downloads`, `Desktop`, `ProgramData`, `AppData\Roaming` e outros caminhos geram risco alto/medio em diversos modulos. Isso pode ser util em triagem, mas nao deve ser tratado como forte evidencia sem assinatura, hash, execucao, processo pai ou correlacao temporal.

**Impacto:** falsos positivos altos, principalmente para ferramentas legitimas baixadas pelo usuario.

**Correcao sugerida:**

- Separar `severity` de `confidence`.
- Caminho suspeito sozinho deve ser `Low` ou `Medium`, nao `High`.
- Elevar risco apenas quando houver combinacao: sem assinatura + execucao recente + rede externa + processo pai suspeito + remocao posterior.

### P1.7 - Ferramentas legitimas sao marcadas como suspeitas sem contexto

**Arquivo:** `src/Scanner/Modules/PrefetchModule.cs:88-100`

Wireshark, Fiddler, CharlesProxy, System Informer e debuggers podem ser ferramentas legitimas de suporte, desenvolvimento ou analise.

**Impacto:** relatorio pode acusar uso indevido sem evidencia suficiente.

**Correcao sugerida:**

- Mover para categoria "dual-use tooling".
- Exigir contexto adicional para severidade alta.
- No relatorio, usar linguagem investigativa: "requer validacao" em vez de conclusao.

### P1.8 - Score soma severidades sem deduplicacao nem confianca

**Arquivos:** `src/Scanner/Models/Finding.cs`, `src/Scanner/Models/ScanResult.cs`, `src/Scanner/Core/Correlator.cs`

Cada finding soma pontos ate 100. O mesmo evento pode aparecer em BAM, Prefetch, USN, Registro e Correlator, elevando score sem deduplicacao por entidade/tempo/hash.

**Impacto:** risco final pode parecer mais conclusivo do que a evidencia permite.

**Correcao sugerida:**

- Adicionar `Confidence` e `EvidenceId`.
- Deduplicar por `ArtifactKey`: tipo, caminho/hash/event id/timestamp.
- Separar score de evento, score de entidade e score final.
- Explicar no relatorio quais regras compuseram o score.

### P1.9 - Correlator usa busca textual fragil

**Arquivo:** `src/Scanner/Core/Correlator.cs:18-32`

Correlacoes dependem de `Title.Contains("1102")`, `Title.Contains("USN")`, `Title.Contains("defender")`. Isso e fragil e pode gerar correlacoes erradas.

**Impacto:** falso positivo/falso negativo por mudanca de titulo ou idioma.

**Correcao sugerida:**

- Adicionar campos estruturados em `Finding`: `RuleId`, `EventId`, `ArtifactType`, `EntityKey`, `SourceLog`.
- Correlacionar por campos estruturados.

### P1.10 - `ReportGenerator` nao cria pasta de saida

**Arquivos:** `src/Scanner/Core/ScanOrchestrator.cs`, `src/Scanner/Reports/ReportGenerator.cs`

Se `--output` apontar para uma pasta inexistente, `File.WriteAllText` falha.

**Impacto:** varredura conclui mas relatorio nao e salvo.

**Correcao sugerida:**

- Validar `ReportOutputPath`.
- Criar pasta com `Directory.CreateDirectory`.
- Retornar caminho de relatorio como parte de `ScanResult`.

## Achados P2 - arquitetura, manutencao e produto

### P2.1 - Nome/posicionamento conflita com a especificacao

**Arquivos:** `Scanner.csproj`, `BUILD.bat`, `Program.cs`, `ConsoleUI.cs`

O documento tecnico diz que o produto deve ser defensivo e nao posicionado como "bypass". O codigo, executavel e solucao usam "Bypass Nerfados".

**Impacto:** risco reputacional/comercial e desalinhamento com escopo permitido do documento.

**Correcao sugerida:**

- Renomear produto/assembly para `Nerfados Shield XDR`.
- Remover linguagem que pareca ofensiva ou acusatoria.
- Manter aviso explicito de uso autorizado.

### P2.2 - `AllowUnsafeBlocks=true` sem codigo unsafe

**Arquivo:** `src/Scanner/Scanner.csproj:8`

Nao encontrei uso de `unsafe` no codigo.

**Impacto:** superficie de build desnecessariamente permissiva.

**Correcao sugerida:** remover `AllowUnsafeBlocks` ate existir necessidade real.

### P2.3 - Falta README, `.gitignore`, lockfile e padrao de SDK

Nao ha `README.md`, `.gitignore`, `global.json`, `packages.lock.json`, `Directory.Build.props` ou `Directory.Packages.props`.

**Impacto:** ambiente de dev pouco reproduzivel; build local depende da maquina.

**Correcao sugerida:**

- Criar `README.md` com instalacao, build, uso admin, permissoes e limitacoes.
- Criar `.gitignore` para `bin/`, `obj/`, `build/`, relatorios gerados e arquivos temporarios.
- Criar `global.json` para fixar SDK.
- Habilitar lockfile NuGet.
- Adicionar configuracoes de analisadores.

### P2.4 - `BUILD.bat` e interativo demais para CI

**Arquivo:** `BUILD.bat`

O script usa `pause` e nao faz auditoria de pacotes, testes, warnings-as-errors ou publicacao reproduzivel.

**Correcao sugerida:**

- Manter `BUILD.bat` para uso manual, mas criar pipeline CI separado.
- Comandos minimos recomendados:

```powershell
dotnet restore .\BypassNerfados.sln --locked-mode
dotnet build .\BypassNerfados.sln -c Release --no-restore -warnaserror
dotnet test .\BypassNerfados.sln -c Release --no-build
dotnet list .\BypassNerfados.sln package --vulnerable --include-transitive
```

### P2.5 - Nao ha testes

Nao existe projeto de testes.

**Impacto:** parsers de artefatos, score e correlacao podem quebrar sem aviso.

**Correcao sugerida:**

Criar `tests/Scanner.Tests` com xUnit/NUnit e fixtures para:

- normalizacao de Prefetch;
- validacao de `TargetDrive`;
- timeout de comandos externos;
- parsing de RecentDocs;
- score/deduplicacao;
- `IsLocalAddress`;
- correlacoes por `RuleId`;
- geracao de relatorio com escaping.

### P2.6 - Sem abstracao para APIs do Windows

Os modulos chamam diretamente Registry, EventLog, filesystem, Process, P/Invoke e comandos externos.

**Impacto:** dificil testar sem maquina Windows real e privilegios de admin.

**Correcao sugerida:**

Criar interfaces como:

- `IRegistryReader`
- `IEventLogReader`
- `IFileSystem`
- `IProcessInspector`
- `ICommandRunner`
- `IClock`

Isso permite testes unitarios e mocks de artefatos.

### P2.7 - Relatorios nao tem cadeia de custodia

O relatorio HTML/TXT e visualmente util, mas nao inclui manifesto de evidencia, SHA256 do relatorio, hash por artefato coletado, identidade do operador validada, metodo de coleta ou trilha de auditoria.

**Impacto:** desalinhado ao documento tecnico e fraco para auditoria formal.

**Correcao sugerida:**

- Gerar `evidence-manifest.json`.
- Hash SHA256 do relatorio e de evidencias coletadas.
- Registrar versao da ferramenta, parametros de execucao, horario UTC, timezone, usuario, host e hash do binario.
- Incluir `ChainOfCustody` com responsavel, caso, escopo autorizado e motivo.

## Melhorias por modulo

### Program/CLI

- Validar argumentos com parser robusto (`System.CommandLine` ou Spectre.Console.Cli).
- Adicionar `--mode quick|complete|deep`.
- Adicionar `--since`, `--until`, `--case-id`, `--json`, `--no-html`.
- Validar `--drive` e `--output`.
- Retornar codigos de saida documentados.

### BaseModule

- Trocar `RunCmd` por runner assincrono e seguro.
- Trocar SHA1 por SHA256.
- Remover `catch` silencioso.
- Padronizar logging e erros parciais.

### Prefetch

- Corrigir normalizacao de nome.
- Ler metadados reais do Prefetch quando possivel, nao apenas `LastWriteTime`.
- Nao classificar ausencia de Prefetch como alto risco sem verificar configuracao do SysMain/Prefetch.

### BAM/DAM

- Mapear SID para usuario.
- Registrar origem estruturada (`bam`/`dam`, hive, value name, timestamp).
- Tratar timestamps invalidos como diagnostico.

### USN Journal

- Validar drive.
- Evitar `cmd.exe`, `findstr` e split CSV manual.
- Usar parser CSV.
- Permitir limite temporal.
- Diferenciar "journal indisponivel" de "sem findings".

### Event Viewer/Defender

- Consultar por janela temporal.
- Usar `ReverseDirection`.
- Incluir `EventId`, log, provider e record id como campos estruturados.
- Limitar volume por configuracao.
- Melhorar parsing de `EventRecord.Properties` em vez de depender de `FormatDescription()`.

### Registry Artifacts

- Corrigir conversao do PCA Store.
- Adicionar UserAssist, Amcache/ShimCache quando possivel.
- Enumerar usuarios/HKU, nao apenas `CurrentUser`.

### File System/Known Cheats

- Corrigir recursao.
- Usar limites de tempo/quantidade e cancelar com token.
- Evitar `Directory.GetFiles(..., AllDirectories)` sem `IgnoreInaccessible`.
- Usar `TargetDrive` e todos os perfis.
- Separar IOC confirmado de heuristica por nome.

### Process Memory

- Reduzir falsos positivos em memoria executavel privada, especialmente para JIT, engines de jogos e anticheats.
- Mascara correta de flags de protecao de memoria.
- Enriquecer com modulo, assinatura, mapa de memoria e processo pai antes de classificar como critico.
- Verificar layout P/Invoke em x64 e overflow ao avancar enderecos.

### Network

- Trocar `IsLocalAddress` por `IPAddress` e checagem de ranges privados completos:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 127.0.0.0/8
  - link-local/IPv6 loopback/ULA
- Converter portas com API confiavel (`IPAddress.NetworkToHostOrder` ou equivalente).
- Enriquecer IP externo com processo, assinatura, hash e DNS quando disponivel.

## Roadmap recomendado para o dev

### Sprint 0 - Build reproduzivel e higiene

1. Instalar/padronizar SDK via `global.json`.
2. Corrigir `ServiceControllerStatus.Disabled`.
3. Declarar `System.ServiceProcess.ServiceController`.
4. Remover `AllowUnsafeBlocks` se nao for necessario.
5. Criar README, `.gitignore`, lockfile e pipeline minimo.
6. Rodar build com warnings como erro.

### Sprint 1 - Bugs de coleta e seguranca local

1. Corrigir `RunCmd`.
2. Validar `TargetDrive`.
3. Corrigir Prefetch.
4. Trocar SHA1 por SHA256.
5. Criar pasta de relatorio automaticamente.
6. Remover os principais `catch { }` silenciosos.

### Sprint 2 - Reducao de falso positivo/falso negativo

1. Adicionar janela temporal em Event Viewer/Defender.
2. Adicionar `Confidence`.
3. Deduplicar findings.
4. Corrigir recursao de arquivos.
5. Melhorar rede privada/externa.
6. Separar IOC confirmado de heuristica.

### Sprint 3 - Base forense/auditavel

1. Criar modelo estruturado de evidencia.
2. Gerar `evidence-manifest.json`.
3. Hash SHA256 do relatorio e evidencias.
4. Adicionar `CaseId`, operador, escopo e parametros de execucao.
5. Exportar JSON alem de HTML/TXT.

### Sprint 4 - Evolucao para o produto do documento tecnico

1. Transformar scanner em agente Windows/servico.
2. Criar API de ingestao.
3. Normalizar eventos.
4. Criar timeline unificada.
5. Planejar backend, dashboard, armazenamento e RBAC.

## Checklist rapido para PR inicial

- [ ] Projeto compila em maquina limpa com .NET SDK padronizado.
- [ ] `dotnet restore` roda com NuGet Audit habilitado.
- [ ] `dotnet build -c Release -warnaserror` passa.
- [ ] Existe projeto de testes com pelo menos parsers e score.
- [ ] `--drive` invalido e rejeitado.
- [ ] `RunCmd` nao trava e mata processo em timeout.
- [ ] Prefetch detecta corretamente `APP.EXE-HASH.pf`.
- [ ] Relatorio e salvo mesmo quando `--output` ainda nao existe.
- [ ] Findings incluem campos estruturados suficientes para correlacao.
- [ ] SHA256 substitui SHA1 como hash primario.

## Ideia de interface para o produto

### Direcao geral

A interface deve parecer uma ferramenta de investigacao operacional, nao uma pagina promocional. O primeiro contato do usuario deve ser um console de trabalho com maquinas, alertas, score, timeline e evidencias. Visual recomendado: escuro, denso, legivel, com cores usadas para severidade e nao como decoracao.

Principios:

- Priorizar leitura rapida e comparacao entre evidencias.
- Sempre mostrar contexto: maquina, usuario, horario, origem, score e confianca.
- Evitar linguagem acusatoria; usar "indicador", "evidencia", "requer validacao" e "confirmado por hash/regra".
- Separar severidade de confianca.
- Toda tela investigativa deve permitir exportar ou anexar item ao caso.

### Navegacao principal

Menu lateral fixo:

- Visao Geral
- Maquinas
- Alertas
- Investigacoes
- Timeline
- Processos
- Arquivos/Hashes
- Rede
- Regras
- Relatorios
- Configuracoes

Topo fixo:

- Busca global por maquina, usuario, processo, hash, caminho, IP ou caso.
- Seletor de intervalo: 24h, 7d, 30d, personalizado.
- Filtro de severidade.
- Botao "Nova investigacao".
- Status do agente/coleta.

### Tela 1 - Visao Geral

Objetivo: triagem rapida do ambiente.

Blocos principais:

- Cards compactos: endpoints monitorados, criticos, altos, offline, investigacoes abertas.
- Grafico de alertas por hora/dia.
- Lista de alertas recentes com severidade, confianca, maquina, usuario e hora.
- Top maquinas por risco.
- Top processos suspeitos.
- Modulos com erro de coleta.

Wireframe textual:

```text
+--------------------------------------------------------------------------------+
| Busca global...                                      24h | Severidade | Novo caso |
+----------------------+---------------------------------------------------------+
| Visao Geral          | Criticos 7 | Altos 19 | Medios 42 | Offline 3          |
| Maquinas             +---------------------------------------------------------+
| Alertas              | Alertas por hora                                       |
| Investigacoes        | [grafico compacto]                                     |
| Timeline             +----------------------------+----------------------------+
| Processos            | Alertas recentes           | Top maquinas por risco    |
| Arquivos/Hashes      | CRIT DESKTOP-01 1102       | DESKTOP-01 92             |
| Rede                 | HIGH NOTE-23 PowerShell    | NOTE-23    76             |
| Regras               +----------------------------+----------------------------+
+----------------------+ Modulos com falha: USN Journal em 2 maquinas           |
```

### Tela 2 - Detalhe da maquina

Objetivo: responder "o que existe nesta maquina e qual o risco atual?".

Secoes:

- Cabecalho: hostname, usuario atual, SO, ultimo check-in, IP, status do agente.
- Score total, severidade e confianca.
- Abas: Resumo, Timeline, Processos, Arquivos, Registro, Rede, Servicos, Evidencias.
- Painel de modulos: executado, parcial, erro, sem permissao.
- Botao: "Iniciar varredura" com opcoes rapido, completo, profundo.

### Tela 3 - Alerta

Objetivo: analisar um alerta sem perder o contexto.

Layout em tres colunas:

- Esquerda: lista filtravel de alertas.
- Centro: detalhe do alerta, evidencias, regras disparadas e recomendacao.
- Direita: entidades relacionadas: processo pai, usuario, arquivos, IPs, eventos proximos.

Campos importantes:

- Severidade
- Confianca
- Regra
- Categoria
- Maquina
- Usuario/SID
- Primeiro visto
- Ultimo visto
- Evidencias relacionadas
- Justificativa do score

### Tela 4 - Timeline unificada

Objetivo: reconstruir a historia.

Recursos:

- Linha cronologica vertical ou tabela temporal.
- Filtros por maquina, usuario, processo, hash, IP, categoria e severidade.
- Agrupamento por minuto/processo/caso.
- Marcadores visuais por origem: Event Viewer, Defender, USN, Prefetch, BAM, Registro, Rede, Memoria.
- Clique em um item abre painel lateral com raw data e evidencias.

Colunas recomendadas:

```text
Horario | Severidade | Confianca | Origem | Entidade | Evento | Evidencia
```

### Tela 5 - Arvore de processos

Objetivo: entender encadeamento de execucao.

Visual:

- Arvore com processo pai e filhos.
- Cada no mostra nome, PID, usuario, caminho, assinatura, hash, inicio/fim e score.
- Destaque para PowerShell/cmd/script host, processos sem assinatura e filhos em Temp/AppData.
- Painel lateral mostra linha de comando, conexoes, arquivos criados e eventos correlacionados.

### Tela 6 - Arquivo/Hash

Objetivo: investigar um binario ou artefato.

Secoes:

- SHA256, SHA1 opcional, nome, caminho, tamanho, assinatura, primeira/ultima ocorrencia.
- Maquinas afetadas.
- Execucoes confirmadas por Prefetch/BAM/Registro.
- Conexoes de rede associadas.
- Vereditos: IOC conhecido, heuristica, permitido, falso positivo.
- Botao: "Adicionar ao caso" e "Criar regra".

### Tela 7 - Investigacao/caso

Objetivo: organizar evidencias e gerar relatorio.

Campos:

- ID do caso
- Responsavel
- Escopo autorizado
- Suspeito/maquina/usuario
- Periodo analisado
- Status: aberto, em analise, aguardando validacao, concluido
- Evidencias anexadas
- Linha do tempo do caso
- Notas do analista
- Relatorios gerados com hash SHA256

### Tela 8 - Regras

Objetivo: permitir evolucao sem recompilar o scanner.

Recursos:

- Lista de regras com status ativo/inativo.
- Severidade base.
- Confianca base.
- Condicoes.
- Ultimas ocorrencias.
- Testar regra contra eventos existentes.
- Versionamento simples da regra.

### Design visual recomendado

- Fundo: cinza muito escuro.
- Superficies: cinza escuro levemente mais claro, sem excesso de cards aninhados.
- Severidades:
  - Critico: vermelho
  - Alto: laranja
  - Medio: amarelo
  - Baixo: verde
  - Info: cinza/azul discreto
- Usar tabelas densas para dados investigativos.
- Usar badges pequenos para severidade, origem e categoria.
- Usar icones simples para acoes: buscar, filtrar, exportar, anexar, iniciar varredura, abrir detalhe.
- Evitar gradientes chamativos, mascotes, ilustracoes e "hero section".

### MVP de interface recomendado

Para uma primeira entrega util, construir apenas:

1. Visao Geral com cards e alertas recentes.
2. Detalhe da maquina com findings agrupados por modulo.
3. Timeline unificada simples em tabela.
4. Tela de alerta com evidencias relacionadas.
5. Exportacao de relatorio HTML/JSON.

Isso ja transformaria o scanner local em uma experiencia investigativa bem mais clara para operador e dev.

## Referencias pesquisadas

- Microsoft Learn - .NET releases and support: .NET 8 LTS suportado ate novembro de 2026; .NET 10 LTS suportado ate novembro de 2028; updates de servicing sao mensais.  
  https://learn.microsoft.com/en-us/dotnet/core/releases-and-support

- Microsoft Learn - `ServiceControllerStatus`: enum lista `Stopped`, `StartPending`, `StopPending`, `Running`, `ContinuePending`, `PausePending`, `Paused`; nao ha `Disabled`.  
  https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicecontrollerstatus

- Microsoft Learn - `ServiceController.StartType`: propriedade correta para identificar modo de inicializacao do servico.  
  https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicecontroller.starttype

- NuGet - `System.ServiceProcess.ServiceController`: pacote fornece API para consultar/manipular servicos Windows e tem versao atual 10.0.7 no NuGet.  
  https://www.nuget.org/packages/System.ServiceProcess.ServiceController/

- NuGet - `Spectre.Console`: o projeto usa 0.49.1; NuGet mostra versoes mais novas, incluindo 0.55.2 publicada em 17/04/2026.  
  https://www.nuget.org/packages/Spectre.Console/0.49.1

- Microsoft Learn - NuGet Audit: recomenda auditar dependencias em restore/CI e usar `dotnet list package --vulnerable --include-transitive`.  
  https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages

- Microsoft Learn - PackageReference lock files: `RestorePackagesWithLockFile`, `packages.lock.json` e `restore --locked-mode` para builds reproduziveis.  
  https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files
