# Documentacao para o dev - Transformar em app unico

## Objetivo

Transformar o projeto atual em um aplicativo Windows unico, instalavel ou executavel em arquivo unico, que rode localmente com permissao de administrador, execute a varredura, mostre os resultados em interface grafica e exporte relatorios/evidencias sem depender de backend, dashboard web separado, API externa ou servico remoto.

Resumo da direcao:

- Manter o motor de scanner atual.
- Trocar a experiencia principal de CLI para app desktop.
- Embutir relatorio, timeline, historico local e configuracoes no proprio app.
- Publicar como um app unico para Windows.
- Nao criar backend, Next.js, PostgreSQL, OpenSearch, API de ingestao ou agente remoto nesta fase.

## Estado atual do projeto

O repositorio esta limpo e possui dois commits:

- `4669ee3 feat: initial implementation — Bypass Nerfados Shield XDR v1.0`
- `7824136 fix: align hash evidence and CLI docs`

O projeto atual e um scanner CLI em C#/.NET 8 para Windows:

- Projeto: `src/Scanner/Scanner.csproj`
- Entrada: `src/Scanner/Program.cs`
- Orquestrador: `src/Scanner/Core/ScanOrchestrator.cs`
- Modulos: `src/Scanner/Modules/*`
- Relatorios: `src/Scanner/Reports/*`
- Documentacao atual: `README.md` e `ANALISE_MELHORIAS_DEV.md`

Nao consegui validar `dotnet build` neste terminal porque `dotnet` ainda nao esta disponivel no PATH. O dev deve validar em maquina com .NET 8 SDK.

## Decisao de arquitetura

### Opcao recomendada

Criar um app desktop Windows com WPF em .NET 8/10, reaproveitando o scanner atual como biblioteca interna.

Motivos:

- O produto depende de APIs Windows, Registry, Event Viewer, servicos, processos e execucao como administrador.
- WPF e maduro, simples de publicar e bom para app operacional local.
- Nao exige Node, navegador, API separada ou servidor local.
- Permite publish self-contained/single-file.
- Facilita progresso de varredura, cancelamento, tabelas, abas, filtros e exportacao.

### Resultado esperado para o usuario

O usuario baixa/recebe um app, executa como administrador e faz tudo dentro dele:

1. Abre o aplicativo.
2. Preenche dados do caso.
3. Escolhe modo de varredura.
4. Clica em "Iniciar".
5. Acompanha progresso por modulo.
6. Analisa findings, timeline e evidencias.
7. Exporta HTML/TXT/JSON e pacote de evidencias.

## Estrutura recomendada da solucao

O produto pode continuar gerando um unico app mesmo com multiplos projetos internos. A separacao abaixo melhora manutencao e testes, mas o publish final continua sendo um executavel unico.

```text
BypassNerfados.sln
|
|-- src/
|   |-- Nerfados.App/              # WPF desktop app, EXE final
|   |-- Nerfados.Scanner.Core/     # motor de varredura, modulos e modelos
|   |-- Nerfados.Reporting/        # HTML/TXT/JSON/evidence manifest
|   |-- Nerfados.Storage/          # historico local, SQLite ou JSON
|
|-- tests/
|   |-- Nerfados.Scanner.Tests/
|
|-- docs/
|   |-- app-unico.md
|   |-- arquitetura.md
|   |-- ux.md
```

Se o dev quiser velocidade maxima agora, pode manter um unico projeto e organizar por pastas:

```text
src/Scanner/
|-- App/            # telas WPF
|-- ViewModels/
|-- Services/
|-- Core/
|-- Modules/
|-- Reports/
|-- Storage/
|-- Models/
```

Mas a recomendacao profissional e separar em projetos internos e publicar um unico EXE.

## Como reaproveitar o scanner atual

O `ScanOrchestrator` deve virar um servico consumido pela UI.

Hoje:

```text
Program.cs -> ScanOrchestrator -> Modules -> ReportGenerator
```

No app unico:

```text
MainWindow/ViewModel
  -> ScanService
  -> ScanOrchestrator
  -> Modules
  -> ResultStore
  -> ReportGenerator
```

Alteracoes necessarias:

- Fazer `ScanOrchestrator` emitir eventos de progresso por modulo.
- Permitir `CancellationToken`.
- Retornar resultados parciais para a UI.
- Remover dependencia direta de `Spectre.Console` do core.
- Deixar Spectre.Console apenas no modo CLI, se o CLI continuar existindo.
- Criar modelos estruturados para tela: `FindingViewModel`, `ScanProgress`, `ModuleStatus`, `TimelineItem`.

## Telas do app unico

### 1. Tela inicial

Objetivo: iniciar uma investigacao de forma simples.

Campos:

- ID do caso
- Investigador
- Suspeito
- Drive
- Pasta de saida
- Modo: Rapido, Completo, Profundo
- Janela temporal: 24h, 7 dias, 30 dias, personalizado
- Checkboxes: USN Journal, memoria, rede, relatorio automatico

Acoes:

- Iniciar varredura
- Abrir caso anterior
- Abrir pasta de relatorios

### 2. Varredura em andamento

Objetivo: o operador precisa ver que o app esta vivo.

Elementos:

- Barra geral de progresso.
- Lista de modulos com status: pendente, rodando, concluido, erro, pulado.
- Tempo por modulo.
- Findings importantes aparecendo em tempo real.
- Botao cancelar.
- Aviso de permissao de administrador.

### 3. Resultado geral

Objetivo: triagem imediata apos a varredura.

Elementos:

- Score total.
- Nivel de risco.
- Quantidade por severidade.
- Modulos executados.
- Modulos com erro.
- Top 10 findings relevantes.
- Botao exportar relatorio.

### 4. Findings

Objetivo: analisar tudo que foi encontrado.

Tabela com filtros:

```text
Severidade | Confianca | Categoria | Modulo | Titulo | Evidencia | Horario
```

Filtros:

- Severidade
- Categoria
- Modulo
- Texto livre
- Apenas cheats confirmados
- Apenas anti-forense
- Apenas com timestamp

Ao clicar em um item, abrir painel lateral com:

- Detalhe completo.
- Evidencia bruta.
- Caminho/hash/IP/event id.
- Recomendacao de validacao.
- Botao "Adicionar ao caso".

### 5. Timeline

Objetivo: reconstruir a historia.

Tabela ordenada por horario:

```text
Horario | Severidade | Origem | Entidade | Evento | Evidencia
```

Recursos:

- Agrupar por minuto.
- Filtrar por modulo.
- Buscar por processo, arquivo, hash, usuario ou IP.
- Mostrar correlacoes acima da lista.

### 6. Evidencias e relatorios

Objetivo: fechar a investigacao.

Elementos:

- Lista de relatorios gerados.
- Hash SHA256 de cada relatorio.
- Manifesto de evidencias.
- Botao exportar HTML.
- Botao exportar TXT.
- Botao exportar JSON.
- Botao abrir pasta.

### 7. Configuracoes

Campos:

- Pasta padrao de saida.
- Janela temporal padrao.
- Modulos habilitados por padrao.
- Nivel minimo para exibir alerta.
- Tema claro/escuro, se quiser.
- Politica de retencao do historico local.

## Design da interface

Direcao visual:

- Interface operacional, densa e objetiva.
- Nao fazer landing page.
- Nao usar tela hero.
- Nao usar cards decorativos grandes.
- Priorizar tabelas, abas, filtros e paineis laterais.

Cores:

- Fundo escuro neutro.
- Superficies em cinza escuro.
- Texto claro.
- Critico: vermelho.
- Alto: laranja.
- Medio: amarelo.
- Baixo: verde.
- Info: cinza/azul discreto.

Componentes esperados:

- Sidebar ou tabs no topo.
- Tabelas com ordenacao.
- Badges pequenos de severidade.
- Barra de progresso por modulo.
- Painel lateral de detalhe.
- Dialog de confirmacao para cancelar varredura.
- Toast ou status bar para erros.

## Melhorias tecnicas antes de virar app

### P0 - indispensavel

1. Validar build em maquina com .NET 8 SDK.
2. Criar `packages.lock.json` e versionar para build reproduzivel.
3. Criar projeto de testes.
4. Remover dependencia de `Spectre.Console` do core antes de chamar pela UI.
5. Adicionar `CancellationToken` ao fluxo inteiro.
6. Adicionar progresso estruturado por modulo.

### P1 - alta prioridade

1. `CaseId` ja e parseado em `Program.cs`, mas ainda nao aparece no HTML/TXT.
2. `DefenderModule` ainda nao usa janela temporal configuravel nem `ReverseDirection`.
3. Em `EventViewerModule`, so parte das consultas usa janela temporal; `ScanUsnResetEvent` e `ScanProcessCreationEvents` ainda devem receber `since` e `ReverseDirection`.
4. `UsnJournalModule` ainda usa `cmd.exe /c` com pipeline; melhor chamar `fsutil.exe` diretamente e filtrar em C#.
5. Muitos `catch { }` silenciosos continuam escondendo falhas parciais.
6. `ReportGenerator` deve gerar JSON estruturado alem de HTML/TXT.
7. Adicionar `Confidence` aos findings para separar severidade de certeza.
8. Deduplicar findings por arquivo/hash/evento/timestamp.

### P2 - qualidade e produto

1. Renomear o produto para algo defensivo, como `Nerfados Shield XDR`, evitando "Bypass" no nome final.
2. Melhorar linguagem dos relatórios: trocar afirmacoes absolutas por "indicador", "evidencia", "confirmado por hash" e "requer validacao".
3. Criar `evidence-manifest.json`.
4. Adicionar historico local de varreduras.
5. Permitir abrir relatorios antigos dentro do app.
6. Assinar o executavel no futuro para reduzir alerta do Windows.

## Armazenamento local

Como o app deve ser unico, nao usar banco remoto.

Opcoes:

### Simples

Salvar cada varredura em uma pasta:

```text
Documents/NerfadosShield/Cases/
|-- CASO-001/
|   |-- scan-result.json
|   |-- report.html
|   |-- report.txt
|   |-- evidence-manifest.json
```

### Melhor para historico

Usar SQLite local:

```text
%ProgramData%/NerfadosShield/data.db
```

Tabelas:

- `cases`
- `scans`
- `findings`
- `timeline_items`
- `reports`
- `module_runs`

Recomendacao: comecar com JSON por caso. Migrar para SQLite quando a UI precisar listar muitas varreduras antigas.

## Publicacao como app unico

Publicar self-contained/single-file para Windows:

```powershell
dotnet publish .\src\Nerfados.App\Nerfados.App.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -o .\publish\NerfadosShield
```

Se continuar temporariamente no projeto atual:

```powershell
dotnet publish .\src\Scanner\Scanner.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -o .\publish\NerfadosShield
```

Observacao: para WPF com manifest `requireAdministrator`, testar abertura por clique duplo e por terminal elevado.

## Backlog recomendado

### Sprint A - Preparar o core para UI

- [ ] Criar `ScanProgress`.
- [ ] Criar `ModuleRunResult`.
- [ ] Adicionar `CancellationToken`.
- [ ] Remover uso direto de `AnsiConsole` do `ScanOrchestrator`.
- [ ] Fazer `ScanOrchestrator` retornar progresso por callback/evento.
- [ ] Garantir build com .NET SDK.

### Sprint B - Criar app desktop minimo

- [ ] Criar projeto WPF `Nerfados.App`.
- [ ] Tela inicial com dados do caso.
- [ ] Tela de progresso por modulo.
- [ ] Tela de resultado com score e findings.
- [ ] Exportar HTML/TXT.
- [ ] Publicar single-file.

### Sprint C - Investigacao dentro do app

- [ ] Tela de findings com filtros.
- [ ] Timeline.
- [ ] Painel lateral de detalhe.
- [ ] Historico local por JSON.
- [ ] Abrir relatorio antigo.

### Sprint D - Evidencia e qualidade

- [ ] `evidence-manifest.json`.
- [ ] SHA256 do relatorio.
- [ ] JSON estruturado do resultado.
- [ ] Confidence score.
- [ ] Deduplicacao.
- [ ] Testes unitarios dos parsers.

## Criterios de aceite

O app unico so deve ser considerado pronto quando:

- Abre por clique duplo no Windows.
- Solicita permissao de administrador.
- Inicia varredura sem terminal.
- Mostra progresso por modulo.
- Permite cancelar varredura.
- Mostra resultado dentro do app.
- Exporta HTML/TXT/JSON.
- Salva historico local.
- Inclui `CaseId`, investigador e suspeito no relatorio.
- Gera SHA256 dos relatorios.
- Funciona sem backend, internet, Node.js ou banco externo.
- Pode ser publicado em uma pasta ou em um unico executavel.

## Pontos para alinhar com o dev

Perguntas objetivas:

1. O app final deve ser WPF nativo ou WinUI 3?
2. Precisa instalador `.msi`/`.exe` ou basta pasta publicada/single EXE?
3. O historico local pode ser JSON por caso ou precisa SQLite?
4. O CLI atual deve continuar existindo como modo avancado?
5. O nome final sera `Bypass Nerfados` ou `Nerfados Shield XDR`?
6. O app sera usado em uma maquina por vez ou precisa importar/exportar casos entre maquinas?

Minha recomendacao:

- WPF.
- Publish single-file self-contained.
- JSON por caso no MVP.
- Manter CLI apenas como fallback tecnico.
- Renomear produto final para `Nerfados Shield XDR`.
- Sem backend nesta fase.

