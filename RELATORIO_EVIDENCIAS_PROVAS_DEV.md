# Relatorio para o dev - Evidencias, provas e timeline por artefato

## Contexto

Projeto: Bypass Nerfados Shield XDR  
Commit base validado: `4fe10d6 feat: separate cheat display section in console summary`  
Data da validacao: 09/05/2026  
Build local: `dotnet build .\BypassNerfados.sln -c Release` aprovado com 0 erros e 0 avisos.

O scanner ja passou por uma etapa importante de calibracao:

- falsos positivos graves foram reduzidos;
- `launcher.exe` generico foi rebaixado para baixa confianca;
- cheats/indicios agora aparecem em uma secao propria no console;
- Defender 5007, USN 3079 e eventos NTP 4616 foram calibrados;
- `d3d10.dll` legitimo em Windows/WinSxS/System32 deixou de ser tratado como cheat.

O proximo problema nao e apenas detectar mais coisas. O problema agora e apresentar prova suficiente para o investigador decidir rapido se o artefato e cheat, legitimo, indicio fraco ou tentativa de bypass.

## Objetivo do proximo sprint

Transformar cada finding relevante em um dossie de evidencias.

Hoje o scanner mostra algo como:

```text
INDICIO | MEDIO | Prefetch | Executavel com nome de cheat: launcher.exe
```

O esperado e mostrar algo como:

```text
INDICIO | MEDIO | launcher.exe
Caminho: C:\Users\...\FiveM\FiveM.app\data\game-storage\launcher\Launcher.exe
Origem: KnownCheats + Prefetch + MuiCache
Historico: executado em 26/04/2026 19:46, registrado no MuiCache, crash do FiveM perto do horario
Provas: SHA256, tamanho, Prefetch PF, MuiCache path, timestamps relacionados
Validacao: comparar hash/caminho com base GOSTH e verificar artefatos System32 0 KB
```

## Problema atual

O modelo atual de finding ainda e simples demais para investigacao:

```csharp
Risk
Category
Module
Title
Detail
Evidence
Timestamp
Confidence
RuleId
Entity
ValidationHint
```

Esses campos ajudam, mas ainda nao respondem claramente:

- qual e o caminho completo do arquivo?
- de onde o artefato veio?
- quando ele executou?
- que modulos confirmam a mesma coisa?
- o que ele alterou no sistema?
- existe prova de bypass ou anti-forense perto do horario?
- e legitimo, suspeito ou confirmado?
- o que o investigador precisa validar manualmente?

## Requisito principal

Criar uma camada de enriquecimento de evidencias por artefato.

Nome sugerido:

```text
EvidenceEnricher
ArtifactEvidenceBundle
ArtifactTimeline
```

Essa camada deve rodar apos os modulos principais e antes da geracao do resumo/relatorio.

Fluxo recomendado:

```text
Modules -> Findings brutos -> Deduplicator -> EvidenceEnricher -> Correlator -> Result/Report/UI
```

## Novo modelo recomendado

Adicionar um modelo estruturado para evidencias enriquecidas.

```csharp
public sealed class EvidenceBundle
{
    public string ArtifactId { get; init; }
    public string ArtifactName { get; init; }
    public string? FullPath { get; init; }
    public string? OriginalPath { get; init; }
    public string? ProcessName { get; init; }
    public int? ProcessId { get; init; }
    public string Verdict { get; init; } // Confirmado, Forte indicio, Indicio, Baixa confianca, Legitimo
    public RiskLevel Risk { get; init; }
    public Confidence Confidence { get; init; }
    public string Summary { get; init; }
    public List<EvidenceSignal> Signals { get; init; } = new();
    public List<ArtifactTimelineItem> Timeline { get; init; } = new();
    public List<string> ModifiedArtifacts { get; init; } = new();
    public List<string> BypassIndicators { get; init; } = new();
    public List<string> ValidationSteps { get; init; } = new();
}

public sealed class EvidenceSignal
{
    public string SourceModule { get; init; }
    public string SignalType { get; init; } // Prefetch, MuiCache, BAM, Defender, USN, EventLog, FileHash
    public string Description { get; init; }
    public string? EvidenceValue { get; init; }
    public DateTime? Timestamp { get; init; }
    public Confidence Confidence { get; init; }
}

public sealed class ArtifactTimelineItem
{
    public DateTime? Timestamp { get; init; }
    public string Source { get; init; }
    public string Action { get; init; } // Executado, Criado, Deletado, Renomeado, Alterado, Conectou, Servico criado
    public string Detail { get; init; }
}
```

O `Finding` pode continuar existindo, mas findings relevantes devem apontar para um `EvidenceBundle`.

## Colunas obrigatorias na tela

Na secao `CHEATS DETECTADOS / INDICIOS`, adicionar colunas ou painel expandido com:

```text
Confianca
Risco
Artefato
Caminho
Origem / Historico
Acao / Alteracao
Provas
Validar?
```

Exemplo de linha:

```text
BAIXA CONFIANCA | MEDIO | launcher.exe
Caminho: C:\Users\guilh\AppData\Local\FiveM\FiveM.app\data\game-storage\launcher\Launcher.exe
Origem: KnownCheats, Prefetch, MuiCache
Acao: executado em 26/04/2026 19:46
Provas: SHA256=..., Prefetch=LAUNCHER.EXE-B6892D66.pf, MuiCache=...
Validar: confirmar hash/caminho com base GOSTH e buscar artefato System32 0 KB
```

## Varredura profunda automatica

Quando um artefato suspeito for encontrado, o scanner deve abrir uma investigacao local ao redor dele.

Gatilhos:

- `launcher.exe`
- `dxsetup.exe`
- `WhatsApp Installer.exe`
- `d3d10.dll`
- `farinhafree.exe`
- nomes com `gosth`, `ghost`, `cheat`, `loader`, `inject`, `bypass`
- `citizenfx_uninstall_*`
- comando `fsutil usn deletejournal`
- comando `wevtutil cl`
- exclusao Defender
- Defender desativado
- servico suspeito instalado
- tarefa agendada suspeita
- processo com memoria suspeita
- conexao externa de processo suspeito

Ao encontrar um gatilho, executar:

```text
1. Resolver caminho completo do artefato.
2. Calcular SHA256 e SHA1.
3. Verificar assinatura digital e publisher.
4. Verificar se o arquivo ainda existe.
5. Coletar tamanho, created/modified/accessed time.
6. Procurar Prefetch relacionado.
7. Procurar BAM/DAM relacionado.
8. Procurar MuiCache e PCA Store relacionado.
9. Procurar RecentDocs, 7-Zip e WinRAR relacionado.
10. Procurar USN Journal perto do timestamp.
11. Procurar EventViewer perto do timestamp.
12. Procurar Defender perto do timestamp.
13. Procurar Run keys, servicos e tarefas relacionadas.
14. Procurar Lixeira, Temp, Downloads e AppData relacionados.
15. Montar timeline unica do artefato.
16. Classificar veredito final.
```

## Classificacao de veredito

Usar uma decisao mais clara que apenas severidade.

### Confirmado

Quando houver:

- hash conhecido batendo com base interna;
- assinatura/indicador direto do cheat;
- arquivo conhecido em caminho exato e especifico;
- DLL confirmada no local correto, por exemplo `FiveM Application Data\Plugins\d3d10.dll`, com hash/tamanho esperado.

### Forte indicio

Quando houver combinacao de pelo menos dois sinais fortes:

- caminho tipico;
- Prefetch;
- MuiCache;
- BAM/DAM;
- Defender detectou ameaca relacionada;
- USN mostra criacao/delecao perto do horario;
- crash dump do FiveM perto da execucao;
- anti-forense proximo ao timestamp.

### Indicio

Quando houver sinal relevante, mas nao conclusivo:

- nome unico conhecido sem hash;
- caminho suspeito sem confirmacao adicional;
- execucao isolada em Prefetch/MuiCache.

### Baixa confianca

Quando houver nome generico:

- `launcher.exe`;
- `dxsetup.exe`;
- qualquer nome que tambem seja comum em software legitimo.

Esses casos devem continuar aparecendo, mas sempre com `ValidationHint`.

### Legitimo

Quando bater allowlist ou assinatura confiavel:

- Microsoft/Windows;
- Rockstar Launcher;
- Steam;
- Epic;
- Spotify;
- Discord;
- OneDrive;
- Google Drive;
- Dropbox;
- Teams;
- Skype;
- Zoom;
- OBS;
- NVIDIA;
- BattlEye, se instalado em caminho oficial.

Itens legitimos podem aparecer apenas em modo verbose ou numa secao "Ignorados/legitimos", nao devem inflar score.

## Regras especificas para GOSTH / launcher.exe

`launcher.exe` nunca deve ser confirmado sozinho.

Tabela recomendada:

```text
Cenario                                                     Veredito
launcher.exe por nome apenas                                Baixa confianca
launcher.exe em Prefetch                                    Indicio
launcher.exe + MuiCache/PCA                                 Indicio
launcher.exe + caminho tipico GOSTH                         Forte indicio
launcher.exe + hash conhecido                               Confirmado
launcher.exe + System32 0 KB artifact + anti-forense        Forte indicio ou Confirmado, conforme base
Rockstar/Steam/Epic/Wallpaper/Wuthering launcher            Legitimo ou baixa confianca, sem score alto
```

Para GOSTH, procurar automaticamente:

- arquivo 8-10 caracteres 0 KB em `System32`;
- arquivo numerico 8-10 digitos 0 KB em `System32`;
- `dxsetup` em `AppData\Local\Programs\Common`;
- `WhatsApp Installer.exe` em `System32\WinBioDatabase`;
- Prefetch de `launcher.exe`;
- MuiCache/PCA Store de `launcher.exe`;
- entradas em Defender perto do timestamp;
- USN create/delete/rename perto do timestamp;
- logs limpos ou Defender alterado perto do timestamp.

## Regras para tentativa de bypass

Criar secao propria:

```text
TENTATIVAS DE BYPASS / ANTI-FORENSE
```

Cada item deve mostrar:

```text
Tipo
Comando/evento
Caminho/chave afetada
Timestamp
Processo/usuario
Prova bruta
Correlacao com cheat
```

Detectar:

- Event Log limpo: `1102`, `104`;
- USN suspeito: `3079`, mas so escalar se houver `fsutil usn deletejournal`, PSReadLine ou outro sinal;
- Defender desativado;
- exclusoes Defender adicionadas;
- Prefetch removido/vazio;
- alteracao manual de horario, nao NTP;
- servicos de protecao desativados;
- tarefas agendadas suspeitas;
- servicos criados perto do horario do cheat;
- comandos PowerShell suspeitos;
- limpeza de logs via `wevtutil`;
- uso de ferramentas de memoria/injecao.

## Relatorio HTML/TXT

O relatorio deve ter secoes mais investigativas:

```text
1. Resumo executivo
2. Cheats confirmados
3. Indicios de cheat
4. Tentativas de bypass / anti-forense
5. Dossie por artefato
6. Timeline consolidada
7. Itens legitimos ignorados
8. Itens que exigem validacao manual
9. Evidencias brutas
```

Para cada artefato, exemplo:

```text
ARTEFATO: launcher.exe
Veredito: Indicio / baixa confianca
Caminho principal: C:\Users\...\FiveM\...\launcher.exe
Hash SHA256: ...
Hash SHA1: ...
Assinatura: ausente / valida / invalida / publisher

Sinais encontrados:
- Prefetch: LAUNCHER.EXE-B6892D66.pf, 26/04/2026 19:46:23
- MuiCache: C:\Users\...\launcher.exe
- KnownCheats: nome coincide com indicador GOSTH, baixa confianca
- FileSystem: crash dump FiveM perto do horario

Alteracoes relacionadas:
- Defender: nenhuma exclusao critica encontrada
- EventViewer: servico instalado proximo ao horario? sim/nao
- USN: verificar com scan completo

Conclusao:
Nao confirmado por hash. Requer validacao manual com base GOSTH.
```

## Interface futura

Na UI desktop, usar tres visoes:

### 1. Resultado

Cards:

- Confirmados
- Fortes indicios
- Indicios
- Bypass/anti-forense
- Validacao manual

### 2. Artefatos

Tabela:

```text
Veredito | Risco | Artefato | Caminho | Primeira evidência | Ultima evidência | Provas | Validar?
```

Painel lateral ao clicar:

```text
Resumo
Historico
Timeline
Hashes
Assinatura
Registro
Eventos
Arquivos relacionados
Bypass relacionado
Recomendacao
```

### 3. Timeline

Linha do tempo unificada:

```text
Horario | Artefato | Acao | Fonte | Evidencia | Confianca
```

## Criterios de aceite

O sprint so deve ser considerado concluido quando:

- `launcher.exe` medio/baixo aparecer na tela final com caminho completo;
- cada cheat/indicio mostrar origem e historico;
- o relatorio mostrar hash, caminho, timestamp e fonte de cada prova;
- tentativas de bypass aparecerem em secao propria;
- `3079` sozinho nao virar conclusao critica;
- `5007` generico nao inflar score;
- `d3d10.dll` legitimo fora de FiveM Plugins nao for detectado;
- `d3d10.dll` em FiveM Plugins aparecer com caminho completo e prova;
- itens legitimos forem identificados como legitimos ou ignorados;
- score nao depender apenas de volume de eventos repetidos;
- build continuar com 0 erros e 0 avisos.

## Teste recomendado

Rodar em PowerShell como Administrador:

```powershell
cd D:\BypassNerfados
dotnet build .\BypassNerfados.sln -c Release
dotnet run --project src\Scanner\Scanner.csproj -c Release -- --no-memory --no-usn
$LASTEXITCODE
```

Validar no console:

- existe secao `CHEATS DETECTADOS / INDICIOS`;
- existe caminho completo do artefato;
- existe coluna ou campo de historico/origem;
- existe campo de alteracao/modificacao;
- existe orientacao de validacao.

Validar no TXT/HTML:

- dossie por artefato;
- timeline consolidada;
- provas brutas;
- secao anti-forense;
- itens legitimos nao poluem o topo.

## Resumo executivo para o dev

O scanner nao deve apenas dizer "suspeito". Ele deve explicar:

```text
O que foi encontrado?
Onde estava?
Quando executou?
De onde veio o sinal?
Que provas confirmam?
O que foi alterado?
Existe bypass?
E legitimo, indicio ou confirmado?
O que falta validar?
```

Esse e o proximo sprint recomendado: `Evidence Enrichment + Artifact Timeline + Provas por Finding`.
