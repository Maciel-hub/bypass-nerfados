# Sprint B — Qualidade do Veredito e Experiência de Análise

## Contexto

O scanner passou do ponto "funciona": build limpo, smoke test ok, tag `sprint-a-complete` criada.
O próximo salto não é detectar mais coisa — é classificar melhor, agrupar, reduzir ruído e
transformar o resultado em uma investigação legível.

Resultado observado no primeiro smoke test real:
- 1153 CRITICAL e 2169 HIGH → score saturado em 100/100 → perde valor investigativo
- `launcher.exe` disparou GOSTH para Rockstar, Wallpaper Engine e outros launchers comuns
- Spotify e Python apareceram como rede suspeita
- O relatório tem volume, mas não tem triagem

---

## Prioridade P0 — Impede uso real

### 1. Reduzir falso positivo de `launcher.exe`

**Problema:** `launcher.exe` vira GOSTH apenas pelo nome em
`src/Scanner/Data/CheatDatabase.cs:16`. Nome sozinho é sinal fraco — qualquer launcher comum
(Rockstar, Wallpaper Engine, Epic) dispara Critical.

**Solução:** exigir combinação de sinais antes de marcar como Critical:
- Caminho típico do GOSTH (`AppData\Local\Programs\Common`, `AppData\Local\Temp`)
- Hash SHA1 conhecido (`CheatDatabase.KnownExecutables["launcher.exe"].Hashes`)
- Registro no Prefetch ou MuiCache
- Assinatura digital ausente ou publisher desconhecido

**Regra de confiança sugerida:**
- Nome apenas → `Confidence.Low`, `RiskLevel.Medium`
- Nome + caminho típico → `Confidence.Medium`, `RiskLevel.High`
- Nome + caminho + hash confirmado → `Confidence.High`, `RiskLevel.Critical`

**Referências:**
- `CheatDatabase.cs:16` — entrada `launcher.exe`
- `KnownCheatsModule.cs:57` — `TryGetValue` por nome, sem verificação de caminho
- `BaseModule.cs:51` — `ClassifyExecutablePath` existe mas não é chamado aqui

---

### 2. Deduplicar findings

**Problema:** o mesmo arquivo/evento aparece N vezes — uma vez por módulo que o detectou,
uma vez por cada varredura de pasta. 2169 HIGH não significa 2169 evidências distintas.

**Solução:** criar `EvidenceKey` por entidade antes de adicionar à lista:

```
module|category|path_normalizado|eventId|timestampBucket(hora)
```

Implementar em `ScanResult` ou em um `FindingDeduplicator` chamado antes do
`Correlator.Correlate()` em `ScanOrchestrator.cs:97`.

**Referências:**
- `ScanResult.cs:19` — `TotalScore` soma tudo sem distinção
- `ScanOrchestrator.cs:57` — `_result.Findings.AddRange(findings)` sem dedup

---

### 3. Adicionar `ConfidenceScore` ao modelo de Finding

**Problema:** `Finding.cs` tem `Risk`, `Category`, `Evidence`, `Timestamp` — mas não tem
como separar "certeza" de "severidade". Um hash confirmado e um nome suspeito aparecem
com o mesmo peso no relatório.

**Campos sugeridos para `Finding`:**

```csharp
public enum Confidence { Low = 1, Medium = 2, High = 3, Confirmed = 4 }

public record Finding(
    RiskLevel Risk,
    FindingCategory Category,
    string Module,
    string Title,
    string Detail,
    string? Evidence = null,
    DateTime? Timestamp = null,
    Confidence Confidence = Confidence.Medium,  // novo
    string? RuleId = null,                      // novo — ex: "GOSTH_HASH_CONFIRMED"
    string? Entity = null,                      // novo — arquivo, PID, IP, EventID
    string? ValidationHint = null               // novo — "Validar assinatura digital"
);
```

**Por que `RuleId`:** permite correlação estruturada, deduplication por regra, e futuro
filtro na UI ("mostrar apenas RuleId=GOSTH_*").

**Referências:**
- `Finding.cs:3` — definição do record

---

### 4. Refazer cálculo de score

**Problema:** `ScanResult.cs:19` soma `f.Score` de todos os findings e limita em 100.
Com 3000+ findings, o resultado é sempre 100, independente do que foi encontrado.

**Solução:** calcular por sinais únicos ponderados por confiança:

```csharp
TotalScore = Math.Min(
    Findings
        .DistinctBy(f => f.EvidenceKey)   // após dedup
        .Sum(f => f.Score * (int)f.Confidence / 2),
    100
);
```

Onde `Score` base permanece (Critical=50, High=25, Medium=10, Low=5), mas é multiplicado
pela confiança: Low=0.5x, Medium=1x, High=1.5x, Confirmed=2x.

**Referências:**
- `ScanResult.cs:19` — `TotalScore`
- `Finding.cs:14` — `Score` property

---

## Prioridade P1 — Qualidade e produto

### 5. Calibrar Event Viewer

**Problema:** `ScanUsnResetEvent` em `EventViewerModule.cs:106` e outras rotinas pontuais
não aplicam `EventWindowLookback` da mesma forma que as rotinas principais. Isso gera
ruído de eventos históricos.

**Solução:**
- Aplicar `since = DateTime.UtcNow - config.EventWindowLookback` em TODAS as consultas
- Adicionar `MaxResults` por EventID (ex: máximo 10 por ID único na janela)
- Agrupar eventos repetidos do mesmo ID no mesmo minuto

**Referências:**
- `EventViewerModule.cs:106` — `ScanUsnResetEvent`
- `ScanConfig.cs` — `EventWindowLookback`

---

### 6. Reduzir falsos positivos de rede

**Problema:** Spotify, Python e outros processos comuns com conexão externa aparecem como
HIGH em `NetworkModule.cs:72`.

**Solução antes de marcar como suspeito:**
1. Allowlist de publishers conhecidos (Spotify AB, Python Software Foundation, Microsoft)
2. Verificar assinatura digital do executável (`Authenticode`)
3. Checar se IP de destino é CDN/ASN conhecida antes de marcar como externo suspeito
4. Só marcar HIGH se: processo sem assinatura + IP externo + caminho em AppData/Temp

**Referências:**
- `NetworkModule.cs:72` — lógica de classificação de conexões

---

### 7. Relatório executivo

**Problema:** o relatório abre direto com a tabela de 3000+ findings, sem triagem.

**Solução:** adicionar seção executiva no topo do HTML com cinco grupos:

| Grupo | Critério |
|---|---|
| **Cheat confirmado** | `Confidence.Confirmed` ou `Confidence.High` + `FindingCategory.Cheat` |
| **Indícios fortes** | `RiskLevel.Critical` + `Confidence.Medium` |
| **Possíveis falsos positivos** | `Confidence.Low` ou nome-apenas sem hash |
| **Requer validação manual** | Findings com `ValidationHint != null` |
| **Evidências correlacionadas** | Findings gerados pelo `Correlator` |

**Referências:**
- `HtmlTemplate.cs:9` — método `Build`, inserir seção antes dos findings por categoria

---

### 8. Modos de varredura

**Solução:** criar enum `ScanMode` em `ScanConfig` e ajustar `BuildModuleList` em
`ScanOrchestrator.cs:161`:

```csharp
public enum ScanMode { Quick, Full, Deep }

// Quick: BamDam, Prefetch, Registry, KnownCheats, EventViewer (janela 7d)
// Full: tudo atual (padrão)
// Deep: Full + USN + ProcessMemory + FileSystem pesado
```

CLI: `--mode quick|full|deep`

**Referências:**
- `ScanOrchestrator.cs:161` — `BuildModuleList`
- `ScanConfig.cs` — adicionar `ScanMode`

---

## Interface WPF (Sprint B paralelo)

Conforme `DOCUMENTACAO_APP_UNICO_DEV.md`. Com as mudanças de modelo acima, a UI pode
expor diretamente:

- Filtro por `Confidence` na tela de findings
- Badge de `RuleId` no painel lateral
- `ValidationHint` como ação sugerida por finding
- Score calculado por sinais únicos no gauge da tela de resultado
- Seção executiva como tela de "Resumo" antes da lista completa

---

## Ordem de implementação recomendada

```
1. Finding.cs     — adicionar Confidence, RuleId, Entity, ValidationHint
2. CheatDatabase  — revisar entrada launcher.exe: exigir caminho ou hash
3. KnownCheatsModule — usar Confidence ao criar findings por nome vs hash
4. FindingDeduplicator — novo helper, chamado em ScanOrchestrator antes de Correlate
5. ScanResult     — TotalScore ponderado por Confidence
6. NetworkModule  — allowlist + assinatura digital
7. EventViewerModule — EventWindowLookback uniforme
8. HtmlTemplate   — seção executiva no topo
9. ScanConfig     — ScanMode enum
10. ScanOrchestrator — BuildModuleList por ScanMode
```

Não começar a UI antes dos itens 1–5, porque `Confidence` e `RuleId` são campos que a
UI precisa consumir.
