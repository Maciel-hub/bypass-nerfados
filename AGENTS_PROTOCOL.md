# Echo Nerfados - Protocolo de colaboracao entre agentes

Este documento define o fluxo entre agentes para evitar conflito, regressao e trabalho duplicado.

## Papeis

### Claude - Dev executor

Responsavel por:

- implementar codigo;
- ajustar projetos, builds e installer;
- criar commits;
- publicar artefatos locais;
- preencher `handoff/CLAUDE_DONE.md` ao terminar cada sprint/fix.

Claude nao deve iniciar outro sprint antes de receber QA em `handoff/CODEX_QA.md`, salvo se o usuario pedir explicitamente.

### Codex - QA, arquitetura e analise

Responsavel por:

- revisar escopo tecnico;
- validar riscos P0/P1/P2;
- analisar falso positivo/falso negativo;
- revisar UX, seguranca, cadeia de custodia e packaging;
- gerar criterios de aceite;
- preencher `handoff/CODEX_QA.md`;
- propor o proximo sprint em `handoff/NEXT_SPRINT.md`.

Codex nao deve alterar codigo de produto durante o ciclo normal. Excecoes: docs, templates, roteiros QA ou scripts auxiliares quando o usuario pedir.

## Ciclo padrao

1. Claude implementa uma entrega pequena e rastreavel.
2. Claude roda build/teste minimo.
3. Claude atualiza `handoff/CLAUDE_DONE.md`.
4. Codex roda/analisa o QA possivel.
5. Codex atualiza `handoff/CODEX_QA.md`.
6. Se aprovado, Codex atualiza `handoff/NEXT_SPRINT.md`.
7. Se reprovado, Claude corrige apenas os blockers listados.

## Regras obrigatorias

- Um agente por vez altera codigo.
- Commits devem ser pequenos e descrever claramente o objetivo.
- Artefato publicado precisa ter ProductVersion e SHA256 documentados.
- Toda entrega deve ter criterios de aceite.
- QA deve separar P0, P1 e P2.
- P0 bloqueia envio externo.
- P1 bloqueia release comercial, mas pode permitir teste controlado.
- P2 entra no backlog se nao afetar seguranca, deteccao ou integridade.

## Definicao de P0/P1/P2

| Prioridade | Significado | Acao |
|---|---|---|
| P0 | Crash, travamento, dado incorreto, falha de custodia, falso positivo grave, falso negativo critico, installer quebrado | Corrigir antes de seguir |
| P1 | Risco relevante de UX, performance, diagnostico incompleto, falta de evidencia ou docs erradas | Corrigir antes de release ampla |
| P2 | Melhoria incremental, clareza, refino visual, automacao extra | Backlog |

## Arquivos de handoff

| Arquivo | Dono principal | Finalidade |
|---|---|---|
| `handoff/CLAUDE_DONE.md` | Claude | Entrega feita pelo dev |
| `handoff/CODEX_QA.md` | Codex | Parecer QA da entrega |
| `handoff/NEXT_SPRINT.md` | Codex + usuario | Proximo escopo aprovado |
| `QA_RUNTIME_CHECKLIST.md` | Codex | Checklist manual/runtime reutilizavel |

## Comando de status

Use:

```powershell
pwsh -File scripts\agent-status.ps1
```

Esse script e read-only. Ele nao faz build, nao altera arquivos e nao executa o produto.

## Mensagem padrao para Claude

```text
Siga AGENTS_PROTOCOL.md.

Ao terminar, atualize handoff/CLAUDE_DONE.md com:
1. commit;
2. build/ProductVersion;
3. SHA256;
4. arquivos alterados;
5. o que mudou;
6. riscos conhecidos;
7. comandos de QA;
8. criterios de aceite.

Depois pare e aguarde handoff/CODEX_QA.md.
```

