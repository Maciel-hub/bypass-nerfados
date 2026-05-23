# Next Sprint

Status: P0 fix sprint recomendado

## 1. Sprint recomendado

| Campo | Valor |
|---|---|
| Nome | QA fixes - VM false positive + GUI runtime + artifact alignment |
| Prioridade | P0 |
| Objetivo | Corrigir falso positivo de VM em host Hyper-V, garantir GUI responsiva no scan e publicar artefato rastreavel |
| Bloqueia release? | Sim |

## 2. Escopo

- Corrigir `SystemInfoModule.CheckVirtualization`.
- Separar indicadores:
  - VM guest confirmado;
  - Hyper-V host capability;
  - guest additions;
  - BIOS/disk virtual;
  - service key isolada.
- Corrigir typo `fvem_b_harness`.
- Garantir que GUI rode scan em background e nao trave.
- Publicar RC/GUI com ProductVersion e SHA256 alinhados.
- Atualizar `handoff/CLAUDE_DONE.md` depois da entrega.

## 3. Fora de escopo

- Novas familias de cheat.
- Obfuscacao/rules encryption.
- Certificado Authenticode comercial.
- Redesign completo da GUI.

## 4. Arquivos provaveis

| Arquivo/Area | Motivo |
|---|---|
| `src/Scanner/Modules/SystemInfoModule.cs` | Ajustar heuristica VM |
| `src/Scanner/Data/CheatDatabase.cs` | Corrigir harness alias |
| `src/EchoNerfados.App/ViewModels/ScanViewModel.cs` | Rodar scan fora da UI thread |
| `BUILD-RC.bat` / `scripts/package.ps1` | Apenas se necessario para publicar artefato final |

## 5. Criterios de aceite

- [ ] Host fisico com Hyper-V instalado nao gera `MÁQUINA VIRTUAL DETECTADA` High.
- [ ] Hyper-V host capability isolado, se reportado, fica Info/scoreEligible=false.
- [ ] VM real ainda e detectada por BIOS/disk/guest additions.
- [ ] `fivem_b_harness` esta allowlisted corretamente.
- [ ] GUI nao trava ao iniciar scan.
- [ ] GUI cria pasta `Echo_Nerfados_*` ao concluir.
- [ ] ProductVersion do CLI/GUI/installer alinha com commit da entrega.
- [ ] SHA256 documentado em `handoff/CLAUDE_DONE.md`.

## 6. Riscos

| Risco | Mitigacao |
|---|---|
| Rebaixar VM demais e perder deteccao real | Exigir 2 sinais ou 1 sinal forte: BIOS/disk virtual, VMware/VirtualBox guest additions |
| Task.Run na GUI quebrar progress updates | Criar `Progress<ScanProgressUpdate>` na UI thread antes do `Task.Run` |
| Publicar artefato antigo | Rodar `scripts\agent-status.ps1` e conferir ProductVersion/SHA |

## 7. Prompt para enviar ao Claude

```text
Siga AGENTS_PROTOCOL.md.

Sprint: QA fixes - VM false positive + GUI runtime + artifact alignment

Objetivo:
Corrigir os P0/P1 apontados em handoff/CODEX_QA.md para o commit aa0f26f.

Escopo:
- Corrigir SystemInfoModule.CheckVirtualization para nao marcar host fisico com Hyper-V instalado como VM.
- Service keys vmbus/vmicheartbeat isoladas nao podem gerar High.
- VM High apenas com BIOS/disk virtual, guest additions reais ou service guest rodando + outro indicador.
- Corrigir typo fvem_b_harness para fivem_b_harness.
- Confirmar/corrigir GUI travando ao iniciar scan: ScanOrchestrator deve rodar fora da UI thread, mantendo Progress na UI thread.
- Publicar novo artefato RC/GUI e documentar ProductVersion + SHA256.

Criterios de aceite:
- Build 0 erros.
- Host fisico com Hyper-V instalado nao gera VM High.
- GUI inicia scan sem congelar.
- Pasta de relatorio e criada ao concluir.
- handoff/CLAUDE_DONE.md preenchido com commit, ProductVersion e SHA256.

Ao terminar, atualize handoff/CLAUDE_DONE.md e pare para QA.
```

