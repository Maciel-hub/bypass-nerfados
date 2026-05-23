# Handoff - Codex QA

Status: Reprovado com P0/P1

## 1. Veredito

| Campo | Valor |
|---|---|
| Resultado | Reprovado para envio externo |
| Entrega avaliada | False positive reduction + VM detection + Steam count |
| Commit avaliado | `aa0f26f` |
| Artefato avaliado | Nao publicado/alinhado neste handoff |
| SHA256 avaliado | N/A |
| Data/hora QA | 23/05/2026 |

## 2. Resumo do QA

O commit `aa0f26f` compila com sucesso e resolve parte relevante dos falsos positivos conhecidos: `citizen` amplo, dev path do Echo, runtime DLLs no USN, Defender/harness e correlacao FiveM com entidades legitimas.

Porem a nova heuristica de virtualizacao introduz um falso positivo de severidade alta em host fisico com Hyper-V instalado. Na maquina atual, BIOS/disco indicam hardware fisico Gigabyte/Samsung, mas as chaves `vmbus` e `vmicheartbeat` existem porque Hyper-V esta instalado. O codigo atual adiciona esses sinais e emitiria `MÁQUINA VIRTUAL DETECTADA`, mesmo com servicos parados e sem indicadores de guest.

Tambem nao ha artefato publicado com ProductVersion/SHA256 alinhado ao commit `aa0f26f`, entao nao existe runtime QA fechado desta entrega.

## 3. Blockers P0

| ID | Achado | Evidencia | Correcao esperada |
|---|---|---|---|
| P0-1 | Falso positivo de VM em host fisico com Hyper-V instalado | Registro local: `vmbus=True`, `vmicheartbeat=True`; servicos `Stopped/Manual`; BIOS `Gigabyte B450 AORUS M`; disco `SAMSUNG HD161HJ` | Nao considerar mera existencia de chaves Hyper-V como VM. Exigir BIOS/disco virtual, guest additions, servicos guest em execucao, ou marcar Hyper-V host capability como Info/Low nao score-eligible |
| P0-2 | Entrega sem artefato runtime rastreavel | `handoff/CLAUDE_DONE.md` nao trouxe ProductVersion/SHA256; `agent-status` mostra artefatos antigos `1.0.0+f587b72`, nao `aa0f26f` | Publicar novo RC/GUI depois do fix e informar ProductVersion + SHA256 |
| P0-3 | Bloqueio anterior de GUI travando nao aparece resolvido nesta entrega | QA anterior: GUI inicia scan, CPU sobe, nenhuma pasta de relatorio e UI sem progresso confiavel | Confirmar fix do `ScanViewModel` com `Task.Run`/background worker e runtime GUI antes de enviar installer a tester |

## 4. Issues P1

| ID | Achado | Evidencia | Correcao esperada |
|---|---|---|---|
| P1-1 | Typo provavel no allowlist do harness | `CheatDatabase.cs` adiciona `fvem_b_harness`; o harness usado no QA foi `fivem_b_harness.exe` | Corrigir para `fivem_b_harness` e manter alias antigo se quiser |
| P1-2 | BrowserDownloads perdeu contexto de path suspeito | Agora Condition A usa apenas `fileName`; um `setup.exe` em pasta suspeita pode nao gerar sinal se URL tambem for neutra | Reintroduzir path scoring calibrado: self/dev paths suprimidos, paths suspeitos reais viram Medium/Low com ValidationHint |
| P1-3 | Falhas de Steam/VM sao silenciosas | Novos blocos usam varios `catch { }` sem `LogPartialError` | Para chaves principais, agregar falhas como partial info; para paths opcionais, ok silenciar |

## 5. Melhorias P2

| ID | Sugestao | Motivo |
|---|---|---|
| P2-1 | Steam Info deveria usar categoria mais neutra se existir | Hoje cai como `SystemTampering` por falta de categoria de inventario; pode confundir relatorio |
| P2-2 | Deteccao VM deveria ter subtipos: Guest, Host Hyper-V, Sandbox, Unknown | Ajuda analista a distinguir VM real de maquina fisica com recurso de virtualizacao |

## 6. Comandos/validacoes realizadas

```powershell
git show --stat --oneline --decorate aa0f26f
git show --name-only --format=medium aa0f26f
dotnet build .\EchoNerfados.sln -c Release --no-restore

$checks=@(
  'SYSTEM\CurrentControlSet\Services\vmbus',
  'SYSTEM\CurrentControlSet\Services\vmicheartbeat',
  'SOFTWARE\VMware, Inc.\VMware Tools',
  'SOFTWARE\Oracle\VirtualBox Guest Additions'
)

Get-Service vmbus,vmicheartbeat
Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Disk\Enum'
```

## 7. Evidencias coletadas

- Build: sucesso, 0 erros.
- Warnings: `NU1701 ManagedEsent` e `CS0162 LicenseValidator` ja conhecidos.
- Host local:
  - `vmbus`: chave existe, servico `Stopped`, `Manual`.
  - `vmicheartbeat`: chave existe, servico `Stopped`, `Manual`.
  - BIOS: `Gigabyte Technology Co., Ltd. / B450 AORUS M`.
  - Disco: `SCSI\Disk&Ven_SAMSUNG&Prod_HD161HJ`.

## 8. Decisao

- [ ] Aprovado para proximo sprint
- [x] Requer fixes P0
- [x] Requer fixes P1
- [ ] Liberado apenas para teste controlado

## 9. Mensagem curta para o dev

```text
QA do commit aa0f26f reprovado para envio externo.

Build passou, mas a nova deteccao de VM tem falso positivo serio:
em host fisico com Hyper-V instalado, as chaves vmbus/vmicheartbeat existem mesmo sem ser VM.
Nesta maquina: BIOS Gigabyte B450 AORUS M, disco Samsung fisico, vmbus/vmicheartbeat Stopped/Manual.
O codigo atual emitiria "MÁQUINA VIRTUAL DETECTADA".

Corrigir:
1. Nao usar existencia de service key Hyper-V como evidencia de VM.
2. Hyper-V host capability isolado = Info/scoreEligible=false ou ignorar.
3. VM High apenas com BIOS/disco virtual, guest additions reais ou servico guest rodando + outro indicador.
4. Corrigir typo fvem_b_harness -> fivem_b_harness.
5. Publicar novo artefato com ProductVersion/SHA256 alinhado.
6. Confirmar tambem o P0 anterior da GUI travando no scan.
```

