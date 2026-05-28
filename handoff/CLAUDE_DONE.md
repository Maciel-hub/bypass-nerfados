# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | Fix P1 — MemoryStringScan self-scan FP (MEMSTR_BR_ANTICHEAT_BYPASS em EchoNerfados) |
| Commit produto | `f4d5994` |
| Branch | `master` |
| ProductVersion CLI/GUI | `1.0.1+f4d5994` |
| CLI SHA256 | `B083F8BFB60F935BAD93761BEB512ADD038435E807981A93192B0A6CC8FDF687` |
| GUI SHA256 | `929CA338829D1E0A5245FD5FE377D3293866C9DFB0E870DFEC0C009441DCE3EC` |
| Installer per-user | `dist/EchoNerfadosSetup-RC-User-1.0.1+f4d5994.exe` |
| Installer per-user SHA256 | `7F978BD8672A054D1939804AD4FBADA57A775A2FAD4EDEA6182662395AD9928E` |
| Installer admin | `dist/EchoNerfadosSetup-RC-1.0.1+f4d5994.exe` |
| Installer admin SHA256 | `8035442308043A9A3E28CF0A17B3F17919FC3214816E50D9B3B59F0D542D1230` |
| Data/hora | 27/05/2026 |

## 2. Objetivo da entrega

Fix de auto-detecção: MemoryStringScanModule estava varrendo a memória do próprio
scanner (EchoNerfados.exe) e encontrando as strings de cheat embutidas no detector.
Resultado: MEMSTR_BR_ANTICHEAT_BYPASS com origem em EchoNerfados.Core.dll.

## 3. Causa raiz

`IsRandomName("EchoNerfados")` = TRUE porque E e N são uppercase (2 upper + 11 lower
satisfaz o critério mixed-case). Resultado:

1. `SuspiciousCoProcessResolver.Resolve()` identificava EchoNerfados como co-processo
   suspeito (user-writable path + nome "aleatório")
2. `CollectTargetProcesses()` adicionava o PID do scanner à lista de alvos
3. O scanner varria a sua própria memória — EchoNerfados.Core.dll carrega as strings
   de cheat como literais para matching, que então eram "detectadas"

## 4. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `src/Scanner/Core/SuspiciousCoProcessResolver.cs` | `f4d5994` | "echonerfados" + aliases adicionados ao s_knownSafe |
| `src/Scanner/Modules/MemoryStringScanModule.cs` | `f4d5994` | CollectTargetProcesses: filtro duplo ownPid + IsOwnProcess; ShouldScanModule: IsOwnProcess(path) |
| `src/Scanner/Modules/MemoryDllTraceModule.cs` | `f4d5994` | CollectTargetProcesses: mesmo filtro duplo |

## 5. Mudancas tecnicas

### Layer 1 — SuspiciousCoProcessResolver.s_knownSafe

Adicionados ao conjunto de nomes seguros (matcheado por stem em lowercase):
- `"echonerfados"` — CLI scanner
- `"bypassnerfados"` — nome historico
- `"memoryharness"` — harness de teste
- `"ecoharness"` — variante de harness

### Layer 2 — CollectTargetProcesses (MemoryStringScan + MemoryDllTrace)

```csharp
var ownPid = Environment.ProcessId;

void Add(Process p)
{
    if (p.Id == ownPid) return;             // nunca varrer o proprio processo
    if (IsOwnProcess(p.ProcessName)) return; // cobre EchoNerfados, EchoNerfados.App, etc.
    if (seen.Add(p.Id)) result.Add(p);
}
```

`IsOwnProcess` (definido em BaseModule) verifica:
- Nome exato do processo atual
- Aliases historicos (_selfExeAliases): "echonerfados.exe", "bypassnerfados.exe"
- Fragmentos de path de build (_selfPathFragments): \bypassnerfados\, \echonerfados\

### Layer 3 — ShouldScanModule (MemoryStringScan)

```csharp
if (IsOwnProcess(path)) return false;
```

Adicionado como primeira verificacao — impede que EchoNerfados.Core.dll seja varrido
mesmo que o assembly esteja carregado em outro processo (cenario improvavel mas seguro).

MemoryDllTraceModule ja tinha `IsOwnProcess(path)` no filtro de modulo (linha 300) —
nenhuma alteracao necessaria la.

## 6. Criterios de aceite

- [x] Build 0 erros (9 avisos pre-existentes)
- [x] Commit `f4d5994` com ProductVersion `1.0.1+f4d5994`
- [x] Installers gerados e SHA256 documentados
- [ ] Varredura pos-limpeza: MEMSTR_BR_ANTICHEAT_BYPASS NAO aparece para EchoNerfados
- [ ] EchoNerfados.Core.dll NAO aparece em findings de Memory String Scan / Memory DLL Trace
- [ ] Processo EchoNerfados NAO aparece em "Co-processos ativos" na aba Sessao FiveM

## 7. Comandos para QA

```powershell
# 1. Verificar allowlist
Select-String "echonerfados" src\Scanner\Core\SuspiciousCoProcessResolver.cs
# Esperado: 1 match em s_knownSafe

# 2. Verificar filtro duplo em CollectTargetProcesses
Select-String "ownPid|IsOwnProcess" src\Scanner\Modules\MemoryStringScanModule.cs
# Esperado: 3 matches (var ownPid, if p.Id == ownPid, if IsOwnProcess)

# 3. Verificar ShouldScanModule
Select-String "IsOwnProcess" src\Scanner\Modules\MemoryStringScanModule.cs
# Esperado: 2 matches (CollectTargetProcesses + ShouldScanModule)

# 4. Teste funcional:
# - Executar varredura com admin em maquina pos-limpeza
# - Verificar: nenhum finding com Module="Memory String Scan" e Title contendo "EchoNerfados"
# - Verificar: EchoNerfados.Core.dll NAO aparece em findings

# 5. SHA256 installers
certutil -hashfile dist\EchoNerfadosSetup-RC-User-1.0.1+f4d5994.exe SHA256
# Esperado: 7F978BD8672A054D1939804AD4FBADA57A775A2FAD4EDEA6182662395AD9928E
```

## 8. Observacoes para o Codex

- Installer anterior (a17f02e) invalido para este QA — usar f4d5994.
- A causa raiz e o criterio mixed-case em IsRandomName: 2+ uppercase + 2+ lowercase.
  "EchoNerfados" tem E,N uppercase (2) + 11 lowercase → trigava. Corrigido na allowlist.
- O filtro duplo em CollectTargetProcesses (ownPid + IsOwnProcess) e defense-in-depth:
  a allowlist em s_knownSafe e a correcao primaria; os filtros de colecao e modulo
  garantem que mesmo uma renomeacao do scanner nao resulte em auto-varredura.
- MemoryDllTraceModule.ShouldInspectModule ja tinha IsOwnProcess(path) — nao alterado.
