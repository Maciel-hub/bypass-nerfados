# Handoff - Claude Done

Status: Entrega recebida para QA

## 1. Identificacao

| Campo | Valor |
|---|---|
| Sprint/Fix | P0 smoke — installer per-user sem admin |
| Commit produto | `9fca162` |
| Branch | `master` |
| ProductVersion CLI/GUI | `1.0.1+f194191` (binarios nao mudaram) |
| GUI SHA256 | `9028F2A0DE1CC8FEC91D6FB94D2F8E8A38D14C21760C90F37E28B9506252D84D` |
| CLI SHA256 | `E1AAAD7F57A7053A6F451FCD2BE1BEFA51B3AE6D204A26D8C3457AF962013E4C` |
| Installer per-user | `dist/EchoNerfadosSetup-RC-User-1.0.1+f194191.exe` |
| Installer SHA256 | `FD3FB5851BDA023D8A6CCF2570556C11B2E858822C73251AFD4BDBE53A94A4CF` |
| Data/hora | 23/05/2026 |

## 2. Objetivo da entrega

P0 smoke externo: tester recebia "You must be logged in as an administrator".

Causa: `EchoNerfados.iss` usa `PrivilegesRequired=admin`, `{commonappdata}` e `{commondesktop}`.

Solucao: novo script `installer/EchoNerfados-RC-User.iss` para distribuicao de teste externo.

## 3. Arquivos alterados

| Arquivo | Commit | Descricao |
|---|---|---|
| `installer/EchoNerfados-RC-User.iss` | `9fca162` | Novo — installer per-user sem admin |

Binarios CLI/GUI nao foram republicados (nenhuma mudanca de codigo).

## 4. Mudancas tecnicas

### EchoNerfados-RC-User.iss vs EchoNerfados.iss

| Campo | Admin (original) | Per-user (novo) |
|---|---|---|
| `PrivilegesRequired` | `admin` | `lowest` |
| `DefaultDirName` | `{autopf}\EchoNerfados` | `{localappdata}\Programs\EchoNerfados` |
| Desktop shortcut | `{commondesktop}` | `{userdesktop}` |
| Start menu | `{group}` (commonprograms) | `{group}` (userprograms — resolve per-user com lowest) |
| `[Dirs]` commonappdata | Sim | Nao |
| `IncludeLicense` | Suportado | Removido |
| `AppId` | `{5E8D7F2A-...}` | `{A1F3C7D2-...}` (GUID diferente) |
| OutputBaseFilename | `EchoNerfadosSetup-RC-*` | `EchoNerfadosSetup-RC-User-*` |

O `[Code]` de desinstalacao que referenciava `{commonappdata}` foi removido
(nao existe ProgramData nesta variante).

## 5. Criterios de aceite

- [x] Script compila com 0 erros no ISCC.
- [x] Installer gerado: `EchoNerfadosSetup-RC-User-1.0.1+f194191.exe`.
- [x] SHA256 documentado.
- [ ] Instala sem pedir elevacao UAC.
- [ ] GUI abre apos instalacao.
- [ ] Varredura inicia e gera relatorio.

## 6. Comandos executados pelo dev

```powershell
& 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' /DAppVersion=1.0.1 /DBuildTag=+f194191 installer\EchoNerfados-RC-User.iss

Get-FileHash dist\EchoNerfadosSetup-RC-User-1.0.1+f194191.exe -Algorithm SHA256
# FD3FB5851BDA023D8A6CCF2570556C11B2E858822C73251AFD4BDBE53A94A4CF
```

## 7. Comandos para QA

```powershell
# Verificar PrivilegesRequired no novo script
rg "PrivilegesRequired|DefaultDirName|commonappdata|commondesktop|userdesktop" installer\EchoNerfados-RC-User.iss

# SHA256 do installer
Get-FileHash dist\EchoNerfadosSetup-RC-User-1.0.1+f194191.exe -Algorithm SHA256
# Esperado: FD3FB5851BDA023D8A6CCF2570556C11B2E858822C73251AFD4BDBE53A94A4CF

# Smoke test:
# 1. Instalar como usuario sem direitos de admin
# 2. Verificar instalacao em %LOCALAPPDATA%\Programs\EchoNerfados
# 3. Abrir GUI
# 4. Iniciar varredura
# 5. Verificar relatorio gerado
```

## 8. Observacoes para o Codex

- Enviar somente `EchoNerfadosSetup-RC-User-1.0.1+f194191.exe` para o tester externo.
- O installer admin original `EchoNerfadosSetup-RC-1.0.1+f194191.exe` permanece valido para uso interno/QA.
- `EchoNerfados-RC-User.iss` nao inclui suporte a `IncludeLicense` — adequado enquanto `EnforceLicense=false`.
- Quando a licenca comercial for ativada, este script precisara de revisao.
