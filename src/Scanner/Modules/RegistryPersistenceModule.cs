using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Scans advanced registry persistence mechanisms and known cheat auto-run locations.
/// Covers: IFEO debugger hijack, AppInit_DLLs, AppCertDlls, Winlogon hooks,
/// BootExecute, and cheat-specific Run key entries.
/// </summary>
public class RegistryPersistenceModule : BaseModule
{
    public override string Name        => "RegistryPersistence";
    public override string Description => "Persistência no registro — IFEO, AppInit, AppCertDlls, Winlogon, BootExecute, Run keys";

    // Legitimate debuggers for IFEO — not suspicious when set as Debugger value
    private static readonly HashSet<string> LegitDebuggers = new(StringComparer.OrdinalIgnoreCase)
    {
        "vsjitdebugger.exe",
        "drwtsn32.exe",
        "windbg.exe",
        "ntsd.exe",
        "cdb.exe",
    };

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        ScanIfeo(findings, ct);
        ct.ThrowIfCancellationRequested();

        ScanAppInitDlls(findings);
        ct.ThrowIfCancellationRequested();

        ScanAppCertDlls(findings);
        ct.ThrowIfCancellationRequested();

        ScanWinlogon(findings);
        ct.ThrowIfCancellationRequested();

        ScanBootExecute(findings);
        ct.ThrowIfCancellationRequested();

        ScanCheatRunKeys(findings);

        return Task.FromResult(findings);
    }

    // ── IFEO (Image File Execution Options) debugger hijack ────────────────────────

    private static void ScanIfeo(List<Finding> findings, CancellationToken ct)
    {
        const string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        try
        {
            using var ifeoKey = Registry.LocalMachine.OpenSubKey(ifeoPath);
            if (ifeoKey == null) return;

            foreach (var subKeyName in ifeoKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var subKey = ifeoKey.OpenSubKey(subKeyName);
                    if (subKey == null) continue;

                    var debugger = subKey.GetValue("Debugger")?.ToString() ?? "";
                    if (string.IsNullOrWhiteSpace(debugger)) continue;

                    var debuggerExe = Path.GetFileName(debugger.Trim()).ToLowerInvariant();
                    if (LegitDebuggers.Contains(debuggerExe)) continue;

                    var targetLower = subKeyName.ToLowerInvariant();

                    // If the IFEO target matches a known cheat executable → Critical
                    if (CheatDatabase.IsKnownCheatExecutable(targetLower))
                    {
                        var cheat = CheatDatabase.KnownExecutables[targetLower];
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.Cheat,
                            "RegistryPersistence",
                            $"IFEO HIJACK — CHEAT: {cheat.Name} ({subKeyName})",
                            $"Cheat configurado como debugger via IFEO. Qualquer execução de '{subKeyName}' " +
                            $"dispara '{debugger}' em seu lugar — técnica de sequestro de processo.\n{cheat.Description}",
                            $"IFEO\\{subKeyName}\\Debugger = {debugger}",
                            confidence: Confidence.High,
                            ruleId: $"IFEO_CHEAT_{targetLower.ToUpperInvariant().Replace('.', '_')}",
                            entity: subKeyName
                        ));
                    }
                    else
                    {
                        // Any non-legit debugger configured under IFEO is suspicious system tampering
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.SystemTampering,
                            "RegistryPersistence",
                            $"IFEO Debugger suspeito: {subKeyName} → {debuggerExe}",
                            $"Entrada IFEO com debugger não padrão. Pode ser usado para injeção de processo " +
                            $"ou evasão de proteção anti-cheat.\nDebugger: {debugger}",
                            $"IFEO\\{subKeyName}\\Debugger = {debugger}",
                            confidence: Confidence.Medium,
                            ruleId: $"IFEO_DEBUGGER_{targetLower.ToUpperInvariant().Replace('.', '_')}",
                            entity: subKeyName
                        ));
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    // ── AppInit_DLLs (global DLL injection into every user-mode process) ───────────

    private static void ScanAppInitDlls(List<Finding> findings)
    {
        var appInitPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        };

        foreach (var regPath in appInitPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;

                var value = key.GetValue("AppInit_DLLs")?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(value)) continue;

                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.SystemTampering,
                    "RegistryPersistence",
                    $"AppInit_DLLs configurado: {value}",
                    $"DLLs listadas em AppInit_DLLs são carregadas em todos os processos que usam User32.dll. " +
                    $"Técnica clássica de injeção de DLL. Chave: HKLM\\{regPath}",
                    $"AppInit_DLLs = {value}",
                    confidence: Confidence.High,
                    ruleId: "APPINIT_DLLS",
                    entity: value
                ));
            }
            catch { }
        }
    }

    // ── AppCertDlls (loaded into every process, code-signing bypass) ───────────────

    private static void ScanAppCertDlls(List<Finding> findings)
    {
        const string appCertPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(appCertPath);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                var dll = key.GetValue(valueName)?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(dll)) continue;

                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.SystemTampering,
                    "RegistryPersistence",
                    $"AppCertDlls — DLL carregada em todos os processos: {Path.GetFileName(dll)}",
                    $"AppCertDlls é um vetor de persistência avançado. A DLL é carregada em cada novo processo " +
                    $"por CreateProcess(). Normalmente vazia em sistemas limpos.",
                    $"HKLM\\{appCertPath}\\{valueName} = {dll}",
                    confidence: Confidence.High,
                    ruleId: $"APPCERT_{valueName.ToUpperInvariant().Replace(' ', '_')}",
                    entity: dll
                ));
            }
        }
        catch { }
    }

    // ── Winlogon hooks (Userinit / Shell hijack) ───────────────────────────────────

    private static void ScanWinlogon(List<Finding> findings)
    {
        const string winlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(winlogonPath);
            if (key == null) return;

            // Userinit: expected canonical value
            var userinit = key.GetValue("Userinit")?.ToString() ?? "";
            if (!string.IsNullOrEmpty(userinit))
            {
                var canonical = @"C:\Windows\system32\userinit.exe,";
                if (!userinit.Equals(canonical, StringComparison.OrdinalIgnoreCase) &&
                    !userinit.Equals(canonical.TrimEnd(','), StringComparison.OrdinalIgnoreCase))
                {
                    // Check if extra executables were added after the canonical value
                    var extra = userinit
                        .Replace(canonical, "", StringComparison.OrdinalIgnoreCase)
                        .Replace(canonical.TrimEnd(','), "", StringComparison.OrdinalIgnoreCase)
                        .Trim().Trim(',');

                    if (!string.IsNullOrWhiteSpace(extra) ||
                        !userinit.Contains("userinit", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.SystemTampering,
                            "RegistryPersistence",
                            $"Winlogon\\Userinit modificado",
                            $"O valor Userinit deveria ser apenas '{canonical}'. " +
                            $"Valor atual indica possível sequestro de logon.\nValor: {userinit}",
                            $"HKLM\\{winlogonPath}\\Userinit = {userinit}",
                            confidence: Confidence.High,
                            ruleId: "WINLOGON_USERINIT",
                            entity: userinit
                        ));
                    }
                }
            }

            // Shell: expected value is explorer.exe
            var shell = key.GetValue("Shell")?.ToString() ?? "";
            if (!string.IsNullOrEmpty(shell) &&
                !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.SystemTampering,
                    "RegistryPersistence",
                    $"Winlogon\\Shell modificado: {shell}",
                    $"O valor Shell deveria ser 'explorer.exe'. " +
                    $"Valor não padrão pode indicar shell replacement por malware/cheat loader.",
                    $"HKLM\\{winlogonPath}\\Shell = {shell}",
                    confidence: Confidence.High,
                    ruleId: "WINLOGON_SHELL",
                    entity: shell
                ));
            }
        }
        catch { }
    }

    // ── BootExecute (runs before Windows fully loads) ─────────────────────────────

    private static void ScanBootExecute(List<Finding> findings)
    {
        const string smPath = @"SYSTEM\CurrentControlSet\Control\Session Manager";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(smPath);
            if (key == null) return;

            var value = key.GetValue("BootExecute");
            if (value == null) return;

            // The value is typically a REG_MULTI_SZ: ["autocheck autochk *"]
            string[] entries = value switch
            {
                string[] arr => arr,
                string s     => [s],
                _            => []
            };

            // Remove standard canonical entry, flag anything extra
            var extra = entries
                .Where(e => !string.IsNullOrWhiteSpace(e) &&
                            !e.Equals("autocheck autochk *", StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var entry in extra)
            {
                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.SystemTampering,
                    "RegistryPersistence",
                    $"BootExecute com entrada não padrão: {entry}",
                    $"Entradas em BootExecute são executadas pelo Session Manager antes que o Windows carregue " +
                    $"completamente. Técnica usada por bootkits e drivers de kernel maliciosos.",
                    $"HKLM\\{smPath}\\BootExecute += {entry}",
                    confidence: Confidence.High,
                    ruleId: "BOOTEXECUTE_EXTRA",
                    entity: entry
                ));
            }
        }
        catch { }
    }

    // ── Run keys — cheat-specific scan ────────────────────────────────────────────

    private static void ScanCheatRunKeys(List<Finding> findings)
    {
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        };

        foreach (var regPath in runKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    if (string.IsNullOrWhiteSpace(value)) continue;

                    // Normalize: strip quotes and arguments, get just the exe path
                    var cleanValue = value.TrimStart('"');
                    var exePath    = cleanValue.Contains('"')
                        ? cleanValue[..cleanValue.IndexOf('"')]
                        : cleanValue.Split(' ')[0];

                    var exeName = Path.GetFileName(exePath).ToLowerInvariant();

                    if (IsOwnProcess(exeName)) continue;
                    if (CheatDatabase.IsKnownLegitimate(exePath) || CheatDatabase.IsKnownLegitimate(valueName)) continue;

                    // Cheat executable name → Cheat finding
                    if (CheatDatabase.IsKnownCheatExecutable(exeName))
                    {
                        var cheat = CheatDatabase.KnownExecutables[exeName];
                        findings.Add(new Finding(
                            cheat.IsGenericName ? RiskLevel.Medium : RiskLevel.Critical,
                            FindingCategory.Cheat,
                            "RegistryPersistence",
                            cheat.IsGenericName
                                ? $"Run key — cheat (baixa confiança): {exeName}"
                                : $"RUN KEY — PERSISTÊNCIA DE CHEAT: {cheat.Name}",
                            $"Executável cheat configurado para iniciar automaticamente com o Windows.\n{cheat.Description}",
                            $"HKLM\\{regPath}\\{valueName} = {value}",
                            confidence: cheat.IsGenericName ? Confidence.Low : Confidence.High,
                            ruleId: $"RUN_CHEAT_{exeName.ToUpperInvariant().Replace('.', '_')}",
                            entity: exePath,
                            validationHint: cheat.IsGenericName ? "Confirmar por hash ou caminho típico do GOSTH" : null
                        ));
                        continue;
                    }

                    // Suspicious keyword in path or value name → SuspiciousExecution
                    if (CheatDatabase.HasSuspiciousKeyword(exePath) ||
                        CheatDatabase.HasSuspiciousKeyword(valueName))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.SuspiciousExecution,
                            "RegistryPersistence",
                            $"Run key suspeito (HKLM): {valueName}",
                            $"Entrada de inicialização automática com nome/caminho suspeito.",
                            $"HKLM\\{regPath}\\{valueName} = {value}",
                            confidence: Confidence.Medium,
                            ruleId: $"RUN_SUSPICIOUS_{valueName.ToUpperInvariant().Replace(' ', '_')}",
                            entity: exePath
                        ));
                    }
                }
            }
            catch { }
        }
    }
}
