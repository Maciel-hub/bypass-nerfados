using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class RegistryArtifactsModule : BaseModule
{
    public override string Name => ModuleName;
    public override string Description => "Store, MuiCache, RecentDocs, 7-Zip, ArcHistory, MountedDevices";

    private const string ModuleName = "Registry Artifacts";

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        ScanCompatibilityStore(findings);
        cancellationToken.ThrowIfCancellationRequested();
        ScanMuiCache(findings);
        cancellationToken.ThrowIfCancellationRequested();
        ScanRecentDocs(findings);
        cancellationToken.ThrowIfCancellationRequested();
        ScanArchiveHistory(findings);
        cancellationToken.ThrowIfCancellationRequested();
        ScanMountedDevices(findings);
        cancellationToken.ThrowIfCancellationRequested();
        ScanStartupEntries(findings);

        return Task.FromResult(findings);
    }

    private void ScanCompatibilityStore(List<Finding> findings)
    {
        const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(path);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                if (string.IsNullOrEmpty(valueName)) continue;
                var lower = valueName.ToLowerInvariant();
                var fileName = Path.GetFileName(lower);
                var data = key.GetValue(valueName);
                // Data contains hex PCA flags like 0x4477000
                string pca = data != null ? $"PCA: 0x{Convert.ToInt32(data):X}" : "";

                if (IsOwnProcess(fileName)) continue;
                if (CheatDatabase.IsKnownLegitimate(fileName) || CheatDatabase.IsKnownLegitimate(valueName)) continue;

                if (CheatDatabase.KnownExecutables.TryGetValue(fileName, out var cheat))
                {
                    var confidence = cheat.IsGenericName ? Confidence.Low : Confidence.Medium;
                    var risk       = cheat.IsGenericName ? RiskLevel.Medium : RiskLevel.High;
                    findings.Add(new Finding(
                        risk,
                        FindingCategory.Cheat,
                        ModuleName,
                        cheat.IsGenericName
                            ? $"Executável com nome de cheat na Store (baixa confiança): {fileName}"
                            : $"CHEAT NA STORE: {cheat.Name} ({fileName})",
                        $"Executável encontrado na chave PCA Store.\n{cheat.Description}",
                        $"Caminho: {valueName} | {pca}",
                        confidence: confidence,
                        ruleId: $"STORE_{cheat.Name.ToUpperInvariant().Replace(" ", "_")}",
                        entity: valueName,
                        validationHint: cheat.IsGenericName ? "Confirmar por hash ou caminho típico do GOSTH" : null
                    ));
                    continue;
                }

                if (CheatDatabase.HasSuspiciousKeyword(fileName) || CheatDatabase.IsSuspiciousPath(valueName))
                {
                    findings.Add(new Finding(
                        RiskLevel.Medium,
                        FindingCategory.RegistryArtifact,
                        ModuleName,
                        $"Execução suspeita na Store: {fileName}",
                        $"Caminho: {valueName}",
                        pca,
                        confidence: Confidence.Low,
                        entity: valueName
                    ));
                }
            }
        }
        catch (Exception ex) { LogPartialError("CompatibilityAssistant registry inacessível", ex); }
    }

    private void ScanMuiCache(List<Finding> findings)
    {
        const string path = @"Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        try
        {
            using var key = Registry.ClassesRoot.OpenSubKey(path);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                if (!valueName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !valueName.EndsWith(".exe.FriendlyAppName", StringComparison.OrdinalIgnoreCase))
                    continue;

                var exePath = valueName.Replace(".FriendlyAppName", "").Replace(".ApplicationCompany", "");
                var fileName = Path.GetFileName(exePath).ToLowerInvariant()
                    .Replace(".friendlyappname", "").Replace(".applicationcompany", "");

                if (IsOwnProcess(fileName) || IsOwnProcess(exePath)) continue;
                if (CheatDatabase.IsKnownLegitimate(fileName) || CheatDatabase.IsKnownLegitimate(exePath)) continue;

                if (CheatDatabase.KnownExecutables.TryGetValue(fileName, out var cheat))
                {
                    var confidence = cheat.IsGenericName ? Confidence.Low : Confidence.Medium;
                    var risk       = cheat.IsGenericName ? RiskLevel.Medium : RiskLevel.High;
                    findings.Add(new Finding(
                        risk,
                        FindingCategory.Cheat,
                        ModuleName,
                        cheat.IsGenericName
                            ? $"Executável com nome de cheat no MuiCache (baixa confiança): {fileName}"
                            : $"CHEAT NO MUICACHE: {cheat.Name} ({fileName})",
                        $"Executável registrado no MuiCache (confirma execução).\n{cheat.Description}",
                        $"Caminho: {exePath}",
                        confidence: confidence,
                        ruleId: $"MUICACHE_{cheat.Name.ToUpperInvariant().Replace(" ", "_")}",
                        entity: exePath,
                        validationHint: cheat.IsGenericName ? "Confirmar por hash ou caminho típico do GOSTH" : null
                    ));
                    continue;
                }

                if (CheatDatabase.HasSuspiciousKeyword(fileName))
                {
                    findings.Add(new Finding(
                        RiskLevel.Medium,
                        FindingCategory.RegistryArtifact,
                        ModuleName,
                        $"Execução suspeita no MuiCache: {fileName}",
                        $"Caminho: {exePath}",
                        confidence: Confidence.Low,
                        entity: exePath
                    ));
                }
            }
        }
        catch (Exception ex) { LogPartialError("MuiCache registry inacessível", ex); }
    }

    private void ScanRecentDocs(List<Finding> findings)
    {
        const string path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(path);
            if (key == null) return;

            // Check .rar subkey for recent archives (citizen, props, etc.)
            using var rarKey = key.OpenSubKey(".rar");
            if (rarKey != null)
            {
                CheckRecentDocsSubkey(rarKey, ".rar", findings);
            }

            using var zipKey = key.OpenSubKey(".zip");
            if (zipKey != null)
            {
                CheckRecentDocsSubkey(zipKey, ".zip", findings);
            }

            using var exeKey = key.OpenSubKey(".exe");
            if (exeKey != null)
            {
                CheckRecentDocsSubkey(exeKey, ".exe", findings);
            }
        }
        catch (Exception ex) { LogPartialError("RecentDocs registry inacessível", ex); }
    }

    private void CheckRecentDocsSubkey(RegistryKey key, string ext, List<Finding> findings)
    {
        var failCount = 0;

        foreach (var valueName in key.GetValueNames())
        {
            if (valueName == "MRUListEx") continue;
            try
            {
                var data = key.GetValue(valueName) as byte[];
                if (data == null) continue;
                // Binary data starts with null-terminated Unicode string (the filename)
                var name = System.Text.Encoding.Unicode.GetString(data).Split('\0')[0];
                if (string.IsNullOrEmpty(name)) continue;

                var lower = name.ToLowerInvariant();
                if (CheatDatabase.HasSuspiciousKeyword(lower) ||
                    lower.Contains("citizen") || lower.Contains("props") ||
                    lower.Contains("aimbot") || lower.Contains("recoil"))
                {
                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.RegistryArtifact,
                        ModuleName,
                        $"Arquivo suspeito nos Docs Recentes: {name}",
                        $"Arquivo {ext} suspeito acessado recentemente.",
                        $"Nome: {name}"
                    ));
                }
            }
            catch { failCount++; }
        }

        if (failCount > 0)
            LogPartialError($"{failCount} entrada(s) de registry inacessíveis/ignoradas");
    }

    private void ScanArchiveHistory(List<Finding> findings)
    {
        // 7-Zip FM history
        const string sevenZipPath = @"Software\7-Zip\FM";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(sevenZipPath);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                var val = key.GetValue(valueName)?.ToString() ?? "";
                if (string.IsNullOrEmpty(val)) continue;

                var lower = val.ToLowerInvariant();
                if (CheatDatabase.HasSuspiciousKeyword(lower) || lower.Contains("citizen") || lower.Contains(".rar"))
                {
                    findings.Add(new Finding(
                        RiskLevel.Medium,
                        FindingCategory.RegistryArtifact,
                        ModuleName,
                        $"7-Zip: arquivo suspeito acessado",
                        $"Caminho/arquivo acessado pelo 7-Zip: {val}"
                    ));
                }
            }
        }
        catch (Exception ex) { LogPartialError("Histórico do 7-Zip inacessível", ex); }

        // WinRAR ArcHistory
        const string winrarPath = @"Software\WinRAR\ArcHistory";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(winrarPath);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                var val = key.GetValue(valueName)?.ToString() ?? "";
                var lower = val.ToLowerInvariant();
                if (CheatDatabase.HasSuspiciousKeyword(lower) || lower.Contains("citizen"))
                {
                    findings.Add(new Finding(
                        RiskLevel.Medium,
                        FindingCategory.RegistryArtifact,
                        ModuleName,
                        $"WinRAR: arquivo suspeito: {Path.GetFileName(val)}",
                        $"Arquivo acessado recentemente pelo WinRAR: {val}"
                    ));
                }
            }
        }
        catch (Exception ex) { LogPartialError("Histórico do WinRAR inacessível", ex); }
    }

    private void ScanMountedDevices(List<Finding> findings)
    {
        const string path = @"SYSTEM\MountedDevices";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            if (key == null) return;

            var driveCount = key.GetValueNames()
                .Count(v => v.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase));

            if (driveCount > 4)
            {
                findings.Add(new Finding(
                    RiskLevel.Medium,
                    FindingCategory.DeviceAnomaly,
                    ModuleName,
                    $"Múltiplos volumes montados: {driveCount} dispositivos",
                    "Histórico de discos conectados ao sistema. Verificar se há volumes suspeitos.",
                    $"Total de dispositivos: {driveCount}"
                ));
            }
        }
        catch (Exception ex) { LogPartialError("MountedDevices registry inacessível", ex); }
    }

    private void ScanStartupEntries(List<Finding> findings)
    {
        var startupKeys = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser, "HKCU Run"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM Run"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser, "HKCU RunOnce"),
        };

        var failCount = 0;

        foreach (var (path, hive, label) in startupKeys)
        {
            try
            {
                using var key = hive.OpenSubKey(path);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    var lower = value.ToLowerInvariant();

                    // Extract executable name from the command (strip arguments after space)
                    var exeName = Path.GetFileName(lower.Split('"', ' ')[0]);
                    if (IsOwnProcess(exeName)) continue;
                    if (CheatDatabase.IsKnownLegitimate(exeName) || CheatDatabase.IsKnownLegitimate(valueName)) continue;

                    // IsSuspiciousPath alone produces many FPs (Spotify, Discord, etc. live in AppData)
                    // Only flag on keyword match, which is more precise for startup entries
                    if (CheatDatabase.HasSuspiciousKeyword(lower))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.SuspiciousExecution,
                            ModuleName,
                            $"Inicialização suspeita ({label}): {valueName}",
                            $"Entrada de inicialização automática suspeita.\nComando: {value}",
                            $"Chave: {label}\\{valueName}"
                        ));
                    }
                }
            }
            catch { failCount++; }
        }

        if (failCount > 0)
            LogPartialError($"{failCount} entrada(s) de registry inacessíveis/ignoradas");
    }
}
