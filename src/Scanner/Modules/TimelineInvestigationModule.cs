using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Win32;

namespace BypassNerfados.Scanner.Modules;

// Aggregates execution timestamps from multiple independent artifact sources into a
// unified chronological view. Useful for establishing sequence of events during investigation.
public class TimelineInvestigationModule : BaseModule
{
    public override string Name        => "Timeline";
    public override string Description => "Linha do tempo unificada — Prefetch, BAM, LNK, Downloads, Temp (últimos 60 dias)";

    private static readonly string[] _execExtensions = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".wsf"];

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var cutoff   = DateTime.Now - config.EventWindowLookback;

        CollectPrefetchTimeline(findings, cutoff, ct);
        ct.ThrowIfCancellationRequested();
        CollectBamTimeline(findings, cutoff, ct);
        ct.ThrowIfCancellationRequested();
        CollectRecentLnkTimeline(findings, cutoff, ct);
        ct.ThrowIfCancellationRequested();
        CollectDownloadsTimeline(findings, cutoff, ct);
        ct.ThrowIfCancellationRequested();
        CollectTempTimeline(findings, cutoff, ct);

        return Task.FromResult(findings);
    }

    // Prefetch: each .pf file's LastWriteTime = last execution time
    private void CollectPrefetchTimeline(List<Finding> findings, DateTime cutoff, CancellationToken ct)
    {
        var prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var pf in Directory.GetFiles(prefetchDir, "*.pf"))
            {
                ct.ThrowIfCancellationRequested();

                var lastRun = File.GetLastWriteTime(pf);
                if (lastRun < cutoff) continue;

                var pfName  = Path.GetFileNameWithoutExtension(pf);
                var dash    = pfName.LastIndexOf('-');
                var exeName = (dash > 0 ? pfName[..dash] : pfName).ToLowerInvariant();
                if (!exeName.EndsWith(".exe")) exeName += ".exe";

                if (IsOwnProcess(exeName)) continue;
                if (CheatDatabase.IsKnownLegitimate(exeName)) continue;

                var (risk, confidence) = ClassifyForTimeline(exeName, "");
                if (risk < RiskLevel.Medium) continue;

                findings.Add(new Finding(
                    risk,
                    FindingCategory.SuspiciousExecution,
                    Name,
                    $"TIMELINE [Prefetch] {exeName}",
                    $"Execução confirmada pelo Prefetch.",
                    $"Arquivo: {Path.GetFileName(pf)} | Última execução: {lastRun:dd/MM/yyyy HH:mm:ss}",
                    timestamp: lastRun,
                    confidence: confidence,
                    ruleId: $"TL_PREFETCH_{exeName.ToUpperInvariant().Replace('.', '_')}",
                    entity: exeName
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Timeline: Prefetch inacessível", ex); }
    }

    // BAM/DAM: HKLM\SYSTEM\CurrentControlSet\Services\{bam|dam}\State\UserSettings
    private void CollectBamTimeline(List<Finding> findings, DateTime cutoff, CancellationToken ct)
    {
        foreach (var svc in new[] { "bam", "dam" })
        {
            try
            {
                var hivePath = $@"SYSTEM\CurrentControlSet\Services\{svc}\State\UserSettings";
                using var hive = Registry.LocalMachine.OpenSubKey(hivePath);
                if (hive == null) continue;

                foreach (var sid in hive.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    using var userKey = hive.OpenSubKey(sid);
                    if (userKey == null) continue;

                    foreach (var valueName in userKey.GetValueNames())
                    {
                        if (valueName is "Version" or "SequenceNumber" or "") continue;

                        var data = userKey.GetValue(valueName) as byte[];
                        if (data == null || data.Length < 8) continue;

                        var ft      = BitConverter.ToInt64(data, 0);
                        var lastRun = FileTimeToDateTime(ft);
                        if (!lastRun.HasValue || lastRun.Value < cutoff) continue;

                        var exePath = ConvertDevicePath(valueName);
                        var exeName = Path.GetFileName(exePath).ToLowerInvariant();

                        if (IsOwnProcess(exePath)) continue;
                        if (CheatDatabase.IsKnownLegitimate(exePath)) continue;

                        var (risk, confidence) = ClassifyForTimeline(exeName, exePath);
                        if (risk < RiskLevel.Medium) continue;

                        findings.Add(new Finding(
                            risk,
                            FindingCategory.SuspiciousExecution,
                            Name,
                            $"TIMELINE [{svc.ToUpper()}] {exeName}",
                            $"Execução registrada no {svc.ToUpper()} (Background Activity Monitor).",
                            $"Caminho: {exePath} | {lastRun.Value:dd/MM/yyyy HH:mm:ss}",
                            timestamp: lastRun,
                            confidence: confidence,
                            ruleId: $"TL_BAM_{exeName.ToUpperInvariant().Replace('.', '_')}",
                            entity: exePath
                        ));
                    }
                }
            }
            catch (Exception ex) { LogPartialError($"Timeline: {svc.ToUpper()} inacessível", ex); }
        }
    }

    // LNK Recent: %APPDATA%\Microsoft\Windows\Recent\*.lnk — creation time = first access
    private void CollectRecentLnkTimeline(List<Finding> findings, DateTime cutoff, CancellationToken ct)
    {
        var recentDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recentDir)) return;

        try
        {
            foreach (var lnk in Directory.GetFiles(recentDir, "*.lnk"))
            {
                ct.ThrowIfCancellationRequested();

                var created = File.GetCreationTime(lnk);
                if (created < cutoff) continue;

                var baseName = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                if (IsOwnProcess(baseName + ".exe") || IsOwnProcess(baseName + @"\")) continue;
                if (CheatDatabase.IsKnownLegitimate(baseName)) continue;

                var (risk, confidence) = ClassifyForTimeline(baseName + ".exe", lnk);
                if (risk < RiskLevel.Medium) continue;

                findings.Add(new Finding(
                    risk,
                    FindingCategory.RegistryArtifact,
                    Name,
                    $"TIMELINE [Recent] {baseName}",
                    "Acesso recente registrado pelo Windows Shell.",
                    $"LNK: {Path.GetFileName(lnk)} | Criado: {created:dd/MM/yyyy HH:mm:ss}",
                    timestamp: created,
                    confidence: confidence,
                    ruleId: $"TL_RECENT_{baseName.ToUpperInvariant().Replace(' ', '_')}",
                    entity: lnk
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Timeline: Recent LNK inacessível", ex); }
    }

    // Downloads: executáveis baixados recentemente
    private void CollectDownloadsTimeline(List<Finding> findings, DateTime cutoff, CancellationToken ct)
    {
        var downloadsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!Directory.Exists(downloadsDir)) return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(downloadsDir, "*",
                new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 2 }))
            {
                ct.ThrowIfCancellationRequested();

                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (!_execExtensions.Contains(ext)) continue;

                var created = File.GetCreationTime(file);
                if (created < cutoff) continue;

                var fileName = Path.GetFileName(file).ToLowerInvariant();
                if (IsOwnProcess(file)) continue;
                if (CheatDatabase.IsKnownLegitimate(file)) continue;

                var (risk, confidence) = ClassifyForTimeline(fileName, file);
                if (risk < RiskLevel.Medium) continue;

                findings.Add(new Finding(
                    risk,
                    FindingCategory.FileSystem,
                    Name,
                    $"TIMELINE [Downloads] {fileName}",
                    "Executável baixado recentemente.",
                    $"Arquivo: {file} | SHA256: {GetFileHash(file) ?? "N/A"} | Criado: {created:dd/MM/yyyy HH:mm:ss}",
                    timestamp: created,
                    confidence: confidence,
                    ruleId: $"TL_DOWNLOAD_{fileName.ToUpperInvariant().Replace('.', '_')}",
                    entity: file
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Timeline: Downloads inacessível", ex); }
    }

    // Temp: executáveis em %TEMP% criados recentemente
    private void CollectTempTimeline(List<Finding> findings, DateTime cutoff, CancellationToken ct)
    {
        var tempDir = Path.GetTempPath();
        try
        {
            foreach (var file in Directory.EnumerateFiles(tempDir, "*",
                new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 1 }))
            {
                ct.ThrowIfCancellationRequested();

                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is not (".exe" or ".dll" or ".bat" or ".cmd" or ".ps1" or ".vbs")) continue;

                var created = File.GetCreationTime(file);
                if (created < cutoff) continue;

                var fileName = Path.GetFileName(file).ToLowerInvariant();
                if (IsOwnProcess(file)) continue;

                var (risk, confidence) = ClassifyForTimeline(fileName, file);
                if (risk < RiskLevel.Medium) continue;

                findings.Add(new Finding(
                    risk,
                    FindingCategory.FileSystem,
                    Name,
                    $"TIMELINE [Temp] {fileName}",
                    "Executável em pasta temporária — indicador de execução transitória.",
                    $"Arquivo: {file} | SHA256: {GetFileHash(file) ?? "N/A"} | Criado: {created:dd/MM/yyyy HH:mm:ss}",
                    timestamp: created,
                    confidence: confidence,
                    ruleId: $"TL_TEMP_{fileName.ToUpperInvariant().Replace('.', '_')}",
                    entity: file
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Timeline: Temp inacessível", ex); }
    }

    private static (RiskLevel risk, Confidence confidence) ClassifyForTimeline(string fileName, string fullPath)
    {
        if (CheatDatabase.TryGetCredibleCheat(fileName, fullPath) != null)
            return (RiskLevel.High, Confidence.High);
        if (CheatDatabase.IsKnownCheatExecutable(fileName))
            return (RiskLevel.Medium, Confidence.Low);
        if (CheatDatabase.HasSuspiciousKeyword(fileName))
            return (RiskLevel.Medium, Confidence.Medium);
        if (CheatDatabase.IsSuspiciousPath(fullPath.ToLowerInvariant()))
            return (RiskLevel.Medium, Confidence.Low);
        return (RiskLevel.Info, Confidence.Low);
    }

    // Needed for BAM path conversion — reuse from BaseModule scope via helper
    private new static string ConvertDevicePath(string devicePath)
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            var letter = drive.Name.TrimEnd('\\');
            var sb = new System.Text.StringBuilder(256);
            if (QueryDosDevice(letter, sb, (uint)sb.Capacity) > 0)
            {
                var dev = sb.ToString();
                if (devicePath.StartsWith(dev, StringComparison.OrdinalIgnoreCase))
                    return letter + devicePath[dev.Length..];
            }
        }
        return devicePath;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, uint ucchMax);
}
