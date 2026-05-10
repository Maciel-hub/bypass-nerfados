using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Win32;

namespace BypassNerfados.Scanner.Modules;

public class AmcacheModule : BaseModule
{
    public override string Name        => "Amcache";
    public override string Description => "Histórico persistente de executáveis — confirma presença/registro; execução requer correlação com Prefetch/BAM";

    private const string HivePath = @"C:\Windows\appcompat\Programs\Amcache.hve";

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        if (!File.Exists(HivePath)) return Task.FromResult(findings);

        // Unique key per run (PID + GUID) avoids collisions if a previous scan crashed mid-run
        var tempKeyName = $"ECHO_AMCACHE_{Environment.ProcessId}_{Guid.NewGuid():N}";
        var hive = LoadOfflineHive(HivePath, tempKeyName, out var tempFile,
            onVssCleanupFail: warn => LogPartialError(warn));
        if (hive == null)
        {
            LogPartialError("Amcache.hve — não foi possível carregar offline hive (acesso negado, arquivo em uso, ou VSS indisponível)");
            return Task.FromResult(findings);
        }

        try
        {
            ScanInventoryApplicationFile(hive, findings, ct);
        }
        finally
        {
            hive.Dispose();
            UnloadOfflineHive(tempKeyName, tempFile);
        }

        return Task.FromResult(findings);
    }

    private static void ScanInventoryApplicationFile(RegistryKey hive, List<Finding> findings, CancellationToken ct)
    {
        using var appFileKey = hive.OpenSubKey(@"Root\InventoryApplicationFile");
        if (appFileKey == null) return;

        foreach (var subKeyName in appFileKey.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();

            using var entry = appFileKey.OpenSubKey(subKeyName);
            if (entry == null) continue;

            var path      = (entry.GetValue("LowerCaseLongPath") as string ?? "").Trim();
            var name      = (entry.GetValue("Name")              as string ?? "").Trim();
            var publisher = (entry.GetValue("Publisher")         as string ?? "").Trim();
            var fileId    = (entry.GetValue("FileId")            as string ?? "").Trim(); // "0000" + SHA1
            var linkDate  = (entry.GetValue("LinkDate")          as string ?? "").Trim();

            if (string.IsNullOrEmpty(path) && string.IsNullOrEmpty(name)) continue;
            // Use IsOwnToolArtifact (not just IsOwnProcess) to catch historical builds:
            // combines path/name match with publisher metadata so renamed binaries with
            // an unrelated publisher are not silently excluded.
            if (IsOwnToolArtifact(path, publisher: publisher) ||
                (!string.IsNullOrEmpty(name) && IsOwnProcess(name))) continue;
            if (CheatDatabase.IsKnownLegitimate(path)) continue;

            // Skip software signed by well-known publishers installed in standard (non-risky) paths.
            // Publisher field in Amcache comes from PE version info and can be spoofed, so we only
            // skip when the path is also NOT in a known high-risk location.
            if (CheatDatabase.IsKnownLegitimatePublisher(publisher) &&
                !CheatDatabase.IsSuspiciousPath(path.ToLowerInvariant())) continue;

            var fileName = Path.GetFileName(path).ToLowerInvariant();
            if (string.IsNullOrEmpty(fileName)) fileName = name.ToLowerInvariant();

            var (risk, confidence, label) = ClassifyAmcacheEntry(fileName, path, publisher);
            if (risk < RiskLevel.Medium) continue;

            var sha1     = fileId.Length > 4 ? fileId[4..] : fileId;
            var onDisk   = File.Exists(path);
            var deleted  = !onDisk && path.Contains('\\');

            findings.Add(new Finding(
                deleted && risk < RiskLevel.High ? RiskLevel.High : risk,
                FindingCategory.Cheat,
                "Amcache",
                $"AMCACHE: {label ?? fileName}{(deleted ? " [ARQUIVO DELETADO]" : "")}",
                $"Executável registrado no Amcache — confirma presença/registro no sistema." +
                (deleted ? " Arquivo removido após registro — possível tentativa de ocultação; eleva confiança." : " Correlacionar com Prefetch, BAM/DAM ou UserAssist para confirmar execução.") +
                (publisher != "" ? $" Publisher: {publisher}." : ""),
                $"SHA1: {(sha1 != "" ? sha1 : "N/A")} | LinkDate: {linkDate} | Caminho: {path}",
                timestamp: null,
                confidence: deleted ? Confidence.High : confidence,
                entity: path,
                ruleId: $"AMCACHE_{fileName.ToUpperInvariant().Replace('.', '_')}",
                validationHint: sha1 != "" ? $"Consultar SHA1 {sha1} no VirusTotal" : null
            ));
        }
    }

    private static (RiskLevel, Confidence, string?) ClassifyAmcacheEntry(string fileName, string path, string publisher)
    {
        // Known cheat executable name — use centralized credibility check.
        // TryGetCredibleCheat returns null for generic names (launcher.exe, dxsetup.exe)
        // when the path does not match a known cheat install location.
        var cheatEntry = CheatDatabase.TryGetCredibleCheat(fileName, path);
        if (cheatEntry != null)
        {
            var wasGeneric = CheatDatabase.KnownExecutables[fileName].IsGenericName;
            // Generic entries use null label so the title shows the filename, not the cheat name.
            // "GOSTH Loader (dxsetup)" in the title is misleading without a hash/path-specific match.
            return wasGeneric
                ? (RiskLevel.Medium, Confidence.Low, null)
                : (RiskLevel.High, Confidence.High, cheatEntry.Name);
        }
        if (CheatDatabase.IsKnownCheatExecutable(fileName))
            return (RiskLevel.Info, Confidence.Low, null); // generic name, wrong path — suppress

        // Known cheat DLL
        if (CheatDatabase.IsKnownCheatDll(fileName))
        {
            var entry = CheatDatabase.KnownDlls[fileName];
            return (RiskLevel.High, Confidence.High, entry.Name);
        }

        // Suspicious keywords in filename
        if (CheatDatabase.HasSuspiciousKeyword(fileName))
            return (RiskLevel.Medium, Confidence.Medium, null);

        // Suspicious path (Temp, AppData\Roaming\hidden, etc.)
        if (CheatDatabase.IsSuspiciousPath(path.ToLowerInvariant()))
            return (RiskLevel.Medium, Confidence.Low, null);

        return (RiskLevel.Info, Confidence.Low, null);
    }
}
