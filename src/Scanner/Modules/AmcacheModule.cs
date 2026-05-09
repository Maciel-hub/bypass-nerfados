using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Win32;

namespace BypassNerfados.Scanner.Modules;

public class AmcacheModule : BaseModule
{
    public override string Name        => "Amcache";
    public override string Description => "Histórico persistente de executáveis — confirma presença/registro; execução requer correlação com Prefetch/BAM";

    private const string HivePath   = @"C:\Windows\appcompat\Programs\Amcache.hve";
    private const string TempKeyName = "ECHO_AMCACHE_SCAN";

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        if (!File.Exists(HivePath)) return Task.FromResult(findings);

        var hive = LoadOfflineHive(HivePath, TempKeyName, out var tempFile);
        if (hive == null) return Task.FromResult(findings);

        try
        {
            ScanInventoryApplicationFile(hive, findings, ct);
        }
        finally
        {
            hive.Dispose();
            UnloadOfflineHive(TempKeyName, tempFile);
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
            if (IsOwnProcess(path) || IsOwnProcess(name)) continue;
            if (CheatDatabase.IsKnownLegitimate(path)) continue;

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
        // Known cheat executable name → High confidence
        if (CheatDatabase.IsKnownCheatExecutable(fileName))
        {
            var entry = CheatDatabase.KnownExecutables[fileName];
            return (RiskLevel.High, Confidence.High, entry.Name);
        }

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
