using System.Diagnostics.Eventing.Reader;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class DefenderModule : BaseModule
{
    public override string Name => "Windows Defender";
    public override string Description => "Histórico de detecções e alterações de configuração do Defender";

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        ScanProtectionHistory(findings, cancellationToken);
        ScanDefenderConfigChanges(findings, cancellationToken);
        CheckDefenderStatus(findings);

        return Task.FromResult(findings);
    }

    private static void ScanProtectionHistory(List<Finding> findings, CancellationToken cancellationToken)
    {
        // Event IDs for Defender:
        // 1116 = malware detected
        // 1117 = action taken (quarantine/remove)
        // 1118 = remediation failed
        // 1119 = remediation success
        // 5007 = configuration changed

        try
        {
            var query = new EventLogQuery(
                "Microsoft-Windows-Windows Defender/Operational",
                PathType.LogName,
                "*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119)]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;

            while ((record = reader.ReadEvent()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (record)
                {
                    try
                    {
                        var threatName = record.FormatDescription() ?? "";
                        var ts = record.TimeCreated;

                        // Extract relevant data from the event
                        string detail = threatName.Length > 500 ? threatName[..500] : threatName;

                        // Look for known cheat names in detection
                        var lower = detail.ToLowerInvariant();
                        bool isCheat = CheatDatabase.KnownExecutables.Keys
                            .Any(k => lower.Contains(k.Replace(".exe", "")));
                        bool isSuspicious = CheatDatabase.HasSuspiciousKeyword(lower);

                        var risk = (record.Id == 1116 || record.Id == 1118)
                            ? (isCheat || isSuspicious ? RiskLevel.Critical : RiskLevel.High)
                            : RiskLevel.Medium;

                        findings.Add(new Finding(
                            risk,
                            isCheat ? FindingCategory.Cheat : FindingCategory.SystemTampering,
                            "Defender",
                            $"Detecção Defender (ID {record.Id}): {ExtractThreatName(detail)}",
                            detail,
                            $"Data: {ts:dd/MM/yyyy HH:mm:ss}",
                            ts
                        ));
                    }
                    catch { /* skip malformed records */ }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* Defender log unavailable */ }
    }

    private static void ScanDefenderConfigChanges(List<Finding> findings, CancellationToken cancellationToken)
    {
        try
        {
            var query = new EventLogQuery(
                "Microsoft-Windows-Windows Defender/Operational",
                PathType.LogName,
                "*[System[EventID=5007]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;

            while ((record = reader.ReadEvent()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (record)
                {
                    try
                    {
                        var description = record.FormatDescription() ?? "";
                        var ts = record.TimeCreated;

                        bool isDisable =
                            description.Contains("DisableRealtimeMonitoring", StringComparison.OrdinalIgnoreCase) ||
                            description.Contains("DisableBehaviorMonitoring", StringComparison.OrdinalIgnoreCase) ||
                            description.Contains("DisableIOAVProtection", StringComparison.OrdinalIgnoreCase) ||
                            description.Contains("DisableScriptScanning", StringComparison.OrdinalIgnoreCase);

                        findings.Add(new Finding(
                            isDisable ? RiskLevel.Critical : RiskLevel.High,
                            FindingCategory.SystemTampering,
                            "Defender",
                            isDisable
                                ? "DEFENDER DESATIVADO (ID 5007)"
                                : "Configuração do Defender alterada (ID 5007)",
                            description.Length > 300 ? description[..300] : description,
                            $"Data: {ts:dd/MM/yyyy HH:mm:ss}",
                            ts
                        ));
                    }
                    catch { }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private static void CheckDefenderStatus(List<Finding> findings)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender");
            if (key == null) return;

            var realTimeEnabled = key.GetValue("DisableAntiSpyware");
            if (realTimeEnabled is int val && val == 1)
            {
                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.SystemTampering,
                    "Defender",
                    "Windows Defender desabilitado via Registry",
                    "DisableAntiSpyware = 1 detectado no registro. Proteção em tempo real desativada.",
                    @"HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware"
                ));
            }
        }
        catch { }
    }

    private static string ExtractThreatName(string description)
    {
        var idx = description.IndexOf("Name:", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var rest = description[(idx + 5)..].TrimStart();
            var end = rest.IndexOf('\n');
            return end > 0 ? rest[..end].Trim() : rest.Length > 60 ? rest[..60] : rest;
        }
        return description.Length > 60 ? description[..60] : description;
    }
}
