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
        ScanDefenderConfigChanges(findings, config.EventWindowLookback, cancellationToken);
        CheckDefenderStatus(findings);

        return Task.FromResult(findings);
    }

    private void ScanProtectionHistory(List<Finding> findings, CancellationToken cancellationToken)
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
            var failCount = 0;

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
                        // Guard: skip keyword check if description refers to a known-legitimate path
                        // (e.g. Defender events for Echo's own harness files at D:\BypassNerfados\)
                        bool isSuspicious = CheatDatabase.HasSuspiciousKeyword(lower) &&
                                            !CheatDatabase.IsKnownLegitimate(lower);

                        var risk = (record.Id == 1116 || record.Id == 1118)
                            ? (isCheat || isSuspicious ? RiskLevel.Critical : RiskLevel.High)
                            : RiskLevel.Medium;

                        findings.Add(new Finding(
                            risk,
                            isCheat ? FindingCategory.Cheat : FindingCategory.SystemTampering,
                            Name,
                            $"Detecção Defender (ID {record.Id}): {ExtractThreatName(detail)}",
                            detail,
                            $"Data: {ts:dd/MM/yyyy HH:mm:ss}",
                            ts
                        ));
                    }
                    catch { failCount++; }
                }
            }

            if (failCount > 0)
                LogPartialError($"{failCount} evento(s) do Defender malformados/ignorados");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Log do Defender (Protection History) inacessível", ex); }
    }

    private void ScanDefenderConfigChanges(List<Finding> findings, TimeSpan lookback, CancellationToken cancellationToken)
    {
        try
        {
            var since = DateTime.UtcNow - lookback;
            var sinceStr = since.ToString("yyyy-MM-ddTHH:mm:ss.000Z");

            var query = new EventLogQuery(
                "Microsoft-Windows-Windows Defender/Operational",
                PathType.LogName,
                $"*[System[EventID=5007 and TimeCreated[@SystemTime>='{sinceStr}']]]")
            { ReverseDirection = true };

            using var reader = new EventLogReader(query);
            EventRecord? record;

            // Deduplicate by changed registry key — one finding per key
            var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int genericCount = 0;
            var failCount = 0;

            while ((record = reader.ReadEvent()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (record)
                {
                    try
                    {
                        var description = record.FormatDescription() ?? "";
                        var ts = record.TimeCreated;
                        var lower = description.ToLowerInvariant();

                        var changedKey = ExtractChangedKey(description);
                        if (!string.IsNullOrEmpty(changedKey) && !seenKeys.Add(changedKey))
                            continue;

                        bool isCriticalDisable =
                            lower.Contains("disablerealtimemonitoring") ||
                            lower.Contains("tamperprotection") ||
                            lower.Contains("disablebehaviormonitoring") ||
                            lower.Contains("disableioavprotection") ||
                            lower.Contains("disablescriptscanning") ||
                            lower.Contains("disableantispyware") ||
                            lower.Contains("disableantivirus");

                        bool isExclusion =
                            lower.Contains("exclusionpath") ||
                            lower.Contains("exclusionextension") ||
                            lower.Contains("exclusionprocess") ||
                            lower.Contains("exclusionipaddress");

                        if (isCriticalDisable)
                        {
                            findings.Add(new Finding(
                                RiskLevel.Critical,
                                FindingCategory.SystemTampering,
                                Name,
                                "DEFENDER DESATIVADO (ID 5007)",
                                description.Length > 400 ? description[..400] : description,
                                $"Data: {ts:dd/MM/yyyy HH:mm:ss}",
                                ts,
                                confidence: Confidence.High,
                                ruleId: "DEFENDER_DISABLED_5007",
                                entity: changedKey ?? "defender-config"
                            ));
                        }
                        else if (isExclusion)
                        {
                            findings.Add(new Finding(
                                RiskLevel.High,
                                FindingCategory.SystemTampering,
                                Name,
                                $"Exclusão adicionada ao Defender (ID 5007): {changedKey ?? "exclusão"}",
                                description.Length > 400 ? description[..400] : description,
                                $"Data: {ts:dd/MM/yyyy HH:mm:ss}",
                                ts,
                                confidence: Confidence.Medium,
                                ruleId: "DEFENDER_EXCLUSION_5007",
                                entity: changedKey ?? "defender-exclusion"
                            ));
                        }
                        else
                        {
                            // Generic config change (signature updates, scan schedules, Windows Update noise)
                            if (genericCount >= 3) continue;
                            genericCount++;
                            findings.Add(new Finding(
                                RiskLevel.Low,
                                FindingCategory.SystemTampering,
                                Name,
                                $"Configuração do Defender alterada (ID 5007): {changedKey ?? "configuração"}",
                                description.Length > 400 ? description[..400] : description,
                                $"Data: {ts:dd/MM/yyyy HH:mm:ss}",
                                ts,
                                confidence: Confidence.Low,
                                ruleId: "DEFENDER_CONFIG_5007",
                                entity: changedKey ?? "defender-generic"
                            ));
                        }
                    }
                    catch { failCount++; }
                }
            }

            if (failCount > 0)
                LogPartialError($"{failCount} evento(s) do Defender malformados/ignorados");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Log de alterações de configuração do Defender inacessível", ex); }
    }

    private static string? ExtractChangedKey(string description)
    {
        // 5007 format: "New value: HKLM\...\KeyName = value"
        var idx = description.IndexOf("New value:", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) idx = description.IndexOf("Old value:", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        var rest = description[(idx + 10)..].TrimStart();
        var eqIdx = rest.IndexOf('=');
        if (eqIdx < 0) return null;

        var keyPath = rest[..eqIdx].Trim();
        var lastSlash = keyPath.LastIndexOf('\\');
        return lastSlash >= 0 ? keyPath[(lastSlash + 1)..] : keyPath;
    }

    private void CheckDefenderStatus(List<Finding> findings)
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
                    Name,
                    "Windows Defender desabilitado via Registry",
                    "DisableAntiSpyware = 1 detectado no registro. Proteção em tempo real desativada.",
                    @"HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware"
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Status do Defender inacessível via registry", ex); }
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
