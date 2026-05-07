using System.Diagnostics.Eventing.Reader;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class EventViewerModule : BaseModule
{
    public override string Name => "Event Viewer";
    public override string Description => "Logs de segurança, sistema e aplicação — IDs críticos";

    private record EventSpec(string Log, int EventId, RiskLevel Risk, FindingCategory Category, string Label);

    private static readonly EventSpec[] Specs =
    [
        new("Security", 1102, RiskLevel.Critical, FindingCategory.AntiForensics,  "Log de SEGURANÇA limpo (1102)"),
        new("Security", 4616, RiskLevel.High,     FindingCategory.SystemTampering, "Horário do sistema alterado (4616)"),
        new("Security", 4698, RiskLevel.High,     FindingCategory.SuspiciousExecution, "Tarefa agendada criada (4698)"),
        new("Security", 4699, RiskLevel.Medium,   FindingCategory.SuspiciousExecution, "Tarefa agendada deletada (4699)"),
        new("Security", 4720, RiskLevel.Medium,   FindingCategory.SystemTampering, "Conta de usuário criada (4720)"),
        new("Security", 4732, RiskLevel.Medium,   FindingCategory.SystemTampering, "Membro adicionado ao grupo Administradores (4732)"),
        new("System",   104,  RiskLevel.Critical, FindingCategory.AntiForensics,  "Log do SISTEMA limpo (104)"),
        new("System",   7045, RiskLevel.High,     FindingCategory.SuspiciousExecution, "Serviço instalado (7045)"),
        new("Application", 1000, RiskLevel.Medium, FindingCategory.SystemTampering, "Aplicação crashou (1000)"),
    ];

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var since = DateTime.UtcNow - config.EventWindowLookback;

        foreach (var spec in Specs)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                QueryEventLog(spec, findings, since, cancellationToken);
            }
            catch (OperationCanceledException) { throw; }
            catch { /* log not available or access denied */ }
        }

        // Check for USN reset event (ID 3079 in Application log - NTFS)
        ScanUsnResetEvent(findings, cancellationToken);

        // Check 4688 for suspicious process creation
        ScanProcessCreationEvents(findings, cancellationToken);

        return Task.FromResult(findings);
    }

    private static void QueryEventLog(EventSpec spec, List<Finding> findings, DateTime since, CancellationToken cancellationToken)
    {
        // Use time window to show recent events first (ReverseDirection)
        var sinceStr = since.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
        var xpathFilter = $"*[System[EventID={spec.EventId} and TimeCreated[@SystemTime>='{sinceStr}']]]";

        var query = new EventLogQuery(
            spec.Log,
            PathType.LogName,
            xpathFilter)
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(query);
        int count = 0;
        EventRecord? record;

        while ((record = reader.ReadEvent()) != null && count < 20)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (record)
            {
                count++;
                string description;
                try { description = record.FormatDescription() ?? ""; }
                catch { description = $"EventID {spec.EventId}"; }

                // For 7045, check if it's a suspicious service
                string title = spec.Label;
                var detail = description.Length > 400 ? description[..400] : description;

                if (spec.EventId == 7045)
                {
                    var lower = description.ToLowerInvariant();
                    if (Data.CheatDatabase.HasSuspiciousKeyword(lower))
                        title = $"SERVIÇO SUSPEITO INSTALADO: {ExtractServiceName(description)}";
                }

                findings.Add(new Finding(
                    spec.Risk,
                    spec.Category,
                    "EventViewer",
                    $"{title}",
                    detail,
                    $"Log: {spec.Log} | Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                    record.TimeCreated
                ));
            }
        }
    }

    private static void ScanUsnResetEvent(List<Finding> findings, CancellationToken cancellationToken)
    {
        // ID 3079 in Application log = NTFS volume reset (possible USN journal bypass)
        try
        {
            var query = new EventLogQuery(
                "Application",
                PathType.LogName,
                "*[System[EventID=3079]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (record)
                {
                    string description;
                    try { description = record.FormatDescription() ?? ""; }
                    catch { description = "Evento NTFS 3079"; }

                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.AntiForensics,
                        "EventViewer",
                        "TENTATIVA DE BYPASS NTFS (3079) — USN Journal possivelmente apagado",
                        $"NTFS realizou reset ou detectou inconsistências. Possível limpeza do USN Journal.\n{description}",
                        $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                        record.TimeCreated
                    ));
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private static void ScanProcessCreationEvents(List<Finding> findings, CancellationToken cancellationToken)
    {
        // ID 4688 = Process created. Look for suspicious cmd/powershell patterns
        try
        {
            var query = new EventLogQuery(
                "Security",
                PathType.LogName,
                "*[System[EventID=4688]]");

            using var reader = new EventLogReader(query);
            int count = 0;
            EventRecord? record;

            while ((record = reader.ReadEvent()) != null && count < 200)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (record)
                {
                    count++;
                    string description;
                    try { description = record.FormatDescription() ?? ""; }
                    catch { continue; }

                    var lower = description.ToLowerInvariant();

                    // Detect encoded PowerShell (bypass technique)
                    if (lower.Contains("encodedcommand") || lower.Contains("-enc ") ||
                        lower.Contains("powershell") && lower.Contains("bypass"))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.SuspiciousExecution,
                            "EventViewer",
                            "PowerShell encodado/bypass detectado (4688)",
                            "Execução de PowerShell com parâmetros de evasão detectada.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated
                        ));
                    }

                    // Detect wevtutil (log clearing tool)
                    if (lower.Contains("wevtutil") && (lower.Contains(" cl ") || lower.Contains(" clear-log ")))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.AntiForensics,
                            "EventViewer",
                            "wevtutil LIMPEZA DE LOGS detectada (4688)",
                            "Comando wevtutil usado para limpar logs de eventos.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated
                        ));
                    }

                    // Detect fsutil usn deletejournal
                    if (lower.Contains("fsutil") && lower.Contains("usn") && lower.Contains("delete"))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.AntiForensics,
                            "EventViewer",
                            "Deleção do USN Journal detectada (4688)",
                            "Comando fsutil usn deletejournal detectado — apagamento do diário NTFS.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated
                        ));
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private static string ExtractServiceName(string description)
    {
        var idx = description.IndexOf("Service Name:", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var rest = description[(idx + 13)..].TrimStart();
            var end = rest.IndexOf('\n');
            return end > 0 ? rest[..end].Trim() : rest.Length > 50 ? rest[..50] : rest;
        }
        return description.Length > 50 ? description[..50] : description;
    }
}
