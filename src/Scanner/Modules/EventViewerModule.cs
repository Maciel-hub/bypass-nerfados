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

        var failedLogs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var spec in Specs)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                QueryEventLog(spec, findings, since, cancellationToken);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                // Log once per failing event log name to avoid duplicate messages
                if (failedLogs.Add(spec.Log))
                    LogPartialError($"Log '{spec.Log}' inacessível ou negado", ex);
            }
        }

        // Check for USN reset event (ID 3079 in Application log - NTFS)
        ScanUsnResetEvent(findings, since, cancellationToken);

        // Check 4688 for suspicious process creation
        ScanProcessCreationEvents(findings, since, cancellationToken);

        // Warn if any critical log has less than the required lookback coverage
        CheckLogCoverage(findings, since, config.EventWindowLookback);

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

                // 4616 time-change events from W32Time/svchost are NTP sync — downgrade to Info
                if (spec.EventId == 4616)
                {
                    var lower = description.ToLowerInvariant();
                    bool isNormalSync =
                        lower.Contains("w32tm") || lower.Contains("w32time") ||
                        lower.Contains("svchost") || lower.Contains("local service") ||
                        lower.Contains("serviço local") || lower.Contains("nt authority");

                    if (isNormalSync)
                    {
                        findings.Add(new Finding(
                            RiskLevel.Info,
                            spec.Category,
                            "Event Viewer",
                            "Sincronização de horário NTP (4616) — normal",
                            detail,
                            $"Log: {spec.Log} | Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated,
                            confidence: Confidence.Low,
                            ruleId: "EVENT_4616_NTP",
                            entity: "4616-ntp"
                        ));
                        continue;
                    }
                }

                findings.Add(new Finding(
                    spec.Risk,
                    spec.Category,
                    "Event Viewer",
                    $"{title}",
                    detail,
                    $"Log: {spec.Log} | Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                    record.TimeCreated
                ));
            }
        }
    }

    private void ScanUsnResetEvent(List<Finding> findings, DateTime since, CancellationToken cancellationToken)
    {
        // ID 3079: NTFS volume reset — can indicate USN Journal bypass but also benign disk events
        try
        {
            var sinceStr = since.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
            var query = new EventLogQuery(
                "Application",
                PathType.LogName,
                $"*[System[EventID=3079 and TimeCreated[@SystemTime>='{sinceStr}']]]")
            { ReverseDirection = true };

            using var reader = new EventLogReader(query);
            int count = 0;
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null && count < 5)
            {
                cancellationToken.ThrowIfCancellationRequested();
                count++;
                using (record)
                {
                    string description;
                    try { description = record.FormatDescription() ?? ""; }
                    catch { description = "Evento NTFS 3079"; }

                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.AntiForensics,
                        Name,
                        "POSSÍVEL BYPASS NTFS (3079) — inconsistência no USN Journal",
                        $"NTFS detectou inconsistências. Pode indicar limpeza do USN Journal.\n{description}",
                        $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                        record.TimeCreated,
                        confidence: Confidence.Low,
                        ruleId: $"EVENT_3079@{record.TimeCreated:yyyyMMddHH}",
                        entity: $"3079@{record.TimeCreated:yyyyMMddHH}",
                        validationHint: "Confirmar com PSReadLine: fsutil usn deletejournal — evento 3079 sozinho é inconclusivo"
                    ));
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Eventos NTFS 3079 inacessíveis", ex); }
    }

    private void ScanProcessCreationEvents(List<Finding> findings, DateTime since, CancellationToken cancellationToken)
    {
        // ID 4688 = Process created. Look for suspicious cmd/powershell patterns
        try
        {
            var sinceStr = since.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
            var query = new EventLogQuery(
                "Security",
                PathType.LogName,
                $"*[System[EventID=4688 and TimeCreated[@SystemTime>='{sinceStr}']]]");

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
                            Name,
                            "PowerShell encodado/bypass detectado (4688)",
                            "Execução de PowerShell com parâmetros de evasão detectada.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated,
                            ruleId: $"EVENT_4688_PSENC@{record.TimeCreated:yyyyMMddHH}",
                            entity: "powershell-enc"
                        ));
                    }

                    // Detect wevtutil (log clearing tool)
                    if (lower.Contains("wevtutil") && (lower.Contains(" cl ") || lower.Contains(" clear-log ")))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.AntiForensics,
                            Name,
                            "wevtutil LIMPEZA DE LOGS detectada (4688)",
                            "Comando wevtutil usado para limpar logs de eventos.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated,
                            ruleId: $"EVENT_4688_WEVTUTIL@{record.TimeCreated:yyyyMMddHH}",
                            entity: "wevtutil-clear"
                        ));
                    }

                    // Detect fsutil usn deletejournal
                    if (lower.Contains("fsutil") && lower.Contains("usn") && lower.Contains("delete"))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.AntiForensics,
                            Name,
                            "Deleção do USN Journal detectada (4688)",
                            "Comando fsutil usn deletejournal detectado — apagamento do diário NTFS.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated,
                            ruleId: $"EVENT_4688_FSUTIL_USN@{record.TimeCreated:yyyyMMddHH}",
                            entity: "fsutil-usn-delete"
                        ));
                    }

                    // Detect rundll32 ClearMyTracksByProcess — clears IE/Edge history and tracks
                    if (lower.Contains("rundll32") && lower.Contains("clearmytracksbyprocess"))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.AntiForensics,
                            Name,
                            "rundll32 ClearMyTracksByProcess detectado (4688)",
                            "Limpeza de histórico via rundll32 InetCpl.cpl,ClearMyTracksByProcess — apaga cookies, histórico do browser e cache.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated,
                            ruleId: $"EVENT_4688_CLEARTRACK@{record.TimeCreated:yyyyMMddHH}",
                            entity: "rundll32-cleartrack"
                        ));
                    }

                    // Detect reg.exe delete on forensic registry keys (BAM, UserAssist, AppCompatCache)
                    if (lower.Contains("reg") && lower.Contains("delete") &&
                        (lower.Contains("bam") || lower.Contains("userassist") ||
                         lower.Contains("appcompatcache") || lower.Contains("shimcache")))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.AntiForensics,
                            Name,
                            "Deleção de chave de histórico de registro detectada (4688)",
                            "reg.exe delete em chaves forenses (BAM/UserAssist/AppCompatCache/ShimCache) — apaga histórico de execução de processos.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated,
                            ruleId: $"EVENT_4688_REG_HISTORY_CLEAR@{record.TimeCreated:yyyyMMddHH}",
                            entity: "reg-delete-forensic"
                        ));
                    }

                    // Detect python executing anti-echo/brembo scripts
                    if (lower.Contains("python") &&
                        (lower.Contains("anti-echo") || lower.Contains("antiecho") ||
                         lower.Contains("brembo") || lower.Contains("bypass_echo")))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.AntiForensics,
                            Name,
                            "Script anti-echo Python executado (4688)",
                            "python.exe executando script com nome/args relacionados a limpeza anti-Echo Nerfados.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated,
                            ruleId: $"EVENT_4688_ANTIECHO_SCRIPT@{record.TimeCreated:yyyyMMddHH}",
                            entity: "python-antiecho"
                        ));
                    }

                    // Detect wscript/cscript running getadmin.vbs (BatchGotAdmin UAC stub)
                    if ((lower.Contains("wscript") || lower.Contains("cscript")) &&
                        lower.Contains("getadmin.vbs"))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.SystemTampering,
                            Name,
                            "Execução do script BatchGotAdmin (4688)",
                            "wscript.exe/cscript.exe executando getadmin.vbs — autoelevação UAC via BatchGotAdmin.",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated,
                            ruleId: $"EVENT_4688_BATCHGOTADMIN@{record.TimeCreated:yyyyMMddHH}",
                            entity: "batchgotadmin-vbs"
                        ));
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Eventos de criação de processo (4688) inacessíveis", ex); }
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

    // For each critical log, queries the oldest available record and emits a warning
    // finding when coverage is less than the configured lookback window.
    private void CheckLogCoverage(List<Finding> findings, DateTime since, TimeSpan lookback)
    {
        var requiredDays = (int)lookback.TotalDays;
        foreach (var logName in new[] { "Security", "System", "Application" })
        {
            try
            {
                var query = new EventLogQuery(logName, PathType.LogName, "*")
                {
                    ReverseDirection = false // oldest first
                };
                using var reader = new EventLogReader(query);
                using var record = reader.ReadEvent();
                if (record?.TimeCreated == null) continue;

                var oldestLocal = record.TimeCreated.Value.ToLocalTime();
                var coverageDays = (int)(DateTime.Now - oldestLocal).TotalDays;

                if (record.TimeCreated.Value > since.AddDays(1))
                {
                    var risk = logName == "Security" ? RiskLevel.Medium : RiskLevel.Low;
                    var lostEvidence = LogLostEvidence(logName);

                    findings.Add(new Finding(
                        risk,
                        FindingCategory.SystemTampering,
                        "Event Viewer",
                        $"AVISO: Log {logName} com cobertura insuficiente ({coverageDays} dias disponíveis)",
                        $"Retenção mínima de {requiredDays} dias não pôde ser confirmada. " +
                        $"O log {logName} possui registros a partir de {oldestLocal:dd/MM/yyyy}. " +
                        "Possível limpeza de log ou política de retenção insuficiente. " +
                        $"Evidências que podem ter sido perdidas: {lostEvidence}",
                        $"Registro mais antigo: {oldestLocal:dd/MM/yyyy HH:mm:ss} | Cobertura: {coverageDays} dias de {requiredDays} dias necessários",
                        timestamp: null,
                        confidence: Confidence.Medium,
                        ruleId: $"LOG_COVERAGE_{logName.ToUpperInvariant()}",
                        entity: logName
                    ));
                }
            }
            catch (Exception ex) { LogPartialError($"Falha ao calcular cobertura do log '{logName}'", ex); }
        }
    }

    private static string LogLostEvidence(string logName) => logName switch
    {
        "Security" =>
            "autenticações (4624/4625), escalação de privilégio (4672), " +
            "limpeza de log anterior (1102), alterações de política de auditoria (4719), " +
            "Defender config (5007), criação de conta (4720), tarefas agendadas (4698)",
        "System" =>
            "instalação de serviços (7045), reinicializações, " +
            "limpeza de log anterior (104), alteração de driver, falhas de sistema",
        "Application" =>
            "crashes de aplicativos (1000), erros de instalação/desinstalação, " +
            "exceções de processos suspeitos",
        _ => "eventos históricos do período não coberto"
    };
}
