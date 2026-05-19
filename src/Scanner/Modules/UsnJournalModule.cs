using System.Globalization;
using System.Text;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class UsnJournalModule : BaseModule
{
    public override string Name => "USN Journal";
    public override string Description => "Registro NTFS — EXE/DLL/SYS/arquivos criados, deletados e renomeados";

    // USN reason bitmasks (from <winioctl.h>)
    private const uint FILE_CREATE = 0x00000100;
    private const uint FILE_DELETE = 0x00000200;
    private const uint RENAME_OLD  = 0x00001000;
    private const uint RENAME_NEW  = 0x00002000;

    private static readonly HashSet<string> ArchiveExts =
        new([".zip", ".rar", ".7z"], StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> ExecutableExts =
        new([".exe", ".dll", ".sys", ".ps1", ".bat", ".vbs"], StringComparer.OrdinalIgnoreCase);

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var records = await ReadJournalAsync(config.TargetDrive, ct);
        if (records.Count == 0) return findings;

        var creates = records.Where(r => (r.Reason & FILE_CREATE) != 0).ToList();
        var deletes = records.Where(r => (r.Reason & FILE_DELETE) != 0).ToList();
        var renames = records.Where(r => (r.Reason & (RENAME_OLD | RENAME_NEW)) != 0).ToList();

        foreach (var rec in deletes)
        {
            ct.ThrowIfCancellationRequested();
            ClassifyDeletion(rec, findings);
        }

        foreach (var rec in creates)
        {
            ct.ThrowIfCancellationRequested();
            ClassifyCreation(rec, findings);
        }

        foreach (var rec in renames)
        {
            ct.ThrowIfCancellationRequested();
            ClassifyRename(rec, findings);
        }

        DetectTimelinePatterns(creates, deletes, findings, ct);

        return findings;
    }

    private void ClassifyDeletion(UsnRecord rec, List<Finding> findings)
    {
        var lower = rec.FileNameLower;
        var ext = Path.GetExtension(lower);

        // Prefetch file deleted — anti-forensics classic
        if (lower.EndsWith(".pf"))
        {
            var name = Path.GetFileNameWithoutExtension(lower);
            var dash = name.LastIndexOf('-');
            if (dash > 0) name = name[..dash];

            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                Name,
                $"Prefetch deletado: {name}.exe",
                "Arquivo Prefetch removido manualmente — possível tentativa de ocultar histórico de execução.",
                rec.FileName,
                rec.Timestamp,
                ruleId: $"USN_PF_DEL_{name}"
            ));
            return;
        }

        // Known cheat binary deleted
        if (CheatDatabase.KnownExecutables.TryGetValue(lower, out var cheat))
        {
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.Cheat,
                Name,
                $"CHEAT DELETADO (USN): {cheat.Name}",
                $"Arquivo de cheat conhecido registrado como deletado no USN Journal.\n{cheat.Description}",
                rec.FileName,
                rec.Timestamp,
                confidence: Confidence.High,
                ruleId: $"USN_CHEAT_DEL_{lower}",
                entity: lower
            ));
            return;
        }

        // Suspicious keyword in exe/dll name
        if ((ext == ".exe" || ext == ".dll") && CheatDatabase.HasSuspiciousKeyword(lower))
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.SuspiciousExecution,
                Name,
                $"Arquivo suspeito deletado (USN): {rec.FileName}",
                "Nome contém indicador de cheat — arquivo deletado do disco.",
                null,
                rec.Timestamp,
                ruleId: $"USN_SUSP_DEL_{lower}",
                entity: lower
            ));
            return;
        }

        // Archive deletion → delivery artifact cleanup
        if (ArchiveExts.Contains(ext))
        {
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.AntiForensics,
                Name,
                $"Arquivo compactado deletado: {rec.FileName}",
                "ZIP/RAR/7Z deletado — possível limpeza de artefato de entrega de cheat.",
                rec.FileName,
                rec.Timestamp,
                confidence: Confidence.Low,
                ruleId: $"USN_ARCHIVE_DEL_{lower}",
                entity: lower
            ));
            return;
        }

        // Event log file deleted — strongest anti-forensic signal
        if (ext == ".evtx")
        {
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.AntiForensics,
                Name,
                $"LOG DE EVENTOS DELETADO (USN): {rec.FileName}",
                "Arquivo .evtx removido do diário NTFS — deleção manual de log de eventos Windows.",
                rec.FileName,
                rec.Timestamp,
                confidence: Confidence.High,
                ruleId: "ANTI_ECHO_EVTX_DELETE",
                entity: lower
            ));
            return;
        }

        // JumpList files deleted — hides per-application access history
        if (ext is ".automaticDestinations-ms" or ".customDestinations-ms")
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                Name,
                $"JUMPLIST DELETADA (USN): {rec.FileName}",
                "Arquivo de JumpList removido — oculta histórico de acesso recente por aplicação.",
                rec.FileName,
                rec.Timestamp,
                confidence: Confidence.High,
                ruleId: "ANTI_ECHO_JUMPLIST_DELETE",
                entity: lower
            ));
            return;
        }

        // DriverBooster loader artifacts deleted — require specific loader filename, not just any DriverBooster file.
        // Generic driverbooster.exe deletions (uninstall/update) are not a signal on their own.
        if (lower is "loader.dll" or "loader.cfg" or "driverbooster.dll" or "driverbooster.cfg")
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                Name,
                $"ARTEFATO DRIVERBOOSTER LOADER DELETADO (USN): {rec.FileName}",
                "Arquivo de loader de driver vulnerável removido — padrão de limpeza pós-bypass BYOVD.",
                rec.FileName,
                rec.Timestamp,
                confidence: Confidence.Medium,
                ruleId: "ANTIECHO_DRIVERBOOSTER_USN",
                entity: lower,
                validationHint: "Correlacionar com Driver & Kernel module para .sys não assinado e USN Journal para criação recente do mesmo arquivo"
            ));
        }
        else if (lower.Contains("driverbooster") || lower.Contains("driver booster"))
        {
            findings.Add(new Finding(
                RiskLevel.Low,
                FindingCategory.AntiForensics,
                Name,
                $"Arquivo DriverBooster deletado (USN): {rec.FileName}",
                "Arquivo com nome DriverBooster removido — pode ser uninstall/update legítimo.\nCorrelacionar com Driver & Kernel module antes de concluir.",
                rec.FileName,
                rec.Timestamp,
                confidence: Confidence.Low,
                ruleId: "ANTIECHO_DRIVERBOOSTER_USN",
                entity: lower,
                validationHint: "Baixo sinal isolado — correlacionar com .sys não assinado ou sessão de cheat"
            ));
        }
    }

    private void ClassifyCreation(UsnRecord rec, List<Finding> findings)
    {
        var lower = rec.FileNameLower;

        // Known cheat binary created on disk
        if (CheatDatabase.KnownExecutables.TryGetValue(lower, out var cheat))
        {
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.Cheat,
                Name,
                $"CHEAT CRIADO (USN): {cheat.Name}",
                $"Arquivo de cheat conhecido criado no disco.\n{cheat.Description}",
                rec.FileName,
                rec.Timestamp,
                confidence: Confidence.High,
                ruleId: $"USN_CHEAT_CREATE_{lower}",
                entity: lower
            ));
        }
        // Note: .sys creation is NOT flagged here — USN Journal provides only the filename,
        // not the full path. Path-based .sys analysis is handled by DriverKernelModule,
        // which has the full registry path context.
    }

    private void ClassifyRename(UsnRecord rec, List<Finding> findings)
    {
        var lower = rec.FileNameLower;

        if (!CheatDatabase.KnownExecutables.ContainsKey(lower) &&
            !CheatDatabase.HasSuspiciousKeyword(lower))
            return;

        var direction = (rec.Reason & RENAME_OLD) != 0 ? "renomeado (nome anterior)" : "renomeado (novo nome)";
        findings.Add(new Finding(
            RiskLevel.High,
            FindingCategory.SuspiciousExecution,
            Name,
            $"Arquivo suspeito {direction} (USN): {rec.FileName}",
            "Arquivo com nome suspeito renomeado — possível ofuscação ou remoção de rastro.",
            null,
            rec.Timestamp,
            ruleId: $"USN_RENAME_{lower}_{rec.Timestamp:yyyyMMddHHmm}",
            entity: lower
        ));
    }

    private static void DetectTimelinePatterns(
        List<UsnRecord> creates, List<UsnRecord> deletes,
        List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Rapid create→delete: same filename in creates AND deletes.
        // Requires suspicious name + narrow timestamp window to avoid flagging normal dev/runtime churn
        // (node.exe, libssl, sqlite3 cycle through temp dirs constantly).
        var createdByName = creates
            .GroupBy(r => r.FileNameLower, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Timestamp);

        // confirmedPairs: suspicious name + both timestamps within 30 min → High
        // untimedPairs:  suspicious name + no usable timestamps         → Medium/Low
        var confirmedPairs = new List<string>();
        var untimedPairs   = new List<string>();

        foreach (var del in deletes)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(del.FileNameLower);
            if (!ExecutableExts.Contains(ext) && !ArchiveExts.Contains(ext)) continue;
            if (!createdByName.TryGetValue(del.FileNameLower, out var createTime)) continue;

            bool isSuspicious = CheatDatabase.KnownExecutables.ContainsKey(del.FileNameLower)
                             || CheatDatabase.HasSuspiciousKeyword(del.FileNameLower);
            if (!isSuspicious) continue; // generic runtime files (node, libssl, sqlite…) — not a signal

            if (del.Timestamp.HasValue && createTime.HasValue)
            {
                var gapMinutes = Math.Abs((del.Timestamp.Value - createTime.Value).TotalMinutes);
                if (gapMinutes <= 30) confirmedPairs.Add(del.FileName);
                // gap > 30 min: different sessions, not a rapid pattern — skip
            }
            else
            {
                untimedPairs.Add(del.FileName); // suspicious name but can't confirm timing
            }
        }

        if (confirmedPairs.Count > 0)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                "USN Journal",
                $"Padrão criar→deletar: {confirmedPairs.Count} arquivo(s) suspeito(s) em <30min",
                "Arquivo suspeito criado e removido em menos de 30 minutos — padrão típico de loader fileless.\n" +
                "Arquivos: " + string.Join(", ", confirmedPairs.Take(5)),
                string.Join(", ", confirmedPairs.Take(5)),
                ruleId: "USN_RAPID_CREATE_DELETE",
                entity: "rapid-create-delete"
            ));
        }
        else if (untimedPairs.Count > 0)
        {
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.AntiForensics,
                "USN Journal",
                $"Padrão criar→deletar sem timestamp: {untimedPairs.Count} arquivo(s) suspeito(s)",
                "Arquivos com nome suspeito presentes em criações e deleções, mas sem timestamp para confirmar janela.\n" +
                "Arquivos: " + string.Join(", ", untimedPairs.Take(5)),
                string.Join(", ", untimedPairs.Take(5)),
                confidence: Confidence.Low,
                ruleId: "USN_RAPID_CREATE_DELETE_UNTIMED",
                entity: "rapid-create-delete"
            ));
        }

        // Bulk archive deletion — 3+ archives signals delivery-artifact cleanup
        var archiveDeletes = deletes
            .Where(r => ArchiveExts.Contains(Path.GetExtension(r.FileNameLower)))
            .ToList();

        if (archiveDeletes.Count >= 3)
        {
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.AntiForensics,
                "USN Journal",
                $"Limpeza em massa de compactados: {archiveDeletes.Count} arquivo(s)",
                "Múltiplos arquivos ZIP/RAR/7Z deletados — padrão de limpeza pós-instalação de cheat.",
                string.Join(", ", archiveDeletes.Take(5).Select(r => r.FileName)),
                confidence: Confidence.Low,
                ruleId: "USN_ARCHIVE_CLEANUP",
                entity: "archive-cleanup"
            ));
        }

        // Bulk JumpList deletion — 3+ JumpList files in one session = coordinated history wipe
        var jumpListDeletes = deletes
            .Where(r => r.FileNameLower.EndsWith(".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase) ||
                        r.FileNameLower.EndsWith(".customDestinations-ms",    StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (jumpListDeletes.Count >= 3)
        {
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.AntiForensics,
                "USN Journal",
                $"LIMPEZA EM MASSA DE JUMPLISTS: {jumpListDeletes.Count} arquivo(s)",
                "Múltiplos arquivos de JumpList deletados em sessão — padrão de limpeza coordenada de histórico de acesso.",
                string.Join(", ", jumpListDeletes.Take(5).Select(r => r.FileName)),
                confidence: Confidence.High,
                ruleId: "ANTI_ECHO_JUMPLIST_CLEAR",
                entity: "jumplist-bulk-clear"
            ));
        }
    }

    private async Task<List<UsnRecord>> ReadJournalAsync(string drive, CancellationToken ct)
    {
        var records = new List<UsnRecord>();
        try
        {
            // Single pass — findstr /c: applies OR logic across multiple flags
            var output = await RunCmdAsync("cmd.exe",
                "/c fsutil usn readjournal " + drive + " csv" +
                " | findstr /i /c:.exe /c:.dll /c:.sys /c:.zip /c:.rar /c:.7z /c:.pf /c:.ps1 /c:.bat" +
                " /c:.evtx /c:.lnk /c:.automaticDestinations-ms /c:.customDestinations-ms /c:.py /c:.cfg",
                90000, ct);

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                ct.ThrowIfCancellationRequested();
                var rec = ParseLine(line);
                if (rec != null) records.Add(rec);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("USN Journal inacessível ou fsutil falhou", ex); }

        return records;
    }

    // Windows 10/11 fsutil usn readjournal csv column layout:
    //   [0] USN
    //   [1] "FileName"
    //   [2] FileNameLength
    //   [3] ReasonHex       ← reason bitmask
    //   [4] ReasonText      (may contain spaces/pipes, but no commas)
    //   [5] Timestamp       ← e.g. "2024-01-15 10:23:45"
    //   [6] FileAttributesHex
    //   [7] FileAttributesText
    //   [8] FileRef
    //   [9] ParentRef
    private static UsnRecord? ParseLine(string line)
    {
        var parts = SplitCsv(line);
        if (parts.Length < 6) return null;

        var fileName = parts[1].Trim().Trim('"');
        if (string.IsNullOrEmpty(fileName)) return null;

        // USN only provides the filename, not the full path
        var fileNameOnly = Path.GetFileName(fileName);
        var ext = Path.GetExtension(fileNameOnly).ToLowerInvariant();
        if (!IsTargetExtension(ext)) return null;

        uint reason = 0;
        var reasonStr = parts[3].Trim();
        if (reasonStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            uint.TryParse(reasonStr[2..], System.Globalization.NumberStyles.HexNumber, null, out reason);

        // Timestamp position varies by Windows version: col 4 (no ReasonText) or col 5 (with ReasonText).
        // Try both with InvariantCulture first, then current culture as fallback.
        DateTime? timestamp = null;
        for (int i = 4; i <= 5 && i < parts.Length; i++)
        {
            var raw = parts[i].Trim().Trim('"');
            if (DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt) ||
                DateTime.TryParse(raw, CultureInfo.CurrentCulture,   DateTimeStyles.None, out dt))
            {
                timestamp = dt;
                break;
            }
        }

        return new UsnRecord(fileNameOnly, reason, timestamp);
    }

    // Quote-aware CSV splitter: respects "field,with,commas" as a single token
    private static string[] SplitCsv(string line)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        bool inQuotes = false;

        foreach (char c in line)
        {
            switch (c)
            {
                case '"':
                    inQuotes = !inQuotes;
                    sb.Append(c);
                    break;
                case ',' when !inQuotes:
                    fields.Add(sb.ToString());
                    sb.Clear();
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }

        fields.Add(sb.ToString());
        return [.. fields];
    }

    private static bool IsTargetExtension(string ext) => ext is
        ".exe" or ".dll" or ".sys" or ".zip" or ".rar" or ".7z"
        or ".ps1" or ".bat" or ".vbs" or ".pf"
        or ".evtx" or ".lnk" or ".automaticDestinations-ms" or ".customDestinations-ms"
        or ".py" or ".cfg";

    // FullPath intentionally omitted — USN Journal provides filename only.
    // Path-based analysis requires MFT parent-chain reconstruction (out of scope).
    private sealed record UsnRecord(string FileName, uint Reason, DateTime? Timestamp)
    {
        public string FileNameLower => FileName.ToLowerInvariant();
    }
}
