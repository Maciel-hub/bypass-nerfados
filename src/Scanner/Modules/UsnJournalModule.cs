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

        // Rapid create→delete: same filename in both lists — fileless loader pattern
        var createdNames = creates
            .GroupBy(r => r.FileNameLower, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Timestamp);

        var rapidPairs = new List<string>();
        foreach (var del in deletes)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(del.FileNameLower);
            if (!ExecutableExts.Contains(ext) && !ArchiveExts.Contains(ext)) continue;

            if (createdNames.ContainsKey(del.FileNameLower))
                rapidPairs.Add(del.FileName);
        }

        if (rapidPairs.Count > 0)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                "USN Journal",
                $"Padrão criar→deletar: {rapidPairs.Count} arquivo(s)",
                "Arquivos criados e depois deletados — padrão típico de loader fileless ou limpeza de rastros.\n" +
                "Arquivos: " + string.Join(", ", rapidPairs.Take(5)),
                string.Join(", ", rapidPairs.Take(5)),
                ruleId: "USN_RAPID_CREATE_DELETE",
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
    }

    private async Task<List<UsnRecord>> ReadJournalAsync(string drive, CancellationToken ct)
    {
        var records = new List<UsnRecord>();
        try
        {
            // Single pass — findstr /c: applies OR logic across multiple flags
            var output = await RunCmdAsync("cmd.exe",
                "/c fsutil usn readjournal " + drive + " csv" +
                " | findstr /i /c:.exe /c:.dll /c:.sys /c:.zip /c:.rar /c:.7z /c:.pf /c:.ps1 /c:.bat",
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

        DateTime? timestamp = null;
        if (DateTime.TryParse(parts[5].Trim(), out var ts)) timestamp = ts;

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
        or ".ps1" or ".bat" or ".vbs" or ".pf";

    // FullPath intentionally omitted — USN Journal provides filename only.
    // Path-based analysis requires MFT parent-chain reconstruction (out of scope).
    private sealed record UsnRecord(string FileName, uint Reason, DateTime? Timestamp)
    {
        public string FileNameLower => FileName.ToLowerInvariant();
    }
}
