using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class UsnJournalModule : BaseModule
{
    public override string Name => "USN Journal";
    public override string Description => "Registro de alterações NTFS — arquivos .exe criados, deletados e renomeados";

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var drive = config.TargetDrive;

        var tasks = new[]
        {
            ReadJournalAsync(drive, "0x80000200", "Deletados", cancellationToken),
            ReadJournalAsync(drive, "0x00000100", "Criados", cancellationToken),
            ReadJournalAsync(drive, "0x00001000", "Renomeados (nome antigo)", cancellationToken),
            ReadJournalAsync(drive, "0x00002000", "Renomeados (novo nome)", cancellationToken),
        };

        var results = await Task.WhenAll(tasks);

        foreach (var (label, lines) in results)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var line in lines)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var parts = line.Split(',');
                if (parts.Length < 5) continue;

                var exeName = parts[^1].Trim().Trim('"');
                if (string.IsNullOrEmpty(exeName)) continue;

                var fileNameLower = Path.GetFileName(exeName).ToLowerInvariant();
                DateTime? timestamp = null;
                if (parts.Length > 1 && DateTime.TryParse(parts[1].Trim(), out var ts))
                    timestamp = ts;

                if (CheatDatabase.KnownExecutables.TryGetValue(fileNameLower, out var cheat))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        Name,
                        $"CHEAT NO USN ({label}): {cheat.Name}",
                        $"Arquivo {fileNameLower} encontrado no USN Journal ({label}).\n{cheat.Description}",
                        $"Caminho: {exeName}",
                        timestamp
                    ));
                    continue;
                }

                if (label == "Deletados" && fileNameLower.EndsWith(".pf"))
                {
                    var exeFromPrefetch = Path.GetFileNameWithoutExtension(fileNameLower);
                    var dashIdx = exeFromPrefetch.LastIndexOf('-');
                    if (dashIdx > 0) exeFromPrefetch = exeFromPrefetch[..dashIdx];

                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.AntiForensics,
                        Name,
                        $"Prefetch deletado: {exeFromPrefetch}.exe",
                        "Arquivo Prefetch removido manualmente. Possível tentativa de ocultar histórico de execução.",
                        $"Arquivo .pf: {exeName}",
                        timestamp
                    ));
                    continue;
                }

                if (CheatDatabase.HasSuspiciousKeyword(fileNameLower))
                {
                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.SuspiciousExecution,
                        Name,
                        $"Arquivo suspeito ({label}): {fileNameLower}",
                        $"Nome contém indicador de cheat.\nCaminho: {exeName}",
                        null,
                        timestamp
                    ));
                }
            }
        }

        if (!findings.Any(f => f.Risk >= RiskLevel.High))
        {
            // Check for rapid create+delete pattern (typical of fileless loader)
            DetectRapidCreateDelete(results[0].Lines, results[1].Lines, findings, cancellationToken);
        }

        return findings;
    }

    private static void DetectRapidCreateDelete(
        IEnumerable<string> deleted, IEnumerable<string> created, List<Finding> findings,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var createdNames = new HashSet<string>(
            created.Select(l => l.Split(',').LastOrDefault()?.Trim().Trim('"') ?? ""),
            StringComparer.OrdinalIgnoreCase);

        var rapidDeletes = deleted
            .Select(l => l.Split(',').LastOrDefault()?.Trim().Trim('"') ?? "")
            .Where(name => !string.IsNullOrEmpty(name) && createdNames.Contains(name))
            .ToList();

        if (rapidDeletes.Count > 0)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                "USN Journal",
                $"Padrão criar+deletar: {rapidDeletes.Count} arquivo(s)",
                "Arquivos criados e deletados rapidamente. Padrão típico de loader fileless ou limpeza de rastros.",
                string.Join(", ", rapidDeletes.Take(5))
            ));
        }
    }

    private async Task<(string Label, List<string> Lines)> ReadJournalAsync(
        string drive, string reasonMask, string label, CancellationToken cancellationToken)
    {
        var tempFile = Path.GetTempFileName();
        var lines = new List<string>();
        try
        {
            var output = await Task.Run(() => RunCmd("cmd.exe",
                $"/c fsutil usn readjournal {drive} csv | findstr /i /c:.exe | findstr /i /c:{reasonMask}",
                60000,
                cancellationToken), cancellationToken);

            lines = output
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(l => l.Contains(".exe", StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("USN Journal inacessível ou fsutil falhou", ex); }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
        return (label, lines);
    }
}
