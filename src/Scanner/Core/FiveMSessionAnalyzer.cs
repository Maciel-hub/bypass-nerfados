using Microsoft.Win32;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Core;

public static class FiveMSessionAnalyzer
{
    private static readonly string[] s_fivemDataPaths =
    [
        "fivem application data",
        @"fivem\plugins",
        "fivem/plugins",
        "citizenfx",
        "game-storage",
        "fivem_b_harness",
    ];

    public static void Analyze(ScanResult result)
    {
        var sessions = CollectSessions(result);
        bool hasCoExec = result.Findings.Any(f => f.RuleId?.StartsWith("BAM_COEXEC_") == true);
        if (sessions.Count == 0 && !hasCoExec)
            return;

        var relevant = result.Findings
            .Where(f => f.Module != "Correlação" &&
                        !CheatDatabase.IsKnownLegitimate(f.Entity ?? "") &&
                        IsExecutableFinding(f))
            .ToList();

        // Group by normalized filename to get one row per executable
        var groups = relevant
            .GroupBy(f => NormalizeEntity(f.Entity ?? f.Title), StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var group in groups)
        {
            var findings = group.ToList();
            var relation = DetermineRelation(findings, sessions,
                out var sessionTime, out var deltaMinutes);

            if (relation == FiveMRelation.Unknown)
                continue;

            var representative = findings.OrderByDescending(f => (int)f.Risk).First();
            var sources = findings.Select(f => f.Module).Distinct().Order().ToArray();
            var path = ExtractPath(representative);
            var fileName = ExtractFileName(group.Key);

            result.FiveMSessionContexts.Add(new FiveMSessionContext(
                Entity:         group.Key,
                FileName:       fileName,
                Path:           path,
                Relation:       relation,
                EventTime:      representative.Timestamp,
                SessionTime:    sessionTime,
                DeltaMinutes:   deltaMinutes,
                Sources:        sources,
                EvidenceSummary: BuildSummary(representative, relation, deltaMinutes),
                Risk:           representative.Risk,
                Confidence:     representative.Confidence,
                RuleId:         representative.RuleId,
                ValidationHint: representative.ValidationHint));

            // OutsideSession generic/low-confidence: suppress from Top Findings and scoring
            if (relation == FiveMRelation.OutsideSession && representative.Confidence < Confidence.High)
            {
                foreach (var f in findings)
                {
                    if (f.ValidationHint == null)
                        f.ValidationHint = "Fora da janela de sessão FiveM — sem prova de interação direta.";
                    f.ScoreEligible = false;
                    if (f.Risk > RiskLevel.Medium)
                        f.Risk = RiskLevel.Medium;
                }
            }
        }
    }

    private static bool IsExecutableFinding(Finding f) =>
        f.Category is FindingCategory.Cheat
                   or FindingCategory.SuspiciousExecution
                   or FindingCategory.MemoryAnomaly
                   or FindingCategory.KernelArtifact ||
        f.RuleId?.StartsWith("BAM_COEXEC_") == true ||
        f.RuleId?.StartsWith("REDENGINE_") == true ||
        f.RuleId?.StartsWith("ASTRIX_") == true ||
        f.RuleId?.StartsWith("STAN_") == true ||
        (f.Entity ?? f.Title).EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
        (f.Entity ?? f.Title).EndsWith(".dll", StringComparison.OrdinalIgnoreCase);

    private static FiveMRelation DetermineRelation(
        List<Finding> findings,
        List<DateTime> sessions,
        out DateTime? sessionTime,
        out double? deltaMinutes)
    {
        sessionTime  = null;
        deltaMinutes = null;

        bool isDirect = findings.Any(f =>
            f.RuleId?.StartsWith("BAM_COEXEC_") == true ||
            f.Module is "Memory DLL Trace" or "Memory String Scan" ||
            HasFiveMDataPath(f));

        if (isDirect)
        {
            var pivot = findings.FirstOrDefault(f => f.Timestamp.HasValue)?.Timestamp;
            if (pivot.HasValue && sessions.Count > 0)
            {
                var closest = sessions.MinBy(s => Math.Abs((s - pivot.Value).TotalMinutes));
                sessionTime  = closest;
                deltaMinutes = (pivot.Value - closest).TotalMinutes;
            }
            return FiveMRelation.DirectInteraction;
        }

        // Co-process: random loader with -cf payload, cfg.dat, C2 port, Astrix, or Stan with credentials/prefetch/BAM
        bool isCoProcess = findings.Any(f =>
            f.RuleId is "REDENGINE_CFG_DAT_NEAR_LOADER"
                     or "REDENGINE_CMDLINE_CF_PAYLOAD"
                     or "REDENGINE_NUMERIC_PAYLOAD_EXECUTED"
                     or "REDENGINE_ACTIVE_C2_PORT"
                     or "REDENGINE_RANDOM_LOADER_NET"
                     or "ASTRIX_ACTIVE_PROCESS"
                     or "ASTRIX_EXE_USERPATH"
                     or "ASTRIX_CONFIG_FILE"
                     or "ASTRIX_PREFETCH_EXECUTED"
                     or "ASTRIX_BAM_EXECUTED"
                     or "STAN_LOADER_WITH_CREDENTIAL"
                     or "STAN_CREDENTIALS_NEAR_LOADER"
                     or "STAN_PREFETCH_EXECUTED"
                     or "STAN_BAM_EXECUTED");

        if (isCoProcess)
        {
            if (sessions.Count > 0)
            {
                // Pick the finding timestamp closest to any FiveM session.
                // Prefers execution-trace timestamps (Prefetch/BAM) over disk-artifact modification times.
                var best = findings
                    .Where(f => f.Timestamp.HasValue)
                    .SelectMany(f => sessions.Select(s =>
                        (Finding: f, Session: s, Delta: (f.Timestamp!.Value - s).TotalMinutes)))
                    .OrderBy(t => Math.Abs(t.Delta))
                    .FirstOrDefault();
                if (best.Finding != null)
                {
                    sessionTime  = best.Session;
                    deltaMinutes = best.Delta;
                }
            }
            return FiveMRelation.CoProcessInteraction;
        }

        var timed = findings.Where(f => f.Timestamp.HasValue).ToList();
        if (timed.Count == 0)
            return FiveMRelation.Unknown;

        foreach (var f in timed.OrderByDescending(f => f.Timestamp!.Value))
        {
            foreach (var session in sessions.OrderByDescending(s => s))
            {
                if (f.Timestamp!.Value >= session.AddMinutes(-30) &&
                    f.Timestamp!.Value <= session.AddHours(2))
                {
                    sessionTime  = session;
                    deltaMinutes = (f.Timestamp.Value - session).TotalMinutes;
                    return FiveMRelation.NearSession;
                }
            }
        }

        return FiveMRelation.OutsideSession;
    }

    internal static bool HasFiveMDataPath(Finding f)
    {
        var text = $"{f.Entity} {f.Detail} {f.Evidence}".ToLowerInvariant();
        return s_fivemDataPaths.Any(p => text.Contains(p));
    }

    private static string NormalizeEntity(string entity)
    {
        try
        {
            var lower = entity.ToLowerInvariant().TrimEnd('\\', '/');
            var name  = Path.GetFileName(lower);
            return string.IsNullOrEmpty(name) ? lower : name;
        }
        catch { return entity.ToLowerInvariant(); }
    }

    private static string ExtractFileName(string entity)
    {
        try
        {
            var name = Path.GetFileName(entity);
            return string.IsNullOrEmpty(name) ? entity : name;
        }
        catch { return entity; }
    }

    private static string? ExtractPath(Finding f)
    {
        var entity = f.Entity ?? "";
        return (entity.Contains('\\') || entity.Contains('/')) ? entity : null;
    }

    private static string BuildSummary(Finding f, FiveMRelation relation, double? delta) =>
        relation switch
        {
            FiveMRelation.DirectInteraction when f.RuleId?.StartsWith("BAM_COEXEC_") == true
                => "Co-execução BAM com FiveM.exe",
            FiveMRelation.DirectInteraction when f.Module == "Memory DLL Trace"
                => "DLL/módulo detectado em processo FiveM/GTA",
            FiveMRelation.DirectInteraction when f.Module == "Memory String Scan"
                => "String de cheat em memória de processo FiveM/GTA",
            FiveMRelation.DirectInteraction
                => $"Caminho em FiveM Application Data ({f.Module})",
            FiveMRelation.CoProcessInteraction when f.RuleId?.StartsWith("ASTRIX_") == true
                => $"Co-processo Astrix External ({f.Module})",
            FiveMRelation.CoProcessInteraction when f.RuleId?.StartsWith("REDENGINE_") == true
                => $"Co-processo RedENGINE loader ({f.Module})",
            FiveMRelation.CoProcessInteraction when f.RuleId?.StartsWith("STAN_") == true
                => $"Co-processo Stan loader ({f.Module})",
            FiveMRelation.CoProcessInteraction
                => $"Co-processo suspeito junto ao FiveM ({f.Module})",
            FiveMRelation.NearSession
                => $"Próximo à sessão FiveM ({FormatDelta(delta)})",
            FiveMRelation.OutsideSession
                => $"Fora da janela FiveM — {f.Module}",
            _ => f.Title
        };

    private static string FormatDelta(double? delta)
    {
        if (delta is null) return "?";
        var abs  = Math.Abs(delta.Value);
        var sign = delta.Value >= 0 ? "+" : "-";
        return abs >= 60
            ? $"{sign}{(int)(abs / 60)}h{(int)(abs % 60):00}"
            : $"{sign}{abs:F1} min";
    }

    private static List<DateTime> CollectSessions(ScanResult result)
    {
        var times = new List<DateTime>();

        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (Directory.Exists(prefetchDir))
        {
            try
            {
                foreach (var pf in Directory.GetFiles(prefetchDir, "FIVEM*.PF")
                    .Concat(Directory.GetFiles(prefetchDir, "GTA5*.PF")))
                    times.Add(File.GetLastWriteTime(pf));
            }
            catch { }
        }

        foreach (var svc in new[] { "bam", "dam" })
        {
            try
            {
                using var hive = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svc}\State\UserSettings");
                if (hive == null) continue;
                foreach (var sid in hive.GetSubKeyNames())
                {
                    using var key = hive.OpenSubKey(sid);
                    if (key == null) continue;
                    foreach (var vname in key.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(vname)) continue;
                        var lower = vname.ToLowerInvariant();
                        if (!lower.EndsWith("\\fivem.exe") && !lower.EndsWith("\\gta5.exe")) continue;
                        var data = key.GetValue(vname, null,
                            RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                        if (data?.Length < 8) continue;
                        var ft = BitConverter.ToInt64(data!, 0);
                        if (ft > 0) try { times.Add(DateTime.FromFileTime(ft)); } catch { }
                    }
                }
            }
            catch { }
        }

        times.AddRange(result.Findings
            .Where(f => f.RuleId?.StartsWith("BAM_COEXEC_") == true && f.Timestamp.HasValue)
            .Select(f => f.Timestamp!.Value));

        return times.Distinct().OrderBy(t => t).ToList();
    }
}
