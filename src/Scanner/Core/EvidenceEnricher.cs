using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Core;

public static class EvidenceEnricher
{
    /// <summary>
    /// Groups cheat findings by artifact (SHA256 > path > name), builds a dossier for each,
    /// and cross-references with bypass/anti-forensic signals. Runs after Correlator.
    /// </summary>
    public static List<EvidenceBundle> Enrich(IEnumerable<Finding> allFindings)
    {
        var findings = allFindings.ToList();

        // Only group cheat findings that represent real file artifacts (skip Correlator meta-findings)
        var cheatGroups = findings
            .Where(f => f.Category == FindingCategory.Cheat && f.Module != "Correlação")
            .GroupBy(NormalizeArtifactKey)
            .ToList();

        var bundles = new List<EvidenceBundle>();

        foreach (var group in cheatGroups)
        {
            var groupList = group.ToList();
            var best = groupList
                .OrderByDescending(f => f.Confidence)
                .ThenByDescending(f => f.Risk)
                .First();

            var signals = groupList.Select(f => new EvidenceSignal
            {
                SourceModule  = f.Module,
                SignalType    = ModuleToSignalType(f.Module),
                Description   = f.Title,
                EvidenceValue = f.Evidence,
                Timestamp     = f.Timestamp,
                Confidence    = f.Confidence
            }).ToList();

            var timeline = groupList
                .Where(f => f.Timestamp.HasValue)
                .OrderBy(f => f.Timestamp)
                .Select(f => new ArtifactTimelineItem
                {
                    Timestamp = f.Timestamp,
                    Source    = f.Module,
                    Action    = ClassifyAction(f),
                    Detail    = f.Title
                }).ToList();

            var fullPath    = ExtractFullPath(groupList);
            var (sha256, sha1) = ExtractHashes(groupList);
            var verdict     = ClassifyVerdict(groupList);
            var bypass      = FindBypassIndicators(groupList, findings);
            var validation  = groupList
                .Where(f => f.ValidationHint != null)
                .Select(f => f.ValidationHint!)
                .Distinct()
                .ToList();

            var sourceModules = signals.Select(s => s.SourceModule).Distinct().ToList();

            var artifactName = ArtifactDisplayName(group.Key, groupList);

            bundles.Add(new EvidenceBundle
            {
                ArtifactId       = group.Key,
                ArtifactName     = artifactName,
                FullPath         = fullPath,
                Verdict          = verdict,
                Risk             = best.Risk,
                Confidence       = best.Confidence,
                Summary          = string.Join(" + ", sourceModules),
                Sha256           = sha256,
                Sha1             = sha1,
                Signals          = signals,
                Timeline         = timeline,
                BypassIndicators = bypass,
                ValidationSteps  = validation
            });
        }

        return bundles
            .OrderByDescending(b => b.Confidence)
            .ThenByDescending(b => b.Risk)
            .ToList();
    }

    // Priority: SHA256 > full path > filename
    // SHA256 uniquely identifies an artifact regardless of where it was copied.
    // Full path separates launcher.exe from Rockstar / Epic / FiveM / Wuthering Waves.
    // Filename is the fallback for Prefetch and other module findings without a path.
    private static string NormalizeArtifactKey(Finding f)
    {
        // Priority 1: SHA256 — two files with the same hash are the same artifact
        var sha256 = ExtractHashField(f.Evidence ?? "", "SHA256:");
        if (!string.IsNullOrEmpty(sha256))
            return $"sha256:{sha256}";

        // Priority 2: Full path from entity
        if (!string.IsNullOrEmpty(f.Entity) && (f.Entity.Contains('\\') || f.Entity.Contains('/')))
            return $"path:{f.Entity.ToLowerInvariant()}";

        // Priority 3: Full path extracted from Detail/Evidence text
        var pathFromText = ExtractPathLabel(f.Detail) ?? ExtractPathLabel(f.Evidence);
        if (!string.IsNullOrEmpty(pathFromText) && (pathFromText.Contains('\\') || pathFromText.Contains('/')))
            return $"path:{pathFromText.ToLowerInvariant()}";

        // Priority 4: Filename (Prefetch, BAM — no full path available)
        if (!string.IsNullOrEmpty(f.Entity))
        {
            var name = Path.GetFileName(f.Entity);
            if (!string.IsNullOrEmpty(name) && name.Contains('.'))
                return name.ToLowerInvariant();
        }

        // Last resort: extract .exe/.dll from title text
        var title = f.Title.ToLowerInvariant();
        foreach (var ext in new[] { ".exe", ".dll" })
        {
            var idx = title.LastIndexOf(ext, StringComparison.Ordinal);
            if (idx > 0)
            {
                var start = Math.Max(title.LastIndexOf(' ', idx) + 1, 0);
                return title[start..(idx + ext.Length)];
            }
        }

        return (f.Entity ?? f.Title).ToLowerInvariant();
    }

    // Converts the stable grouping key back to a human-readable file name for display
    private static string ArtifactDisplayName(string key, List<Finding> group)
    {
        if (key.StartsWith("sha256:") || key.StartsWith("path:"))
        {
            // Try to get the actual file name from one of the group's entities
            var name = group
                .Select(f => Path.GetFileName(f.Entity ?? ""))
                .FirstOrDefault(n => !string.IsNullOrEmpty(n) && n.Contains('.'));
            if (!string.IsNullOrEmpty(name)) return name.ToLowerInvariant();

            // Fall back to last segment of path key
            if (key.StartsWith("path:"))
                return Path.GetFileName(key["path:".Length..]);
        }
        return key;
    }

    // Prefers entity that looks like a full file-system path
    private static string? ExtractFullPath(List<Finding> group)
    {
        foreach (var f in group.OrderByDescending(f => f.Confidence))
        {
            if (string.IsNullOrEmpty(f.Entity)) continue;
            if (f.Entity.Contains('\\') || f.Entity.Contains('/'))
                return f.Entity;
        }

        // Fall back to "Arquivo:" / "Caminho:" patterns in Detail or Evidence
        foreach (var f in group)
        {
            var path = ExtractPathLabel(f.Detail) ?? ExtractPathLabel(f.Evidence);
            if (path != null) return path;
        }

        return group.First().Entity;
    }

    private static string? ExtractPathLabel(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        var lower = text.ToLowerInvariant();
        foreach (var prefix in new[] { "arquivo:", "caminho:", "path:" })
        {
            var idx = lower.IndexOf(prefix, StringComparison.Ordinal);
            if (idx < 0) continue;
            var rest = text[(idx + prefix.Length)..].TrimStart();
            var end  = rest.IndexOfAny(['\n', '|', '\r']);
            return (end > 0 ? rest[..end] : rest).Trim();
        }
        return null;
    }

    private static (string? sha256, string? sha1) ExtractHashes(List<Finding> group)
    {
        string? sha256 = null, sha1 = null;
        foreach (var f in group)
        {
            var ev = f.Evidence ?? "";
            sha256 ??= ExtractHashField(ev, "SHA256:");
            sha1   ??= ExtractHashField(ev, "SHA1:");
        }
        return (sha256, sha1);
    }

    private static string? ExtractHashField(string text, string prefix)
    {
        var idx = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var rest = text[(idx + prefix.Length)..].TrimStart();
        var end  = rest.IndexOfAny([' ', '|', '\n', '\r']);
        var hash = (end > 0 ? rest[..end] : rest).Trim();
        return hash is "N/A" or "" ? null : hash;
    }

    private static string ClassifyVerdict(List<Finding> group)
    {
        var best = group.OrderByDescending(f => f.Confidence).First();
        return best.Confidence switch
        {
            Confidence.Confirmed => "Confirmado",
            Confidence.High      => "Forte Indício",
            Confidence.Medium    => "Indício",
            _                    => "Baixa Confiança"
        };
    }

    // Finds bypass/anti-forensic signals that are temporally close to the cheat artifact.
    // Covers: AntiForensics, ServiceTampering, Defender disable/exclusion,
    // suspicious services, and high-risk SystemTampering events.
    private static List<string> FindBypassIndicators(List<Finding> cheatGroup, List<Finding> allFindings)
    {
        var bypassFindings = allFindings
            .Where(IsRelevantBypassSignal)
            .ToList();

        if (bypassFindings.Count == 0) return [];

        var timestamps = cheatGroup
            .Where(f => f.Timestamp.HasValue)
            .Select(f => f.Timestamp!.Value)
            .ToList();

        IEnumerable<Finding> relevant;
        if (timestamps.Count > 0)
        {
            var earliest = timestamps.Min().AddHours(-1);
            var latest   = timestamps.Max().AddHours(1);
            relevant = bypassFindings.Where(f =>
                !f.Timestamp.HasValue ||
                (f.Timestamp.Value >= earliest && f.Timestamp.Value <= latest));
        }
        else
        {
            // No cheat timestamps — include any high-confidence bypass signal
            relevant = bypassFindings.Where(f => f.Risk >= RiskLevel.High);
        }

        return relevant
            .Take(5)
            .Select(f => $"[{f.RiskLabel}] {f.Module}: {f.Title}")
            .ToList();
    }

    private static bool IsRelevantBypassSignal(Finding f)
    {
        if (f.Risk < RiskLevel.Medium) return false;

        // Direct anti-forensic events (log clearing, USN manipulation, Prefetch gone)
        if (f.Category == FindingCategory.AntiForensics) return true;

        // Service tampering (protection services stopped/disabled)
        if (f.Category == FindingCategory.ServiceTampering) return true;

        // Specific Defender events — disable or exclusion additions (not generic 5007 noise)
        if (f.RuleId is "DEFENDER_DISABLED_5007" or "DEFENDER_EXCLUSION_5007") return true;

        // Suspicious service installed near the artifact
        if (f.Category == FindingCategory.SuspiciousExecution &&
            (f.Title.Contains("SERVIÇO SUSPEITO", StringComparison.OrdinalIgnoreCase) ||
             f.Title.Contains("7045", StringComparison.Ordinal)))
            return true;

        // High-risk system tampering (policy change, Defender registry disable, etc.)
        if (f.Category == FindingCategory.SystemTampering && f.Risk >= RiskLevel.High) return true;

        return false;
    }

    private static string ModuleToSignalType(string module) => module switch
    {
        "Known Cheats"       => "FileSystem",
        "Prefetch"           => "Prefetch",
        "File System"        => "FileSystem",
        "Registry Artifacts" => "Registry",
        "BAM/DAM"            => "BAM",
        "Event Viewer"       => "EventLog",
        "Defender"           => "Defender",
        _                    => module
    };

    private static string ClassifyAction(Finding f)
    {
        var t = f.Title.ToLowerInvariant();
        if (t.Contains("lixeira"))             return "Deletado";
        if (t.Contains("prefetch"))            return "Executado";
        if (t.Contains("muicache") || t.Contains("store")) return "Registrado";
        if (t.Contains("download"))            return "Baixado";
        if (t.Contains("temp"))                return "Executado/Temp";
        if (t.Contains("bam") || t.Contains("dam")) return "Executado";
        return "Detectado";
    }
}
