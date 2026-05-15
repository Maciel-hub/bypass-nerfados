using System.Text.Json;
using System.Text.Json.Nodes;

namespace BypassNerfados.Scanner.Core;

public sealed class ExternalRules
{
    public IReadOnlyList<string> CheatNames        { get; init; } = [];
    public IReadOnlyList<string> CheatHashes       { get; init; } = [];
    public IReadOnlyList<string> SuspiciousDomains { get; init; } = [];
    public IReadOnlyList<string> LegitPublishers   { get; init; } = [];
    public ExternalScoreConfig   Score             { get; init; } = new();

    public static ExternalRules Empty => new();
}

public sealed class ExternalScoreConfig
{
    // Findings at this risk level with confidence <= NoiseMaxConfidence are non-score-eligible
    public string NoiseMinRisk        { get; init; } = "Medium";
    public string NoiseMaxConfidence  { get; init; } = "Low";
}

public static class RulesLoader
{
    private static readonly JsonDocumentOptions s_opts = new() { CommentHandling = JsonCommentHandling.Skip };

    public static ExternalRules Load()
    {
        var rulesDir = Path.Combine(AppContext.BaseDirectory, "rules");
        if (!Directory.Exists(rulesDir)) return ExternalRules.Empty;

        return new ExternalRules
        {
            CheatNames        = LoadList(rulesDir, "cheat_names.json"),
            CheatHashes       = LoadList(rulesDir, "cheat_hashes.json"),
            SuspiciousDomains = LoadList(rulesDir, "suspicious_domains.json"),
            LegitPublishers   = LoadList(rulesDir, "known_legit_publishers.json"),
            Score             = LoadScore(rulesDir)
        };
    }

    private static IReadOnlyList<string> LoadList(string dir, string file)
    {
        var path = Path.Combine(dir, file);
        if (!File.Exists(path)) return [];
        try
        {
            using var doc  = JsonDocument.Parse(File.ReadAllText(path), s_opts);
            if (!doc.RootElement.TryGetProperty("items", out var arr) || arr.ValueKind != JsonValueKind.Array)
                return [];
            return arr.EnumerateArray()
                      .Where(e => e.ValueKind == JsonValueKind.String)
                      .Select(e => e.GetString()!)
                      .Where(s => !string.IsNullOrWhiteSpace(s))
                      .ToList();
        }
        catch { return []; }
    }

    private static ExternalScoreConfig LoadScore(string dir)
    {
        var path = Path.Combine(dir, "score_weights.json");
        if (!File.Exists(path)) return new();
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path), s_opts);
            var r = doc.RootElement;
            return new ExternalScoreConfig
            {
                NoiseMinRisk       = r.TryGetProperty("noiseMinRisk",       out var nr) ? nr.GetString() ?? "Medium" : "Medium",
                NoiseMaxConfidence = r.TryGetProperty("noiseMaxConfidence", out var nc) ? nc.GetString() ?? "Low"    : "Low"
            };
        }
        catch { return new(); }
    }
}
