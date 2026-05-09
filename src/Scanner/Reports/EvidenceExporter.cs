using System.Text.Json;
using System.Text.Json.Serialization;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Reports;

public static class EvidenceExporter
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        WriteIndented = true,
        Converters    = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static void Export(ScanResult result, ScanConfig config, string runFolder)
    {
        var lookback = (int)config.EventWindowLookback.TotalDays;

        var dto = new EvidenceExportDto
        {
            Machine         = result.MachineName,
            User            = result.CurrentUser,
            ScanTime        = result.ScanTime,
            LookbackDays    = lookback,
            TotalScore      = result.TotalScore,
            OverallRisk     = result.OverallRiskLabel,
            Findings        = result.Findings.Select(FindingDto.From).ToList(),
            EvidenceBundles = result.EvidenceBundles.Select(BundleDto.From).ToList()
        };
        WriteJson(Path.Combine(runFolder, "evidence.json"), dto);

        // Always export per-source files — even when empty, so the investigator can verify coverage
        WriteModuleJson(result, runFolder, "Event Viewer",   "eventviewer_60d.json", lookback);
        WriteModuleJson(result, runFolder, "Windows Defender","defender_60d.json",   lookback);
        WriteModuleJson(result, runFolder, "Services",       "services_60d.json",    lookback);
    }

    private static void WriteModuleJson(
        ScanResult result, string runFolder,
        string module, string fileName, int lookbackDays)
    {
        var findings = result.Findings
            .Where(f => f.Module == module)
            .ToList();

        var timed = findings.Where(f => f.Timestamp.HasValue).ToList();
        DateTime? oldest = timed.Count > 0 ? timed.Min(f => f.Timestamp!.Value) : null;
        DateTime? newest = timed.Count > 0 ? timed.Max(f => f.Timestamp!.Value) : null;
        var coverageDays  = oldest.HasValue ? (int)(DateTime.Now - oldest.Value).TotalDays : 0;
        var coverageOk    = coverageDays >= lookbackDays;

        var dto = new ModuleExportDto
        {
            Module       = module,
            LookbackDays = lookbackDays,
            OldestEvent  = oldest,
            NewestEvent  = newest,
            CoverageDays = coverageDays,
            CoverageOk   = coverageOk,
            FindingCount = findings.Count,
            Findings     = findings.Select(FindingDto.From).ToList()
        };
        WriteJson(Path.Combine(runFolder, fileName), dto);
    }

    private static void WriteJson<T>(string path, T data) =>
        File.WriteAllText(path, JsonSerializer.Serialize(data, Opts), System.Text.Encoding.UTF8);
}

file sealed class EvidenceExportDto
{
    public string   Machine         { get; init; } = "";
    public string   User            { get; init; } = "";
    public DateTime ScanTime        { get; init; }
    public int      LookbackDays    { get; init; }
    public int      TotalScore      { get; init; }
    public string   OverallRisk     { get; init; } = "";
    public List<FindingDto> Findings        { get; init; } = [];
    public List<BundleDto>  EvidenceBundles { get; init; } = [];
}

file sealed class ModuleExportDto
{
    public string    Module       { get; init; } = "";
    public int       LookbackDays { get; init; }
    public DateTime? OldestEvent  { get; init; }
    public DateTime? NewestEvent  { get; init; }
    public int       CoverageDays { get; init; }
    public bool      CoverageOk   { get; init; }
    public int       FindingCount { get; init; }
    public List<FindingDto> Findings { get; init; } = [];
}

file sealed class FindingDto
{
    public string    Risk           { get; init; } = "";
    public string    Category       { get; init; } = "";
    public string    Module         { get; init; } = "";
    public string    Title          { get; init; } = "";
    public string    Detail         { get; init; } = "";
    public string?   Evidence       { get; init; }
    public DateTime? Timestamp      { get; init; }
    public string    Confidence     { get; init; } = "";
    public string?   RuleId         { get; init; }
    public string?   Entity         { get; init; }
    public string?   ValidationHint { get; init; }

    public static FindingDto From(Finding f) => new()
    {
        Risk           = f.Risk.ToString(),
        Category       = f.Category.ToString(),
        Module         = f.Module,
        Title          = f.Title,
        Detail         = f.Detail,
        Evidence       = f.Evidence,
        Timestamp      = f.Timestamp,
        Confidence     = f.Confidence.ToString(),
        RuleId         = f.RuleId,
        Entity         = f.Entity,
        ValidationHint = f.ValidationHint
    };
}

file sealed class BundleDto
{
    public string  ArtifactName     { get; init; } = "";
    public string  Verdict          { get; init; } = "";
    public string  Risk             { get; init; } = "";
    public string  Confidence       { get; init; } = "";
    public string? FullPath         { get; init; }
    public string? Sha256           { get; init; }
    public string? Sha1             { get; init; }
    public string  Summary          { get; init; } = "";
    public List<string> BypassIndicators { get; init; } = [];
    public List<string> ValidationSteps  { get; init; } = [];

    public static BundleDto From(EvidenceBundle b) => new()
    {
        ArtifactName     = b.ArtifactName,
        Verdict          = b.Verdict,
        Risk             = b.Risk.ToString(),
        Confidence       = b.Confidence.ToString(),
        FullPath         = b.FullPath,
        Sha256           = b.Sha256,
        Sha1             = b.Sha1,
        Summary          = b.Summary,
        BypassIndicators = b.BypassIndicators,
        ValidationSteps  = b.ValidationSteps
    };
}
