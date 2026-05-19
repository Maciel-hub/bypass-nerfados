using System.Text.Json;
using System.Text.Json.Serialization;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Reports;

public static class EvidenceExporter
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        WriteIndented       = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters          = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static void Export(ScanResult result, ScanConfig config, string runFolder)
    {
        var lookback = (int)config.EventWindowLookback.TotalDays;

        var dto = new EvidenceExportDto
        {
            Machine               = result.MachineName,
            User                  = result.CurrentUser,
            MachineId             = result.MachineId,
            ScanTime              = result.ScanTime,
            LookbackDays          = lookback,
            License               = result.License is { } lic ? new LicenseExportEntry
            {
                CustomerId         = lic.CustomerId,
                LicenseMachineId   = lic.LicenseMachineId,
                EffectiveMachineId = lic.EffectiveMachineId,
                IsWildcard         = lic.IsWildcard,
                ExpiresAt          = lic.ExpiresAt,
                Features           = lic.Features,
            } : null,
            TotalScore            = result.TotalScore,
            RawScore              = result.RawScore,
            UncappedRawScore      = result.UncappedRawScore,
            UncappedEligibleScore = result.UncappedEligibleScore,
            FilteredWeightedScore = result.FilteredWeightedScore,
            FilteredCount         = result.FilteredCount,
            EligibleFindingCount  = result.Findings.Count(f => f.ScoreEligible),
            FilteredFindingCount  = result.FilteredCount,
            OverallRisk           = result.OverallRiskLabel,
            Findings              = result.Findings.Select(FindingDto.From).ToList(),
            EvidenceBundles       = result.EvidenceBundles.Select(BundleDto.From).ToList(),
            ModuleCoverage        = result.ModuleCoverage.Select(ModuleCoverageDto.From).ToList()
        };
        WriteJson(Path.Combine(runFolder, "evidence.json"), dto);

        // machine_id.txt — human-readable identity record for chain-of-custody
        var idLines = new List<string>
        {
            $"machineId={result.MachineId}",
            $"machineName={result.MachineName}",
            $"user={result.CurrentUser}",
            $"scanStarted={result.ScanTime:yyyy-MM-ddTHH:mm:ss}",
        };
        if (result.License is { } mid)
        {
            idLines.Add($"licenseCustomerId={mid.CustomerId}");
            idLines.Add($"licenseMachineId={mid.LicenseMachineId}");
            idLines.Add($"licenseWildcard={mid.IsWildcard.ToString().ToLowerInvariant()}");
            idLines.Add($"licenseExpiresAt={mid.ExpiresAt:yyyy-MM-ddTHH:mm:ssZ}");
        }
        File.WriteAllText(Path.Combine(runFolder, "machine_id.txt"),
            string.Join(Environment.NewLine, idLines) + Environment.NewLine,
            System.Text.Encoding.UTF8);

        var d = $"{lookback}d";

        // Core execution-evidence modules — first consulted in any FiveM investigation
        WriteModuleJson(result, runFolder, "BAM/DAM",             $"bamdam_{d}.json",             lookback);
        WriteModuleJson(result, runFolder, "Prefetch",            $"prefetch_{d}.json",           lookback);
        WriteModuleJson(result, runFolder, "Known Cheats",        $"knowncheats_{d}.json",        lookback);
        WriteModuleJson(result, runFolder, "Registry Artifacts",  $"registryartifacts_{d}.json",  lookback);

        // Always export per-source files — even when empty, so the investigator can verify coverage
        WriteModuleJson(result, runFolder, "Event Viewer",        $"eventviewer_{d}.json",        lookback);
        WriteModuleJson(result, runFolder, "Windows Defender",    $"defender_{d}.json",           lookback);
        WriteModuleJson(result, runFolder, "Services",            $"services_{d}.json",           lookback);
        WriteModuleJson(result, runFolder, "System Info",         $"systeminfo_{d}.json",         lookback);

        // Artifact-trail modules: no event-log coverage backing; coverage estimated from findings
        WriteModuleJson(result, runFolder, "Amcache",               $"amcache_{d}.json",              lookback);
        WriteModuleJson(result, runFolder, "UserAssist",            $"userassist_{d}.json",           lookback);
        WriteModuleJson(result, runFolder, "ShimCache",             $"shimcache_{d}.json",            lookback);
        WriteModuleJson(result, runFolder, "LNK Recent",            $"lnk_{d}.json",                 lookback);
        WriteModuleJson(result, runFolder, "RegistryPersistence",   $"registrypersistence_{d}.json", lookback);

        // Extended modules
        WriteModuleJson(result, runFolder, "System Reset/Restore",  $"systemreset_{d}.json",         lookback);
        WriteModuleJson(result, runFolder, "System Tampering",       $"systemtampering_{d}.json",      lookback);
        WriteModuleJson(result, runFolder, "Anti-Forensic Scripts", $"antiforensicscripts_{d}.json",  lookback);
        WriteModuleJson(result, runFolder, "Browser Downloads",     $"browserdownloads_{d}.json",    lookback);
        WriteModuleJson(result, runFolder, "ShellBags",             $"shellbags_{d}.json",           lookback);
        WriteModuleJson(result, runFolder, "Jump Lists",            $"jumplists_{d}.json",           lookback);
        WriteModuleJson(result, runFolder, "NVIDIA Artifacts",      $"nvidia_{d}.json",              lookback);
        WriteModuleJson(result, runFolder, "External Tool Residue", $"externaltools_{d}.json",       lookback);
        WriteModuleJson(result, runFolder, "Recycle Bin",           $"recyclebin_{d}.json",          lookback);
        WriteModuleJson(result, runFolder, "Timeline",              $"timeline_{d}.json",            lookback);
        WriteModuleJson(result, runFolder, "SRUM",                  $"srum_{d}.json",               lookback);
        WriteModuleJson(result, runFolder, "File System",           $"filesystem_{d}.json",          lookback);
        WriteModuleJson(result, runFolder, "Network Usage",         $"network_{d}.json",             lookback);

        // Cheat-family artifact modules
        WriteModuleJson(result, runFolder, "RedENGINE Artifacts",   $"redengine_{d}.json",           lookback);

        // Optional modules — always written so investigator can confirm whether they ran
        WriteModuleJson(result, runFolder, "USN Journal",           $"usnjournal_{d}.json",          lookback);
        WriteModuleJson(result, runFolder, "Driver & Kernel",       $"driverkernel_{d}.json",        lookback);
        WriteModuleJson(result, runFolder, "Process Memory",        $"processmemory_{d}.json",       lookback);
        WriteModuleJson(result, runFolder, "Memory DLL Trace",      $"memorydlltrace_{d}.json",      lookback);
        WriteModuleJson(result, runFolder, "Memory String Scan",    $"memorystrscan_{d}.json",       lookback);
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

        // Prefer coverage days from CheckLogCoverage findings (actual oldest record in the log)
        // over estimating from finding timestamps (quiet periods undercount real log depth).
        // When no coverage warning exists the log met the requirement — report full lookback.
        var coverageDays = ResolveCoverageDays(result, module, oldest, lookbackDays);
        var coverageOk   = coverageDays >= lookbackDays;

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

    // Filesystem-scan and registry-scan modules cover the current state of the system —
    // their finding timestamps reflect artifact age, NOT how far back the scan can see.
    // Always report full lookback for these to avoid coverageOk=false on clean/synthetic runs.
    private static readonly HashSet<string> _fullCoverageModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "Known Cheats", "File System", "RedENGINE Artifacts",
        "Registry Artifacts", "RegistryPersistence", "SystemTampering",
        "System Reset/Restore", "System Info", "Services",
        "Process Memory", "Memory DLL Trace", "Memory String Scan", "Network Usage",
        "Anti-Forensic Scripts",
        // USN Journal and Driver & Kernel cover system-wide state, not a bounded event-log window.
        // Their findings' timestamps reflect artifact age, not scan depth — report full lookback.
        "USN Journal", "Driver & Kernel",
    };

    // Maps each module export to the Windows logs that back it, then reads coverage days
    // from the LOG_COVERAGE_* findings emitted by EventViewerModule.CheckLogCoverage.
    // Those findings embed "Cobertura: N dias" in their Evidence field.
    // When no coverage warning is present the log had sufficient data — return lookbackDays.
    // When multiple logs are relevant, return the worst (minimum) coverage.
    private static int ResolveCoverageDays(
        ScanResult result, string module, DateTime? oldestFinding, int lookbackDays)
    {
        string[] relevantLogs = module switch
        {
            "Event Viewer"     => ["Security", "System", "Application"],
            "Windows Defender" => ["Security"],
            "Services"         => ["System"],
            _                  => []
        };

        if (relevantLogs.Length == 0)
        {
            // Filesystem/registry modules: coverage is always the full lookback window
            if (_fullCoverageModules.Contains(module))
                return lookbackDays;

            return oldestFinding.HasValue
                ? (int)(DateTime.Now - oldestFinding.Value).TotalDays
                : lookbackDays;
        }

        var coverageWarnings = result.Findings
            .Where(f => f.RuleId?.StartsWith("LOG_COVERAGE_") == true &&
                        f.Entity != null &&
                        relevantLogs.Contains(f.Entity))
            .ToList();

        if (coverageWarnings.Count == 0)
            return lookbackDays; // no warning = log has sufficient history

        // Parse "Cobertura: N dias" from each relevant warning and return the worst
        var regex = new System.Text.RegularExpressions.Regex(@"Cobertura: (\d+) dias");
        return coverageWarnings
            .Select(f =>
            {
                var m = regex.Match(f.Evidence ?? "");
                return m.Success && int.TryParse(m.Groups[1].Value, out var d) ? d : lookbackDays;
            })
            .Min();
    }

    private static void WriteJson<T>(string path, T data) =>
        File.WriteAllText(path, JsonSerializer.Serialize(data, Opts), System.Text.Encoding.UTF8);
}

file sealed class EvidenceExportDto
{
    public string   Machine               { get; init; } = "";
    public string   User                  { get; init; } = "";
    public string   MachineId             { get; init; } = "";
    public DateTime ScanTime              { get; init; }
    public int      LookbackDays          { get; init; }
    public LicenseExportEntry? License    { get; init; }
    public int      TotalScore            { get; init; }
    public int      RawScore              { get; init; }
    public double   UncappedRawScore      { get; init; }
    public double   UncappedEligibleScore { get; init; }
    public double   FilteredWeightedScore { get; init; }
    public int      FilteredCount         { get; init; }
    public int      EligibleFindingCount  { get; init; }
    public int      FilteredFindingCount  { get; init; }
    public string   OverallRisk           { get; init; } = "";
    public List<FindingDto>         Findings        { get; init; } = [];
    public List<BundleDto>          EvidenceBundles { get; init; } = [];
    public List<ModuleCoverageDto>  ModuleCoverage  { get; init; } = [];
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
    public bool      ScoreEligible  { get; init; }
    public int       BaseScore      { get; init; }
    public double    WeightedScore  { get; init; }

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
        ValidationHint = f.ValidationHint,
        ScoreEligible  = f.ScoreEligible,
        BaseScore      = f.BaseScore,
        WeightedScore  = f.WeightedScore
    };
}

file sealed class ModuleCoverageDto
{
    public string Name   { get; init; } = "";
    public string Status { get; init; } = "";
    public string Reason { get; init; } = "";
    public string Impact { get; init; } = "";

    public static ModuleCoverageDto From(Models.ModuleCoverageEntry e) => new()
    {
        Name   = e.Name,
        Status = e.Status.ToString(),
        Reason = e.Reason,
        Impact = e.ForensicImpact
    };
}

file sealed class LicenseExportEntry
{
    public string         CustomerId         { get; init; } = "";
    public string         LicenseMachineId   { get; init; } = "";
    public string         EffectiveMachineId { get; init; } = "";
    public bool           IsWildcard         { get; init; }
    public DateTimeOffset ExpiresAt          { get; init; }
    public string[]       Features           { get; init; } = [];
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
