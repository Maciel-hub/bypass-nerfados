namespace BypassNerfados.Scanner.Models;

public class ScanResult
{
    public string MachineName { get; init; } = Environment.MachineName;
    public string CurrentUser { get; init; } = Environment.UserName;
    public string ScanMode { get; set; } = "Completo";
    public DateTime ScanTime { get; init; } = DateTime.Now;
    public DateTime? ScanCompleted { get; set; }
    public string WindowsVersion { get; set; } = string.Empty;
    public string InstallDate { get; set; } = string.Empty;
    public string LastBoot { get; set; } = string.Empty;
    public bool IsAdministrator { get; set; }

    public List<Finding> Findings { get; } = new();
    public List<EvidenceBundle> EvidenceBundles { get; } = new();
    public List<ModuleCoverageEntry> ModuleCoverage { get; } = new();
    public List<string> ModulesRun { get; } = new();
    public List<string> ModuleErrors { get; } = new();
    public Dictionary<string, TimeSpan> ModuleDurations { get; } = new();

    // Only eligible findings count toward score (Medium+Low without correlation are filtered out)
    public int    TotalScore            => (int)Math.Min(Findings.Where(f => f.ScoreEligible).Sum(f => f.WeightedScore), 100);
    public int    RawScore              => (int)Math.Min(Findings.Sum(f => f.WeightedScore), 100);
    public int    FilteredCount         => Findings.Count(f => !f.ScoreEligible);
    public double UncappedRawScore      => Findings.Sum(f => f.WeightedScore);
    public double UncappedEligibleScore => Findings.Where(f => f.ScoreEligible).Sum(f => f.WeightedScore);
    public double FilteredWeightedScore => Findings.Where(f => !f.ScoreEligible).Sum(f => f.WeightedScore);

    public RiskLevel OverallRisk => TotalScore switch
    {
        >= 76 => RiskLevel.Critical,
        >= 51 => RiskLevel.High,
        >= 26 => RiskLevel.Medium,
        >= 1  => RiskLevel.Low,
        _     => RiskLevel.Info
    };

    public string OverallRiskLabel => OverallRisk switch
    {
        RiskLevel.Critical => "CRÍTICO",
        RiskLevel.High     => "ALTO",
        RiskLevel.Medium   => "MÉDIO",
        RiskLevel.Low      => "BAIXO",
        _                  => "LIMPO"
    };

    public IEnumerable<Finding> CriticalFindings =>
        Findings.Where(f => f.Risk == RiskLevel.Critical);

    public IEnumerable<Finding> HighFindings =>
        Findings.Where(f => f.Risk == RiskLevel.High);

    public IEnumerable<Finding> CheatFindings =>
        Findings.Where(f => f.Category == FindingCategory.Cheat);

    public IEnumerable<Finding> BypassFindings =>
        Findings.Where(f =>
            f.Category == FindingCategory.AntiForensics &&
            f.Risk >= RiskLevel.High);

    public IEnumerable<Finding> SortedByTime =>
        Findings.Where(f => f.Timestamp.HasValue)
                .OrderByDescending(f => f.Timestamp!.Value);
}
