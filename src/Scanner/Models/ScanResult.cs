namespace BypassNerfados.Scanner.Models;

public class ScanResult
{
    public string MachineName { get; init; } = Environment.MachineName;
    public string CurrentUser { get; init; } = Environment.UserName;
    public string ScanMode { get; init; } = "Completo";
    public DateTime ScanTime { get; init; } = DateTime.Now;
    public string WindowsVersion { get; set; } = string.Empty;
    public string InstallDate { get; set; } = string.Empty;
    public string LastBoot { get; set; } = string.Empty;
    public bool IsAdministrator { get; set; }

    public List<Finding> Findings { get; } = new();
    public List<EvidenceBundle> EvidenceBundles { get; } = new();
    public List<string> ModulesRun { get; } = new();
    public List<string> ModuleErrors { get; } = new();
    public Dictionary<string, TimeSpan> ModuleDurations { get; } = new();

    // Weighted by confidence; deduplication happens in ScanOrchestrator before score is read
    public int TotalScore => (int)Math.Min(Findings.Sum(f => f.WeightedScore), 100);

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
