namespace BypassNerfados.Scanner.Models;

public enum RiskLevel
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum Confidence
{
    Low = 1,       // name-only or weak heuristic
    Medium = 2,    // path or keyword match
    High = 3,      // path + multiple signals
    Confirmed = 4  // hash match or direct signature
}

public enum FindingCategory
{
    Cheat,
    AntiForensics,
    SuspiciousExecution,
    NetworkActivity,
    MemoryAnomaly,
    SystemTampering,
    RegistryArtifact,
    FileSystem,
    DeviceAnomaly,
    ServiceTampering,
    LogCoverage   // log coverage warnings and module partial-collection errors
}

public class Finding
{
    public RiskLevel Risk { get; init; }
    public FindingCategory Category { get; init; }
    public string Module { get; init; }
    public string Title { get; init; }
    public string Detail { get; init; }
    public string? Evidence { get; init; }
    public DateTime? Timestamp { get; init; }
    public Confidence Confidence { get; init; }
    public string? RuleId { get; init; }
    public string? Entity { get; init; }
    public string? ValidationHint { get; init; }
    public bool ScoreEligible { get; set; } = true;

    public Finding(
        RiskLevel risk,
        FindingCategory category,
        string module,
        string title,
        string detail,
        string? evidence = null,
        DateTime? timestamp = null,
        Confidence confidence = Confidence.Medium,
        string? ruleId = null,
        string? entity = null,
        string? validationHint = null)
    {
        Risk = risk;
        Category = category;
        Module = module;
        Title = title;
        Detail = detail;
        Evidence = evidence;
        Timestamp = timestamp;
        Confidence = confidence;
        RuleId = ruleId;
        Entity = entity;
        ValidationHint = validationHint;
    }

    public int BaseScore => Risk switch
    {
        RiskLevel.Critical => 50,
        RiskLevel.High     => 25,
        RiskLevel.Medium   => 10,
        RiskLevel.Low      => 5,
        _                  => 0
    };

    // Weighted by confidence: Low=0.5x, Medium=1x, High=1.5x, Confirmed=2x
    public double WeightedScore => BaseScore * (int)Confidence / 2.0;

    // Deduplication key: same entity+category+timebucket collapses to one finding
    public string EvidenceKey
    {
        get
        {
            var ent = (Entity ?? Title).ToLowerInvariant();
            var bucket = Timestamp.HasValue
                ? Timestamp.Value.ToString("yyyyMMddHH")
                : "notime";
            return $"{Category}|{ent}|{bucket}";
        }
    }

    public string RiskLabel => Risk switch
    {
        RiskLevel.Critical => "CRÍTICO",
        RiskLevel.High     => "ALTO",
        RiskLevel.Medium   => "MÉDIO",
        RiskLevel.Low      => "BAIXO",
        _                  => "INFO"
    };

    public string ConfidenceLabel => Confidence switch
    {
        Confidence.Confirmed => "CONFIRMADO",
        Confidence.High      => "Alta",
        Confidence.Medium    => "Média",
        _                    => "Baixa"
    };

    public string CategoryLabel => Category switch
    {
        FindingCategory.Cheat               => "Cheat Detectado",
        FindingCategory.AntiForensics       => "Anti-Forense",
        FindingCategory.SuspiciousExecution => "Execução Suspeita",
        FindingCategory.NetworkActivity     => "Atividade de Rede",
        FindingCategory.MemoryAnomaly       => "Anomalia de Memória",
        FindingCategory.SystemTampering     => "Adulteração do Sistema",
        FindingCategory.RegistryArtifact    => "Artefato de Registro",
        FindingCategory.FileSystem          => "Sistema de Arquivos",
        FindingCategory.DeviceAnomaly       => "Dispositivo Suspeito",
        FindingCategory.ServiceTampering    => "Serviço Adulterado",
        _                                   => Category.ToString()
    };
}
