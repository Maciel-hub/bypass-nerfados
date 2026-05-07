namespace BypassNerfados.Scanner.Models;

public enum RiskLevel
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
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
    ServiceTampering
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

    public Finding(RiskLevel risk, FindingCategory category, string module,
        string title, string detail, string? evidence = null, DateTime? timestamp = null)
    {
        Risk = risk;
        Category = category;
        Module = module;
        Title = title;
        Detail = detail;
        Evidence = evidence;
        Timestamp = timestamp;
    }

    public int Score => Risk switch
    {
        RiskLevel.Critical => 50,
        RiskLevel.High     => 25,
        RiskLevel.Medium   => 10,
        RiskLevel.Low      => 5,
        _                  => 0
    };

    public string RiskLabel => Risk switch
    {
        RiskLevel.Critical => "CRÍTICO",
        RiskLevel.High     => "ALTO",
        RiskLevel.Medium   => "MÉDIO",
        RiskLevel.Low      => "BAIXO",
        _                  => "INFO"
    };

    public string CategoryLabel => Category switch
    {
        FindingCategory.Cheat              => "Cheat Detectado",
        FindingCategory.AntiForensics      => "Anti-Forense",
        FindingCategory.SuspiciousExecution => "Execução Suspeita",
        FindingCategory.NetworkActivity    => "Atividade de Rede",
        FindingCategory.MemoryAnomaly      => "Anomalia de Memória",
        FindingCategory.SystemTampering    => "Adulteração do Sistema",
        FindingCategory.RegistryArtifact   => "Artefato de Registro",
        FindingCategory.FileSystem         => "Sistema de Arquivos",
        FindingCategory.DeviceAnomaly      => "Dispositivo Suspeito",
        FindingCategory.ServiceTampering   => "Serviço Adulterado",
        _                                  => Category.ToString()
    };
}
