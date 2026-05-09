namespace BypassNerfados.Scanner.Models;

public sealed class EvidenceBundle
{
    public required string ArtifactId { get; init; }
    public required string ArtifactName { get; init; }
    public string? FullPath { get; init; }
    public required string Verdict { get; init; }
    public required RiskLevel Risk { get; init; }
    public required Confidence Confidence { get; init; }
    public required string Summary { get; init; }
    public string? Sha256 { get; init; }
    public string? Sha1 { get; init; }
    public List<EvidenceSignal> Signals { get; init; } = [];
    public List<ArtifactTimelineItem> Timeline { get; init; } = [];
    public List<string> BypassIndicators { get; init; } = [];
    public List<string> ValidationSteps { get; init; } = [];
}

public sealed class EvidenceSignal
{
    public required string SourceModule { get; init; }
    public required string SignalType { get; init; }
    public required string Description { get; init; }
    public string? EvidenceValue { get; init; }
    public DateTime? Timestamp { get; init; }
    public Confidence Confidence { get; init; }
}

public sealed class ArtifactTimelineItem
{
    public DateTime? Timestamp { get; init; }
    public required string Source { get; init; }
    public required string Action { get; init; }
    public required string Detail { get; init; }
}
