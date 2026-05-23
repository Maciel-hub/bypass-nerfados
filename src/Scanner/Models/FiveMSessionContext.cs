namespace BypassNerfados.Scanner.Models;

public enum FiveMRelation
{
    DirectInteraction,
    NearSession,
    OutsideSession,
    Unknown
}

public sealed record FiveMSessionContext(
    string Entity,
    string FileName,
    string? Path,
    FiveMRelation Relation,
    DateTime? EventTime,
    DateTime? SessionTime,
    double? DeltaMinutes,
    string[] Sources,
    string EvidenceSummary,
    RiskLevel Risk,
    Confidence Confidence,
    string? RuleId,
    string? ValidationHint);
