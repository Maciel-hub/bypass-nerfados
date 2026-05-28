namespace BypassNerfados.Scanner.Models;

public enum FiveMRelation
{
    DirectInteraction,
    CoProcessInteraction,   // suspicious loader/co-process running alongside FiveM
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
