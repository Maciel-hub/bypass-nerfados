using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Core;

public static class FindingDeduplicator
{
    /// <summary>
    /// Collapses findings with the same EvidenceKey into one, keeping the
    /// highest-confidence instance. Runs before the Correlator so duplicates
    /// don't inflate the score or correlation signals.
    /// </summary>
    public static List<Finding> Deduplicate(IEnumerable<Finding> findings)
    {
        return findings
            .GroupBy(f => f.EvidenceKey)
            .Select(g => g
                .OrderByDescending(f => f.Confidence)
                .ThenByDescending(f => f.Risk)
                .First())
            .OrderByDescending(f => f.Risk)
            .ThenByDescending(f => f.Confidence)
            .ToList();
    }
}
