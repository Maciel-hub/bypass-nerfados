namespace BypassNerfados.Scanner.Models;

public enum ModuleStatus { Queued, Executed, Partial, Skipped, Failed }

public class ModuleCoverageEntry
{
    public required string Name { get; init; }
    public ModuleStatus Status { get; set; } = ModuleStatus.Queued;
    public string Reason { get; set; } = "";
    public string ForensicImpact { get; init; } = "";
}
