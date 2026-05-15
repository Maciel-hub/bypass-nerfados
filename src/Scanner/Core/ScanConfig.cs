using System.Text.RegularExpressions;

namespace BypassNerfados.Scanner.Core;

public enum ConsoleUiMode { Minimal, Detailed }

public enum ScanProfile { Default, Fast, Deep, FiveM, Florence }

public class ScanConfig
{
    private string _targetDrive = "C:";

    public string TargetDrive
    {
        get => _targetDrive;
        set
        {
            if (!IsValidDrive(value))
                throw new ArgumentException($"Drive inválido: '{value}'. Use formato letra: (ex: C:)");
            _targetDrive = value.ToUpperInvariant().TrimEnd('\\');
        }
    }

    public string? InvestigatorName { get; set; }
    public string? SuspectName { get; set; }
    public string? CaseId { get; set; }
    public DateTime? BanDate { get; set; }
    public bool VerboseOutput { get; set; } = false;
    public bool SaveReport { get; set; } = true;
    public string ReportOutputPath { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    public bool ScanAllUsers { get; set; } = true;
    public bool DeepMemoryScan { get; set; } = true;
    public bool ScanNetworkUsage { get; set; } = true;
    public bool RunUsnJournal { get; set; } = true;
    public TimeSpan EventWindowLookback { get; set; } = TimeSpan.FromDays(90);
    public ConsoleUiMode UiMode { get; set; } = ConsoleUiMode.Minimal;
    public bool OpenReportAfterScan { get; set; } = false;
    public ScanProfile Profile { get; set; } = ScanProfile.Default;

    public string ReportFileName =>
        $"Echo_Nerfados_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";

    public static bool IsValidDrive(string drive) =>
        Regex.IsMatch(drive?.Trim() ?? "", @"^[A-Za-z]:[\\/]?$");
}
