using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BypassNerfados.Scanner.Models;
using EchoNerfados.App.Converters;

namespace EchoNerfados.App.ViewModels;

public sealed partial class ResultViewModel : ObservableObject
{
    private readonly Action _newScan;

    // Score / Risk
    public int Score { get; }
    public string RiskLabel { get; }
    public Brush RiskBrush { get; }
    public RiskLevel OverallRisk { get; }

    // Severity counts
    public int CriticalCount { get; }
    public int HighCount { get; }
    public int MediumCount { get; }
    public int LowCount { get; }
    public int InfoCount { get; }

    // Report paths
    public bool HasReport { get; }
    public string HtmlReportPath { get; }
    public string ExecutiveReportPath { get; }
    public string ReportFolder { get; }

    // Top findings (top 10 High+Critical)
    public ObservableCollection<FindingViewModel> TopFindings { get; } = new();

    // Scan meta
    public string ScanDuration { get; }
    public int TotalFindings { get; }
    public int ModulesRun { get; }

    public ResultViewModel(ScanResult result, string? htmlReportPath, Action newScan)
    {
        _newScan = newScan;

        Score = result.TotalScore;
        OverallRisk = result.OverallRisk;
        RiskLabel = result.OverallRisk.ToString().ToUpperInvariant();
        RiskBrush = RiskColors.Get(result.OverallRisk);

        // Single pass over findings to tally severity counts
        int critical = 0, high = 0, medium = 0, low = 0, info = 0;
        foreach (var f in result.Findings)
        {
            switch (f.Risk)
            {
                case RiskLevel.Critical: critical++; break;
                case RiskLevel.High:     high++;     break;
                case RiskLevel.Medium:   medium++;   break;
                case RiskLevel.Low:      low++;      break;
                case RiskLevel.Info:     info++;     break;
            }
        }
        CriticalCount = critical;
        HighCount = high;
        MediumCount = medium;
        LowCount = low;
        InfoCount = info;

        TotalFindings = result.Findings.Count;
        ModulesRun = result.ModulesRun.Count;

        ScanDuration = result.ScanCompleted.HasValue
            ? (result.ScanCompleted.Value - result.ScanTime).ToString(@"mm\:ss")
            : "—";

        if (htmlReportPath is not null)
        {
            HasReport = true;
            HtmlReportPath = htmlReportPath;
            ReportFolder = Path.GetDirectoryName(htmlReportPath) ?? "";
            ExecutiveReportPath = Path.Combine(ReportFolder, "report_executive.html");
        }
        else
        {
            HasReport = false;
            HtmlReportPath = "";
            ReportFolder = "";
            ExecutiveReportPath = "";
        }

        foreach (var f in result.Findings
            .Where(f => f.Risk >= RiskLevel.High)
            .OrderByDescending(f => f.Risk)
            .ThenByDescending(f => f.Confidence)
            .Take(10))
        {
            TopFindings.Add(new FindingViewModel(f));
        }
    }

    [RelayCommand]
    private void OpenHtmlReport()
    {
        if (!HasReport) return;
        TryOpen(HtmlReportPath);
    }

    [RelayCommand]
    private void OpenExecutiveReport()
    {
        if (!HasReport) return;
        var path = ExecutiveReportPath;
        if (File.Exists(path)) TryOpen(path);
    }

    [RelayCommand]
    private void OpenReportFolder()
    {
        if (!HasReport) return;
        TryOpen(ReportFolder);
    }

    [RelayCommand]
    private void NewScan() => _newScan();

    private static void TryOpen(string path)
    {
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch { /* user will see nothing opened — acceptable for P0 */ }
    }
}

public sealed class FindingViewModel
{
    public string RiskLabel { get; }
    public Brush RiskBrush { get; }
    public string Title { get; }
    public string Module { get; }
    public string Evidence { get; }

    public FindingViewModel(Finding f)
    {
        RiskLabel = f.Risk.ToString().ToUpperInvariant();
        RiskBrush = RiskColors.Get(f.Risk);
        Title = f.Title ?? f.Entity ?? "(sem título)";
        Module = f.Module ?? "";
        Evidence = string.IsNullOrEmpty(f.Evidence) ? "" : Truncate(f.Evidence, 80);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 3)] + "...";
}
