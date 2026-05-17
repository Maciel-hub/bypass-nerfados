using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace EchoNerfados.App.ViewModels;

public sealed partial class ScanViewModel : ObservableObject
{
    private readonly ScanConfig _config;
    private readonly Action<ScanResult, string?> _onComplete;
    private readonly Action _navigateHome;
    private readonly CancellationTokenSource _cts = new();

    private ScanResult? _result;
    private string? _htmlReportPath;

    // Progress properties
    [ObservableProperty] private string _currentModule = "Iniciando...";
    [ObservableProperty] private string _phase = "";
    [ObservableProperty] private int _moduleIndex;
    [ObservableProperty] private int _moduleCount = 1;
    [ObservableProperty] private double _progressPercent;

    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _lowCount;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    private bool _isRunning = true;

    [ObservableProperty] private bool _isAborted;

    public ObservableCollection<ScanLogLine> LogLines { get; } = new();

    public ScanViewModel(ScanConfig config, Action<ScanResult, string?> onComplete, Action navigateHome)
    {
        _config = config;
        _onComplete = onComplete;
        _navigateHome = navigateHome;
        _ = RunAsync();
    }

    private async Task RunAsync()
    {
        IsRunning = true;
        try
        {
            var progress = new Progress<ScanProgressUpdate>(OnProgress);
            var orchestrator = new ScanOrchestrator(_config, progress);
            _result = await orchestrator.RunAsync(_cts.Token);
        }
        catch (OperationCanceledException)
        {
            AddLog("⊘", "Varredura cancelada.", isError: true);
            Phase = "Cancelado";
            IsRunning = false;
            IsAborted = true;
            return;
        }
        catch (Exception ex)
        {
            AddLog("✕", $"Erro fatal: {ex.Message}", isError: true);
            Phase = "Erro";
            IsRunning = false;
            IsAborted = true;
            return;
        }

        IsRunning = false;
        _onComplete(_result, _htmlReportPath);
    }

    private void OnProgress(ScanProgressUpdate update)
    {
        Application.Current.Dispatcher.BeginInvoke(() =>
        {
            switch (update.Kind)
            {
                case ScanProgressKind.ScanStarted:
                    ModuleCount = update.ModuleCount;
                    Phase = "Executando módulos...";
                    AddLog("▶", update.Message);
                    break;

                case ScanProgressKind.ModuleStarted:
                    CurrentModule = update.ModuleName ?? "";
                    ModuleIndex = update.ModuleIndex;
                    ProgressPercent = ModuleCount > 0
                        ? (update.ModuleIndex - 1) * 100.0 / ModuleCount
                        : 0;
                    break;

                case ScanProgressKind.ModuleCompleted:
                {
                    ProgressPercent = ModuleCount > 0
                        ? update.ModuleIndex * 100.0 / ModuleCount
                        : 100;
                    var count = update.Findings?.Count ?? 0;
                    var dur = update.Duration?.TotalSeconds.ToString("F1") ?? "0.0";
                    AddLog("✓", $"{update.ModuleName} ({dur}s, {count} finding{(count != 1 ? "s" : "")})");
                    UpdateCounts(update.Findings);
                    break;
                }

                case ScanProgressKind.ModuleFailed:
                    AddLog("✕", $"{update.ModuleName}: {update.Message}", isError: true);
                    break;

                case ScanProgressKind.Warning:
                    AddLog("⚠", update.Message, isWarning: true);
                    break;

                case ScanProgressKind.CorrelationStarted:
                    CurrentModule = "Correlação";
                    Phase = "Correlacionando módulos...";
                    break;

                case ScanProgressKind.CorrelationCompleted:
                    Phase = "Correlação concluída.";
                    break;

                case ScanProgressKind.ReportStarted:
                    CurrentModule = "Relatório";
                    Phase = "Exportando relatório...";
                    break;

                case ScanProgressKind.ReportGenerated:
                    _htmlReportPath = update.HtmlReportPath;
                    AddLog("✓", "Relatório exportado.");
                    break;

                case ScanProgressKind.ReportFailed:
                    AddLog("✕", $"Falha ao exportar: {update.Message}", isError: true);
                    break;

                case ScanProgressKind.ScanCompleted:
                    Phase = "Concluído";
                    ProgressPercent = 100;
                    break;
            }
        });
    }

    private void UpdateCounts(IReadOnlyList<Finding>? findings)
    {
        if (findings is null) return;
        foreach (var f in findings)
        {
            switch (f.Risk)
            {
                case RiskLevel.Critical: CriticalCount++; break;
                case RiskLevel.High:     HighCount++;     break;
                case RiskLevel.Medium:   MediumCount++;   break;
                case RiskLevel.Low:      LowCount++;      break;
            }
        }
    }

    private void AddLog(string icon, string text, bool isError = false, bool isWarning = false)
    {
        LogLines.Add(new ScanLogLine(icon, text, isError, isWarning));
        if (LogLines.Count > 200) LogLines.RemoveAt(0);
    }

    [RelayCommand(CanExecute = nameof(IsRunning))]
    private void Cancel()
    {
        _cts.Cancel();
        Phase = "Cancelando...";
    }

    [RelayCommand]
    private void NewScan() => _navigateHome();
}

public sealed record ScanLogLine(string Icon, string Text, bool IsError, bool IsWarning);
