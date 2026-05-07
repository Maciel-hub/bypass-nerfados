using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Core;

public enum ScanProgressKind
{
    ScanStarted,
    Warning,
    ModuleStarted,
    ModuleCompleted,
    ModuleFailed,
    CorrelationStarted,
    CorrelationCompleted,
    ResultReady,
    ReportStarted,
    ReportGenerated,
    ReportFailed,
    ScanCompleted
}

public sealed record ScanProgressUpdate(
    ScanProgressKind Kind,
    string Message,
    string? ModuleName = null,
    int ModuleIndex = 0,
    int ModuleCount = 0,
    IReadOnlyList<Finding>? Findings = null,
    TimeSpan? Duration = null,
    string? HtmlReportPath = null,
    string? TextReportPath = null,
    ScanResult? Result = null,
    Exception? Exception = null
);
