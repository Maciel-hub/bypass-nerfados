using Spectre.Console;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.Title = "Bypass Nerfados Shield XDR v1.0";

var config = new ScanConfig();

// Parse arguments
for (int i = 0; i < args.Length; i++)
{
    switch (args[i].ToLowerInvariant())
    {
        case "--investigator" when i + 1 < args.Length:
            config.InvestigatorName = args[++i];
            break;
        case "--suspect" when i + 1 < args.Length:
            config.SuspectName = args[++i];
            break;
        case "--case-id" when i + 1 < args.Length:
            config.CaseId = args[++i];
            break;
        case "--drive" when i + 1 < args.Length:
            config.TargetDrive = args[++i];
            break;
        case "--no-usn":
            config.RunUsnJournal = false;
            break;
        case "--no-memory":
            config.DeepMemoryScan = false;
            break;
        case "--no-report":
            config.SaveReport = false;
            break;
        case "--output" when i + 1 < args.Length:
            config.ReportOutputPath = args[++i];
            break;
        case "--verbose":
            config.VerboseOutput = true;
            break;
        case "--help" or "-h":
            PrintHelp();
            return 0;
    }
}

try
{
    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        cts.Cancel();
        ConsoleUI.PrintError("Cancelamento solicitado. Finalizando módulo atual...");
    };

    ConsoleUI.PrintBanner();

    var progress = new InlineProgress<ScanProgressUpdate>(PrintProgress);
    var orchestrator = new ScanOrchestrator(config, progress);
    var result = await orchestrator.RunAsync(cts.Token);

    AnsiConsole.WriteLine();
    AnsiConsole.Write(new Rule("[bold]VARREDURA CONCLUÍDA[/]"));
    AnsiConsole.MarkupLine($"[bold]Score: [/][bold {GetRiskColor(result.TotalScore)}]{result.TotalScore}/100 — {result.OverallRiskLabel}[/]");
    AnsiConsole.WriteLine();

    // Return exit code based on risk
    return result.OverallRisk switch
    {
        BypassNerfados.Scanner.Models.RiskLevel.Critical => 4,
        BypassNerfados.Scanner.Models.RiskLevel.High     => 3,
        BypassNerfados.Scanner.Models.RiskLevel.Medium   => 2,
        BypassNerfados.Scanner.Models.RiskLevel.Low      => 1,
        _                                                 => 0
    };
}
catch (OperationCanceledException)
{
    ConsoleUI.PrintError("Varredura cancelada pelo usuário.");
    return 98;
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex);
    return 99;
}

static string GetRiskColor(int score) => score switch
{
    >= 76 => "red",
    >= 51 => "darkorange",
    >= 26 => "yellow",
    >= 1  => "green",
    _     => "grey"
};

static void PrintProgress(ScanProgressUpdate update)
{
    switch (update.Kind)
    {
        case ScanProgressKind.Warning:
            ConsoleUI.PrintError($"AVISO: {update.Message}");
            AnsiConsole.WriteLine();
            break;

        case ScanProgressKind.ScanStarted:
            AnsiConsole.Write(new Rule($"[bold]INICIANDO VARREDURA[/] [grey]— {update.ModuleCount} módulos[/]"));
            AnsiConsole.WriteLine();
            break;

        case ScanProgressKind.ModuleStarted:
            ConsoleUI.PrintModuleStart(
                $"{update.ModuleIndex}/{update.ModuleCount} {update.ModuleName}",
                update.Message);
            break;

        case ScanProgressKind.ModuleCompleted:
            ConsoleUI.PrintModuleOk(
                update.ModuleName ?? "Módulo",
                update.Findings?.Count ?? 0,
                update.Duration ?? TimeSpan.Zero);

            if (update.Findings != null)
            {
                foreach (var finding in update.Findings.Where(f => f.Risk >= RiskLevel.Medium))
                    ConsoleUI.PrintFinding(finding);
            }
            break;

        case ScanProgressKind.ModuleFailed:
            ConsoleUI.PrintModuleError(update.ModuleName ?? "Módulo", update.Exception?.Message ?? update.Message);
            break;

        case ScanProgressKind.CorrelationStarted:
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold cyan]▶[/] [bold]Correlação[/] [grey]— analisando padrões entre módulos...[/]");
            break;

        case ScanProgressKind.CorrelationCompleted:
            AnsiConsole.MarkupLine("  [green]✓[/] Correlação concluída");
            break;

        case ScanProgressKind.ResultReady when update.Result != null:
            ConsoleUI.PrintSummary(update.Result);
            break;

        case ScanProgressKind.ReportStarted:
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold]EXPORTANDO RELATÓRIO[/]"));
            break;

        case ScanProgressKind.ReportGenerated:
            if (update.HtmlReportPath != null)
                AnsiConsole.MarkupLine($"[green]✓ HTML:[/] {Markup.Escape(update.HtmlReportPath)}");
            if (update.TextReportPath != null)
                AnsiConsole.MarkupLine($"[green]✓ TXT: [/] {Markup.Escape(update.TextReportPath)}");
            if (update.HtmlReportPath != null)
            {
                var evidencePath = Path.Combine(Path.GetDirectoryName(update.HtmlReportPath)!, "evidence.json");
                AnsiConsole.MarkupLine($"[green]✓ JSON:[/] {Markup.Escape(evidencePath)}");
            }
            break;

        case ScanProgressKind.ReportFailed:
            ConsoleUI.PrintError(update.Message);
            break;
    }
}

static void PrintHelp()
{
    AnsiConsole.MarkupLine("[bold]BYPASS NERFADOS SHIELD XDR v1.0[/]");
    AnsiConsole.MarkupLine("[grey]Plataforma Anti-Cheat para investigação de Screen-Share[/]");
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[bold]USO:[/]");
    AnsiConsole.MarkupLine("  BypassNerfados.exe [opções]");
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[bold]OPÇÕES:[/]");
    AnsiConsole.MarkupLine("  --investigator <nome>   Nome do investigador (para o relatório)");
    AnsiConsole.MarkupLine("  --suspect <nome>        Nome do suspeito (para o relatório)");
    AnsiConsole.MarkupLine("  --case-id <id>          ID do caso/investigação");
    AnsiConsole.MarkupLine("  --drive <letra>         Drive a ser analisado (padrão: C:)");
    AnsiConsole.MarkupLine("  --output <caminho>      Pasta de saída do relatório");
    AnsiConsole.MarkupLine("  --no-usn                Pular análise do USN Journal");
    AnsiConsole.MarkupLine("  --no-memory             Pular análise de memória de processos");
    AnsiConsole.MarkupLine("  --no-report             Não gerar relatório em arquivo");
    AnsiConsole.MarkupLine("  --verbose               Mostrar todos os findings (incluindo INFO)");
    AnsiConsole.MarkupLine("  --help                  Exibir esta ajuda");
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[bold]EXEMPLOS:[/]");
    AnsiConsole.MarkupLine("  BypassNerfados.exe");
    AnsiConsole.MarkupLine("  BypassNerfados.exe --investigator \"Fulano\" --suspect \"Ciclano\" --case-id \"CASO-001\"");
    AnsiConsole.MarkupLine("  BypassNerfados.exe --no-memory --output C:\\Relatorios");
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[grey]IMPORTANTE: Execute como Administrador para acesso completo.[/]");
}

internal sealed class InlineProgress<T>(Action<T> handler) : IProgress<T>
{
    public void Report(T value) => handler(value);
}
