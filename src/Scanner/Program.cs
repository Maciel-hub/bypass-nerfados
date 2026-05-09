using Spectre.Console;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.Title = "Echo Nerfados Shield XDR v1.0";

// --help / -h: process before authentication — no login required, exit 0
if (args.Any(a => a is "--help" or "-h"))
{
    PrintHelp();
    return 0;
}

// Require interactive terminal — AnsiConsole.Clear() and prompts crash otherwise
if (Console.IsInputRedirected || Console.IsOutputRedirected || Console.IsErrorRedirected)
{
    Console.Error.WriteLine("Echo Nerfados Shield XDR requires an interactive terminal.");
    Console.Error.WriteLine("Usage: EchoNerfados.exe [--help]");
    return 1;
}

// Authentication gate — must pass before any scan activity
if (!ConsoleUI.PromptLogin())
    return 2; // exit code 2 = auth failed

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
    // Plain Console.WriteLine — safe for pipes and non-interactive terminals.
    // Never use AnsiConsole here: brackets in help text crash Spectre markup parser.
    Console.WriteLine("ECHO NERFADOS SHIELD XDR v1.0");
    Console.WriteLine("Plataforma Anti-Cheat para investigacao de Screen-Share");
    Console.WriteLine();
    Console.WriteLine("USO:");
    Console.WriteLine("  EchoNerfados.exe [opcoes]");
    Console.WriteLine();
    Console.WriteLine("OPCOES:");
    Console.WriteLine("  --investigator <nome>   Nome do investigador (para o relatorio)");
    Console.WriteLine("  --suspect <nome>        Nome do suspeito (para o relatorio)");
    Console.WriteLine("  --case-id <id>          ID do caso/investigacao");
    Console.WriteLine("  --drive <letra>         Drive a ser analisado (padrao: C:)");
    Console.WriteLine("  --output <caminho>      Pasta de saida do relatorio");
    Console.WriteLine("  --no-usn                Pular analise do USN Journal");
    Console.WriteLine("  --no-memory             Pular analise de memoria de processos");
    Console.WriteLine("  --no-report             Nao gerar relatorio em arquivo");
    Console.WriteLine("  --verbose               Mostrar todos os findings (incluindo INFO)");
    Console.WriteLine("  --help                  Exibir esta ajuda");
    Console.WriteLine();
    Console.WriteLine("EXEMPLOS:");
    Console.WriteLine("  EchoNerfados.exe");
    Console.WriteLine("  EchoNerfados.exe --investigator \"Fulano\" --suspect \"Ciclano\" --case-id \"CASO-001\"");
    Console.WriteLine("  EchoNerfados.exe --no-memory --output C:\\Relatorios");
    Console.WriteLine();
    Console.WriteLine("IMPORTANTE: Execute como Administrador para acesso completo (Amcache, UserAssist, USN Journal).");
}

internal sealed class InlineProgress<T>(Action<T> handler) : IProgress<T>
{
    public void Report(T value) => handler(value);
}
