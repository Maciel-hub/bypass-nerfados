using Spectre.Console;
using BypassNerfados.Scanner.Core;

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
    var orchestrator = new ScanOrchestrator(config);
    var result = await orchestrator.RunAsync();

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
