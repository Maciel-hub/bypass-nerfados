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

// Authentication gate
if (!ConsoleUI.PromptLogin())
    return 2;

var config        = new ScanConfig();
var noFinalPrompt = false;

// Parse arguments
for (int i = 0; i < args.Length; i++)
{
    switch (args[i].ToLowerInvariant())
    {
        case "--investigator" when i + 1 < args.Length: config.InvestigatorName = args[++i]; break;
        case "--suspect"      when i + 1 < args.Length: config.SuspectName      = args[++i]; break;
        case "--case-id"      when i + 1 < args.Length: config.CaseId           = args[++i]; break;
        case "--drive"        when i + 1 < args.Length: config.TargetDrive      = args[++i]; break;
        case "--no-usn":    config.RunUsnJournal  = false; break;
        case "--no-memory": config.DeepMemoryScan = false; break;
        case "--no-report": config.SaveReport     = false; break;
        case "--output"   when i + 1 < args.Length: config.ReportOutputPath = args[++i]; break;
        case "--lookback" when i + 1 < args.Length:
            if (int.TryParse(args[++i], out var days) && days > 0)
                config.EventWindowLookback = TimeSpan.FromDays(days);
            break;
        case "--verbose": config.VerboseOutput = true; break;
        case "--no-final-prompt": noFinalPrompt = true; break;
        case "--help" or "-h": PrintHelp(); return 0;
    }
}

AnsiConsole.Clear();
Console.Title = "Echo Nerfados Shield XDR v1.0 — Varrendo...";

ScanResult? finalResult    = null;
string?     htmlReportPath = null;
string?     txtReportPath  = null;

var spinnerFrames = new[] { "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
var frame         = 0;
var dashboard     = new LiveDashboard();

try
{
    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        cts.Cancel();
    };

    await AnsiConsole.Live(dashboard.Build(spinnerFrames[0]))
        .AutoClear(false)
        .Overflow(VerticalOverflow.Ellipsis)
        .StartAsync(async ctx =>
        {
            // Animation loop — sole renderer; updates at ~12 fps.
            // try-catch inside the loop is intentional: a render exception must never kill
            // the animation task, otherwise the display freezes with no indication of progress.
            using var animCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
            var animTask = Task.Run(async () =>
            {
                while (!animCts.Token.IsCancellationRequested)
                {
                    frame = (frame + 1) % spinnerFrames.Length;
                    try { ctx.UpdateTarget(dashboard.Build(spinnerFrames[frame])); }
                    catch { /* swallow render errors — animation must survive */ }
                    try   { await Task.Delay(80, animCts.Token); }
                    catch (OperationCanceledException) { break; }
                }
            });

            // Progress callback — only mutates state, never renders
            var progress = new InlineProgress<ScanProgressUpdate>(update =>
            {
                switch (update.Kind)
                {
                    case ScanProgressKind.Warning:
                        // Absorbed — shown in dashboard after done
                        break;
                    case ScanProgressKind.ScanStarted:
                        dashboard.SetExpectedModules(update.ModuleCount);
                        dashboard.SetPhase("Iniciando...");
                        break;
                    case ScanProgressKind.ModuleStarted:
                        dashboard.ModuleStarted(update.ModuleName ?? "");
                        break;
                    case ScanProgressKind.ModuleCompleted:
                        dashboard.ModuleCompleted(
                            update.ModuleName ?? "",
                            update.Findings,
                            update.Duration ?? TimeSpan.Zero);
                        break;
                    case ScanProgressKind.ModuleFailed:
                        dashboard.ModuleFailed(update.ModuleName ?? "");
                        break;
                    case ScanProgressKind.CorrelationStarted:
                        dashboard.SetPhase("Correlacionando módulos...");
                        break;
                    case ScanProgressKind.CorrelationCompleted:
                        dashboard.SetPhase("Correlação concluída");
                        break;
                    case ScanProgressKind.ReportStarted:
                        dashboard.SetPhase("Exportando relatório...");
                        break;
                    case ScanProgressKind.ReportGenerated:
                        htmlReportPath = update.HtmlReportPath;
                        txtReportPath  = update.TextReportPath;
                        break;
                    case ScanProgressKind.ScanCompleted:
                        dashboard.SetDone();
                        break;
                }
            });

            var orchestrator = new ScanOrchestrator(config, progress);
            finalResult = await orchestrator.RunAsync(cts.Token);

            dashboard.SetDone();
            Console.Title = "Echo Nerfados Shield XDR v1.0 — Concluído";

            // Stop animation, then do one final stable render
            animCts.Cancel();
            try { await animTask; } catch { }
            try { ctx.UpdateTarget(dashboard.Build("✓")); } catch { }
        });
}
catch (OperationCanceledException)
{
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[red]Varredura cancelada pelo usuário.[/]");
    return 98;
}
catch (Exception ex)
{
    AnsiConsole.WriteLine();
    AnsiConsole.WriteException(ex);
    return 99;
}

// ── Post-scan: detailed summary ───────────────────────────────────────────────
AnsiConsole.WriteLine();

if (finalResult != null)
    ConsoleUI.PrintSummary(finalResult);

// Report paths
if (htmlReportPath != null || txtReportPath != null)
{
    AnsiConsole.WriteLine();
    AnsiConsole.Write(new Rule("[bold]RELATÓRIO EXPORTADO[/]"));
    if (htmlReportPath != null)
        AnsiConsole.MarkupLine($"[green]✓ HTML:[/] {Markup.Escape(htmlReportPath)}");
    if (txtReportPath != null)
        AnsiConsole.MarkupLine($"[green]✓ TXT: [/] {Markup.Escape(txtReportPath)}");
    if (htmlReportPath != null)
    {
        var evidencePath = Path.Combine(Path.GetDirectoryName(htmlReportPath)!, "evidence.json");
        AnsiConsole.MarkupLine($"[green]✓ JSON:[/] {Markup.Escape(evidencePath)}");
    }
}

AnsiConsole.WriteLine();
AnsiConsole.Write(new Rule("[bold]VARREDURA CONCLUÍDA[/]"));

// ── Prompt para abrir relatório ───────────────────────────────────────────────
if (!noFinalPrompt && htmlReportPath != null && File.Exists(htmlReportPath))
{
    AnsiConsole.WriteLine();

    var choice = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[bold]O que deseja fazer agora?[/]")
            .HighlightStyle(new Style(foreground: Color.Red))
            .AddChoices(
                "Abrir relatório HTML com evidências",
                "Abrir pasta do relatório",
                "Sair"
            ));

    switch (choice)
    {
        case "Abrir relatório HTML com evidências":
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(htmlReportPath)
                    { UseShellExecute = true });
                AnsiConsole.MarkupLine("[green]Relatório aberto no navegador padrão.[/]");
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Não foi possível abrir o relatório: {Markup.Escape(ex.Message)}[/]");
                AnsiConsole.MarkupLine($"Caminho: [dim]{Markup.Escape(htmlReportPath)}[/]");
            }
            break;

        case "Abrir pasta do relatório":
            try
            {
                var folder = Path.GetDirectoryName(htmlReportPath)!;
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"\"{folder}\"")
                    { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Não foi possível abrir a pasta: {Markup.Escape(ex.Message)}[/]");
            }
            break;
    }
}

return finalResult?.OverallRisk switch
{
    RiskLevel.Critical => 4,
    RiskLevel.High     => 3,
    RiskLevel.Medium   => 2,
    RiskLevel.Low      => 1,
    _                  => 0
};

// ── Helpers ───────────────────────────────────────────────────────────────────

static void PrintHelp()
{
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
    Console.WriteLine("  --lookback <dias>       Janela de analise em dias (padrao: 90)");
    Console.WriteLine("  --no-usn                Pular analise do USN Journal");
    Console.WriteLine("  --no-memory             Pular analise de memoria de processos");
    Console.WriteLine("  --no-report             Nao gerar relatorio em arquivo");
    Console.WriteLine("  --no-final-prompt       Nao exibir menu apos conclusao (modo automatico)");
    Console.WriteLine("  --verbose               Mostrar todos os findings (incluindo INFO)");
    Console.WriteLine("  --help                  Exibir esta ajuda");
    Console.WriteLine();
    Console.WriteLine("EXEMPLOS:");
    Console.WriteLine("  EchoNerfados.exe");
    Console.WriteLine("  EchoNerfados.exe --investigator \"Fulano\" --suspect \"Ciclano\" --case-id \"CASO-001\"");
    Console.WriteLine("  EchoNerfados.exe --no-memory --output C:\\Relatorios");
    Console.WriteLine();
    Console.WriteLine("IMPORTANTE: Execute como Administrador para acesso completo.");
}

internal sealed class InlineProgress<T>(Action<T> handler) : IProgress<T>
{
    public void Report(T value) => handler(value);
}
