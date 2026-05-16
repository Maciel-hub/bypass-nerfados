using Spectre.Console;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.Title = "Echo Nerfados Shield XDR v1.0";

// --help / --machine-id: work without license, without interactive terminal
if (args.Any(a => a is "--help" or "-h"))
{
    PrintHelp();
    return 0;
}

if (args.Any(a => a is "--machine-id"))
{
    Console.WriteLine(LicenseValidator.ComputeMachineId());
    return 0;
}

// Require interactive terminal — AnsiConsole rendering crashes otherwise
if (Console.IsInputRedirected || Console.IsOutputRedirected || Console.IsErrorRedirected)
{
    Console.Error.WriteLine("Echo Nerfados Shield XDR requires an interactive terminal.");
    Console.Error.WriteLine("Usage: EchoNerfados.exe [--help]");
    return 1;
}

// Banner
AnsiConsole.Clear();
AnsiConsole.Write(new FigletText("ECHO NERFADOS").Centered().Color(Color.Red));
AnsiConsole.Write(new Rule("[bold red]Shield XDR v1.0 — Anti-Cheat Investigation Platform[/]"));
AnsiConsole.WriteLine();

// License gate
AnsiConsole.Markup("[grey]Verificando licença...[/] ");
var licResult = LicenseValidator.Validate();
if (!licResult.Success)
{
    AnsiConsole.MarkupLine("[red]✗[/]");
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[red bold]LICENÇA INVÁLIDA[/]");
    AnsiConsole.MarkupLine($"[red]{Markup.Escape(licResult.ErrorMessage)}[/]");
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[grey]Contato: contato@nerfados.gg[/]");
    AnsiConsole.WriteLine();
    return 3;
}

var _lic = licResult.License!;
AnsiConsole.MarkupLine($"[green]✓[/] [grey]Cliente: [white]{Markup.Escape(_lic.CustomerId)}[/] · Expira: [white]{_lic.ExpiresAt.LocalDateTime:dd/MM/yyyy}[/][/]");
AnsiConsole.WriteLine();

var config        = new ScanConfig { Rules = RulesLoader.Load() };
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
        case "--profile" when i + 1 < args.Length:
            config.Profile = args[++i].ToLowerInvariant() switch
            {
                "fast"    => ScanProfile.Fast,
                "deep"    => ScanProfile.Deep,
                "fivem"   => ScanProfile.FiveM,
                "florence" => ScanProfile.Florence,
                _          => ScanProfile.Default
            };
            break;
        case "--no-final-prompt": noFinalPrompt = true; break;
        case "--open-report":    config.OpenReportAfterScan = true;  break;
        case "--no-open-report": config.OpenReportAfterScan = false; noFinalPrompt = true; break;
        case "--ui" when i + 1 < args.Length:
            config.UiMode = args[++i].ToLowerInvariant() == "detailed"
                ? ConsoleUiMode.Detailed
                : ConsoleUiMode.Minimal;
            break;
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
    ConsoleUI.PrintSummary(finalResult, config);

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
        var execPath = Path.Combine(Path.GetDirectoryName(htmlReportPath)!, "report_executive.html");
        if (File.Exists(execPath))
            AnsiConsole.MarkupLine($"[green]✓ EXEC:[/] {Markup.Escape(execPath)}");
    }
    if (htmlReportPath != null)
    {
        var evidencePath = Path.Combine(Path.GetDirectoryName(htmlReportPath)!, "evidence.json");
        AnsiConsole.MarkupLine($"[green]✓ JSON:[/] {Markup.Escape(evidencePath)}");
    }
}

AnsiConsole.WriteLine();
AnsiConsole.Write(new Rule("[bold]VARREDURA CONCLUÍDA[/]"));

// ── Pós-scan: abrir relatório ────────────────────────────────────────────────
if (!noFinalPrompt && htmlReportPath != null && File.Exists(htmlReportPath))
{
    AnsiConsole.WriteLine();

    if (config.OpenReportAfterScan)
    {
        // --open-report: abre automaticamente sem menu
        OpenHtmlReport(htmlReportPath);
    }
    else
    {
        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]O que deseja fazer agora?[/]")
                .HighlightStyle(new Style(foreground: Color.Red))
                .AddChoices(
                    "Abrir relatório HTML",
                    "Abrir pasta do relatório",
                    "Sair"
                ));

        switch (choice)
        {
            case "Abrir relatório HTML": OpenHtmlReport(htmlReportPath); break;
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
}

static void OpenHtmlReport(string path)
{
    try
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true });
        AnsiConsole.MarkupLine("[green]Relatório aberto no navegador padrão.[/]");
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[red]Não foi possível abrir o relatório: {Markup.Escape(ex.Message)}[/]");
        AnsiConsole.MarkupLine($"[dim]{Markup.Escape(path)}[/]");
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
    Console.WriteLine("  --profile default       Todos os modulos (padrao)");
    Console.WriteLine("  --profile fast          16 modulos essenciais — scan rapido (~30s)");
    Console.WriteLine("  --profile deep          Todos os modulos + USN + Memory (ignora --no-usn/--no-memory)");
    Console.WriteLine("  --profile fivem         Foco FiveM — todos os modulos + timeline por sessao");
    Console.WriteLine("  --profile florence      Todos os modulos + downgrade single-source High/Critical");
    Console.WriteLine("  --ui minimal            Console limpo: score + top 5 + caminhos (padrao)");
    Console.WriteLine("  --ui detailed           Console detalhado: tabelas + dossies + cobertura");
    Console.WriteLine("  --open-report           Abrir HTML automaticamente ao finalizar");
    Console.WriteLine("  --no-open-report        Nao abrir HTML nem exibir menu (apenas caminho)");
    Console.WriteLine("  --no-usn                Pular analise do USN Journal");
    Console.WriteLine("  --no-memory             Pular analise de memoria de processos");
    Console.WriteLine("  --no-report             Nao gerar relatorio em arquivo");
    Console.WriteLine("  --no-final-prompt       Nao exibir menu apos conclusao (automacao)");
    Console.WriteLine("  --verbose               Mostrar todos os findings (incluindo INFO)");
    Console.WriteLine("  --machine-id            Exibir Machine ID desta máquina (para solicitar licença)");
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
