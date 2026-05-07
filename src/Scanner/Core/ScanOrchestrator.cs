using Spectre.Console;
using BypassNerfados.Scanner.Models;
using BypassNerfados.Scanner.Modules;
using BypassNerfados.Scanner.Reports;

namespace BypassNerfados.Scanner.Core;

public class ScanOrchestrator
{
    private readonly ScanConfig _config;
    private readonly ScanResult _result;

    public ScanOrchestrator(ScanConfig config)
    {
        _config = config;
        _result = new ScanResult
        {
            IsAdministrator = IsAdmin()
        };
    }

    public async Task<ScanResult> RunAsync()
    {
        ConsoleUI.PrintBanner();

        if (!_result.IsAdministrator)
        {
            ConsoleUI.PrintError("AVISO: Executando sem privilégios de Administrador. Alguns módulos serão limitados.");
            AnsiConsole.WriteLine();
        }

        var modules = BuildModuleList();

        AnsiConsole.Write(new Rule($"[bold]INICIANDO VARREDURA[/] [grey]— {modules.Count} módulos[/]"));
        AnsiConsole.WriteLine();

        await AnsiConsole.Progress()
            .AutoClear(false)
            .HideCompleted(false)
            .Columns(
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new ElapsedTimeColumn(),
                new SpinnerColumn())
            .StartAsync(async ctx =>
            {
                var tasks = modules.Select(m =>
                    ctx.AddTask($"[cyan]{m.Name}[/]", maxValue: 1)).ToList();

                for (int i = 0; i < modules.Count; i++)
                {
                    var module = modules[i];
                    var task = tasks[i];
                    task.StartTask();

                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    try
                    {
                        var findings = await module.RunAsync(_config);
                        sw.Stop();

                        _result.Findings.AddRange(findings);
                        _result.ModulesRun.Add(module.Name);
                        _result.ModuleDurations[module.Name] = sw.Elapsed;

                        foreach (var f in findings.Where(f => f.Risk >= RiskLevel.Medium))
                            ConsoleUI.PrintFinding(f);
                    }
                    catch (Exception ex)
                    {
                        sw.Stop();
                        _result.ModuleErrors.Add($"{module.Name}: {ex.Message}");
                        ConsoleUI.PrintModuleError(module.Name, ex.Message);
                    }
                    finally
                    {
                        task.Value = 1;
                        task.StopTask();
                    }
                }
            });

        AnsiConsole.WriteLine();

        // Run correlation engine
        AnsiConsole.MarkupLine("[bold cyan]▶[/] [bold]Correlação[/] [grey]— analisando padrões entre módulos...[/]");
        Correlator.Correlate(_result);
        AnsiConsole.MarkupLine($"  [green]✓[/] Correlação concluída");

        // Print summary
        ConsoleUI.PrintSummary(_result);

        // Generate report
        if (_config.SaveReport)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold]EXPORTANDO RELATÓRIO[/]"));

            var reportPath = Path.Combine(_config.ReportOutputPath, _config.ReportFileName + ".html");
            var txtPath = Path.Combine(_config.ReportOutputPath, _config.ReportFileName + ".txt");

            try
            {
                Directory.CreateDirectory(_config.ReportOutputPath);
                ReportGenerator.GenerateHtml(_result, _config, reportPath);
                ReportGenerator.GenerateTxt(_result, _config, txtPath);
                AnsiConsole.MarkupLine($"[green]✓ HTML:[/] {Markup.Escape(reportPath)}");
                AnsiConsole.MarkupLine($"[green]✓ TXT: [/] {Markup.Escape(txtPath)}");
            }
            catch (Exception ex)
            {
                ConsoleUI.PrintError($"Erro ao gerar relatório: {ex.Message}");
            }
        }

        return _result;
    }

    private List<BaseModule> BuildModuleList()
    {
        var list = new List<BaseModule>
        {
            new SystemInfoModule(),
            new BamDamModule(),
            new PrefetchModule(),
            new RegistryArtifactsModule(),
            new EventViewerModule(),
            new DefenderModule(),
            new KnownCheatsModule(),
            new FileSystemModule(),
            new NetworkModule(),
            new ServiceCheckModule(),
        };

        if (_config.RunUsnJournal && _result.IsAdministrator)
            list.Add(new UsnJournalModule());

        if (_config.DeepMemoryScan && _result.IsAdministrator)
            list.Add(new ProcessMemoryModule());

        return list;
    }

    private static bool IsAdmin()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
