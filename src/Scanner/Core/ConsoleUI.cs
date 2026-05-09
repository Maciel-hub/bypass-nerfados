using Spectre.Console;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Core;

public static class ConsoleUI
{
    public static void PrintBanner()
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(new FigletText("BYPASS NERFADOS").Centered().Color(Color.Red));
        AnsiConsole.Write(new Rule("[bold red]Shield XDR v1.0 — Anti-Cheat Investigation Platform[/]"));
        AnsiConsole.MarkupLine("[grey]Investigação Forense · Detecção de Cheats · Screen-Share Analysis[/]");
        AnsiConsole.MarkupLine($"[grey]Máquina: [white]{Environment.MachineName}[/] | Usuário: [white]{Environment.UserName}[/] | {DateTime.Now:dd/MM/yyyy HH:mm:ss}[/]");
        AnsiConsole.WriteLine();
    }

    public static void PrintModuleStart(string name, string description)
    {
        AnsiConsole.MarkupLine($"[bold cyan]▶[/] [bold]{name}[/] [grey]— {description}[/]");
    }

    public static void PrintModuleOk(string name, int findingsCount, TimeSpan duration)
    {
        var color = findingsCount > 0 ? "yellow" : "green";
        AnsiConsole.MarkupLine($"  [green]✓[/] [{color}]{findingsCount} findings[/] [grey]({duration.TotalMilliseconds:F0}ms)[/]");
    }

    public static void PrintModuleError(string name, string error)
    {
        AnsiConsole.MarkupLine($"  [red]✗[/] [grey]{Markup.Escape(error)}[/]");
    }

    public static void PrintSummary(ScanResult result)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]RESULTADO DA VARREDURA[/]"));
        AnsiConsole.WriteLine();

        var riskColor = result.OverallRisk switch
        {
            RiskLevel.Critical => "red",
            RiskLevel.High     => "darkorange",
            RiskLevel.Medium   => "yellow",
            RiskLevel.Low      => "green",
            _                  => "grey"
        };

        var scorePanel = new Panel(
            Align.Center(
                new Markup($"[bold {riskColor}]{result.TotalScore}/100[/]\n[bold {riskColor}]{result.OverallRiskLabel}[/]"),
                VerticalAlignment.Middle))
        {
            Header = new PanelHeader("SCORE DE RISCO"),
            Width = 30,
            Height = 5
        };
        AnsiConsole.Write(scorePanel);
        AnsiConsole.WriteLine();

        // Stats table
        var statsTable = new Table().Border(TableBorder.Rounded);
        statsTable.AddColumn("Severidade");
        statsTable.AddColumn("Qtd");
        statsTable.AddColumn("Score");

        var byRisk = result.Findings.GroupBy(f => f.Risk)
            .OrderByDescending(g => g.Key);

        foreach (var group in byRisk)
        {
            var color = group.Key switch
            {
                RiskLevel.Critical => "red",
                RiskLevel.High     => "darkorange",
                RiskLevel.Medium   => "yellow",
                RiskLevel.Low      => "green",
                _                  => "grey"
            };
            statsTable.AddRow(
                $"[{color}]{group.Key.ToString().ToUpper()}[/]",
                $"[bold]{group.Count()}[/]",
                $"+{(int)group.Sum(f => f.WeightedScore)}"
            );
        }
        AnsiConsole.Write(statsTable);

        // Top High/Critical findings (non-cheat noise, system events, etc.)
        var topFindings = result.Findings
            .Where(f => f.Risk >= RiskLevel.High && f.Category != FindingCategory.Cheat)
            .OrderByDescending(f => f.Risk)
            .ThenByDescending(f => f.Confidence)
            .Take(10)
            .ToList();

        if (topFindings.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold red]TOP FINDINGS — HIGH / CRITICAL[/]"));

            var findTable = new Table().Border(TableBorder.Rounded).Expand();
            findTable.AddColumn("Risco");
            findTable.AddColumn("Módulo");
            findTable.AddColumn("Título");
            findTable.AddColumn("Detalhe");

            foreach (var f in topFindings)
            {
                var color = f.Risk == RiskLevel.Critical ? "red" : "darkorange";
                findTable.AddRow(
                    $"[bold {color}]{f.RiskLabel}[/]",
                    $"[cyan]{Markup.Escape(f.Module)}[/]",
                    $"[bold]{Markup.Escape(f.Title)}[/]",
                    Markup.Escape(f.Detail.Length > 80 ? f.Detail[..80] + "..." : f.Detail)
                );
            }
            AnsiConsole.Write(findTable);
        }

        // Cheat section — always shown regardless of risk level, grouped by confidence tier
        var cheatFindings = result.Findings
            .Where(f => f.Category == FindingCategory.Cheat)
            .OrderByDescending(f => f.Confidence)
            .ThenByDescending(f => f.Risk)
            .ToList();

        if (cheatFindings.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold red]CHEATS DETECTADOS / INDÍCIOS[/]"));

            var cheatTable = new Table().Border(TableBorder.Rounded).Expand();
            cheatTable.AddColumn("Confiança");
            cheatTable.AddColumn("Risco");
            cheatTable.AddColumn("Módulo");
            cheatTable.AddColumn("Título");
            cheatTable.AddColumn("Validar?");

            foreach (var f in cheatFindings)
            {
                var (confLabel, confColor) = f.Confidence switch
                {
                    Confidence.Confirmed => ("CONFIRMADO",     "red"),
                    Confidence.High      => ("FORTE INDÍCIO",  "darkorange"),
                    Confidence.Medium    => ("INDÍCIO",        "yellow"),
                    _                    => ("BAIXA CONFIANÇA","grey")
                };
                var rc = f.Risk switch
                {
                    RiskLevel.Critical => "red",
                    RiskLevel.High     => "darkorange",
                    RiskLevel.Medium   => "yellow",
                    _                  => "grey"
                };
                cheatTable.AddRow(
                    $"[bold {confColor}]{confLabel}[/]",
                    $"[{rc}]{f.RiskLabel}[/]",
                    $"[cyan]{Markup.Escape(f.Module)}[/]",
                    $"[bold]{Markup.Escape(f.Title)}[/]",
                    Markup.Escape(f.ValidationHint ?? "—")
                );
            }
            AnsiConsole.Write(cheatTable);
        }
    }

    public static void PrintFinding(Finding finding)
    {
        if (finding.Risk < RiskLevel.Medium) return;

        var color = finding.Risk switch
        {
            RiskLevel.Critical => "red",
            RiskLevel.High     => "darkorange",
            RiskLevel.Medium   => "yellow",
            _                  => "white"
        };

        AnsiConsole.MarkupLine($"    [{color}]■[/] [{color}]{finding.RiskLabel}[/] {Markup.Escape(finding.Title)}");
        if (finding.Evidence != null)
            AnsiConsole.MarkupLine($"       [grey]{Markup.Escape(finding.Evidence)}[/]");
    }

    public static void PrintInfo(string message) =>
        AnsiConsole.MarkupLine($"[grey]{Markup.Escape(message)}[/]");

    public static void PrintSuccess(string message) =>
        AnsiConsole.MarkupLine($"[green]{Markup.Escape(message)}[/]");

    public static void PrintError(string message) =>
        AnsiConsole.MarkupLine($"[red]{Markup.Escape(message)}[/]");
}
