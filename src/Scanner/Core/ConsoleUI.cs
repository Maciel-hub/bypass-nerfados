using System.Security.Cryptography;
using Spectre.Console;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Core;

public static class ConsoleUI
{
    public static void PrintBanner()
    {
        if (!Console.IsOutputRedirected) AnsiConsole.Clear();
        AnsiConsole.Write(new FigletText("ECHO NERFADOS").Centered().Color(Color.Red));
        AnsiConsole.Write(new Rule("[bold red]Shield XDR v1.0 — Anti-Cheat Investigation Platform[/]"));
        AnsiConsole.MarkupLine("[grey]Investigação Forense · Detecção de Cheats · Screen-Share Analysis[/]");
        AnsiConsole.MarkupLine($"[grey]Máquina: [white]{Environment.MachineName}[/] | Usuário: [white]{Environment.UserName}[/] | {DateTime.Now:dd/MM/yyyy HH:mm:ss}[/]");
        AnsiConsole.WriteLine();
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

        // Artifact dossier — one card per unique cheat artifact, enriched with path/hashes/bypass
        if (result.EvidenceBundles.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule($"[bold red]CHEATS DETECTADOS / INDÍCIOS ({result.EvidenceBundles.Count} artefatos)[/]"));

            foreach (var bundle in result.EvidenceBundles)
            {
                var (vColor, vLabel) = bundle.Confidence switch
                {
                    Confidence.Confirmed => ("red",        "CONFIRMADO"),
                    Confidence.High      => ("darkorange", "FORTE INDÍCIO"),
                    Confidence.Medium    => ("yellow",     "INDÍCIO"),
                    _                    => ("grey",       "BAIXA CONFIANÇA")
                };
                var brc = bundle.Risk switch
                {
                    RiskLevel.Critical => "red",
                    RiskLevel.High     => "darkorange",
                    RiskLevel.Medium   => "yellow",
                    _                  => "grey"
                };

                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine(
                    $"  [{vColor}]◆ {vLabel}[/]  [{brc}]{bundle.Risk.ToString().ToUpper()}[/]  " +
                    $"[bold white]{Markup.Escape(bundle.ArtifactName)}[/]");

                if (!string.IsNullOrEmpty(bundle.FullPath))
                    AnsiConsole.MarkupLine(
                        $"    [grey]Caminho :[/] [dim]{Markup.Escape(TruncatePath(bundle.FullPath, 90))}[/]");

                AnsiConsole.MarkupLine(
                    $"    [grey]Origem  :[/] {Markup.Escape(bundle.Summary)}");

                var lastTs = bundle.Timeline.LastOrDefault()?.Timestamp;
                if (lastTs.HasValue)
                    AnsiConsole.MarkupLine(
                        $"    [grey]Histórico:[/] última evidência em {lastTs:dd/MM/yyyy HH:mm:ss}");

                if (!string.IsNullOrEmpty(bundle.Sha256))
                    AnsiConsole.MarkupLine(
                        $"    [grey]SHA256  :[/] [dim]{Markup.Escape(bundle.Sha256)}[/]");

                if (bundle.BypassIndicators.Count > 0)
                    AnsiConsole.MarkupLine(
                        $"    [red]Bypass  :[/] {Markup.Escape(bundle.BypassIndicators[0])}");

                if (bundle.ValidationSteps.Count > 0)
                    AnsiConsole.MarkupLine(
                        $"    [yellow]Validar :[/] {Markup.Escape(bundle.ValidationSteps[0])}");
            }
        }

        // Module coverage table
        if (result.ModuleCoverage.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold]COBERTURA DA VARREDURA[/]"));

            var covTable = new Table().Border(TableBorder.Rounded).Expand();
            covTable.AddColumn("Módulo");
            covTable.AddColumn("Status");
            covTable.AddColumn("Motivo / Impacto");

            foreach (var entry in result.ModuleCoverage.OrderBy(e => e.Status).ThenBy(e => e.Name))
            {
                var (statusColor, statusLabel) = entry.Status switch
                {
                    ModuleStatus.Executed => ("green",      "EXECUTADO"),
                    ModuleStatus.Partial  => ("yellow",     "PARCIAL"),
                    ModuleStatus.Skipped  => ("grey",       "PULADO"),
                    ModuleStatus.Failed   => ("red",        "FALHOU"),
                    _                     => ("white",      "AGUARDANDO")
                };
                var note = entry.Status is ModuleStatus.Skipped or ModuleStatus.Failed or ModuleStatus.Partial
                    ? Markup.Escape(entry.Reason)
                    : string.IsNullOrEmpty(entry.ForensicImpact) ? "[grey]—[/]" : $"[grey]{Markup.Escape(entry.ForensicImpact)}[/]";

                covTable.AddRow(
                    Markup.Escape(entry.Name),
                    $"[{statusColor}]{statusLabel}[/]",
                    note);
            }
            AnsiConsole.Write(covTable);
        }

        // Bypass / anti-forensics section
        var bypassList = result.BypassFindings.OrderByDescending(f => f.Risk).Take(15).ToList();
        if (bypassList.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold red]TENTATIVAS DE BYPASS / ANTI-FORENSE[/]"));

            var bypassTable = new Table().Border(TableBorder.Rounded).Expand();
            bypassTable.AddColumn("Risco");
            bypassTable.AddColumn("Módulo");
            bypassTable.AddColumn("Evento");
            bypassTable.AddColumn("Timestamp");

            foreach (var f in bypassList)
            {
                var bColor = f.Risk == RiskLevel.Critical ? "red" : "darkorange";
                bypassTable.AddRow(
                    $"[bold {bColor}]{f.RiskLabel}[/]",
                    $"[cyan]{Markup.Escape(f.Module)}[/]",
                    $"[bold]{Markup.Escape(f.Title)}[/]",
                    f.Timestamp.HasValue
                        ? $"[grey]{f.Timestamp:dd/MM/yyyy HH:mm:ss}[/]"
                        : "[grey]—[/]"
                );
            }
            AnsiConsole.Write(bypassTable);
        }
    }

    private static string TruncatePath(string path, int maxLen)
    {
        if (path.Length <= maxLen) return path;
        // Keep start and end, put ellipsis in middle
        var keep = (maxLen - 3) / 2;
        return path[..keep] + "..." + path[^keep..];
    }

    public static void PrintInfo(string message) =>
        AnsiConsole.MarkupLine($"[grey]{Markup.Escape(message)}[/]");

    public static void PrintSuccess(string message) =>
        AnsiConsole.MarkupLine($"[green]{Markup.Escape(message)}[/]");

    public static void PrintError(string message) =>
        AnsiConsole.MarkupLine($"[red]{Markup.Escape(message)}[/]");

    // Returns true if the user authenticates successfully within maxAttempts tries.
    public static bool PromptLogin(int maxAttempts = 3)
    {
        if (!Console.IsOutputRedirected) AnsiConsole.Clear();
        Console.Title = "Echo Nerfados Shield XDR v1.0";
        AnsiConsole.Write(new Rule("[bold red]Echo Nerfados Shield XDR — Acesso Restrito[/]"));
        AnsiConsole.WriteLine();

        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var user = AnsiConsole.Prompt(
                new TextPrompt<string>("[bold]Usuário :[/]")
                    .PromptStyle("cyan"));

            var pass = AnsiConsole.Prompt(
                new TextPrompt<string>("[bold]Senha   :[/]")
                    .PromptStyle("cyan")
                    .Secret());

            if (ValidateCredentials(user, pass))
            {
                AnsiConsole.MarkupLine("[green]Autenticado.[/]");
                AnsiConsole.WriteLine();
                return true;
            }

            var remaining = maxAttempts - attempt;
            if (remaining > 0)
                AnsiConsole.MarkupLine($"[red]Credenciais inválidas. {remaining} tentativa(s) restante(s).[/]");
            else
                AnsiConsole.MarkupLine("[red]Acesso negado.[/]");

            AnsiConsole.WriteLine();
        }

        return false;
    }

    private static bool ValidateCredentials(string user, string pass)
    {
        // Username: case-insensitive compare
        if (!string.Equals(user.Trim(), "nerfados", StringComparison.OrdinalIgnoreCase))
            return false;

        // Password: constant-time SHA-256 comparison to resist timing attacks
        var inputHash  = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pass));
        var targetHash = Convert.FromHexString(
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"); // SHA256("admin")
        return CryptographicOperations.FixedTimeEquals(inputHash, targetHash);
    }
}
