using Spectre.Console;
using Spectre.Console.Rendering;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Core;

/// <summary>
/// Thread-safe live TUI dashboard. State is mutated by the progress callback;
/// Build() is called by the animation task to produce a fresh IRenderable each frame.
/// </summary>
internal sealed class LiveDashboard
{
    private readonly object _sync = new();

    private enum RowState { Running, Done, Failed }
    private record ModuleRow(string Name, RowState State, int Findings, double WScore, TimeSpan Duration);

    private readonly List<ModuleRow> _rows = new();
    private int _expectedModules;
    private string _phase = "Iniciando...";
    private bool _done;
    private Finding? _latestHighFinding;
    private readonly Dictionary<RiskLevel, int> _counts = new();
    private double _runningScore;

    // ── Mutations (called from progress callback, any thread) ─────────

    public void SetExpectedModules(int n)      { lock (_sync) _expectedModules = n; }
    public void SetPhase(string phase)         { lock (_sync) _phase = phase; }
    public void SetDone()                      { lock (_sync) { _done = true; _phase = "Concluído"; } }

    public void ModuleStarted(string name)
    {
        lock (_sync)
        {
            _phase = name;
            if (_rows.All(r => r.Name != name))
                _rows.Add(new ModuleRow(name, RowState.Running, 0, 0, TimeSpan.Zero));
        }
    }

    public void ModuleCompleted(string name, IReadOnlyList<Finding>? findings, TimeSpan duration)
    {
        // Pre-compute outside the lock so iteration over (potentially large) finding lists
        // doesn't block the animation task waiting on _sync.
        var count   = findings?.Count ?? 0;
        var ws      = findings?.Sum(f => f.WeightedScore) ?? 0;
        var delta   = new Dictionary<RiskLevel, int>();
        Finding? newLatest = null;

        if (findings != null)
        {
            foreach (var f in findings)
            {
                delta[f.Risk] = delta.GetValueOrDefault(f.Risk) + 1;
                if (f.Risk >= RiskLevel.High && (newLatest == null || f.Risk >= newLatest.Risk))
                    newLatest = f;
            }
        }

        lock (_sync)
        {
            var idx = _rows.FindIndex(r => r.Name == name);
            var row = new ModuleRow(name, RowState.Done, count, ws, duration);
            if (idx >= 0) _rows[idx] = row;
            else          _rows.Add(row);

            _runningScore = Math.Min(_runningScore + ws, 100);

            foreach (var kvp in delta)
                _counts[kvp.Key] = _counts.GetValueOrDefault(kvp.Key) + kvp.Value;

            if (newLatest != null &&
                (_latestHighFinding == null || newLatest.Risk >= _latestHighFinding.Risk))
                _latestHighFinding = newLatest;
        }
    }

    public void ModuleFailed(string name)
    {
        lock (_sync)
        {
            var idx = _rows.FindIndex(r => r.Name == name);
            var row = new ModuleRow(name, RowState.Failed, 0, 0, TimeSpan.Zero);
            if (idx >= 0) _rows[idx] = row;
            else          _rows.Add(row);
        }
    }

    // ── Rendering (called from animation task, single thread) ─────────

    public IRenderable Build(string spinner)
    {
        List<ModuleRow> rows;
        int expected, score;
        string phase;
        bool done;
        Finding? latest;
        Dictionary<RiskLevel, int> counts;

        lock (_sync)
        {
            rows     = new List<ModuleRow>(_rows);
            expected = _expectedModules;
            phase    = _phase;
            done     = _done;
            latest   = _latestHighFinding;
            counts   = new Dictionary<RiskLevel, int>(_counts);
            score    = (int)Math.Min(_runningScore, 100);
        }

        var liveRisk  = ScoreToRisk(score);
        var riskColor = RiskColor(liveRisk);
        var riskLabel = score == 0 && !done ? " — " : RiskLabel(liveRisk);

        var doneCount    = rows.Count(r => r.State is RowState.Done or RowState.Failed);
        var waitingCount = Math.Max(0, expected - rows.Count);

        // ── Header bar ────────────────────────────────────────────────
        var statusMarkup = done
            ? "[bold green]✓  CONCLUÍDO[/]"
            : $"[bold yellow]{Markup.Escape(spinner)}[/]  [grey]varrendo:[/] [bold white]{Markup.Escape(phase)}[/]";

        var header = new Panel(
            new Markup(
                $"  [bold red]ECHO NERFADOS[/][bold white] SHIELD XDR[/]" +
                $"   {statusMarkup}" +
                $"   [dim]{Markup.Escape(Environment.MachineName)} · {Markup.Escape(Environment.UserName)} · {DateTime.Now:HH:mm:ss}[/]  "))
        {
            BorderStyle = new Style(foreground: Color.Red),
            Padding     = new Padding(0, 0)
        };

        // ── Progress bar ──────────────────────────────────────────────
        IRenderable progressBar;
        if (expected > 0)
        {
            var pct     = (double)doneCount / expected;
            const int W = 36;
            var filled  = (int)(W * pct);
            var empty   = W - filled;
            var pctStr  = $"{pct:P0}";
            progressBar = new Markup(
                $"  [dim grey]Progresso:[/]  " +
                $"[green]{new string('█', filled)}[/][dim grey]{new string('░', empty)}[/]" +
                $"  [bold]{doneCount}[/][dim grey]/{expected}[/]  [grey]{pctStr}[/]");
        }
        else
        {
            progressBar = new Text("");
        }

        // ── Module table ──────────────────────────────────────────────
        var progLabel = expected > 0 ? $"{doneCount}/{expected}" : $"{doneCount}";
        var modTable = new Table()
            .Title($"[grey dim] módulos: {progLabel} [/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey23)
            .HideHeaders()
            .AddColumn(new TableColumn("name").NoWrap())
            .AddColumn(new TableColumn("f").RightAligned().Width(5))
            .AddColumn(new TableColumn("t").RightAligned().Width(9));

        foreach (var row in rows)
        {
            var (icon, nameMarkup) = row.State switch
            {
                RowState.Running => ($"[bold yellow]{Markup.Escape(spinner)}[/]", $"[bold white]{Markup.Escape(row.Name)}[/]"),
                RowState.Done    => (row.Findings > 0 ? "[yellow]✓[/]" : "[dim green]✓[/]",
                                     row.Findings > 0 ? $"[white]{Markup.Escape(row.Name)}[/]"
                                                      : $"[grey]{Markup.Escape(row.Name)}[/]"),
                RowState.Failed  => ("[bold red]✗[/]", $"[red]{Markup.Escape(row.Name)}[/]"),
                _                => ("[dim]·[/]", $"[dim grey]{Markup.Escape(row.Name)}[/]")
            };

            var findMarkup = row.State switch
            {
                RowState.Done    => row.Findings > 0 ? $"[yellow]{row.Findings}f[/]" : "[dim]0f[/]",
                RowState.Running => "[dim]...[/]",
                RowState.Failed  => "[red]ERR[/]",
                _                => ""
            };

            var timeMarkup = row.State == RowState.Done
                ? $"[dim]{row.Duration.TotalMilliseconds:F0}ms[/]"
                : "";

            modTable.AddRow(
                $"  {icon} {nameMarkup}",
                findMarkup,
                timeMarkup);
        }

        if (waitingCount > 0)
            modTable.AddRow($"  [dim grey]··· +{waitingCount} aguardando[/]", "", "");

        // ── Score panel ───────────────────────────────────────────────
        var scoreRows = new List<IRenderable>
        {
            new Text(""),
            new Markup($"   [{riskColor}][bold]{score,3}[/] / 100[/]"),
            new Markup($"   [{riskColor}][bold]{riskLabel,-8}[/][/]"),
            new Text(""),
            new Rule().RuleStyle(new Style(foreground: Color.Grey23)),
        };

        foreach (var (rl, col, lbl) in new (RiskLevel, string, string)[]
        {
            (RiskLevel.Critical, "red",        "CRÍTICO"),
            (RiskLevel.High,     "darkorange", "ALTO   "),
            (RiskLevel.Medium,   "yellow",     "MÉDIO  "),
            (RiskLevel.Low,      "green",      "BAIXO  "),
        })
        {
            counts.TryGetValue(rl, out var cnt);
            var cntStyle = cnt > 0 ? $"[bold {col}]{cnt,3}[/]" : $"[dim]{cnt,3}[/]";
            scoreRows.Add(new Markup($"  [{col}]▌[/] {lbl}  {cntStyle}"));
        }
        scoreRows.Add(new Text(""));

        var scorePanel = new Panel(new Rows(scoreRows))
        {
            Header  = new PanelHeader("[bold grey]Score ao Vivo[/]"),
            Width   = 26,
            Padding = new Padding(0, 0)
        };

        // ── Side-by-side grid ─────────────────────────────────────────
        var mainGrid = new Grid()
            .AddColumn(new GridColumn().PadRight(1))
            .AddColumn(new GridColumn().Width(26).NoWrap());
        mainGrid.AddRow(modTable, scorePanel);

        // ── Latest high finding alert ─────────────────────────────────
        IRenderable alertPanel;
        if (latest != null)
        {
            var col = latest.Risk == RiskLevel.Critical ? "red" : "darkorange";
            alertPanel = new Panel(
                new Markup(
                    $"  [{col}][bold]{Markup.Escape(latest.RiskLabel)}[/][/]  " +
                    $"[dim]{Markup.Escape(latest.Module)}[/]  " +
                    $"[white]{Markup.Escape(Truncate(latest.Title, 90))}[/]"))
            {
                Header      = new PanelHeader("[bold]Último achado de alto risco[/]"),
                BorderStyle = latest.Risk == RiskLevel.Critical
                    ? new Style(foreground: Color.Red)
                    : new Style(foreground: Color.DarkOrange)
            };
        }
        else
        {
            alertPanel = new Panel(
                new Markup("[dim grey]  Aguardando módulos...[/]"))
            {
                Header      = new PanelHeader("[dim grey]Último achado de alto risco[/]"),
                BorderStyle = new Style(foreground: Color.Grey23)
            };
        }

        return new Rows(header, new Text(""), progressBar, new Text(""), mainGrid, new Text(""), alertPanel);
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private static RiskLevel ScoreToRisk(int score) => score switch
    {
        >= 76 => RiskLevel.Critical,
        >= 51 => RiskLevel.High,
        >= 26 => RiskLevel.Medium,
        >= 1  => RiskLevel.Low,
        _     => RiskLevel.Info
    };

    private static string RiskColor(RiskLevel r) => r switch
    {
        RiskLevel.Critical => "red",
        RiskLevel.High     => "darkorange",
        RiskLevel.Medium   => "yellow",
        RiskLevel.Low      => "green",
        _                  => "grey"
    };

    private static string RiskLabel(RiskLevel r) => r switch
    {
        RiskLevel.Critical => "CRÍTICO",
        RiskLevel.High     => "ALTO",
        RiskLevel.Medium   => "MÉDIO",
        RiskLevel.Low      => "BAIXO",
        _                  => "LIMPO"
    };

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
