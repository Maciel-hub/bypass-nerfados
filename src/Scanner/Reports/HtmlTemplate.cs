using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;
using System.Text;

namespace BypassNerfados.Scanner.Reports;

public static class HtmlTemplate
{
    private static readonly HashSet<string> s_execModules     = ["BAM/DAM", "Prefetch", "Amcache", "UserAssist", "ShimCache", "Registry Artifacts"];
    private static readonly HashSet<string> s_downloadModules = ["Browser Downloads", "External Tool Residue"];
    private static readonly HashSet<string> s_deletionModules = ["USN Journal", "Recycle Bin"];
    private static readonly HashSet<string> s_folderModules   = ["ShellBags", "Jump Lists", "LNK Recent"];

    private static string GetTabId(Finding f) =>
        f.Category == FindingCategory.LogCoverage                  ? "cobertura" :
        f.Category == FindingCategory.Cheat                        ? "cheats" :
        f.Category is FindingCategory.AntiForensics
            or FindingCategory.SystemTampering
            or FindingCategory.ServiceTampering                    ? "bypass" :
        f.Category == FindingCategory.MemoryAnomaly
            || f.Module == "Process Memory"                        ? "memoria" :
        s_execModules.Contains(f.Module)
            || f.Category == FindingCategory.SuspiciousExecution   ? "execucoes" :
        s_downloadModules.Contains(f.Module)                       ? "downloads" :
        s_deletionModules.Contains(f.Module)                       ? "delecoes" :
        s_folderModules.Contains(f.Module)                         ? "pastas" :
        "outros";

    public static string Build(ScanResult result, ScanConfig config)
    {
        var sb = new StringBuilder();

        var riskColor = result.OverallRisk switch
        {
            RiskLevel.Critical => "#dc2626",
            RiskLevel.High     => "#ea580c",
            RiskLevel.Medium   => "#ca8a04",
            RiskLevel.Low      => "#16a34a",
            _                  => "#6b7280"
        };

        var machineName      = Esc(result.MachineName);
        var currentUser      = Esc(result.CurrentUser);
        var scanTime         = result.ScanTime.ToString("dd/MM/yyyy HH:mm:ss");
        var totalScore       = result.TotalScore;
        var riskLabel        = result.OverallRiskLabel;
        var findingsCount    = result.Findings.Count;
        var modulesCount     = result.ModulesRun.Count;
        var suspectHtml      = config.SuspectName != null
            ? $"""<div><span class="label">Suspeito</span><span class="value">{Esc(config.SuspectName)}</span></div>"""
            : "";
        var investigatorHtml = config.InvestigatorName != null
            ? $"""<div><span class="label">Investigador</span><span class="value">{Esc(config.InvestigatorName)}</span></div>"""
            : "";

        // Pre-compute tabs
        var byTab      = result.Findings.GroupBy(GetTabId).ToDictionary(g => g.Key, g => g.OrderByDescending(f => f.Risk).ToList());
        var allTimed   = result.SortedByTime.ToList();
        var hasBundles = result.EvidenceBundles.Count > 0;

        List<Finding> TabFindings(string id) => byTab.TryGetValue(id, out var l) ? l : [];

        // Tab definitions in display order
        var tabDefs = new (string Id, string Label, string BadgeClass)[]
        {
            ("resumo",      "Resumo",         ""),
            ("cheats",      "Cheats",         "danger"),
            ("diagnostico", "Diagnóstico",    "purple"),
            ("execucoes",   "Execuções",      "warn"),
            ("downloads",   "Downloads",      ""),
            ("delecoes",    "Deleções/USN",   ""),
            ("pastas",      "Pastas",         ""),
            ("memoria",     "Memória",        "warn"),
            ("bypass",      "Bypass",         "danger"),
            ("outros",      "Outros",         ""),
            ("timeline",    "Timeline",       ""),
            ("cobertura",   "Cobertura",      ""),
        };

        bool HasTab(string id) => id switch
        {
            "resumo"      => true,
            "diagnostico" => hasBundles,
            "timeline"    => allTimed.Count > 0,
            "cobertura"   => result.ModuleCoverage.Count > 0 || TabFindings("cobertura").Count > 0,
            _             => TabFindings(id).Count > 0
        };

        int TabCount(string id) => id switch
        {
            "resumo"      => result.Findings.Count,
            "diagnostico" => result.EvidenceBundles.Count,
            "timeline"    => allTimed.Count,
            "cobertura"   => result.ModuleCoverage.Count,
            _             => TabFindings(id).Count
        };

        var visibleTabs = tabDefs.Where(t => HasTab(t.Id)).ToList();

        // ── CSS + JS ─────────────────────────────────────────────────────────────
        sb.Append($$"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Echo Nerfados Shield XDR — Relatório</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0f0f0f; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  .header { background: linear-gradient(135deg, #1a1a2e, #16213e); border-bottom: 2px solid #dc2626; padding: 24px 32px; }
  .header h1 { font-size: 28px; font-weight: 800; color: #dc2626; letter-spacing: 2px; }
  .header h1 span { color: #fff; }
  .header .sub { color: #94a3b8; margin-top: 4px; font-size: 13px; }
  .header .meta { display: flex; gap: 32px; margin-top: 16px; flex-wrap: wrap; }
  .header .meta div { display: flex; flex-direction: column; }
  .header .meta .label { color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  .header .meta .value { color: #e2e8f0; font-weight: 600; margin-top: 2px; }
  .score-bar { background: #1e293b; border-bottom: 1px solid #334155; padding: 20px 32px; display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }
  .score-circle { width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-direction: column; border: 4px solid {{riskColor}}; background: #0f172a; flex-shrink: 0; }
  .score-circle .num { font-size: 24px; font-weight: 800; color: {{riskColor}}; }
  .score-circle .pts { font-size: 10px; color: #64748b; }
  .risk-badge { padding: 6px 16px; border-radius: 6px; font-weight: 800; font-size: 16px; background: {{riskColor}}22; color: {{riskColor}}; border: 1px solid {{riskColor}}44; }
  .stat-row { display: flex; gap: 12px; flex-wrap: wrap; }
  .stat { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px 20px; text-align: center; min-width: 80px; }
  .stat .n { font-size: 22px; font-weight: 700; }
  .stat .l { font-size: 11px; color: #64748b; text-transform: uppercase; margin-top: 2px; }
  /* Tab bar */
  .tab-bar { position: sticky; top: 0; z-index: 100; background: #0d1117; border-bottom: 2px solid #1e293b; padding: 0 24px; display: flex; align-items: flex-end; overflow-x: auto; }
  .tab-btn { padding: 10px 15px; background: transparent; border: none; border-bottom: 3px solid transparent; color: #64748b; font-size: 12px; font-weight: 600; cursor: pointer; white-space: nowrap; margin-bottom: -2px; display: flex; align-items: center; gap: 5px; letter-spacing: 0.3px; }
  .tab-btn:hover { color: #94a3b8; background: #1e293b22; }
  .tab-btn.active { color: #e2e8f0; border-bottom-color: #dc2626; }
  .tab-count { display: inline-flex; align-items: center; justify-content: center; min-width: 18px; height: 18px; border-radius: 9px; font-size: 10px; font-weight: 700; padding: 0 5px; }
  .tab-count.danger { background: #dc262222; color: #dc2626; }
  .tab-count.warn   { background: #ea580c22; color: #ea580c; }
  .tab-count.purple { background: #7c3aed22; color: #a78bfa; }
  .tab-count.plain  { background: #1e293b; color: #64748b; }
  /* Tab panels */
  .tab-panels { padding: 24px 32px; }
  .tab-pane { display: none; }
  .tab-pane.active { display: block; }
  /* Tab heading */
  .tab-heading { font-size: 15px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; padding-bottom: 12px; border-bottom: 1px solid #1e293b; margin-bottom: 18px; }
  .tab-heading span { color: #475569; font-size: 12px; font-weight: 400; text-transform: none; letter-spacing: 0; margin-left: 10px; }
  /* Filter bar */
  .filter-bar { display: flex; gap: 6px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; padding: 10px 14px; background: #111827; border: 1px solid #1e293b; border-radius: 6px; }
  .filter-btn { padding: 3px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; cursor: pointer; border: 1px solid #334155; background: transparent; color: #64748b; }
  .filter-btn:hover { background: #1e293b; color: #e2e8f0; }
  .filter-btn.active { background: #1e293b; color: #e2e8f0; border-color: #475569; }
  /* Module group */
  .module-group { margin-bottom: 20px; }
  .module-group-hdr { font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 1px; padding: 6px 0; border-bottom: 1px solid #1e293b; margin-bottom: 8px; }
  /* Findings */
  .finding { background: #1a1a2e; border: 1px solid #334155; border-radius: 8px; padding: 14px 16px; margin-bottom: 8px; border-left: 4px solid; }
  .finding.critical { border-left-color: #dc2626; }
  .finding.high { border-left-color: #ea580c; }
  .finding.medium { border-left-color: #ca8a04; }
  .finding.low { border-left-color: #16a34a; }
  .finding.info { border-left-color: #475569; }
  .finding-header { display: flex; align-items: flex-start; gap: 8px; flex-wrap: wrap; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; flex-shrink: 0; }
  .badge.critical { background: #dc262222; color: #dc2626; }
  .badge.high { background: #ea580c22; color: #ea580c; }
  .badge.medium { background: #ca8a0422; color: #ca8a04; }
  .badge.low { background: #16a34a22; color: #16a34a; }
  .badge.info { background: #47556922; color: #94a3b8; }
  .badge.conf { background: #0f172a; color: #4b5563; border: 1px solid #1e293b; font-size: 10px; }
  .mod-badge { background: #0f172a; border: 1px solid #334155; padding: 2px 8px; border-radius: 4px; font-size: 11px; color: #64748b; flex-shrink: 0; }
  .finding-title { font-weight: 700; color: #e2e8f0; font-size: 14px; flex: 1; min-width: 0; }
  .finding-detail { color: #94a3b8; font-size: 13px; margin-top: 6px; line-height: 1.5; white-space: pre-wrap; }
  .finding-evidence { background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px 10px; font-family: monospace; font-size: 12px; color: #64748b; margin-top: 6px; word-break: break-all; }
  .finding-hint { background: #ca8a0410; border: 1px solid #ca8a0433; border-radius: 4px; padding: 6px 10px; font-size: 12px; color: #fde68a; margin-top: 6px; }
  /* Timeline */
  .timeline-item { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid #1e293b; align-items: flex-start; }
  .timeline-extra { display: none; }
  .timeline-ts { color: #475569; font-family: monospace; font-size: 12px; flex-shrink: 0; width: 145px; }
  .expand-btn { margin-top: 10px; padding: 5px 18px; background: #1e293b; border: 1px solid #334155; border-radius: 4px; color: #64748b; cursor: pointer; font-size: 12px; }
  .expand-btn:hover { background: #334155; color: #e2e8f0; }
  /* Table */
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; background: #1e293b; color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  td { padding: 8px 12px; border-bottom: 1px solid #1e293b; color: #e2e8f0; font-size: 13px; }
  tr:hover td { background: #1e293b44; }
  /* Artifact dossier */
  .artifact-card { background:#1a1a2e;border:1px solid #334155;border-radius:8px;padding:16px 18px;margin-bottom:10px;border-left:4px solid #7c3aed; }
  .artifact-card.confirmed { border-left-color:#dc2626; }
  .artifact-card.strong { border-left-color:#ea580c; }
  .artifact-card.indicative { border-left-color:#ca8a04; }
  .artifact-card.low-conf { border-left-color:#475569; }
  .artifact-header { display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px; }
  .artifact-name { font-weight:800;color:#e2e8f0;font-size:15px; }
  .verdict-badge { padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700; }
  .verdict-confirmed { background:#dc262222;color:#dc2626; }
  .verdict-strong { background:#ea580c22;color:#ea580c; }
  .verdict-indicative { background:#ca8a0422;color:#ca8a04; }
  .verdict-low { background:#47556922;color:#94a3b8; }
  .artifact-path { font-family:monospace;font-size:12px;color:#64748b;margin-bottom:8px;word-break:break-all; }
  .artifact-meta { display:flex;gap:20px;flex-wrap:wrap;margin-bottom:8px;font-size:12px; }
  .artifact-meta span { color:#64748b; }
  .artifact-meta strong { color:#94a3b8; }
  .signals-grid { margin-top:10px;border-top:1px solid #1e293b;padding-top:8px; }
  .signal-item { font-size:12px;color:#94a3b8;padding:3px 0;border-bottom:1px solid #1e293b11; }
  .signal-mod { color:#64748b;font-size:11px;margin-right:6px; }
  .bypass-alert { background:#dc262210;border:1px solid #dc262233;border-radius:4px;padding:8px 12px;margin-top:8px;font-size:12px;color:#fca5a5; }
  .validation-alert { background:#ca8a0410;border:1px solid #ca8a0433;border-radius:4px;padding:8px 12px;margin-top:6px;font-size:12px;color:#fde68a; }
  /* Footer */
  .footer { background: #0a0a0f; border-top: 1px solid #1e293b; padding: 16px 32px; color: #334155; font-size: 12px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
  /* Print */
  @media print {
    .tab-bar, .filter-bar, .expand-btn { display: none !important; }
    .tab-pane { display: block !important; }
    .tab-heading { color: #333 !important; border-bottom: 2px solid #dc2626; margin-top: 32px; page-break-before: always; }
    .tab-heading:first-child { page-break-before: auto; }
    body { background: #fff; color: #111; font-size: 12px; }
    .header { background: #f0f4f8 !important; border-bottom: 2px solid #dc2626; }
    .header h1 { color: #dc2626; }
    .header .sub, .header .meta .value { color: #333; }
    .header .meta .label { color: #666; }
    .score-bar { background: #f8f8f8; border-bottom: 1px solid #ddd; }
    .score-circle .pts { color: #666; }
    .timeline-extra { display: flex !important; }
    .finding { break-inside: avoid; page-break-inside: avoid; background: #f9f9f9; border-color: #ddd; }
    .finding-detail { color: #444; }
    .finding-evidence { background: #f0f0f0; color: #555; }
    .artifact-card { break-inside: avoid; page-break-inside: avoid; }
    .footer { color: #666; border-top: 1px solid #ccc; }
  }
</style>
<script>
function switchTab(id, btn) {
  document.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
  document.getElementById('tab-' + id).classList.add('active');
  btn.classList.add('active');
}
function filterRisk(risk, btn, scope) {
  var container = scope ? document.getElementById(scope) : document;
  container.querySelectorAll('.finding[data-risk]').forEach(function(f) {
    f.style.display = (risk === 'all' || f.dataset.risk === risk) ? '' : 'none';
  });
  btn.closest('.filter-bar').querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
}
function expandTimeline() {
  document.querySelectorAll('.timeline-extra').forEach(function(el) { el.style.display = 'flex'; });
  var btn = document.getElementById('tl-expand-btn');
  if (btn) btn.style.display = 'none';
}
</script>
</head>
<body>
<div class="header">
  <h1>ECHO NERFADOS <span>SHIELD XDR</span></h1>
  <div class="sub">Investigação Forense Anti-Cheat — Relatório de Screen-Share</div>
  <div class="meta">
    <div><span class="label">Máquina</span><span class="value">{{machineName}}</span></div>
    <div><span class="label">Usuário</span><span class="value">{{currentUser}}</span></div>
    <div><span class="label">Data/Hora</span><span class="value">{{scanTime}}</span></div>
    {{suspectHtml}}
    {{investigatorHtml}}
  </div>
</div>
<div class="score-bar">
  <div class="score-circle">
    <span class="num">{{totalScore}}</span>
    <span class="pts">/ 100</span>
  </div>
  <div>
    <div class="risk-badge">{{riskLabel}}</div>
    <div style="color:#64748b;margin-top:6px;font-size:12px">{{findingsCount}} findings • {{modulesCount}} módulos</div>
  </div>
  <div class="stat-row">
""");

        foreach (var group in result.Findings.GroupBy(f => f.Risk).OrderByDescending(g => g.Key))
        {
            var color = group.Key switch
            {
                RiskLevel.Critical => "#dc2626",
                RiskLevel.High     => "#ea580c",
                RiskLevel.Medium   => "#ca8a04",
                RiskLevel.Low      => "#16a34a",
                _                  => "#475569"
            };
            sb.AppendLine($"""<div class="stat"><div class="n" style="color:{color}">{group.Count()}</div><div class="l">{group.Key}</div></div>""");
        }

        sb.AppendLine("  </div>\n</div>");

        // ── Tab bar ───────────────────────────────────────────────────────────────
        sb.AppendLine("""<div class="tab-bar">""");
        bool firstBtn = true;
        foreach (var tab in visibleTabs)
        {
            var activeClass  = firstBtn ? " active" : "";
            firstBtn = false;
            var count        = TabCount(tab.Id);
            var badgeClass   = string.IsNullOrEmpty(tab.BadgeClass) ? "plain" : tab.BadgeClass;
            var countBadge   = count > 0 ? $"""<span class="tab-count {badgeClass}">{count}</span>""" : "";
            sb.AppendLine($"""  <button class="tab-btn{activeClass}" onclick="switchTab('{tab.Id}',this)">{Esc(tab.Label)}{countBadge}</button>""");
        }
        sb.AppendLine("</div>");

        // ── Tab panels ────────────────────────────────────────────────────────────
        sb.AppendLine("""<div class="tab-panels">""");
        bool firstPane = true;
        foreach (var tab in visibleTabs)
        {
            var activeClass = firstPane ? " active" : "";
            firstPane = false;
            sb.AppendLine($"""<div id="tab-{tab.Id}" class="tab-pane{activeClass}">""");

            switch (tab.Id)
            {
                case "resumo":
                    sb.AppendLine(ExecutiveSummaryHtml(result));
                    break;
                case "cheats":
                    sb.AppendLine(FindingsTabHtml("CHEATS DETECTADOS", TabFindings("cheats"), "cheats", "#dc2626",
                        "Execuções, arquivos e comportamentos de cheats identificados"));
                    break;
                case "diagnostico":
                    sb.AppendLine(ArtifactDossierTabHtml(result));
                    break;
                case "execucoes":
                    sb.AppendLine(FindingsTabHtml("TRILHA DE EXECUÇÃO", TabFindings("execucoes"), "execucoes", "#ea580c",
                        "BAM/DAM · Prefetch · Amcache · UserAssist · ShimCache · Registry Artifacts"));
                    break;
                case "downloads":
                    sb.AppendLine(FindingsTabHtml("DOWNLOADS E FERRAMENTAS EXTERNAS", TabFindings("downloads"), "downloads", "#ca8a04",
                        "Browser Downloads · External Tool Residue"));
                    break;
                case "delecoes":
                    sb.AppendLine(FindingsTabHtml("DELEÇÕES / USN JOURNAL", TabFindings("delecoes"), "delecoes", "#ca8a04",
                        "USN Journal · Recycle Bin — rastros de arquivos deletados"));
                    break;
                case "pastas":
                    sb.AppendLine(FindingsTabHtml("PASTAS ACESSADAS", TabFindings("pastas"), "pastas", "#64748b",
                        "ShellBags · Jump Lists · LNK Recent — navegação de pastas"));
                    break;
                case "memoria":
                    sb.AppendLine(FindingsTabHtml("MEMÓRIA / PROCESSOS", TabFindings("memoria"), "memoria", "#ea580c",
                        "Process Memory — DLLs injetadas, módulos suspeitos em memória"));
                    break;
                case "bypass":
                    sb.AppendLine(FindingsTabHtml("BYPASS / ANTI-FORENSE", TabFindings("bypass"), "bypass", "#dc2626",
                        "Anti-Forensics · System Tampering · Service Tampering — evasão forense"));
                    break;
                case "outros":
                    sb.AppendLine(FindingsTabHtml("OUTROS INDICADORES", TabFindings("outros"), "outros", "#64748b",
                        "System Info · Event Viewer · Defender · Rede · SRUM · File System"));
                    break;
                case "timeline":
                    sb.AppendLine(TimelineTabHtml(allTimed));
                    break;
                case "cobertura":
                    sb.AppendLine(ModuleCoverageTabHtml(result, TabFindings("cobertura")));
                    break;
            }

            sb.AppendLine("</div>");
        }

        sb.AppendLine("</div>"); // tab-panels

        sb.AppendLine($"""
<div class="footer">
  <span>Echo Nerfados Shield XDR v1.0 — Uso Defensivo Autorizado</span>
  <span>Gerado em {DateTime.Now:dd/MM/yyyy HH:mm:ss} | {result.ModulesRun.Count} módulos | {result.Findings.Count} findings</span>
</div>
</body>
</html>
""");

        return sb.ToString();
    }

    // ── Tab content builders ──────────────────────────────────────────────────────

    private static string FindingsTabHtml(
        string heading, List<Finding> findings, string tabId, string headingColor, string? subtitle = null)
    {
        var sb = new StringBuilder();

        var subtitleHtml = subtitle != null ? $"<span>{Esc(subtitle)}</span>" : "";
        sb.AppendLine($"""<div class="tab-heading" style="color:{headingColor}">{Esc(heading)}{subtitleHtml}</div>""");

        if (findings.Count == 0)
        {
            sb.AppendLine("""<div style="color:#475569;font-style:italic;padding:20px 0">Nenhum finding nesta categoria.</div>""");
            return sb.ToString();
        }

        var crit = findings.Count(f => f.Risk == RiskLevel.Critical);
        var high = findings.Count(f => f.Risk == RiskLevel.High);
        var med  = findings.Count(f => f.Risk == RiskLevel.Medium);
        var low  = findings.Count(f => f.Risk == RiskLevel.Low);
        var info = findings.Count(f => f.Risk == RiskLevel.Info);

        sb.AppendLine($"""
<div class="filter-bar">
  <span style="color:#64748b;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px">Filtrar:</span>
  <button class="filter-btn active" onclick="filterRisk('all',this,'tab-{tabId}')">Todos ({findings.Count})</button>
  <button class="filter-btn" onclick="filterRisk('critical',this,'tab-{tabId}')" style="color:#dc2626;border-color:#dc262644">Critical ({crit})</button>
  <button class="filter-btn" onclick="filterRisk('high',this,'tab-{tabId}')" style="color:#ea580c;border-color:#ea580c44">High ({high})</button>
  <button class="filter-btn" onclick="filterRisk('medium',this,'tab-{tabId}')" style="color:#ca8a04;border-color:#ca8a0444">Medium ({med})</button>
  <button class="filter-btn" onclick="filterRisk('low',this,'tab-{tabId}')" style="color:#16a34a;border-color:#16a34a44">Low ({low})</button>
  <button class="filter-btn" onclick="filterRisk('info',this,'tab-{tabId}')">Info ({info})</button>
</div>
""");

        foreach (var moduleGroup in findings.GroupBy(f => f.Module).OrderByDescending(g => g.Max(f => (int)f.Risk)))
        {
            sb.AppendLine($"""<div class="module-group">""");
            sb.AppendLine($"""<div class="module-group-hdr">{Esc(moduleGroup.Key)} <span style="color:#334155;font-size:10px;font-weight:400">({moduleGroup.Count()})</span></div>""");
            foreach (var f in moduleGroup.OrderByDescending(f => f.Risk))
                sb.AppendLine(FindingHtml(f));
            sb.AppendLine("</div>");
        }

        return sb.ToString();
    }

    private static string TimelineTabHtml(List<Finding> allTimed)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"""<div class="tab-heading">LINHA DO TEMPO<span>{allTimed.Count} eventos com timestamp, ordem decrescente</span></div>""");

        if (allTimed.Count == 0)
        {
            sb.AppendLine("""<div style="color:#475569;font-style:italic;padding:20px 0">Nenhum evento com timestamp registrado.</div>""");
            return sb.ToString();
        }

        const int PageSize = 50;
        for (int i = 0; i < allTimed.Count; i++)
        {
            var f = allTimed[i];
            var rColor = f.Risk switch
            {
                RiskLevel.Critical => "#dc2626",
                RiskLevel.High     => "#ea580c",
                RiskLevel.Medium   => "#ca8a04",
                _                  => "#475569"
            };
            var extraClass = i >= PageSize ? " timeline-extra" : "";
            sb.AppendLine($"""
<div class="timeline-item{extraClass}">
  <span class="timeline-ts">{f.Timestamp:dd/MM/yyyy HH:mm:ss}</span>
  <span class="mod-badge">{Esc(f.Module)}</span>
  <span class="badge {f.Risk.ToString().ToLower()}">{Esc(f.RiskLabel)}</span>
  <span style="color:#e2e8f0">{Esc(f.Title)}</span>
</div>
""");
        }

        if (allTimed.Count > PageSize)
            sb.AppendLine($"""<button class="expand-btn" id="tl-expand-btn" onclick="expandTimeline()">Mostrar todos ({allTimed.Count - PageSize} ocultos)</button>""");

        return sb.ToString();
    }

    private static string ModuleCoverageTabHtml(ScanResult result, List<Finding> coverageFindings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("""<div class="tab-heading">COBERTURA E INTEGRIDADE<span>status de execução de cada módulo</span></div>""");

        sb.AppendLine("""
<table>
  <thead>
    <tr><th>Módulo</th><th>Status</th><th>Motivo / Impacto Forense</th></tr>
  </thead>
  <tbody>
""");
        foreach (var entry in result.ModuleCoverage.OrderBy(e => e.Status).ThenBy(e => e.Name))
        {
            var (statusLabel, statusColor) = entry.Status switch
            {
                ModuleStatus.Executed => ("EXECUTADO",  "#28a745"),
                ModuleStatus.Partial  => ("PARCIAL",    "#fd7e14"),
                ModuleStatus.Skipped  => ("PULADO",     "#6c757d"),
                ModuleStatus.Failed   => ("FALHOU",     "#dc3545"),
                _                     => ("AGUARDANDO", "#adb5bd")
            };
            var note = !string.IsNullOrEmpty(entry.Reason)
                ? entry.Reason
                : !string.IsNullOrEmpty(entry.ForensicImpact) ? entry.ForensicImpact : "—";
            sb.AppendLine($"""
    <tr>
      <td>{Esc(entry.Name)}</td>
      <td style="color:{statusColor};font-weight:bold">{statusLabel}</td>
      <td>{Esc(note)}</td>
    </tr>
""");
        }
        sb.AppendLine("  </tbody>\n</table>");

        if (coverageFindings.Count > 0)
        {
            sb.AppendLine($"""<div style="margin-top:20px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">Avisos de cobertura ({coverageFindings.Count})</div>""");
            foreach (var f in coverageFindings.OrderByDescending(f => f.Risk))
                sb.AppendLine(FindingHtml(f));
        }

        return sb.ToString();
    }

    private static string ExecutiveSummaryHtml(ScanResult result)
    {
        var confirmed       = result.Findings.Where(f => f.Category == FindingCategory.Cheat && f.Confidence >= Confidence.High).ToList();
        var strong          = result.Findings.Where(f => f.Risk >= RiskLevel.High && f.Confidence >= Confidence.Medium && f.Category != FindingCategory.Cheat).ToList();
        var needsValidation = result.Findings.Where(f => f.ValidationHint != null).ToList();
        var likelyFp        = result.Findings.Where(f => f.Confidence == Confidence.Low).ToList();
        var correlated      = result.Findings.Where(f => f.RuleId?.StartsWith("CORR_") == true).ToList();

        var sb = new StringBuilder();
        sb.AppendLine("""<div class="tab-heading">RESUMO EXECUTIVO</div>""");
        sb.AppendLine("""<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px">""");

        void Card(string label, string color, int count, string hint) => sb.AppendLine($"""
<div style="background:#1a1a2e;border:1px solid #334155;border-left:4px solid {color};border-radius:8px;padding:12px 16px">
  <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px">{label}</div>
  <div style="font-size:28px;font-weight:800;color:{color};margin:4px 0">{count}</div>
  <div style="font-size:11px;color:#475569">{hint}</div>
</div>
""");

        Card("Cheats confirmados",         "#dc2626", confirmed.Count,       "hash, assinatura ou caminho de cheat verificado");
        Card("Indícios fortes",            "#ea580c", strong.Count,          "High/Critical com média ou alta confiança");
        Card("Requer validação manual",    "#ca8a04", needsValidation.Count, "sinal fraco — investigar antes de concluir");
        Card("Possíveis falsos positivos", "#6b7280", likelyFp.Count,        "nome genérico sem contexto adicional");
        if (correlated.Count > 0)
            Card("Evidências correlacionadas", "#7c3aed", correlated.Count, "padrões detectados entre módulos");

        sb.AppendLine("</div>");

        if (confirmed.Count > 0)
        {
            sb.AppendLine("""<div style="margin-bottom:6px;font-size:13px;font-weight:700;color:#dc2626">Cheats confirmados:</div>""");
            foreach (var f in confirmed.Take(5))
                sb.AppendLine($"""<div style="color:#e2e8f0;font-size:12px;margin:2px 0">• {Esc(f.Title)} <span style="color:#475569">({Esc(f.ConfidenceLabel)})</span></div>""");
        }

        // Category distribution
        sb.AppendLine("""<div style="margin-top:20px;border-top:1px solid #1e293b;padding-top:16px">""");
        sb.AppendLine("""<div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">Distribuição por Categoria</div>""");
        sb.AppendLine("""<div style="display:flex;flex-wrap:wrap;gap:8px;">""");
        foreach (var cat in result.Findings.GroupBy(f => f.Category).OrderByDescending(g => g.Max(f => (int)f.Risk)))
        {
            var maxColor = cat.Max(f => (int)f.Risk) switch
            {
                4 => "#dc2626", 3 => "#ea580c", 2 => "#ca8a04", 1 => "#16a34a", _ => "#475569"
            };
            sb.AppendLine($"""<div style="background:#1e293b;border:1px solid #334155;border-radius:4px;padding:4px 10px;font-size:12px"><span style="color:{maxColor}">{cat.Count()}×</span> <span style="color:#94a3b8">{Esc(cat.First().CategoryLabel)}</span></div>""");
        }
        sb.AppendLine("</div></div>");

        return sb.ToString();
    }

    private static string ArtifactDossierTabHtml(ScanResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"""<div class="tab-heading" style="color:#a78bfa">DIAGNÓSTICO POR ARTEFATO<span>{result.EvidenceBundles.Count} artefatos com sinais cruzados entre módulos</span></div>""");

        foreach (var bundle in result.EvidenceBundles)
        {
            var (verdictClass, verdictBadgeClass, verdictLabel) = bundle.Confidence switch
            {
                Confidence.Confirmed => ("confirmed", "verdict-confirmed", "CONFIRMADO"),
                Confidence.High      => ("strong",    "verdict-strong",    "FORTE INDÍCIO"),
                Confidence.Medium    => ("indicative","verdict-indicative", "INDÍCIO"),
                _                    => ("low-conf",  "verdict-low",       "BAIXA CONFIANÇA")
            };
            var riskCss = bundle.Risk.ToString().ToLower();

            sb.AppendLine($"""<div class="artifact-card {verdictClass}">""");
            sb.AppendLine($"""  <div class="artifact-header">""");
            sb.AppendLine($"""    <span class="verdict-badge {verdictBadgeClass}">{verdictLabel}</span>""");
            sb.AppendLine($"""    <span class="badge {riskCss}">{bundle.Risk.ToString().ToUpper()}</span>""");
            sb.AppendLine($"""    <span class="artifact-name">{Esc(bundle.ArtifactName)}</span>""");
            sb.AppendLine($"""  </div>""");

            if (!string.IsNullOrEmpty(bundle.FullPath))
                sb.AppendLine($"""  <div class="artifact-path">📁 {Esc(bundle.FullPath)}</div>""");

            sb.AppendLine($"""  <div class="artifact-meta">""");
            sb.AppendLine($"""    <span><strong>Origem:</strong> {Esc(bundle.Summary)}</span>""");
            if (!string.IsNullOrEmpty(bundle.Sha256))
                sb.AppendLine($"""    <span><strong>SHA256:</strong> <code>{Esc(bundle.Sha256)}</code></span>""");
            var lastTs = bundle.Timeline.LastOrDefault()?.Timestamp;
            if (lastTs.HasValue)
                sb.AppendLine($"""    <span><strong>Última evidência:</strong> {lastTs:dd/MM/yyyy HH:mm:ss}</span>""");
            sb.AppendLine($"""  </div>""");

            if (bundle.Signals.Count > 0)
            {
                sb.AppendLine($"""  <div class="signals-grid">""");
                foreach (var sig in bundle.Signals)
                {
                    var ts = sig.Timestamp.HasValue ? $" — {sig.Timestamp:dd/MM/yyyy HH:mm:ss}" : "";
                    sb.AppendLine($"""    <div class="signal-item"><span class="signal-mod">[{Esc(sig.SignalType)}] {Esc(sig.SourceModule)}:</span> {Esc(sig.Description)}{Esc(ts)}</div>""");
                }
                sb.AppendLine($"""  </div>""");
            }

            if (bundle.BypassIndicators.Count > 0)
                sb.AppendLine($"""  <div class="bypass-alert">⚡ Bypass próximo: {Esc(string.Join(" | ", bundle.BypassIndicators))}</div>""");
            if (bundle.ValidationSteps.Count > 0)
                sb.AppendLine($"""  <div class="validation-alert">⚠ Validar: {Esc(string.Join(" · ", bundle.ValidationSteps))}</div>""");

            sb.AppendLine("</div>");
        }

        return sb.ToString();
    }

    private static string FindingHtml(Finding f)
    {
        var risk    = f.Risk.ToString().ToLower();
        var hintHtml = f.ValidationHint != null
            ? $"""<div class="finding-hint">⚠ {Esc(f.ValidationHint)}</div>"""
            : "";
        return $"""
<div class="finding {risk}" data-risk="{risk}">
  <div class="finding-header">
    <span class="badge {risk}">{Esc(f.RiskLabel)}</span>
    <span class="mod-badge">{Esc(f.Module)}</span>
    <span class="badge info">{Esc(f.CategoryLabel)}</span>
    <span class="badge conf">{Esc(f.ConfidenceLabel)}</span>
    <span class="finding-title">{Esc(f.Title)}</span>
  </div>
  <div class="finding-detail">{Esc(f.Detail)}</div>
  {(f.Evidence != null ? $"""<div class="finding-evidence">{Esc(f.Evidence)}</div>""" : "")}
  {(f.Timestamp.HasValue ? $"""<div style="color:#475569;font-size:11px;margin-top:4px">🕐 {f.Timestamp:dd/MM/yyyy HH:mm:ss}</div>""" : "")}
  {hintHtml}
</div>
""";
    }

    private static string Esc(string? s) =>
        (s ?? "").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
