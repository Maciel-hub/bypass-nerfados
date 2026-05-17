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

        var riskHex = result.OverallRisk switch
        {
            RiskLevel.Critical => "#ef4444",
            RiskLevel.High     => "#f97316",
            RiskLevel.Medium   => "#eab308",
            RiskLevel.Low      => "#22c55e",
            _                  => "#64748b"
        };

        var machineName      = Esc(result.MachineName);
        var currentUser      = Esc(result.CurrentUser);
        var scanTime         = result.ScanTime.ToString("dd/MM/yyyy HH:mm:ss");
        var totalScore       = result.TotalScore;
        var riskLabel        = result.OverallRiskLabel;
        var findingsCount    = result.Findings.Count;
        var suspectHtml      = config.SuspectName != null
            ? $"""<div class="meta-item"><span class="meta-label">Suspeito</span><span class="meta-val">{Esc(config.SuspectName)}</span></div>"""
            : "";
        var investigatorHtml = config.InvestigatorName != null
            ? $"""<div class="meta-item"><span class="meta-label">Investigador</span><span class="meta-val">{Esc(config.InvestigatorName)}</span></div>"""
            : "";
        var caseIdHtml = config.CaseId != null
            ? $"""<div class="meta-item"><span class="meta-label">Caso</span><span class="meta-val">{Esc(config.CaseId)}</span></div>"""
            : "";
        var machineIdHtml = !string.IsNullOrEmpty(result.MachineId)
            ? $"""<div class="meta-item"><span class="meta-label">Machine ID</span><span class="meta-val">{Esc(result.MachineId)}</span></div>"""
            : "";
        var licenseHtml = result.License != null
            ? $"""<div class="meta-item"><span class="meta-label">Licença</span><span class="meta-val">{Esc(result.License.CustomerId)} ({(result.License.IsWildcard ? "Wildcard QA" : "Machine-bound")}) · Expira: {result.License.ExpiresAt.LocalDateTime:dd/MM/yyyy}</span></div>"""
            : "";

        // Pre-compute tabs
        var byTab    = result.Findings.GroupBy(GetTabId).ToDictionary(g => g.Key, g => g.OrderByDescending(f => f.Risk).ToList());
        var allTimed = result.SortedByTime.ToList();
        var hasBundles = result.EvidenceBundles.Count > 0;

        List<Finding> TabFindings(string id) => byTab.TryGetValue(id, out var l) ? l : [];

        // Strong-evidence set: confirmed hash, high+confidence>=high, or correlated
        var provasFortes = result.Findings
            .Where(f => f.Confidence == Confidence.Confirmed
                     || (f.Risk >= RiskLevel.High && f.Confidence >= Confidence.High)
                     || f.RuleId?.StartsWith("CORR_") == true)
            .OrderByDescending(f => f.Risk).ThenByDescending(f => f.Confidence)
            .ToList();

        var tabDefs = new (string Id, string Label, string BadgeClass)[]
        {
            ("resumo",        "Resumo",         ""),
            ("cheats",        "Cheats",         "danger"),
            ("provas-fortes", "Provas Fortes",  "danger"),
            ("diagnostico",   "Diagnóstico",    "purple"),
            ("execucoes",     "Execuções",      "warn"),
            ("downloads",     "Downloads",      ""),
            ("delecoes",      "Deleções/USN",   ""),
            ("pastas",        "Pastas",         ""),
            ("memoria",       "Memória",        "warn"),
            ("bypass",        "Bypass",         "danger"),
            ("outros",        "Outros",         ""),
            ("timeline",      "Timeline",       ""),
            ("cobertura",     "Cobertura",      ""),
        };

        bool HasTab(string id) => id switch
        {
            "resumo"        => true,
            "diagnostico"   => hasBundles,
            "provas-fortes" => provasFortes.Count > 0,
            "timeline"      => allTimed.Count > 0,
            "cobertura"     => result.ModuleCoverage.Count > 0 || TabFindings("cobertura").Count > 0,
            _               => TabFindings(id).Count > 0
        };

        int TabCount(string id) => id switch
        {
            "resumo"        => result.Findings.Count,
            "diagnostico"   => result.EvidenceBundles.Count,
            "provas-fortes" => provasFortes.Count,
            "timeline"      => allTimed.Count,
            "cobertura"     => result.ModuleCoverage.Count,
            _               => TabFindings(id).Count
        };

        var visibleTabs = tabDefs.Where(t => HasTab(t.Id)).ToList();

        // ── HTML ─────────────────────────────────────────────────────────────────
        sb.Append($$"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Echo Nerfados Shield XDR — Relatório</title>
<style>
:root {
  --bg:       #0b0f14;
  --panel:    #111827;
  --panel-2:  #162033;
  --border:   #1e2d42;
  --border-2: #263244;
  --text:     #e5e7eb;
  --muted:    #8b98aa;
  --dim:      #4b5a6e;
  --critical: #ef4444;
  --high:     #f97316;
  --medium:   #eab308;
  --low:      #22c55e;
  --info:     #64748b;
  --accent:   #7c3aed;
  --sidebar-w: 210px;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; font-size:14px; display:flex; flex-direction:column; min-height:100vh; }
/* Header */
.page-header { background:linear-gradient(135deg,#131c2e,#0f172a); border-bottom:2px solid var(--critical); padding:18px 24px; flex-shrink:0; }
.page-header h1 { font-size:22px; font-weight:800; color:var(--critical); letter-spacing:2px; }
.page-header h1 span { color:#fff; }
.page-header .sub { color:var(--muted); font-size:12px; margin-top:3px; }
.meta-row { display:flex; gap:24px; margin-top:12px; flex-wrap:wrap; }
.meta-item { display:flex; flex-direction:column; }
.meta-label { font-size:10px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }
.meta-val { font-size:13px; font-weight:600; color:var(--text); margin-top:1px; }
/* Score strip */
.score-strip { background:var(--panel); border-bottom:1px solid var(--border); padding:12px 24px; display:flex; align-items:center; gap:20px; flex-wrap:wrap; flex-shrink:0; }
.score-pill { display:flex; align-items:center; gap:10px; }
.score-num { font-size:26px; font-weight:800; color:{{riskHex}}; line-height:1; }
.score-label { font-size:12px; color:var(--muted); }
.risk-chip { padding:4px 12px; border-radius:4px; font-weight:800; font-size:13px; background:{{riskHex}}1a; color:{{riskHex}}; border:1px solid {{riskHex}}44; }
.sev-row { display:flex; gap:10px; flex-wrap:wrap; }
.sev-item { font-size:12px; display:flex; align-items:center; gap:4px; }
.sev-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
/* App shell */
.app-shell { display:flex; flex:1; overflow:hidden; }
/* Sidebar */
.sidebar { width:var(--sidebar-w); flex-shrink:0; background:#0d1117; border-right:1px solid var(--border); display:flex; flex-direction:column; position:sticky; top:0; height:100vh; overflow:hidden; }
.sidebar-search { padding:12px; border-bottom:1px solid var(--border); flex-shrink:0; }
.sidebar-search input { width:100%; background:var(--panel-2); border:1px solid var(--border-2); border-radius:5px; padding:6px 10px; color:var(--text); font-size:12px; outline:none; }
.sidebar-search input::placeholder { color:var(--dim); }
.sidebar-search input:focus { border-color:var(--dim); }
.sidebar-nav { flex:1; overflow-y:auto; padding:6px 0; }
.nav-item { width:100%; display:flex; align-items:center; justify-content:space-between; padding:8px 14px; background:transparent; border:none; color:var(--muted); font-size:12px; font-weight:500; cursor:pointer; text-align:left; border-left:3px solid transparent; transition:background 0.1s,color 0.1s; }
.nav-item:hover { background:var(--panel-2); color:var(--text); }
.nav-item.active { color:var(--text); border-left-color:var(--critical); background:var(--panel-2); font-weight:700; }
.nav-count { font-size:10px; font-weight:700; padding:1px 6px; border-radius:9px; background:var(--panel); color:var(--dim); }
.nav-count.danger { background:#ef444418; color:var(--critical); }
.nav-count.warn   { background:#f9731618; color:var(--high); }
.nav-count.purple { background:#7c3aed18; color:#a78bfa; }
.sidebar-score { padding:14px; border-bottom:1px solid var(--border); flex-shrink:0; }
.sidebar-score .big { font-size:32px; font-weight:800; color:{{riskHex}}; line-height:1; }
.sidebar-score .lbl { font-size:11px; color:var(--muted); margin-top:2px; }
.sidebar-score .chip { display:inline-block; margin-top:6px; padding:2px 10px; border-radius:4px; font-size:11px; font-weight:700; background:{{riskHex}}1a; color:{{riskHex}}; border:1px solid {{riskHex}}33; }
/* Content */
.content { flex:1; overflow-y:auto; overflow-x:hidden; padding:24px 28px; }
.tab-pane { display:none; }
.tab-pane.active { display:block; }
/* Tab heading */
.tab-heading { font-size:14px; font-weight:700; color:var(--muted); text-transform:uppercase; letter-spacing:1px; padding-bottom:10px; border-bottom:1px solid var(--border); margin-bottom:16px; display:flex; align-items:baseline; gap:10px; }
.tab-heading span { font-size:11px; font-weight:400; color:var(--dim); text-transform:none; letter-spacing:0; }
/* Filter bar */
.filter-bar { display:flex; gap:5px; align-items:center; margin-bottom:14px; flex-wrap:wrap; padding:8px 12px; background:var(--panel); border:1px solid var(--border); border-radius:5px; }
.filter-lbl { font-size:10px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; margin-right:4px; }
.filter-btn { padding:2px 10px; border-radius:3px; font-size:11px; font-weight:600; cursor:pointer; border:1px solid var(--border-2); background:transparent; color:var(--dim); transition:background 0.1s; }
.filter-btn:hover,
.filter-btn.active { background:var(--panel-2); color:var(--text); border-color:var(--dim); }
/* Module group */
.module-group { margin-bottom:18px; }
.module-group-hdr { font-size:10px; font-weight:700; color:var(--dim); text-transform:uppercase; letter-spacing:1px; padding:5px 0; border-bottom:1px solid var(--border); margin-bottom:7px; display:flex; align-items:center; gap:6px; }
/* Findings */
.finding { background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:12px 14px; margin-bottom:6px; border-left:3px solid; }
.finding.critical { border-left-color:var(--critical); }
.finding.high     { border-left-color:var(--high); }
.finding.medium   { border-left-color:var(--medium); }
.finding.low      { border-left-color:var(--low); }
.finding.info     { border-left-color:var(--info); }
.finding-hdr { display:flex; align-items:flex-start; gap:6px; flex-wrap:wrap; margin-bottom:5px; }
.badge { padding:1px 7px; border-radius:3px; font-size:10px; font-weight:700; flex-shrink:0; }
.badge.critical { background:#ef444418; color:var(--critical); }
.badge.high     { background:#f9731618; color:var(--high); }
.badge.medium   { background:#eab30818; color:var(--medium); }
.badge.low      { background:#22c55e18; color:var(--low); }
.badge.info     { background:#64748b18; color:var(--info); }
.badge.cat      { background:var(--panel-2); color:var(--dim); border:1px solid var(--border-2); font-size:9px; }
.badge.conf     { background:var(--panel-2); color:var(--dim); border:1px solid var(--border-2); font-size:9px; }
.mod-tag { background:var(--panel-2); border:1px solid var(--border-2); padding:1px 7px; border-radius:3px; font-size:10px; color:var(--muted); flex-shrink:0; }
.finding-title { font-weight:600; color:var(--text); font-size:13px; flex:1; min-width:0; }
.finding-detail { color:var(--muted); font-size:12px; line-height:1.5; white-space:pre-wrap; }
.finding-evidence { background:#0a0f18; border:1px solid var(--border); border-radius:3px; padding:5px 9px; font-family:monospace; font-size:11px; color:var(--dim); margin-top:5px; word-break:break-all; }
.finding-ts { color:var(--dim); font-size:10px; margin-top:3px; font-family:monospace; }
.finding-hint { background:#eab30808; border:1px solid #eab30833; border-radius:3px; padding:5px 9px; font-size:11px; color:#fde68a; margin-top:5px; }
/* Summary cards */
.cards-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:10px; margin-bottom:18px; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:12px 14px; border-left:3px solid; }
.card-label { font-size:10px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }
.card-num { font-size:28px; font-weight:800; margin:4px 0; }
.card-hint { font-size:10px; color:var(--dim); }
/* Artifact dossier */
.dossier-card { background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:14px 16px; margin-bottom:10px; border-left:3px solid var(--accent); }
.dossier-card.confirmed { border-left-color:var(--critical); }
.dossier-card.strong    { border-left-color:var(--high); }
.dossier-card.indicative{ border-left-color:var(--medium); }
.dossier-card.low-conf  { border-left-color:var(--info); }
.dossier-hdr { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:8px; }
.dossier-name { font-weight:700; color:var(--text); font-size:14px; }
.verdict-chip { padding:2px 9px; border-radius:3px; font-size:10px; font-weight:700; }
.vc-confirmed { background:#ef444418; color:var(--critical); }
.vc-strong    { background:#f9731618; color:var(--high); }
.vc-indicative{ background:#eab30818; color:var(--medium); }
.vc-low       { background:#64748b18; color:var(--info); }
.dossier-path { font-family:monospace; font-size:11px; color:var(--dim); margin-bottom:8px; word-break:break-all; }
.dossier-fields { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:6px; margin-bottom:10px; font-size:11px; }
.dossier-field { display:flex; flex-direction:column; gap:2px; }
.dossier-field-label { color:var(--dim); font-size:10px; text-transform:uppercase; letter-spacing:0.5px; }
.dossier-field-val { color:var(--muted); word-break:break-all; }
.signals-list { border-top:1px solid var(--border); padding-top:8px; margin-top:8px; }
.signal-row { display:flex; align-items:baseline; gap:6px; font-size:11px; color:var(--muted); padding:2px 0; border-bottom:1px solid var(--border)11; }
.signal-tag { color:var(--dim); font-size:10px; flex-shrink:0; }
.dossier-alert { background:#ef444408; border:1px solid #ef444428; border-radius:3px; padding:6px 10px; margin-top:6px; font-size:11px; color:#fca5a5; }
.dossier-warn  { background:#eab30808; border:1px solid #eab30828; border-radius:3px; padding:6px 10px; margin-top:4px; font-size:11px; color:#fde68a; }
/* Timeline */
.tl-group { margin-bottom:16px; }
.tl-group-hdr { font-size:11px; font-weight:700; color:var(--dim); padding:4px 0 6px; border-bottom:1px solid var(--border); margin-bottom:6px; font-family:monospace; }
.tl-item { display:flex; gap:10px; padding:5px 0; border-bottom:1px solid var(--border)66; align-items:baseline; }
.tl-time { color:var(--dim); font-family:monospace; font-size:11px; flex-shrink:0; width:50px; }
.tl-mod  { font-size:10px; color:var(--dim); flex-shrink:0; }
.tl-extra { display:none; }
.expand-btn { margin-top:10px; padding:4px 16px; background:var(--panel); border:1px solid var(--border-2); border-radius:4px; color:var(--dim); cursor:pointer; font-size:11px; }
.expand-btn:hover { background:var(--panel-2); color:var(--text); }
/* Table */
table { width:100%; border-collapse:collapse; }
th { text-align:left; padding:7px 10px; background:var(--panel); color:var(--dim); font-size:10px; text-transform:uppercase; letter-spacing:1px; }
td { padding:7px 10px; border-bottom:1px solid var(--border); color:var(--text); font-size:12px; }
tr:hover td { background:var(--panel-2); }
/* Search highlight */
.hl { background:#eab30830; border-radius:2px; }
/* Dist row */
.dist-row { display:flex; flex-wrap:wrap; gap:6px; margin-top:12px; }
.dist-chip { background:var(--panel); border:1px solid var(--border); border-radius:4px; padding:3px 9px; font-size:11px; }
/* Footer */
.page-footer { background:#070b10; border-top:1px solid var(--border); padding:10px 24px; color:var(--dim); font-size:11px; display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px; flex-shrink:0; }
/* Print */
@media print {
  .sidebar { display:none !important; }
  .app-shell { display:block; }
  .tab-pane { display:block !important; page-break-before:always; }
  .tab-pane:first-child { page-break-before:auto; }
  .filter-bar,.expand-btn,.sidebar-search { display:none !important; }
  body { background:#fff; color:#111; }
  .page-header { background:#f0f4f8 !important; }
  .page-header h1 { color:#dc2626; }
  .finding { break-inside:avoid; }
  .dossier-card { break-inside:avoid; }
  .tl-extra { display:flex !important; }
}
/* Responsive */
@media (max-width:700px) {
  .sidebar { display:none; }
  .content { padding:16px; }
}
</style>
<script>
var _activeTab = '{{visibleTabs[0].Id}}';

function showTab(id, btn) {
  document.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(b) { b.classList.remove('active'); });
  document.getElementById('tab-' + id).classList.add('active');
  btn.classList.add('active');
  _activeTab = id;
  // Reset search when switching tabs
  var s = document.getElementById('search-input');
  if (s && s.value) { s.value = ''; globalSearch(''); }
}

function filterRisk(risk, btn, scope) {
  var container = scope ? document.getElementById(scope) : document;
  container.querySelectorAll('.finding[data-risk]').forEach(function(f) {
    var r = f.dataset.risk;
    var show = risk === 'all' || r === risk ||
               (risk === 'highplus' && (r === 'critical' || r === 'high'));
    f.style.display = show ? '' : 'none';
  });
  btn.closest('.filter-bar').querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
}

function globalSearch(term) {
  var q = term.trim().toLowerCase();
  var pane = document.getElementById('tab-' + _activeTab);
  if (!pane) return;

  // Clear previous highlights
  pane.querySelectorAll('.hl').forEach(function(el) {
    el.outerHTML = el.textContent;
  });

  if (!q) {
    pane.querySelectorAll('[data-search]').forEach(function(el) { el.style.display = ''; });
    return;
  }

  pane.querySelectorAll('[data-search]').forEach(function(el) {
    var text = el.dataset.search.toLowerCase();
    el.style.display = text.includes(q) ? '' : 'none';
  });
}

function expandTimeline() {
  document.querySelectorAll('.tl-extra').forEach(function(el) { el.style.display = 'flex'; });
  var btn = document.getElementById('tl-expand-btn');
  if (btn) btn.style.display = 'none';
}

// On load: apply High+ filter to all tabs
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.filter-bar').forEach(function(bar) {
    var btn = bar.querySelector('[data-filter="highplus"]');
    if (btn) btn.click();
  });
});
</script>
</head>
<body>
""");

        // ── Page header ───────────────────────────────────────────────────────────
        sb.Append($$"""
<div class="page-header">
  <h1>ECHO NERFADOS <span>SHIELD XDR</span></h1>
  <div class="sub">Investigação Forense Anti-Cheat — Screen-Share</div>
  <div class="meta-row">
    <div class="meta-item"><span class="meta-label">Máquina</span><span class="meta-val">{{machineName}}</span></div>
    <div class="meta-item"><span class="meta-label">Usuário</span><span class="meta-val">{{currentUser}}</span></div>
    <div class="meta-item"><span class="meta-label">Data/Hora</span><span class="meta-val">{{scanTime}}</span></div>
    {{machineIdHtml}}{{suspectHtml}}{{investigatorHtml}}{{caseIdHtml}}{{licenseHtml}}
  </div>
</div>
""");

        // ── Score strip ───────────────────────────────────────────────────────────
        sb.AppendLine($$"""<div class="score-strip">""");
        sb.AppendLine($$"""  <div class="score-pill"><div class="score-num">{{totalScore}}</div><div class="score-label">/ 100</div></div>""");
        sb.AppendLine($$"""  <div class="risk-chip">{{riskLabel}}</div>""");
        sb.AppendLine($$"""  <div style="color:var(--dim);font-size:12px">{{findingsCount}} findings &bull; {{result.ModulesRun.Count}} módulos</div>""");
        sb.AppendLine("""  <div class="sev-row">""");
        foreach (var group in result.Findings.GroupBy(f => f.Risk).OrderByDescending(g => g.Key))
        {
            var (col, cls) = group.Key switch
            {
                RiskLevel.Critical => ("#ef4444", "critical"),
                RiskLevel.High     => ("#f97316", "high"),
                RiskLevel.Medium   => ("#eab308", "medium"),
                RiskLevel.Low      => ("#22c55e", "low"),
                _                  => ("#64748b", "info")
            };
            sb.AppendLine($"""    <div class="sev-item"><div class="sev-dot" style="background:{col}"></div><span style="color:{col};font-weight:700">{group.Count()}</span><span style="color:var(--dim)">{group.Key}</span></div>""");
        }
        sb.AppendLine("  </div>\n</div>");

        // ── App shell ─────────────────────────────────────────────────────────────
        sb.AppendLine("""<div class="app-shell">""");

        // Sidebar
        sb.AppendLine("""<aside class="sidebar">""");
        sb.AppendLine($$"""
<div class="sidebar-score">
  <div class="big">{{totalScore}}</div>
  <div class="lbl">Score de risco</div>
  <div class="chip">{{riskLabel}}</div>
</div>
<div class="sidebar-search">
  <input id="search-input" type="text" placeholder="Buscar achados..." oninput="globalSearch(this.value)">
</div>
<nav class="sidebar-nav">
""");
        bool firstNavBtn = true;
        foreach (var tab in visibleTabs)
        {
            var count      = TabCount(tab.Id);
            var activeClass = firstNavBtn ? " active" : "";
            firstNavBtn = false;
            var badgeCls   = string.IsNullOrEmpty(tab.BadgeClass) ? "" : tab.BadgeClass;
            var countHtml  = count > 0 ? $"""<span class="nav-count {badgeCls}">{count}</span>""" : "";
            sb.AppendLine($"""  <button class="nav-item{activeClass}" onclick="showTab('{tab.Id}',this)">{Esc(tab.Label)}{countHtml}</button>""");
        }
        sb.AppendLine("</nav>\n</aside>");

        // Content
        sb.AppendLine("""<div class="content">""");
        bool firstPane = true;
        foreach (var tab in visibleTabs)
        {
            var activeClass = firstPane ? " active" : "";
            firstPane = false;
            sb.AppendLine($"""<div id="tab-{tab.Id}" class="tab-pane{activeClass}">""");

            switch (tab.Id)
            {
                case "resumo":        sb.AppendLine(ResumoHtml(result)); break;
                case "cheats":        sb.AppendLine(FindingsTabHtml("CHEATS DETECTADOS",             TabFindings("cheats"),    "cheats",    "var(--critical)", "Execuções, arquivos e comportamentos de cheats identificados")); break;
                case "provas-fortes": sb.AppendLine(ProvasFortesTabHtml(provasFortes, result)); break;
                case "diagnostico":   sb.AppendLine(DossierTabHtml(result)); break;
                case "execucoes":   sb.AppendLine(FindingsTabHtml("TRILHA DE EXECUÇÃO",            TabFindings("execucoes"), "execucoes", "var(--high)",     "BAM/DAM · Prefetch · Amcache · UserAssist · ShimCache · Registry Artifacts")); break;
                case "downloads":   sb.AppendLine(FindingsTabHtml("DOWNLOADS E FERRAMENTAS",       TabFindings("downloads"), "downloads", "var(--medium)",   "Browser Downloads · External Tool Residue")); break;
                case "delecoes":    sb.AppendLine(FindingsTabHtml("DELEÇÕES / USN JOURNAL",        TabFindings("delecoes"),  "delecoes",  "var(--medium)",   "USN Journal · Recycle Bin — rastros de arquivos deletados")); break;
                case "pastas":      sb.AppendLine(FindingsTabHtml("PASTAS ACESSADAS",              TabFindings("pastas"),    "pastas",    "var(--muted)",    "ShellBags · Jump Lists · LNK Recent")); break;
                case "memoria":     sb.AppendLine(FindingsTabHtml("MEMÓRIA / PROCESSOS",           TabFindings("memoria"),   "memoria",   "var(--high)",     "Process Memory — DLLs injetadas, módulos suspeitos")); break;
                case "bypass":        sb.AppendLine(BypassTabHtml(TabFindings("bypass"))); break;
                case "outros":      sb.AppendLine(FindingsTabHtml("OUTROS INDICADORES",            TabFindings("outros"),    "outros",    "var(--muted)",    "System Info · Event Viewer · Defender · Rede · SRUM · File System")); break;
                case "timeline":    sb.AppendLine(TimelineTabHtml(allTimed, config)); break;
                case "cobertura":   sb.AppendLine(CoberturaTabHtml(result, TabFindings("cobertura"))); break;
            }

            sb.AppendLine("</div>");
        }
        sb.AppendLine("</div>"); // content
        sb.AppendLine("</div>"); // app-shell

        sb.AppendLine($"""
<div class="page-footer">
  <span>Echo Nerfados Shield XDR v1.0 — Uso Defensivo Autorizado</span>
  <span>Gerado em {DateTime.Now:dd/MM/yyyy HH:mm:ss} | {result.ModulesRun.Count} módulos | {result.Findings.Count} findings</span>
</div>
</body>
</html>
""");

        return sb.ToString();
    }

    // ── Tab content ───────────────────────────────────────────────────────────────

    private static string FindingsTabHtml(
        string heading, List<Finding> findings, string tabId, string headingColor, string? subtitle = null)
    {
        var sb = new StringBuilder();
        var subtitleHtml = subtitle != null ? $"<span>{Esc(subtitle)}</span>" : "";
        sb.AppendLine($"""<div class="tab-heading" style="color:{headingColor}">{Esc(heading)}{subtitleHtml}</div>""");

        if (findings.Count == 0)
        {
            sb.AppendLine("""<div style="color:var(--dim);padding:20px 0;font-size:13px">Nenhum finding nesta categoria.</div>""");
            return sb.ToString();
        }

        var crit = findings.Count(f => f.Risk == RiskLevel.Critical);
        var high = findings.Count(f => f.Risk == RiskLevel.High);
        var med  = findings.Count(f => f.Risk == RiskLevel.Medium);
        var low  = findings.Count(f => f.Risk == RiskLevel.Low);
        var info = findings.Count(f => f.Risk == RiskLevel.Info);

        sb.AppendLine($"""
<div class="filter-bar">
  <span class="filter-lbl">Filtrar</span>
  <button class="filter-btn" data-filter="highplus" onclick="filterRisk('highplus',this,'tab-{tabId}')">High+ ({crit + high})</button>
  <button class="filter-btn" onclick="filterRisk('all',this,'tab-{tabId}')">Todos ({findings.Count})</button>
  <button class="filter-btn" onclick="filterRisk('critical',this,'tab-{tabId}')" style="color:var(--critical)">Critical ({crit})</button>
  <button class="filter-btn" onclick="filterRisk('high',this,'tab-{tabId}')" style="color:var(--high)">High ({high})</button>
  <button class="filter-btn" onclick="filterRisk('medium',this,'tab-{tabId}')" style="color:var(--medium)">Medium ({med})</button>
  <button class="filter-btn" onclick="filterRisk('low',this,'tab-{tabId}')" style="color:var(--low)">Low ({low})</button>
  <button class="filter-btn" onclick="filterRisk('info',this,'tab-{tabId}')">Info ({info})</button>
</div>
""");

        foreach (var moduleGroup in findings.GroupBy(f => f.Module).OrderByDescending(g => g.Max(f => (int)f.Risk)))
        {
            sb.AppendLine($"""<div class="module-group">""");
            sb.AppendLine($"""<div class="module-group-hdr">{Esc(moduleGroup.Key)}<span style="color:var(--border-2);font-size:10px;font-weight:400"> ({moduleGroup.Count()})</span></div>""");
            foreach (var f in moduleGroup.OrderByDescending(f => f.Risk))
                sb.AppendLine(FindingHtml(f));
            sb.AppendLine("</div>");
        }

        return sb.ToString();
    }

    private static readonly string[] s_fivemKeywords = ["fivem", "gta5", "fivem_gt", "citizenfx", "gtaprocess", "b2372"];

    private static bool IsFiveMRef(Finding f) =>
        s_fivemKeywords.Any(k =>
            (f.Entity ?? f.Title).Contains(k, StringComparison.OrdinalIgnoreCase));

    private static string TimelineTabHtml(List<Finding> allTimed, ScanConfig config)
    {
        var sb = new StringBuilder();

        if (allTimed.Count == 0)
        {
            sb.AppendLine($"""<div class="tab-heading">LINHA DO TEMPO<span>0 eventos</span></div>""");
            sb.AppendLine("""<div style="color:var(--dim);padding:20px 0">Nenhum evento com timestamp.</div>""");
            return sb.ToString();
        }

        // Detect FiveM sessions from anchor events
        var anchorTs = allTimed
            .Where(IsFiveMRef)
            .Select(f => f.Timestamp!.Value)
            .OrderBy(t => t)
            .ToList();

        var sessions = new List<(DateTime WinStart, DateTime WinEnd, DateTime AnchorStart, DateTime AnchorEnd)>();
        if (anchorTs.Count > 0)
        {
            var sStart = anchorTs[0];
            var sEnd   = anchorTs[0];
            for (int i = 1; i < anchorTs.Count; i++)
            {
                if ((anchorTs[i] - sEnd).TotalHours <= 3)
                    sEnd = anchorTs[i];
                else
                {
                    sessions.Add((sStart.AddMinutes(-30), sEnd.AddHours(2), sStart, sEnd));
                    sStart = anchorTs[i];
                    sEnd   = anchorTs[i];
                }
            }
            sessions.Add((sStart.AddMinutes(-30), sEnd.AddHours(2), sStart, sEnd));
        }

        bool useSessions = sessions.Count > 0 &&
            (config.Profile == ScanProfile.FiveM || config.Profile == ScanProfile.Florence || config.Profile == ScanProfile.Default);

        if (!useSessions)
        {
            // Flat chronological view (fast/deep profiles or no FiveM signal)
            sb.AppendLine($"""<div class="tab-heading">LINHA DO TEMPO<span>{allTimed.Count} eventos com timestamp, decrescente</span></div>""");
            RenderFlatTimeline(sb, allTimed);
            return sb.ToString();
        }

        sb.AppendLine($"""<div class="tab-heading">LINHA DO TEMPO — SESSÕES FiveM<span>{sessions.Count} sess{(sessions.Count == 1 ? "ão" : "ões")} detectada{(sessions.Count == 1 ? "" : "s")} · {allTimed.Count} eventos</span></div>""");

        // Assign each event to a session (first matching session wins)
        int SessionIndex(DateTime ts)
        {
            for (int i = 0; i < sessions.Count; i++)
                if (ts >= sessions[i].WinStart && ts <= sessions[i].WinEnd)
                    return i;
            return -1; // outside all sessions
        }

        var buckets = allTimed
            .GroupBy(f => SessionIndex(f.Timestamp!.Value))
            .ToDictionary(g => g.Key, g => g.OrderByDescending(f => f.Timestamp).ToList());

        for (int si = sessions.Count - 1; si >= 0; si--) // oldest session first
        {
            var (winStart, winEnd, ancStart, ancEnd) = sessions[si];
            var label = ancStart.Date == ancEnd.Date
                ? $"Sessão FiveM #{si + 1} — {ancStart:dd/MM HH:mm} até {ancEnd:HH:mm}"
                : $"Sessão FiveM #{si + 1} — {ancStart:dd/MM HH:mm} até {ancEnd:dd/MM HH:mm}";

            sb.AppendLine($"""
<div style="margin:20px 0 8px;padding:10px 14px;background:linear-gradient(90deg,#1e0a0a,var(--panel));border-left:3px solid var(--critical);border-radius:4px;display:flex;align-items:center;gap:10px">
  <span style="color:var(--critical);font-size:13px;font-weight:800">&#9632; {Esc(label)}</span>
  <span style="color:var(--dim);font-size:11px">janela {winStart:HH:mm} → {winEnd:HH:mm}</span>
</div>
""");

            if (!buckets.TryGetValue(si, out var sessionEvents) || sessionEvents.Count == 0)
            {
                sb.AppendLine("""<div style="color:var(--dim);font-size:12px;padding:4px 8px">Nenhum evento nesta janela.</div>""");
                continue;
            }

            // Sub-group: before anchor, during, after anchor
            var before  = sessionEvents.Where(f => f.Timestamp! < ancStart).ToList();
            var during  = sessionEvents.Where(f => f.Timestamp! >= ancStart && f.Timestamp! <= ancEnd).ToList();
            var after   = sessionEvents.Where(f => f.Timestamp! > ancEnd).ToList();

            void SubSection(string title, List<Finding> events, string color)
            {
                if (events.Count == 0) return;
                sb.AppendLine($"""<div style="margin:8px 0 4px;font-size:10px;font-weight:700;color:{color};text-transform:uppercase;letter-spacing:1px">{title} ({events.Count})</div>""");
                foreach (var f in events.OrderByDescending(x => x.Timestamp))
                    sb.AppendLine(TlItem(f));
            }

            SubSection("Antes da sessão",    before, "var(--dim)");
            SubSection("Durante a sessão",   during, "var(--critical)");
            SubSection("Após a sessão",      after,  "var(--high)");
        }

        // Events outside all sessions
        if (buckets.TryGetValue(-1, out var outside) && outside.Count > 0)
        {
            sb.AppendLine($"""
<div style="margin:24px 0 8px;font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:1px;border-top:1px solid var(--border);padding-top:16px">
  Fora das sessões ({outside.Count} eventos)
</div>
""");
            RenderFlatTimeline(sb, outside, maxGroups: 10);
        }

        return sb.ToString();
    }

    private static string TlItem(Finding f)
    {
        var rColor = f.Risk switch
        {
            RiskLevel.Critical => "var(--critical)",
            RiskLevel.High     => "var(--high)",
            RiskLevel.Medium   => "var(--medium)",
            _                  => "var(--dim)"
        };
        return $"""
<div class="tl-item" data-search="{Esc(f.Module + " " + f.Title + " " + f.Detail)}">
  <span class="tl-time">{f.Timestamp!.Value:HH:mm:ss}</span>
  <span class="tl-mod">[{Esc(f.Module)}]</span>
  <span style="color:{rColor};font-size:11px;font-weight:600">{Esc(f.RiskLabel)}</span>
  <span style="color:var(--text);font-size:12px">{Esc(f.Title)}</span>
</div>
""";
    }

    private static void RenderFlatTimeline(StringBuilder sb, List<Finding> events, int maxGroups = 20)
    {
        var groups = events
            .GroupBy(f => f.Timestamp!.Value.ToString("dd/MM/yyyy HH:mm"))
            .OrderByDescending(g => g.Key)
            .ToList();

        for (int gi = 0; gi < groups.Count; gi++)
        {
            var g          = groups[gi];
            var extraClass = gi >= maxGroups ? " tl-extra" : "";
            sb.AppendLine($"""<div class="tl-group{extraClass}">""");
            sb.AppendLine($"""<div class="tl-group-hdr">{Esc(g.Key)}</div>""");
            foreach (var f in g.OrderByDescending(x => x.Risk))
                sb.AppendLine(TlItem(f));
            sb.AppendLine("</div>");
        }

        if (groups.Count > maxGroups)
            sb.AppendLine($"""<button class="expand-btn" id="tl-expand-btn" onclick="expandTimeline()">Mostrar todos ({groups.Count - maxGroups} grupos ocultos, {events.Count - groups.Take(maxGroups).Sum(g => g.Count())} eventos)</button>""");
    }

    private static readonly string[] s_ocultacaoEventIds = ["1102", "104", "3079", "5007", "1116", "1117", "7045"];

    private static string BypassTabHtml(List<Finding> findings)
    {
        var sb = new StringBuilder();

        // Detect critical concealment signals for alert banner
        var alertFindings = findings
            .Where(f => f.Risk >= RiskLevel.High ||
                        s_ocultacaoEventIds.Any(id => f.Detail.Contains(id) || (f.RuleId ?? "").Contains(id) || f.Title.Contains(id)))
            .OrderByDescending(f => f.Risk)
            .ToList();

        if (alertFindings.Count > 0)
        {
            sb.AppendLine($"""
<div style="background:#1a0505;border:1px solid var(--critical);border-radius:6px;padding:14px 18px;margin-bottom:18px">
  <div style="font-size:13px;font-weight:800;color:var(--critical);margin-bottom:8px">&#9888; ALERTA DE OCULTAÇÃO — {alertFindings.Count} sinal{(alertFindings.Count == 1 ? "" : "is")} crítico{(alertFindings.Count == 1 ? "" : "s")} detectado{(alertFindings.Count == 1 ? "" : "s")}</div>
  <div style="display:flex;flex-direction:column;gap:4px">
""");
            foreach (var f in alertFindings.Take(6))
            {
                sb.AppendLine($"""    <div style="font-size:12px;color:var(--muted)">&#8226; [{Esc(f.Module)}] {Esc(f.Title)}</div>""");
            }
            sb.AppendLine("  </div>\n</div>");
        }

        sb.AppendLine(FindingsTabHtml("BYPASS / ANTI-FORENSE", findings, "bypass", "var(--critical)",
            "Anti-Forensics · System Tampering · Service Tampering · Limpeza de Logs · Reconfiguração do Defender"));

        return sb.ToString();
    }

    private static string CoberturaTabHtml(ScanResult result, List<Finding> coverageFindings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("""<div class="tab-heading">COBERTURA E INTEGRIDADE<span>status de execução por módulo</span></div>""");
        sb.AppendLine("""
<table>
  <thead><tr><th>Módulo</th><th>Status</th><th>Motivo / Impacto Forense</th></tr></thead>
  <tbody>
""");
        foreach (var entry in result.ModuleCoverage.OrderBy(e => e.Status).ThenBy(e => e.Name))
        {
            var (statusLabel, statusColor) = entry.Status switch
            {
                ModuleStatus.Executed => ("EXECUTADO", "var(--low)"),
                ModuleStatus.Partial  => ("PARCIAL",   "var(--high)"),
                ModuleStatus.Skipped  => ("PULADO",    "var(--info)"),
                ModuleStatus.Failed   => ("FALHOU",    "var(--critical)"),
                _                     => ("AGUARDANDO","var(--muted)")
            };
            var note = !string.IsNullOrEmpty(entry.Reason)
                ? entry.Reason
                : !string.IsNullOrEmpty(entry.ForensicImpact) ? entry.ForensicImpact : "—";
            sb.AppendLine($"""
    <tr>
      <td>{Esc(entry.Name)}</td>
      <td style="color:{statusColor};font-weight:700;font-size:11px">{statusLabel}</td>
      <td style="color:var(--muted)">{Esc(note)}</td>
    </tr>
""");
        }
        sb.AppendLine("  </tbody>\n</table>");

        if (coverageFindings.Count > 0)
        {
            sb.AppendLine($"""<div style="margin-top:18px;font-size:10px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Avisos de cobertura ({coverageFindings.Count})</div>""");
            foreach (var f in coverageFindings.OrderByDescending(f => f.Risk))
                sb.AppendLine(FindingHtml(f));
        }

        return sb.ToString();
    }

    private static string ResumoHtml(ScanResult result)
    {
        var confirmed       = result.Findings.Where(f => f.Category == FindingCategory.Cheat && f.Confidence >= Confidence.High).ToList();
        var strong          = result.Findings.Where(f => f.Risk >= RiskLevel.High && f.Confidence >= Confidence.Medium && f.Category != FindingCategory.Cheat).ToList();
        var needsValidation = result.Findings.Where(f => f.ValidationHint != null).ToList();
        var likelyFp        = result.Findings.Where(f => f.Confidence == Confidence.Low).ToList();
        var correlated      = result.Findings.Where(f => f.RuleId?.StartsWith("CORR_") == true).ToList();

        var sb = new StringBuilder();
        sb.AppendLine("""<div class="tab-heading">RESUMO EXECUTIVO</div>""");
        sb.AppendLine("""<div class="cards-grid">""");

        void Card(string label, string color, int count, string hint) => sb.AppendLine($"""
<div class="card" style="border-left-color:{color}">
  <div class="card-label">{label}</div>
  <div class="card-num" style="color:{color}">{count}</div>
  <div class="card-hint">{hint}</div>
</div>
""");

        Card("Cheats confirmados",         "var(--critical)", confirmed.Count,       "hash, assinatura ou caminho verificado");
        Card("Indícios fortes",            "var(--high)",     strong.Count,          "High/Critical com confiança média ou alta");
        Card("Requer validação manual",    "var(--medium)",   needsValidation.Count, "sinal fraco — investigar antes de concluir");
        Card("Possíveis falsos positivos", "var(--info)",     likelyFp.Count,        "nome genérico sem contexto adicional");
        if (correlated.Count > 0)
            Card("Evidências correlacionadas", "var(--accent)", correlated.Count, "padrões cruzados entre módulos");

        sb.AppendLine("</div>");

        if (confirmed.Count > 0)
        {
            sb.AppendLine("""<div style="margin-bottom:4px;font-size:12px;font-weight:700;color:var(--critical)">Cheats confirmados:</div>""");
            foreach (var f in confirmed.Take(5))
                sb.AppendLine($"""<div style="color:var(--muted);font-size:12px;margin:2px 0">&bull; {Esc(f.Title)} <span style="color:var(--dim)">({Esc(f.ConfidenceLabel)})</span></div>""");
        }

        // ── Score breakdown ───────────────────────────────────────────────────
        var elig = result.Findings.Where(f => f.ScoreEligible).ToList();
        static string Fmt(double v) => v > 0 ? $"+{(int)Math.Min(v, 99.9)}" : "—";

        var bkConfirmed = elig.Where(f => f.Confidence == Confidence.Confirmed).Sum(f => f.WeightedScore);
        var bkCorr      = elig.Where(f => f.RuleId?.StartsWith("CORR_") == true && f.Confidence != Confidence.Confirmed).Sum(f => f.WeightedScore);
        var bkBypass    = elig.Where(f => f.Category == FindingCategory.AntiForensics
                                       && f.Confidence != Confidence.Confirmed
                                       && f.RuleId?.StartsWith("CORR_") != true).Sum(f => f.WeightedScore);
        var bkHigh      = elig.Where(f => f.Risk >= RiskLevel.High
                                       && f.Confidence != Confidence.Confirmed
                                       && f.RuleId?.StartsWith("CORR_") != true
                                       && f.Category != FindingCategory.AntiForensics).Sum(f => f.WeightedScore);
        var bkOther     = elig.Where(f => f.Risk < RiskLevel.High
                                       && f.Confidence != Confidence.Confirmed
                                       && f.RuleId?.StartsWith("CORR_") != true
                                       && f.Category != FindingCategory.AntiForensics).Sum(f => f.WeightedScore);
        var rawTotal    = result.Findings.Sum(f => f.WeightedScore);
        var filtered    = result.FilteredCount;

        sb.AppendLine("""<div style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">""");
        sb.AppendLine($"""<div style="font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">Por que {result.TotalScore}/100?</div>""");
        sb.AppendLine("""<div style="display:flex;flex-direction:column;gap:4px;max-width:500px">""");

        void BkRow(string label, double val, string color) => sb.AppendLine($"""
<div style="display:flex;justify-content:space-between;font-size:12px;padding:4px 8px;border-radius:4px;background:var(--panel)">
  <span style="color:var(--muted)">{label}</span>
  <span style="color:{color};font-weight:700;font-family:monospace">{Fmt(val)}</span>
</div>
""");

        BkRow("Confirmados por hash / assinatura",    bkConfirmed, "var(--critical)");
        BkRow("Correlações cruzadas entre módulos",   bkCorr,      "var(--accent)");
        BkRow("Anti-forense / bypass",                bkBypass,    "var(--high)");
        BkRow("High/Critical (outros)",               bkHigh,      "var(--high)");
        BkRow("Sinais elegíveis restantes",           bkOther,     "var(--medium)");

        sb.AppendLine($"""
<div style="display:flex;justify-content:space-between;font-size:11px;padding:4px 8px;border-top:1px solid var(--border);margin-top:4px;color:var(--dim)">
  <span>Ruído filtrado (Medium + Baixa confiança sem correlação)</span>
  <span>{filtered} achados — não computados</span>
</div>
<div style="display:flex;justify-content:space-between;font-size:11px;padding:4px 8px;color:var(--dim)">
  <span>Score bruto (sem cap)</span>
  <span style="font-family:monospace">{(int)rawTotal} → limitado a 100</span>
</div>
""");
        sb.AppendLine("</div></div>");

        // ── Category distribution ─────────────────────────────────────────────
        sb.AppendLine("""<div style="margin-top:18px;border-top:1px solid var(--border);padding-top:14px">""");
        sb.AppendLine("""<div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Distribuição por categoria</div>""");
        sb.AppendLine("""<div class="dist-row">""");
        foreach (var cat in result.Findings.GroupBy(f => f.Category).OrderByDescending(g => g.Max(f => (int)f.Risk)))
        {
            var maxColor = cat.Max(f => (int)f.Risk) switch
            {
                4 => "var(--critical)", 3 => "var(--high)", 2 => "var(--medium)", 1 => "var(--low)", _ => "var(--info)"
            };
            sb.AppendLine($"""<div class="dist-chip"><span style="color:{maxColor};font-weight:700">{cat.Count()}&times;</span> <span style="color:var(--muted)">{Esc(cat.First().CategoryLabel)}</span></div>""");
        }
        sb.AppendLine("</div></div>");

        return sb.ToString();
    }

    private static string ProvasFortesTabHtml(List<Finding> findings, ScanResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"""<div class="tab-heading" style="color:var(--critical)">PROVAS FORTES<span>{findings.Count} achados acionáveis — hash confirmado, alta confiança ou correlação cruzada</span></div>""");

        if (findings.Count == 0)
        {
            sb.AppendLine("""<div style="color:var(--dim);padding:20px 0">Nenhuma prova forte encontrada neste scan.</div>""");
            return sb.ToString();
        }

        // Group by evidence type
        var byHash   = findings.Where(f => f.Confidence == Confidence.Confirmed).ToList();
        var byCorr   = findings.Where(f => f.RuleId?.StartsWith("CORR_") == true && f.Confidence != Confidence.Confirmed).ToList();
        var byHigh   = findings.Where(f => f.Confidence != Confidence.Confirmed && f.RuleId?.StartsWith("CORR_") != true).ToList();

        void Section(string title, string color, List<Finding> items)
        {
            if (items.Count == 0) return;
            sb.AppendLine($"""<div style="margin-bottom:6px;font-size:11px;font-weight:700;color:{color};text-transform:uppercase;letter-spacing:1px;padding:8px 0 4px;border-bottom:1px solid var(--border)">{title} ({items.Count})</div>""");
            foreach (var f in items)
                sb.AppendLine(FindingHtml(f));
            sb.AppendLine("""<div style="margin-bottom:16px"></div>""");
        }

        Section("Confirmados por hash / assinatura",  "var(--critical)", byHash);
        Section("Correlações cruzadas entre módulos", "var(--accent)",   byCorr);
        Section("High/Critical — alta confiança",     "var(--high)",     byHigh);

        // Cross-reference with dossiers that have bypass indicators
        var withBypass = result.EvidenceBundles
            .Where(b => b.BypassIndicators.Count > 0)
            .Take(5).ToList();
        if (withBypass.Count > 0)
        {
            sb.AppendLine($"""<div style="margin-top:18px;font-size:11px;font-weight:700;color:var(--critical);text-transform:uppercase;letter-spacing:1px;padding-bottom:4px;border-bottom:1px solid var(--border)">Dossiês com tentativa de ocultação ({withBypass.Count})</div>""");
            foreach (var b in withBypass)
            {
                sb.AppendLine($"""<div style="margin:8px 0;padding:8px 10px;background:var(--panel);border-left:3px solid var(--critical);border-radius:4px">""");
                sb.AppendLine($"""  <div style="font-weight:700;color:var(--text)">{Esc(b.ArtifactName)}</div>""");
                sb.AppendLine($"""  <div style="font-size:11px;color:var(--critical);margin-top:3px">{Esc(b.BypassIndicators[0])}</div>""");
                if (!string.IsNullOrEmpty(b.FullPath))
                    sb.AppendLine($"""  <div style="font-family:monospace;font-size:11px;color:var(--dim);margin-top:2px">{Esc(b.FullPath)}</div>""");
                sb.AppendLine("</div>");
            }
        }

        return sb.ToString();
    }

    private static string DossierTabHtml(ScanResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"""<div class="tab-heading" style="color:var(--accent)">DIAGNÓSTICO POR ARTEFATO<span>{result.EvidenceBundles.Count} artefatos analisados</span></div>""");

        foreach (var bundle in result.EvidenceBundles)
        {
            var (cardClass, chipClass, verdictLabel) = bundle.Confidence switch
            {
                Confidence.Confirmed => ("confirmed", "vc-confirmed", "CONFIRMADO"),
                Confidence.High      => ("strong",    "vc-strong",    "FORTE INDÍCIO"),
                Confidence.Medium    => ("indicative","vc-indicative", "INDÍCIO"),
                _                    => ("low-conf",  "vc-low",       "BAIXA CONFIANÇA")
            };
            var riskCss = bundle.Risk.ToString().ToLower();

            var searchTerms = Esc($"{bundle.ArtifactName} {bundle.FullPath} {bundle.Summary} {bundle.Sha256}");
            sb.AppendLine($"""<div class="dossier-card {cardClass}" data-search="{searchTerms}">""");
            sb.AppendLine($"""  <div class="dossier-hdr">""");
            sb.AppendLine($"""    <span class="verdict-chip {chipClass}">{verdictLabel}</span>""");
            sb.AppendLine($"""    <span class="badge {riskCss}">{bundle.Risk.ToString().ToUpper()}</span>""");
            sb.AppendLine($"""    <span class="dossier-name">{Esc(bundle.ArtifactName)}</span>""");
            sb.AppendLine($"""  </div>""");

            if (!string.IsNullOrEmpty(bundle.FullPath))
                sb.AppendLine($"""  <div class="dossier-path">{Esc(bundle.FullPath)}</div>""");

            // Structured fields
            sb.AppendLine("""  <div class="dossier-fields">""");
            sb.AppendLine($"""    <div class="dossier-field"><span class="dossier-field-label">Origem</span><span class="dossier-field-val">{Esc(bundle.Summary)}</span></div>""");
            if (!string.IsNullOrEmpty(bundle.Sha256))
                sb.AppendLine($"""    <div class="dossier-field"><span class="dossier-field-label">SHA256</span><span class="dossier-field-val" style="font-family:monospace;font-size:10px">{Esc(bundle.Sha256)}</span></div>""");
            var lastTs = bundle.Timeline.LastOrDefault()?.Timestamp;
            if (lastTs.HasValue)
                sb.AppendLine($"""    <div class="dossier-field"><span class="dossier-field-label">Última evidência</span><span class="dossier-field-val" style="font-family:monospace">{lastTs:dd/MM/yyyy HH:mm:ss}</span></div>""");
            sb.AppendLine("""  </div>""");

            if (bundle.Signals.Count > 0)
            {
                sb.AppendLine("""  <div class="signals-list">""");
                foreach (var sig in bundle.Signals)
                {
                    var ts = sig.Timestamp.HasValue ? $" — {sig.Timestamp:HH:mm:ss}" : "";
                    sb.AppendLine($"""    <div class="signal-row"><span class="signal-tag">[{Esc(sig.SignalType)}] {Esc(sig.SourceModule)}</span><span style="color:var(--muted)">{Esc(sig.Description)}{Esc(ts)}</span></div>""");
                }
                sb.AppendLine("""  </div>""");
            }

            if (bundle.BypassIndicators.Count > 0)
                sb.AppendLine($"""  <div class="dossier-alert">Bypass detectado: {Esc(string.Join(" | ", bundle.BypassIndicators))}</div>""");
            if (bundle.ValidationSteps.Count > 0)
                sb.AppendLine($"""  <div class="dossier-warn">Validar: {Esc(string.Join(" · ", bundle.ValidationSteps))}</div>""");

            sb.AppendLine("</div>");
        }

        return sb.ToString();
    }

    private static string FindingHtml(Finding f)
    {
        var risk    = f.Risk.ToString().ToLower();
        var hintHtml = f.ValidationHint != null
            ? $"""<div class="finding-hint">{Esc(f.ValidationHint)}</div>"""
            : "";
        var searchVal = Esc($"{f.Module} {f.Title} {f.Detail} {f.Evidence} {f.Entity}");
        return $"""
<div class="finding {risk}" data-risk="{risk}" data-search="{searchVal}">
  <div class="finding-hdr">
    <span class="badge {risk}">{Esc(f.RiskLabel)}</span>
    <span class="mod-tag">{Esc(f.Module)}</span>
    <span class="badge cat">{Esc(f.CategoryLabel)}</span>
    <span class="badge conf">{Esc(f.ConfidenceLabel)}</span>
    <span class="finding-title">{Esc(f.Title)}</span>
  </div>
  <div class="finding-detail">{Esc(f.Detail)}</div>
  {(f.Evidence != null ? $"""<div class="finding-evidence">{Esc(f.Evidence)}</div>""" : "")}
  {(f.Timestamp.HasValue ? $"""<div class="finding-ts">{f.Timestamp:dd/MM/yyyy HH:mm:ss}</div>""" : "")}
  {hintHtml}
</div>
""";
    }

    private static string Esc(string? s) =>
        (s ?? "").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
