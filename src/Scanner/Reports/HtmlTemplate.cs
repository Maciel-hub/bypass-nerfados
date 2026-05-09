using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;
using System.Text;

namespace BypassNerfados.Scanner.Reports;

public static class HtmlTemplate
{
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

        // Pre-extract complex expressions so they can be used in $$""" raw strings
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

        // $$""" raw string: CSS braces are literal { }, C# interpolations use {{ }}
        sb.Append($$"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bypass Nerfados Shield XDR — Relatório</title>
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
  .score-bar { background: #1e293b; border-bottom: 1px solid #334155; padding: 20px 32px; display: flex; align-items: center; gap: 32px; }
  .score-circle { width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-direction: column; border: 4px solid {{riskColor}}; background: #0f172a; flex-shrink: 0; }
  .score-circle .num { font-size: 24px; font-weight: 800; color: {{riskColor}}; }
  .score-circle .pts { font-size: 10px; color: #64748b; }
  .risk-badge { padding: 6px 16px; border-radius: 6px; font-weight: 800; font-size: 16px; background: {{riskColor}}22; color: {{riskColor}}; border: 1px solid {{riskColor}}44; }
  .stat-row { display: flex; gap: 16px; flex-wrap: wrap; }
  .stat { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px 20px; text-align: center; min-width: 80px; }
  .stat .n { font-size: 22px; font-weight: 700; }
  .stat .l { font-size: 11px; color: #64748b; text-transform: uppercase; margin-top: 2px; }
  .content { padding: 24px 32px; }
  .section { margin-bottom: 32px; }
  .section-title { font-size: 16px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #1e293b; }
  .finding { background: #1a1a2e; border: 1px solid #334155; border-radius: 8px; padding: 14px 16px; margin-bottom: 8px; border-left: 4px solid; }
  .finding.critical { border-left-color: #dc2626; }
  .finding.high { border-left-color: #ea580c; }
  .finding.medium { border-left-color: #ca8a04; }
  .finding.low { border-left-color: #16a34a; }
  .finding.info { border-left-color: #475569; }
  .finding-header { display: flex; align-items: flex-start; gap: 10px; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; flex-shrink: 0; }
  .badge.critical { background: #dc262622; color: #dc2626; }
  .badge.high { background: #ea580c22; color: #ea580c; }
  .badge.medium { background: #ca8a0422; color: #ca8a04; }
  .badge.low { background: #16a34a22; color: #16a34a; }
  .badge.info { background: #47556922; color: #94a3b8; }
  .mod-badge { background: #0f172a; border: 1px solid #334155; padding: 2px 8px; border-radius: 4px; font-size: 11px; color: #64748b; flex-shrink: 0; }
  .finding-title { font-weight: 700; color: #e2e8f0; font-size: 14px; }
  .finding-detail { color: #94a3b8; font-size: 13px; margin-top: 6px; line-height: 1.5; white-space: pre-wrap; }
  .finding-evidence { background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px 10px; font-family: monospace; font-size: 12px; color: #64748b; margin-top: 6px; }
  .timeline-item { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid #1e293b; align-items: flex-start; }
  .timeline-ts { color: #475569; font-family: monospace; font-size: 12px; flex-shrink: 0; width: 145px; }
  .timeline-mod { color: #64748b; font-size: 11px; flex-shrink: 0; width: 100px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; background: #1e293b; color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  td { padding: 8px 12px; border-bottom: 1px solid #1e293b; color: #e2e8f0; font-size: 13px; }
  tr:hover td { background: #1e293b44; }
  .footer { background: #0a0a0f; border-top: 1px solid #1e293b; padding: 16px 32px; color: #334155; font-size: 12px; display: flex; justify-content: space-between; }
</style>
</head>
<body>
<div class="header">
  <h1>BYPASS NERFADOS <span>SHIELD XDR</span></h1>
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

        sb.AppendLine("  </div>\n</div>\n<div class=\"content\">");

        // Executive summary
        sb.AppendLine(ExecutiveSummaryHtml(result));

        // Cheat section first
        var cheats = result.Findings.Where(f => f.Category == FindingCategory.Cheat).ToList();
        if (cheats.Count > 0)
        {
            sb.AppendLine($"""
<div class="section">
<div class="section-title" style="color:#dc2626">⚠ CHEATS DETECTADOS ({cheats.Count})</div>
""");
            foreach (var f in cheats)
                sb.AppendLine(FindingHtml(f));
            sb.AppendLine("</div>");
        }

        // Anti-forensics
        var antiForensics = result.Findings
            .Where(f => f.Category is FindingCategory.AntiForensics or FindingCategory.SystemTampering or FindingCategory.ServiceTampering)
            .Where(f => f.Risk >= RiskLevel.High)
            .ToList();
        if (antiForensics.Count > 0)
        {
            sb.AppendLine($"""
<div class="section">
<div class="section-title" style="color:#ea580c">ADULTERAÇÃO DO SISTEMA / ANTI-FORENSE ({antiForensics.Count})</div>
""");
            foreach (var f in antiForensics)
                sb.AppendLine(FindingHtml(f));
            sb.AppendLine("</div>");
        }

        // All other findings
        var others = result.Findings
            .Where(f => f.Category != FindingCategory.Cheat &&
                        !(f.Category is FindingCategory.AntiForensics or FindingCategory.SystemTampering or FindingCategory.ServiceTampering && f.Risk >= RiskLevel.High))
            .OrderByDescending(f => f.Risk)
            .ToList();

        if (others.Count > 0)
        {
            sb.AppendLine($"""
<div class="section">
<div class="section-title">OUTROS FINDINGS ({others.Count})</div>
""");
            foreach (var f in others)
                sb.AppendLine(FindingHtml(f));
            sb.AppendLine("</div>");
        }

        // Timeline
        var timedFindings = result.SortedByTime.Take(50).ToList();
        if (timedFindings.Count > 0)
        {
            sb.AppendLine($"""
<div class="section">
<div class="section-title">TIMELINE ({timedFindings.Count} eventos)</div>
""");
            foreach (var f in timedFindings)
            {
                var rColor = f.Risk switch
                {
                    RiskLevel.Critical => "#dc2626",
                    RiskLevel.High     => "#ea580c",
                    RiskLevel.Medium   => "#ca8a04",
                    _                  => "#475569"
                };
                sb.AppendLine($"""
<div class="timeline-item">
  <span class="timeline-ts">{f.Timestamp:dd/MM/yyyy HH:mm:ss}</span>
  <span class="mod-badge">{Esc(f.Module)}</span>
  <span class="badge {f.Risk.ToString().ToLower()}">{f.RiskLabel}</span>
  <span style="color:#e2e8f0">{Esc(f.Title)}</span>
</div>
""");
            }
            sb.AppendLine("</div>");
        }

        sb.AppendLine($"""
</div>
<div class="footer">
  <span>Bypass Nerfados Shield XDR v1.0 — Uso Defensivo Autorizado</span>
  <span>Gerado em {DateTime.Now:dd/MM/yyyy HH:mm:ss} | {result.ModulesRun.Count} módulos | {result.Findings.Count} findings</span>
</div>
</body>
</html>
""");

        return sb.ToString();
    }

    private static string ExecutiveSummaryHtml(ScanResult result)
    {
        var confirmed = result.Findings
            .Where(f => f.Category == FindingCategory.Cheat && f.Confidence >= Confidence.High)
            .ToList();
        var strong = result.Findings
            .Where(f => f.Risk >= RiskLevel.High && f.Confidence >= Confidence.Medium && f.Category != FindingCategory.Cheat)
            .ToList();
        var needsValidation = result.Findings
            .Where(f => f.ValidationHint != null)
            .ToList();
        var likelyFp = result.Findings
            .Where(f => f.Confidence == Confidence.Low)
            .ToList();
        var correlated = result.Findings
            .Where(f => f.RuleId?.StartsWith("CORR_") == true)
            .ToList();

        var sb = new StringBuilder();
        sb.AppendLine("""<div class="section"><div class="section-title" style="color:#94a3b8">RESUMO EXECUTIVO</div>""");
        sb.AppendLine("""<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:8px">""");

        void Card(string label, string color, IList<Finding> items, string hint)
        {
            sb.AppendLine($"""
<div style="background:#1a1a2e;border:1px solid #334155;border-left:4px solid {color};border-radius:8px;padding:12px 16px">
  <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px">{label}</div>
  <div style="font-size:28px;font-weight:800;color:{color};margin:4px 0">{items.Count}</div>
  <div style="font-size:11px;color:#475569">{hint}</div>
</div>
""");
        }

        Card("Cheats confirmados",      "#dc2626", confirmed,       "hash ou caminho GOSTH verificado");
        Card("Indícios fortes",         "#ea580c", strong,          "High/Critical com média confiança");
        Card("Requer validação manual", "#ca8a04", needsValidation, "sinal fraco — investigar antes de concluir");
        Card("Possíveis falsos positivos", "#6b7280", likelyFp,     "nome genérico sem contexto adicional");
        if (correlated.Count > 0)
            Card("Evidências correlacionadas", "#7c3aed", correlated, "padrões detectados entre módulos");

        sb.AppendLine("</div>");

        if (confirmed.Count > 0)
        {
            sb.AppendLine("""<div style="margin-top:12px;font-size:13px;font-weight:700;color:#dc2626">Cheats confirmados:</div>""");
            foreach (var f in confirmed.Take(5))
                sb.AppendLine($"""<div style="color:#e2e8f0;font-size:12px;margin:2px 0">• {Esc(f.Title)} <span style="color:#475569">({f.ConfidenceLabel})</span></div>""");
        }

        sb.AppendLine("</div>");
        return sb.ToString();
    }

    private static string FindingHtml(Finding f)
    {
        var risk = f.Risk.ToString().ToLower();
        return $"""
<div class="finding {risk}">
  <div class="finding-header">
    <span class="badge {risk}">{Esc(f.RiskLabel)}</span>
    <span class="mod-badge">{Esc(f.Module)}</span>
    <span class="badge info">{Esc(f.CategoryLabel)}</span>
    <span class="finding-title">{Esc(f.Title)}</span>
  </div>
  <div class="finding-detail">{Esc(f.Detail)}</div>
  {(f.Evidence != null ? $"""<div class="finding-evidence">{Esc(f.Evidence)}</div>""" : "")}
  {(f.Timestamp.HasValue ? $"""<div style="color:#475569;font-size:11px;margin-top:4px">🕐 {f.Timestamp:dd/MM/yyyy HH:mm:ss}</div>""" : "")}
</div>
""";
    }

    private static string Esc(string? s) =>
        (s ?? "").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
