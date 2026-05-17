using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;
using System.Text;

namespace BypassNerfados.Scanner.Reports;

public static class ExecutiveTemplate
{
    private static string Esc(string? s) =>
        System.Web.HttpUtility.HtmlEncode(s ?? "");

    public static string Build(ScanResult result, ScanConfig config, string? manifestHash = null)
    {
        var riskHex = result.OverallRisk switch
        {
            RiskLevel.Critical => "#ef4444",
            RiskLevel.High     => "#f97316",
            RiskLevel.Medium   => "#eab308",
            RiskLevel.Low      => "#22c55e",
            _                  => "#64748b"
        };

        var provasFortes = result.Findings
            .Where(f => f.Confidence == Confidence.Confirmed
                     || (f.Risk >= RiskLevel.High && f.Confidence >= Confidence.High)
                     || f.RuleId?.StartsWith("CORR_") == true)
            .OrderByDescending(f => f.Risk).ThenByDescending(f => f.Confidence)
            .Take(5).ToList();

        var topTimeline = result.SortedByTime
            .Where(f => f.Risk >= RiskLevel.High)
            .Take(10).ToList();

        var bypassAlerts = result.BypassFindings
            .OrderByDescending(f => f.Risk).Take(8).ToList();

        var executed = result.ModuleCoverage.Count(m => m.Status == ModuleStatus.Executed);
        var partial  = result.ModuleCoverage.Count(m => m.Status == ModuleStatus.Partial);
        var skipped  = result.ModuleCoverage.Count(m => m.Status == ModuleStatus.Skipped);
        var failed   = result.ModuleCoverage.Count(m => m.Status == ModuleStatus.Failed);

        var sb = new StringBuilder();
        sb.Append($$"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Echo Nerfados — Relatório Executivo</title>
<style>
* { margin:0;padding:0;box-sizing:border-box; }
body { background:#fff;color:#111;font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;max-width:900px;margin:0 auto;padding:24px; }
@media print { body { padding:12px; } .no-print { display:none; } }
.hdr { border-bottom:3px solid {{riskHex}};padding-bottom:14px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:flex-end; }
.hdr-title { font-size:20px;font-weight:800;color:#111;letter-spacing:1px; }
.hdr-title span { color:{{riskHex}}; }
.hdr-meta { text-align:right;font-size:11px;color:#555;line-height:1.8; }
.verdict { display:flex;align-items:center;gap:20px;background:#f8f8f8;border:2px solid {{riskHex}};border-radius:8px;padding:16px 20px;margin-bottom:20px; }
.verdict-score { font-size:40px;font-weight:900;color:{{riskHex}};line-height:1; }
.verdict-label { font-size:22px;font-weight:800;color:{{riskHex}}; }
.verdict-sub { font-size:12px;color:#666;margin-top:4px; }
.verdict-stats { margin-left:auto;text-align:right;font-size:12px;color:#555;line-height:1.8; }
.section { margin-bottom:20px; }
.section-title { font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:#333;border-bottom:1px solid #ddd;padding-bottom:4px;margin-bottom:10px; }
.proof-row { display:flex;gap:8px;align-items:baseline;padding:5px 0;border-bottom:1px solid #f0f0f0; }
.proof-num { font-size:12px;font-weight:700;color:#999;width:18px;flex-shrink:0; }
.badge { display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700;flex-shrink:0; }
.badge-critical { background:#fef2f2;color:#ef4444;border:1px solid #fecaca; }
.badge-high { background:#fff7ed;color:#f97316;border:1px solid #fed7aa; }
.badge-medium { background:#fefce8;color:#ca8a04;border:1px solid #fef08a; }
.badge-conf { background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0; }
.proof-title { font-size:12px;color:#111;flex:1; }
.proof-mod { font-size:11px;color:#888; }
.tl-row { display:flex;gap:8px;padding:4px 0;border-bottom:1px solid #f5f5f5;align-items:baseline; }
.tl-ts { font-family:monospace;font-size:11px;color:#888;width:140px;flex-shrink:0; }
.tl-mod { font-size:11px;color:#888; }
.bypass-row { padding:5px 8px;border-left:3px solid #ef4444;margin-bottom:4px;background:#fef2f2;border-radius:0 4px 4px 0; }
.bypass-row-high { border-left-color:#f97316;background:#fff7ed; }
.coverage { display:flex;gap:12px;font-size:12px; }
.cov-num { font-size:20px;font-weight:800;line-height:1; }
.cov-lbl { font-size:10px;color:#888;text-transform:uppercase; }
.footer { margin-top:24px;padding-top:12px;border-top:1px solid #ddd;font-size:11px;color:#888;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px; }
.hash-box { background:#f8f8f8;border:1px solid #ddd;border-radius:4px;padding:6px 10px;font-family:monospace;font-size:10px;word-break:break-all;color:#555; }
</style>
</head>
<body>

<div class="hdr">
  <div>
    <div class="hdr-title">ECHO <span>NERFADOS</span> SHIELD XDR</div>
    <div style="font-size:11px;color:#777;margin-top:3px">Relatório Executivo — Uso Defensivo Autorizado</div>
  </div>
  <div class="hdr-meta">
    <div><strong>Máquina:</strong> {{Esc(result.MachineName)}}</div>
    <div><strong>Data:</strong> {{result.ScanTime:dd/MM/yyyy HH:mm:ss}}</div>
    {{(!string.IsNullOrEmpty(result.MachineId) ? $"<div><strong>Machine ID:</strong> {Esc(result.MachineId)}</div>" : "")}}
    {{(result.License != null ? $"<div><strong>Licença:</strong> {Esc(result.License.CustomerId)} ({(result.License.IsWildcard ? "Wildcard QA" : "Machine-bound")}) · Expira: {result.License.ExpiresAt.LocalDateTime:dd/MM/yyyy}</div>" : "")}}
    {{(config.SuspectName != null ? $"<div><strong>Suspeito:</strong> {Esc(config.SuspectName)}</div>" : "")}}
    {{(config.InvestigatorName != null ? $"<div><strong>Investigador:</strong> {Esc(config.InvestigatorName)}</div>" : "")}}
    {{(config.CaseId != null ? $"<div><strong>Caso:</strong> {Esc(config.CaseId)}</div>" : "")}}
  </div>
</div>

<div class="verdict">
  <div>
    <div class="verdict-score">{{result.TotalScore}}<span style="font-size:18px;font-weight:400;color:#999">/100</span></div>
  </div>
  <div>
    <div class="verdict-label">{{Esc(result.OverallRiskLabel)}}</div>
    <div class="verdict-sub">Score de risco · Perfil: {{Esc(result.ScanMode)}} · {{result.Findings.Count}} findings</div>
  </div>
  <div class="verdict-stats">
    <div>Critical: <strong style="color:#ef4444">{{result.CriticalFindings.Count()}}</strong></div>
    <div>High: <strong style="color:#f97316">{{result.HighFindings.Count()}}</strong></div>
    <div>Dossiês: <strong>{{result.EvidenceBundles.Count}}</strong></div>
    <div>Ruído filtrado: <strong>{{result.FilteredCount}}</strong></div>
  </div>
</div>

""");

        // Top 5 provas
        sb.AppendLine("""<div class="section">""");
        sb.AppendLine("""<div class="section-title">Top 5 Provas Fortes</div>""");
        if (provasFortes.Count == 0)
        {
            sb.AppendLine("""<div style="color:#888;font-size:12px">Nenhuma prova forte encontrada.</div>""");
        }
        else
        {
            for (int i = 0; i < provasFortes.Count; i++)
            {
                var f = provasFortes[i];
                var badgeCls = f.Risk switch
                {
                    RiskLevel.Critical => "badge-critical",
                    RiskLevel.High     => "badge-high",
                    _                  => "badge-medium"
                };
                var confBadge = f.Confidence == Confidence.Confirmed
                    ? """<span class="badge badge-conf">CONFIRMADO</span>"""
                    : "";
                sb.AppendLine($"""
<div class="proof-row">
  <span class="proof-num">{i + 1}.</span>
  <span class="badge {badgeCls}">{Esc(f.RiskLabel)}</span>
  {confBadge}
  <span class="proof-title">{Esc(f.Title)}</span>
  <span class="proof-mod">[{Esc(f.Module)}]</span>
</div>
""");
            }
        }
        sb.AppendLine("</div>");

        // Timeline resumida (top 10 High+)
        if (topTimeline.Count > 0)
        {
            sb.AppendLine("""<div class="section">""");
            sb.AppendLine($"""<div class="section-title">Linha do Tempo — Eventos Críticos ({topTimeline.Count})</div>""");
            foreach (var f in topTimeline)
            {
                var tColor = f.Risk == RiskLevel.Critical ? "#ef4444" : "#f97316";
                sb.AppendLine($"""
<div class="tl-row">
  <span class="tl-ts">{f.Timestamp:dd/MM HH:mm:ss}</span>
  <span class="badge" style="background:#fef2f2;color:{tColor};border:1px solid {tColor}44">{Esc(f.RiskLabel)}</span>
  <span class="proof-title">{Esc(f.Title)}</span>
  <span class="tl-mod">[{Esc(f.Module)}]</span>
</div>
""");
            }
            sb.AppendLine("</div>");
        }

        // Bypass / concealment
        if (bypassAlerts.Count > 0)
        {
            sb.AppendLine("""<div class="section">""");
            sb.AppendLine($"""<div class="section-title">Tentativas de Ocultação ({bypassAlerts.Count})</div>""");
            foreach (var f in bypassAlerts)
            {
                var rowCls = f.Risk == RiskLevel.Critical ? "bypass-row" : "bypass-row bypass-row-high";
                sb.AppendLine($"""
<div class="{rowCls}">
  <span style="font-size:11px;font-weight:700">[{Esc(f.Module)}]</span>
  <span style="font-size:12px;margin-left:6px">{Esc(f.Title)}</span>
  {(f.Timestamp.HasValue ? $"""<span style="font-family:monospace;font-size:10px;color:#888;margin-left:8px">{f.Timestamp:dd/MM HH:mm:ss}</span>""" : "")}
</div>
""");
            }
            sb.AppendLine("</div>");
        }

        // Module coverage
        sb.AppendLine("""<div class="section">""");
        sb.AppendLine("""<div class="section-title">Cobertura da Varredura</div>""");
        sb.AppendLine("""<div class="coverage">""");
        void CovStat(string n, string color, int count) => sb.AppendLine($"""
<div style="text-align:center">
  <div class="cov-num" style="color:{color}">{count}</div>
  <div class="cov-lbl">{n}</div>
</div>
""");
        CovStat("Executados", "#16a34a", executed);
        CovStat("Parciais",   "#f97316", partial);
        CovStat("Pulados",    "#64748b", skipped);
        CovStat("Falhos",     "#ef4444", failed);
        sb.AppendLine("</div>");
        sb.AppendLine("</div>");

        // Manifest hash
        if (!string.IsNullOrEmpty(manifestHash))
        {
            sb.AppendLine("""<div class="section">""");
            sb.AppendLine("""<div class="section-title">Integridade — Hash do Manifesto</div>""");
            sb.AppendLine($"""<div class="hash-box">{Esc(manifestHash)}</div>""");
            sb.AppendLine("""<div style="font-size:11px;color:#888;margin-top:4px">Verificar: <code>sha256sum -c manifest.sha256</code></div>""");
            sb.AppendLine("</div>");
        }

        sb.AppendLine($$"""
<div class="footer">
  <span>Echo Nerfados Shield XDR v1.0 · {{result.ScanTime:dd/MM/yyyy HH:mm:ss}}</span>
  <span class="no-print">{{result.ModulesRun.Count}} módulos · {{result.Findings.Count}} findings · score {{result.TotalScore}}/100</span>
  <span>&#128247; Imprimir: Ctrl+P | PDF: Salvar como PDF</span>
</div>
</body>
</html>
""");

        return sb.ToString();
    }
}
