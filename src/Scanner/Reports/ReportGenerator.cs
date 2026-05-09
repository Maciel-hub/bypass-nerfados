using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Reports;

public static class ReportGenerator
{
    public static void GenerateHtml(ScanResult result, ScanConfig config, string outputPath)
    {
        var html = HtmlTemplate.Build(result, config);
        File.WriteAllText(outputPath, html, System.Text.Encoding.UTF8);
    }

    public static void GenerateTxt(ScanResult result, ScanConfig config, string outputPath)
    {
        var sb = new System.Text.StringBuilder();
        var sep = new string('=', 70);
        var dash = new string('-', 70);

        sb.AppendLine(sep);
        sb.AppendLine("  BYPASS NERFADOS SHIELD XDR — Relatório de Investigação");
        sb.AppendLine(sep);
        sb.AppendLine();
        sb.AppendLine($"  Máquina    : {result.MachineName}");
        sb.AppendLine($"  Usuário    : {result.CurrentUser}");
        sb.AppendLine($"  Data/Hora  : {result.ScanTime:dd/MM/yyyy HH:mm:ss}");
        if (config.SuspectName != null)
            sb.AppendLine($"  Suspeito   : {config.SuspectName}");
        if (config.InvestigatorName != null)
            sb.AppendLine($"  Investigador: {config.InvestigatorName}");
        sb.AppendLine();
        sb.AppendLine($"  SCORE DE RISCO: {result.TotalScore}/100  [{result.OverallRiskLabel}]");
        sb.AppendLine();

        sb.AppendLine(sep);
        sb.AppendLine("  RESUMO POR SEVERIDADE");
        sb.AppendLine(dash);
        foreach (var group in result.Findings.GroupBy(f => f.Risk).OrderByDescending(g => g.Key))
        {
            sb.AppendLine($"  {group.Key.ToString().ToUpper(),-12}: {group.Count()} finding(s)  (+{(int)group.Sum(f => f.WeightedScore)} pts)");
        }
        sb.AppendLine();

        // Cheat findings first
        var cheats = result.Findings.Where(f => f.Category == FindingCategory.Cheat).ToList();
        if (cheats.Count > 0)
        {
            sb.AppendLine(sep);
            sb.AppendLine($"  *** CHEATS DETECTADOS ({cheats.Count}) ***");
            sb.AppendLine(dash);
            foreach (var f in cheats)
            {
                sb.AppendLine($"  [{f.RiskLabel}] {f.Title}");
                sb.AppendLine($"  Detalhe: {f.Detail}");
                if (f.Evidence != null) sb.AppendLine($"  Evidência: {f.Evidence}");
                if (f.Timestamp.HasValue) sb.AppendLine($"  Timestamp: {f.Timestamp:dd/MM/yyyy HH:mm:ss}");
                sb.AppendLine();
            }
        }

        sb.AppendLine(sep);
        sb.AppendLine("  TODOS OS FINDINGS");
        sb.AppendLine(dash);

        foreach (var finding in result.Findings.OrderByDescending(f => f.Risk))
        {
            if (finding.Category == FindingCategory.Cheat) continue; // already listed above

            sb.AppendLine($"  [{finding.RiskLabel}] [{finding.Module}] {finding.Title}");
            sb.AppendLine($"  {finding.Detail}");
            if (finding.Evidence != null) sb.AppendLine($"  Evidência: {finding.Evidence}");
            if (finding.Timestamp.HasValue) sb.AppendLine($"  Timestamp: {finding.Timestamp:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine();
        }

        sb.AppendLine(sep);
        sb.AppendLine("  TIMELINE (eventos com timestamp)");
        sb.AppendLine(dash);
        foreach (var f in result.SortedByTime.Take(50))
        {
            sb.AppendLine($"  {f.Timestamp:dd/MM/yyyy HH:mm:ss}  [{f.RiskLabel,-8}]  [{f.Module,-15}]  {f.Title}");
        }

        sb.AppendLine();
        sb.AppendLine(sep);
        sb.AppendLine($"  Módulos executados: {string.Join(", ", result.ModulesRun)}");
        sb.AppendLine($"  Gerado em: {DateTime.Now:dd/MM/yyyy HH:mm:ss}");
        sb.AppendLine(sep);

        File.WriteAllText(outputPath, sb.ToString(), System.Text.Encoding.UTF8);
    }
}
