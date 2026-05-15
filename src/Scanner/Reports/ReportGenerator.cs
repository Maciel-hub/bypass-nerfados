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

    public static string GenerateExecutiveHtml(ScanResult result, ScanConfig config, string runFolder, string? manifestHash = null)
    {
        var path = Path.Combine(runFolder, "report_executive.html");
        var html = ExecutiveTemplate.Build(result, config, manifestHash);
        File.WriteAllText(path, html, System.Text.Encoding.UTF8);
        return path;
    }

    public static void GenerateTxt(ScanResult result, ScanConfig config, string outputPath)
    {
        var sb = new System.Text.StringBuilder();
        var sep = new string('=', 70);
        var dash = new string('-', 70);

        sb.AppendLine(sep);
        sb.AppendLine("  ECHO NERFADOS SHIELD XDR — Relatório de Investigação");
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

        // Artifact dossiers
        if (result.EvidenceBundles.Count > 0)
        {
            sb.AppendLine(sep);
            sb.AppendLine($"  *** DOSSIÊ POR ARTEFATO ({result.EvidenceBundles.Count} artefatos) ***");
            sb.AppendLine(dash);

            foreach (var bundle in result.EvidenceBundles)
            {
                sb.AppendLine($"  ARTEFATO : {bundle.ArtifactName}");
                sb.AppendLine($"  Veredito : {bundle.Verdict}  |  Risco: {bundle.Risk.ToString().ToUpper()}");
                if (!string.IsNullOrEmpty(bundle.FullPath))
                    sb.AppendLine($"  Caminho  : {bundle.FullPath}");
                if (!string.IsNullOrEmpty(bundle.Sha256))
                    sb.AppendLine($"  SHA256   : {bundle.Sha256}");
                if (!string.IsNullOrEmpty(bundle.Sha1))
                    sb.AppendLine($"  SHA1     : {bundle.Sha1}");
                sb.AppendLine($"  Origem   : {bundle.Summary}");

                if (bundle.Signals.Count > 0)
                {
                    sb.AppendLine("  Sinais:");
                    foreach (var sig in bundle.Signals)
                    {
                        var ts = sig.Timestamp.HasValue ? $" | {sig.Timestamp:dd/MM/yyyy HH:mm:ss}" : "";
                        sb.AppendLine($"    • [{sig.SignalType}] {sig.SourceModule}: {sig.Description}{ts}");
                    }
                }

                if (bundle.BypassIndicators.Count > 0)
                {
                    sb.AppendLine("  Bypass próximo:");
                    foreach (var b in bundle.BypassIndicators)
                        sb.AppendLine($"    ⚠ {b}");
                }

                if (bundle.ValidationSteps.Count > 0)
                {
                    sb.AppendLine("  Validar:");
                    foreach (var v in bundle.ValidationSteps)
                        sb.AppendLine($"    → {v}");
                }

                sb.AppendLine(new string('-', 50));
                sb.AppendLine();
            }
        }

        // Bypass / anti-forensics section
        var bypass = result.BypassFindings.OrderByDescending(f => f.Risk).ToList();
        if (bypass.Count > 0)
        {
            sb.AppendLine(sep);
            sb.AppendLine($"  *** TENTATIVAS DE BYPASS / ANTI-FORENSE ({bypass.Count}) ***");
            sb.AppendLine(dash);
            foreach (var f in bypass)
            {
                sb.AppendLine($"  [{f.RiskLabel}] [{f.Module}] {f.Title}");
                sb.AppendLine($"  {f.Detail}");
                if (f.Evidence != null) sb.AppendLine($"  Evidência: {f.Evidence}");
                if (f.Timestamp.HasValue) sb.AppendLine($"  Data: {f.Timestamp:dd/MM/yyyy HH:mm:ss}");
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
        // Module coverage table
        if (result.ModuleCoverage.Count > 0)
        {
            sb.AppendLine(sep);
            sb.AppendLine("  COBERTURA DA VARREDURA");
            sb.AppendLine(dash);
            sb.AppendLine($"  {"MÓDULO",-25} {"STATUS",-12} MOTIVO / IMPACTO FORENSE");
            sb.AppendLine(dash);
            foreach (var entry in result.ModuleCoverage.OrderBy(e => e.Status).ThenBy(e => e.Name))
            {
                var statusStr = entry.Status switch
                {
                    ModuleStatus.Executed => "EXECUTADO",
                    ModuleStatus.Partial  => "PARCIAL",
                    ModuleStatus.Skipped  => "PULADO",
                    ModuleStatus.Failed   => "FALHOU",
                    _                     => "AGUARDANDO"
                };
                var note = !string.IsNullOrEmpty(entry.Reason)
                    ? entry.Reason
                    : !string.IsNullOrEmpty(entry.ForensicImpact) ? entry.ForensicImpact : "—";
                sb.AppendLine($"  {entry.Name,-25} {statusStr,-12} {note}");
            }
            sb.AppendLine();
        }

        sb.AppendLine(sep);
        sb.AppendLine($"  Módulos executados: {string.Join(", ", result.ModulesRun)}");
        sb.AppendLine($"  Gerado em: {DateTime.Now:dd/MM/yyyy HH:mm:ss}");
        sb.AppendLine(sep);

        File.WriteAllText(outputPath, sb.ToString(), System.Text.Encoding.UTF8);
    }
}
