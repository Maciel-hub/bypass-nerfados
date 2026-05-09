using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Core;

public static class Correlator
{
    public static void Correlate(ScanResult result)
    {
        DetectAntiForensicsPattern(result);
        DetectCheatWithHiddenLogs(result);
        CorrelateTemporalBurst(result);
        DetectSystemServiceTampering(result);
    }

    private static void DetectAntiForensicsPattern(ScanResult result)
    {
        var logCleared = result.Findings.Any(f =>
            f.Title.Contains("1102") || f.Title.Contains("104") ||
            f.Title.Contains("log limpo", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("limpeza de log", StringComparison.OrdinalIgnoreCase));

        var prefetchDeleted = result.Findings.Any(f =>
            f.Category == FindingCategory.AntiForensics &&
            f.Detail.Contains("prefetch", StringComparison.OrdinalIgnoreCase));

        var usnManipulated = result.Findings.Any(f =>
            f.Title.Contains("3079") ||
            f.Title.Contains("USN", StringComparison.OrdinalIgnoreCase));

        var defenderDisabled = result.Findings.Any(f =>
            f.Title.Contains("5007") ||
            f.Title.Contains("defender", StringComparison.OrdinalIgnoreCase) &&
            f.Category == FindingCategory.SystemTampering);

        int score = 0;
        var signals = new List<string>();

        if (logCleared)   { score++; signals.Add("Logs de eventos limpos"); }
        if (prefetchDeleted) { score++; signals.Add("Prefetch deletado"); }
        if (usnManipulated)  { score++; signals.Add("USN Journal manipulado"); }
        if (defenderDisabled){ score++; signals.Add("Windows Defender alterado"); }

        if (score >= 2)
        {
            result.Findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.AntiForensics,
                "Correlação",
                $"PADRÃO ANTI-FORENSE DETECTADO ({score}/4 indicadores)",
                $"Múltiplas tentativas de apagar rastros identificadas: {string.Join(", ", signals)}. " +
                "Este padrão é fortemente indicativo de adulteração intencional do sistema.",
                string.Join(" | ", signals),
                confidence: Confidence.High,
                ruleId: "CORR_ANTI_FORENSICS",
                entity: string.Join("|", signals)
            ));
        }
    }

    private static void DetectCheatWithHiddenLogs(ScanResult result)
    {
        var hasCheat = result.Findings.Any(f => f.Category == FindingCategory.Cheat);
        var hasLogClearing = result.Findings.Any(f =>
            f.Category == FindingCategory.AntiForensics ||
            f.Category == FindingCategory.SystemTampering);

        if (hasCheat && hasLogClearing)
        {
            result.Findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.Cheat,
                "Correlação",
                "CHEAT + TENTATIVA DE OCULTAÇÃO",
                "Foram encontrados rastros de cheat E evidências de tentativas de remover rastros. " +
                "Isso confirma uso intencional de cheat com conhecimento da detecção.",
                "Cheat detectado + sinais de anti-forense ativos",
                confidence: Confidence.High,
                ruleId: "CORR_CHEAT_HIDING",
                entity: "cheat+antiforensics"
            ));
        }
    }

    private static void CorrelateTemporalBurst(ScanResult result)
    {
        var timedFindings = result.Findings
            .Where(f => f.Timestamp.HasValue && f.Risk >= RiskLevel.Medium)
            .OrderBy(f => f.Timestamp!.Value)
            .ToList();

        if (timedFindings.Count < 3) return;

        // Look for clusters: 3+ suspicious events within 60 seconds
        for (int i = 0; i < timedFindings.Count - 2; i++)
        {
            var window = timedFindings
                .Skip(i)
                .TakeWhile(f => (f.Timestamp!.Value - timedFindings[i].Timestamp!.Value).TotalMinutes <= 1)
                .ToList();

            if (window.Count >= 3)
            {
                var ts = timedFindings[i].Timestamp!.Value;
                var modules = string.Join(", ", window.Select(f => f.Module).Distinct());
                result.Findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.SuspiciousExecution,
                    "Correlação",
                    $"BURST DE ATIVIDADE SUSPEITA ({window.Count} eventos em <1 min)",
                    $"Múltiplos eventos suspeitos concentrados em {ts:dd/MM/yyyy HH:mm:ss}. " +
                    "Padrão típico de execução de cheat loader.",
                    $"Janela: {ts:HH:mm:ss} | Eventos: {modules}",
                    timestamp: ts,
                    confidence: Confidence.Medium,
                    ruleId: "CORR_TEMPORAL_BURST",
                    entity: $"burst@{ts:yyyyMMddHHmm}"
                ));
                break;
            }
        }
    }

    private static void DetectSystemServiceTampering(ScanResult result)
    {
        var stoppedServices = result.Findings
            .Where(f => f.Category == FindingCategory.ServiceTampering)
            .ToList();

        if (stoppedServices.Count >= 2)
        {
            var serviceList = string.Join(", ", stoppedServices.Select(f => f.Title));
            result.Findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.ServiceTampering,
                "Correlação",
                $"MÚLTIPLOS SERVIÇOS DE PROTEÇÃO DESATIVADOS ({stoppedServices.Count})",
                "Vários serviços de monitoramento do Windows estão desativados. " +
                "Bypass de proteções do sistema para ocultar atividade.",
                serviceList,
                confidence: Confidence.High,
                ruleId: "CORR_SERVICE_TAMPERING",
                entity: serviceList
            ));
        }
    }
}
