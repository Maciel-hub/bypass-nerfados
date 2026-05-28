using Microsoft.Win32;
using BypassNerfados.Scanner.Data;
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
        CorrelateDriverWithCheat(result);
        CorrelateFiveMSession(result);
        CorrelateCheatLoaderChain(result);
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

        // USN 3079 alone is Confidence.Low — don't count it as an anti-forensic signal
        var usnManipulated = result.Findings.Any(f =>
            (f.Title.Contains("3079") || f.Title.Contains("USN", StringComparison.OrdinalIgnoreCase)) &&
            f.Confidence > Confidence.Low);

        // Generic 5007 config changes are now Low confidence — only count real disabling events
        var defenderDisabled = result.Findings.Any(f =>
            (f.Title.Contains("5007") ||
             f.Title.Contains("defender", StringComparison.OrdinalIgnoreCase)) &&
            f.Category == FindingCategory.SystemTampering &&
            f.Confidence >= Confidence.Medium);

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
        // Require credible cheat evidence (High/Confirmed) to avoid Low-confidence DLL name matches
        // escalating into a Critical correlation finding.
        var hasCredibleCheat = result.Findings.Any(f =>
            f.Category == FindingCategory.Cheat && f.Confidence >= Confidence.High);
        var hasAntiForensics = result.Findings.Any(f =>
            (f.Category == FindingCategory.AntiForensics ||
             f.Category == FindingCategory.SystemTampering) &&
            f.Confidence >= Confidence.Medium);

        if (hasCredibleCheat && hasAntiForensics)
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

    private static void CorrelateFiveMSession(ScanResult result)
    {
        // Collect FiveM/GTA5 session timestamps from all available sources.
        // Priority: Prefetch (most precise) → BAM/DAM registry (survives Prefetch deletion).
        var fivemTimes = new List<DateTime>();

        // 1. Prefetch
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (Directory.Exists(prefetchDir))
        {
            try
            {
                foreach (var pf in Directory.GetFiles(prefetchDir, "FIVEM*.PF")
                    .Concat(Directory.GetFiles(prefetchDir, "GTA5*.PF")))
                    fivemTimes.Add(File.GetLastWriteTime(pf));
            }
            catch { /* prefetch inacessível */ }
        }

        // 2. BAM/DAM — always collect regardless of Prefetch availability.
        //    Value names are device paths; we match by filename suffix only.
        foreach (var svcName in new[] { "bam", "dam" })
        {
            try
            {
                using var hive = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svcName}\State\UserSettings");
                if (hive == null) continue;

                foreach (var sid in hive.GetSubKeyNames())
                {
                    using var userKey = hive.OpenSubKey(sid);
                    if (userKey == null) continue;

                    foreach (var valueName in userKey.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(valueName)) continue;
                        var lower = valueName.ToLowerInvariant();
                        if (!lower.EndsWith("\\fivem.exe") && !lower.EndsWith("\\gta5.exe")) continue;

                        var data = userKey.GetValue(valueName, null,
                            RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                        if (data == null || data.Length < 8) continue;

                        var fileTime = BitConverter.ToInt64(data, 0);
                        if (fileTime <= 0) continue;
                        try { fivemTimes.Add(DateTime.FromFileTime(fileTime)); }
                        catch { /* invalid timestamp */ }
                    }
                }
            }
            catch { /* BAM/DAM inacessível sem Admin */ }
        }

        // 3. BAM co-execution findings already emitted by BamDamModule carry FiveM session timestamps
        var bamCoExecTimes = result.Findings
            .Where(f => f.RuleId?.StartsWith("BAM_COEXEC_") == true && f.Timestamp.HasValue)
            .Select(f => f.Timestamp!.Value)
            .ToList();
        fivemTimes.AddRange(bamCoExecTimes);

        if (fivemTimes.Count == 0) return;

        var suspiciousFindings = result.Findings
            .Where(f => f.Timestamp.HasValue &&
                        f.Risk >= RiskLevel.Medium &&
                        (f.Category is FindingCategory.Cheat
                                    or FindingCategory.SuspiciousExecution
                                    or FindingCategory.KernelArtifact) &&
                        !CheatDatabase.IsKnownLegitimate(f.Entity ?? ""))
            .ToList();

        if (suspiciousFindings.Count == 0) return;

        foreach (var sessionTime in fivemTimes.OrderByDescending(t => t))
        {
            var windowStart = sessionTime.AddMinutes(-30);
            var windowEnd   = sessionTime.AddHours(2);

            var inWindow = suspiciousFindings
                .Where(f => f.Timestamp!.Value >= windowStart && f.Timestamp!.Value <= windowEnd)
                .ToList();

            if (inWindow.Count == 0) continue;

            var entities = string.Join(", ", inWindow.Take(5).Select(f => f.Entity ?? f.Title).Distinct());
            var modules  = string.Join(", ", inWindow.Select(f => f.Module).Distinct());
            var ruleKey  = $"CORR_FIVEM_SESSION_{sessionTime:yyyyMMddHH}";

            if (result.Findings.Any(f => f.RuleId == ruleKey)) continue;

            // Critical only when direct evidence or 2+ independent sources exist.
            // Direct: BAM_COEXEC, Memory modules, or FiveM Application Data paths.
            bool hasDirectEvidence = inWindow.Any(f =>
                f.RuleId?.StartsWith("BAM_COEXEC_") == true ||
                f.Module is "Memory DLL Trace" or "Memory String Scan" ||
                FiveMSessionAnalyzer.HasFiveMDataPath(f));

            int distinctModules = inWindow.Select(f => f.Module).Distinct().Count();
            // Two generic Medium sources alone are insufficient for Critical — require at least one
            // score-eligible finding with Confidence >= High alongside the second source.
            bool hasMultipleSources = distinctModules >= 2 &&
                inWindow.Any(f => f.ScoreEligible && f.Confidence >= Confidence.High);

            var risk       = (hasDirectEvidence || hasMultipleSources) ? RiskLevel.Critical : RiskLevel.High;
            var confidence = hasDirectEvidence  ? Confidence.High :
                             hasMultipleSources ? Confidence.Medium : Confidence.Low;
            var hint = (!hasDirectEvidence && !hasMultipleSources)
                ? "Executáveis genéricos próximos à sessão sem prova direta de interação — validar manualmente."
                : null;

            result.Findings.Add(new Finding(
                risk,
                FindingCategory.Cheat,
                "Correlação",
                $"EXECUÇÃO SUSPEITA NA SESSÃO FIVEM ({inWindow.Count} evento(s))",
                $"Loader ou cheat executado na janela de -30min/+2h da sessão FiveM.\n" +
                $"Sessão FiveM: {sessionTime:dd/MM/yyyy HH:mm:ss} | Fontes: {modules}\n" +
                $"Eventos correlacionados: {entities}",
                $"Sessão: {sessionTime:HH:mm:ss} | {inWindow.Count} evento(s) na janela",
                timestamp: sessionTime,
                confidence: confidence,
                ruleId: ruleKey,
                entity: $"fivem-session@{sessionTime:yyyyMMddHH}",
                validationHint: hint
            ));
            break; // uma correlação por run é suficiente
        }
    }

    // Kernel-level cheat: driver artifact (USN or DriverKernel module) co-existing
    // with any cheat/suspicious-execution finding is the strongest possible signal —
    // it means the cheat ran its own kernel driver to bypass AC or read process memory.
    private static void CorrelateDriverWithCheat(ScanResult result)
    {
        var kernelFindings = result.Findings
            .Where(f => f.Category == FindingCategory.KernelArtifact && f.Risk >= RiskLevel.Medium)
            .ToList();

        if (kernelFindings.Count == 0) return;

        var cheatFindings = result.Findings
            .Where(f => (f.Category == FindingCategory.Cheat && f.Confidence >= Confidence.Medium) ||
                        (f.Category == FindingCategory.SuspiciousExecution && f.Risk >= RiskLevel.High))
            .ToList();

        if (cheatFindings.Count == 0) return;

        // When both sides carry timestamps, require temporal proximity (±2h).
        // Without timestamps we still fire — e.g. USN records or registry-only kernel findings.
        var kernelWithTime = kernelFindings.Where(f => f.Timestamp.HasValue).ToList();
        var cheatWithTime  = cheatFindings.Where(f => f.Timestamp.HasValue).ToList();

        if (kernelWithTime.Count > 0 && cheatWithTime.Count > 0)
        {
            bool close = kernelWithTime.Any(k =>
                cheatWithTime.Any(c =>
                    Math.Abs((k.Timestamp!.Value - c.Timestamp!.Value).TotalHours) <= 2.0));
            if (!close) return;
        }

        var driverList = string.Join(", ",
            kernelFindings.Take(3).Select(f => f.Entity ?? f.Title).Distinct());

        result.Findings.Add(new Finding(
            RiskLevel.Critical,
            FindingCategory.KernelArtifact,
            "Correlação",
            $"CHEAT COM DRIVER DE KERNEL ({kernelFindings.Count} artefato(s))",
            "Artefatos de cheat encontrados em conjunto com driver de kernel suspeito. " +
            "Este padrão indica cheat operando em nível de kernel (kernel-mode cheat), " +
            "capaz de bypassar anti-cheats que operam apenas em user-mode.",
            driverList,
            confidence: Confidence.High,
            ruleId: "CORR_KERNEL_CHEAT",
            entity: "kernel-cheat"
        ));
    }

    // Correlates Stan/generic loader credential chain:
    // - Portal download + loader execution → CHEAT_GENERIC_LOADER_FROM_PORTAL_DOWNLOAD (Critical)
    // - Loader co-located with .credentials → CHEAT_GENERIC_LOADER_WITH_CREDENTIAL (High)
    private static void CorrelateCheatLoaderChain(ScanResult result)
    {
        bool hasPortalDownload = result.Findings.Any(f =>
            f.RuleId is "BROWSER_DL_REDENGINE_PORTAL" or "BROWSER_DL_CHEAT_PORTAL_ARCHIVE");

        bool hasLoaderExecution = result.Findings.Any(f =>
            f.RuleId is "STAN_LOADER_EXE"
                     or "STAN_LOADER_WITH_CREDENTIAL"
                     or "STAN_PREFETCH_EXECUTED"
                     or "STAN_BAM_EXECUTED");

        if (hasPortalDownload && hasLoaderExecution)
        {
            var portalSample = result.Findings.First(f =>
                f.RuleId is "BROWSER_DL_REDENGINE_PORTAL" or "BROWSER_DL_CHEAT_PORTAL_ARCHIVE");
            var loaderSample = result.Findings.First(f =>
                f.RuleId is "STAN_LOADER_EXE"
                         or "STAN_LOADER_WITH_CREDENTIAL"
                         or "STAN_PREFETCH_EXECUTED"
                         or "STAN_BAM_EXECUTED");

            result.Findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.Cheat,
                "Correlação",
                "CADEIA STAN: download de portal cheat + execução de loader",
                "Download rastreado em portal de cheat (redengine.net) correlacionado com execução de loader.exe.\n" +
                $"Portal: {portalSample.Entity ?? portalSample.Title}\n" +
                $"Loader: {loaderSample.Entity ?? loaderSample.Title}",
                $"Download: {portalSample.RuleId} | Loader: {loaderSample.RuleId}",
                timestamp: loaderSample.Timestamp ?? portalSample.Timestamp,
                confidence: Confidence.High,
                ruleId: "CHEAT_GENERIC_LOADER_FROM_PORTAL_DOWNLOAD",
                entity: loaderSample.Entity ?? "loader.exe"
            ));
        }

        bool hasCredential = result.Findings.Any(f =>
            f.RuleId is "STAN_LOADER_WITH_CREDENTIAL" or "STAN_CREDENTIALS_NEAR_LOADER");

        bool hasLoaderEvidence = result.Findings.Any(f =>
            f.RuleId is "STAN_LOADER_EXE"
                     or "STAN_LOADER_WITH_CREDENTIAL"
                     or "STAN_PREFETCH_EXECUTED"
                     or "STAN_BAM_EXECUTED");

        if (hasCredential && hasLoaderEvidence)
        {
            var credSample = result.Findings.First(f =>
                f.RuleId is "STAN_LOADER_WITH_CREDENTIAL" or "STAN_CREDENTIALS_NEAR_LOADER");

            result.Findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.Cheat,
                "Correlação",
                "CADEIA STAN: loader + arquivo .credentials de assinante",
                "loader.exe e arquivo .credentials de assinante encontrados em conjunto.\n" +
                "Padrão de entrega Stan Menu: loader.exe + <hex>.credentials no mesmo diretório.\n" +
                $"Credencial: {credSample.Entity ?? credSample.Title}",
                $"Credencial: {credSample.RuleId}",
                timestamp: credSample.Timestamp,
                confidence: Confidence.High,
                ruleId: "CHEAT_GENERIC_LOADER_WITH_CREDENTIAL",
                entity: credSample.Entity ?? ".credentials"
            ));
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
