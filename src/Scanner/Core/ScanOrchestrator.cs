using BypassNerfados.Scanner.Models;
using BypassNerfados.Scanner.Modules;
using BypassNerfados.Scanner.Reports;

namespace BypassNerfados.Scanner.Core;

public class ScanOrchestrator
{
    private readonly ScanConfig _config;
    private readonly ScanResult _result;
    private readonly IProgress<ScanProgressUpdate>? _progress;

    public ScanOrchestrator(ScanConfig config, IProgress<ScanProgressUpdate>? progress = null)
    {
        _config = config;
        _progress = progress;
        _result = new ScanResult
        {
            IsAdministrator = IsAdmin(),
            ScanMode = config.Profile switch
            {
                ScanProfile.Fast    => "Rápido",
                ScanProfile.Deep    => "Profundo",
                ScanProfile.FiveM   => "FiveM",
                ScanProfile.Florence => "Florence",
                _                   => "Completo"
            }
        };
    }

    public async Task<ScanResult> RunAsync(CancellationToken cancellationToken = default)
    {
        if (!_result.IsAdministrator)
        {
            Report(new ScanProgressUpdate(
                ScanProgressKind.Warning,
                "Executando sem privilégios de Administrador. Alguns módulos serão limitados."));
        }

        var modules = BuildModuleList();

        Report(new ScanProgressUpdate(
            ScanProgressKind.ScanStarted,
            $"Iniciando varredura com {modules.Count} módulos.",
            ModuleCount: modules.Count));

        for (int i = 0; i < modules.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var module = modules[i];
            Report(new ScanProgressUpdate(
                ScanProgressKind.ModuleStarted,
                $"Executando módulo {module.Name}.",
                ModuleName: module.Name,
                ModuleIndex: i + 1,
                ModuleCount: modules.Count));

            var coverage = _result.ModuleCoverage.FirstOrDefault(c => c.Name == module.Name);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var findings = await module.RunAsync(_config, cancellationToken);
                sw.Stop();

                _result.Findings.AddRange(findings);
                _result.ModulesRun.Add(module.Name);
                _result.ModuleDurations[module.Name] = sw.Elapsed;

                if (coverage != null)
                {
                    coverage.Status = module.HasPartialErrors ? ModuleStatus.Partial : ModuleStatus.Executed;
                    if (module.HasPartialErrors)
                        coverage.Reason = string.Join("; ", module.GetPartialErrors());
                }

                Report(new ScanProgressUpdate(
                    ScanProgressKind.ModuleCompleted,
                    $"Módulo {module.Name} concluído.",
                    ModuleName: module.Name,
                    ModuleIndex: i + 1,
                    ModuleCount: modules.Count,
                    Findings: findings,
                    Duration: sw.Elapsed));
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                throw;
            }
            catch (Exception ex)
            {
                sw.Stop();
                _result.ModuleErrors.Add($"{module.Name}: {ex.Message}");

                if (coverage != null)
                {
                    coverage.Status = ModuleStatus.Failed;
                    coverage.Reason = ex.Message;
                }

                Report(new ScanProgressUpdate(
                    ScanProgressKind.ModuleFailed,
                    $"Módulo {module.Name} falhou: {ex.Message}",
                    ModuleName: module.Name,
                    ModuleIndex: i + 1,
                    ModuleCount: modules.Count,
                    Duration: sw.Elapsed,
                    Exception: ex));
            }
        }

        // Deduplicate before correlation so cross-module duplicates don't inflate signals
        var deduped = FindingDeduplicator.Deduplicate(_result.Findings);
        _result.Findings.Clear();
        _result.Findings.AddRange(deduped);

        // Run correlation engine first — enricher needs correlated findings for bypass indicators
        cancellationToken.ThrowIfCancellationRequested();
        Report(new ScanProgressUpdate(
            ScanProgressKind.CorrelationStarted,
            "Analisando padrões entre módulos."));

        Correlator.Correlate(_result);

        // Noise reduction: threshold driven by score_weights.json (default: Medium+Low)
        var noiseRisk = ParseRisk(_config.Rules.Score.NoiseMinRisk, RiskLevel.Medium);
        var noiseConf = ParseConf(_config.Rules.Score.NoiseMaxConfidence, Confidence.Low);
        foreach (var f in _result.Findings)
        {
            if (f.Risk == noiseRisk
                && f.Confidence <= noiseConf
                && f.RuleId?.StartsWith("CORR_") != true
                && f.Category != FindingCategory.AntiForensics)
            {
                f.ScoreEligible = false;
            }
        }

        // External rules elevation: cheat hashes → Critical+Confirmed; cheat names → High (if lower)
        ApplyExternalRules(_result, _config.Rules);

        // Florence: downgrade single-source High/Critical to Medium (requires ≥2 modules per entity)
        if (_config.Profile == ScanProfile.Florence)
            ApplyFlorenceElevation(_result);

        Report(new ScanProgressUpdate(
            ScanProgressKind.CorrelationCompleted,
            "Correlação concluída."));

        // Build artifact dossiers after correlation so CORR_ findings are visible in bypass section
        var bundles = EvidenceEnricher.Enrich(_result.Findings);
        _result.EvidenceBundles.AddRange(bundles);

        Report(new ScanProgressUpdate(
            ScanProgressKind.ResultReady,
            "Resultado de varredura pronto.",
            Result: _result));

        // Generate report — all outputs go into a timestamped run folder
        if (_config.SaveReport)
        {
            var runFolder  = Path.Combine(_config.ReportOutputPath, _config.ReportFileName);
            var reportPath = Path.Combine(runFolder, "report.html");
            var txtPath    = Path.Combine(runFolder, "report.txt");

            Report(new ScanProgressUpdate(
                ScanProgressKind.ReportStarted,
                "Exportando relatório.",
                HtmlReportPath: reportPath,
                TextReportPath: txtPath,
                Result: _result));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                Directory.CreateDirectory(runFolder);
                _result.ScanCompleted = DateTime.Now;
                ReportGenerator.GenerateHtml(_result, _config, reportPath);
                ReportGenerator.GenerateTxt(_result, _config, txtPath);
                EvidenceExporter.Export(_result, _config, runFolder);
                ManifestWriter.Write(_result, _config, runFolder); // must run last (hashes all other files)

                // Executive report generated after manifest so we can reference manifest hash
                string? manifestHash = null;
                var sha256Path = Path.Combine(runFolder, "manifest.sha256");
                if (File.Exists(sha256Path))
                    manifestHash = File.ReadAllText(sha256Path).Split(' ', 2)[0].Trim().ToUpperInvariant();
                ReportGenerator.GenerateExecutiveHtml(_result, _config, runFolder, manifestHash);

                Report(new ScanProgressUpdate(
                    ScanProgressKind.ReportGenerated,
                    $"Relatório exportado em {runFolder}",
                    HtmlReportPath: reportPath,
                    TextReportPath: txtPath,
                    Result: _result));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Report(new ScanProgressUpdate(
                    ScanProgressKind.ReportFailed,
                    $"Erro ao gerar relatório: {ex.Message}",
                    HtmlReportPath: reportPath,
                    TextReportPath: txtPath,
                    Result: _result,
                    Exception: ex));
            }
        }

        Report(new ScanProgressUpdate(
            ScanProgressKind.ScanCompleted,
            "Varredura concluída.",
            Result: _result));

        return _result;
    }

    private void Report(ScanProgressUpdate update) => _progress?.Report(update);

    private List<BaseModule> BuildModuleList()
    {
        var list = new List<BaseModule>();
        var isFast = _config.Profile == ScanProfile.Fast;
        var isDeep = _config.Profile == ScanProfile.Deep
                  || _config.Profile == ScanProfile.FiveM
                  || _config.Profile == ScanProfile.Florence;

        void Queue(BaseModule module, string forensicImpact = "")
        {
            list.Add(module);
            _result.ModuleCoverage.Add(new ModuleCoverageEntry
            {
                Name = module.Name,
                Status = ModuleStatus.Queued,
                ForensicImpact = forensicImpact
            });
        }

        void Skip(string name, string reason, string forensicImpact) =>
            _result.ModuleCoverage.Add(new ModuleCoverageEntry
            {
                Name = name,
                Status = ModuleStatus.Skipped,
                Reason = reason,
                ForensicImpact = forensicImpact
            });

        // ── Core modules — always run in every profile ────────────────────────
        Queue(new SystemInfoModule());
        Queue(new BamDamModule(),             "Histórico de atividade recente (Background Activity Monitor)");
        Queue(new PrefetchModule(),            "Evidência de execução de processos");
        Queue(new RegistryArtifactsModule(),   "Autoruns e artefatos de registry");
        Queue(new EventViewerModule(),         "Logs de segurança, sistema e aplicação");
        Queue(new DefenderModule(),            "Alertas e configuração do Windows Defender");
        Queue(new KnownCheatsModule(),         "Arquivos de cheat conhecidos no disco");
        Queue(new FileSystemModule(),          "Arquivos suspeitos em paths de risco");
        Queue(new NetworkModule(),             "Histórico de redes conectadas");
        Queue(new ServiceCheckModule(),        "Serviços instalados com nomes suspeitos");
        Queue(new LnkRecentModule(),           "Atalhos recentes — evidência de acesso a arquivos");
        Queue(new RegistryPersistenceModule(), "Persistência via IFEO, AppInit, Winlogon, BootExecute");
        Queue(new SystemResetRestoreModule(),  "Reinstalação, reset e restauração do Windows — perda de cobertura forense");
        Queue(new SystemTamperingModule(),     "LabConfig/MoSetup bypass, BatchGotAdmin, scripts de elevação UAC");
        Queue(new BrowserDownloadsModule(),    "Downloads do Chrome/Edge/Brave/Opera/Firefox — executáveis e URLs suspeitos");
        Queue(new TimelineInvestigationModule(), "Linha do tempo unificada — Prefetch, BAM, LNK, Downloads, Temp");

        // ── Deep-only modules — skipped in fast profile ───────────────────────
        if (isFast)
        {
            Skip("ShimCache",          "Perfil rápido (--profile fast)", "Indício de execução histórico via AppCompatCache");
            Skip("ShellBags",          "Perfil rápido (--profile fast)", "Navegação de pastas suspeitas");
            Skip("Jump Lists",         "Perfil rápido (--profile fast)", "Histórico de acesso recente por aplicação");
            Skip("NVIDIA Artifacts",   "Perfil rápido (--profile fast)", "Timestamps de uso de GPU/sessão FiveM");
            Skip("External Tool Residue", "Perfil rápido (--profile fast)", "Ferramentas de análise/tampering");
            Skip("Recycle Bin",        "Perfil rápido (--profile fast)", "Caminhos originais de arquivos deletados");
            Skip("SRUM",               "Perfil rápido (--profile fast)", "Uso de rede por processo via SRUDB.dat");
        }
        else
        {
            Queue(new ShimCacheModule(),           "Indício de carregamento de executáveis (AppCompatCache)");
            Queue(new ShellBagsModule(),           "Histórico de navegação de pastas — acesso a diretórios suspeitos mesmo após deleção");
            Queue(new JumpListsModule(),           "Histórico de acesso recente por aplicação — executáveis e caminhos suspeitos");
            Queue(new NvidiaArtifactsModule(),     "Timestamps de uso de GPU — confirma execução de app na sessão FiveM");
            Queue(new ExternalToolResidueModule(), "Ferramentas de análise/tampering — Process Hacker, CheatEngine, Everything, x64dbg");
            Queue(new RecycleBinModule(),          "Lixeira — caminho original e data de deleção de arquivos suspeitos");
            Queue(new SrumModule(),                "Uso de rede por processo via SRUDB.dat (~30-60 dias)");
        }

        // ── Admin-gated modules ───────────────────────────────────────────────
        if (isFast)
        {
            Skip("Amcache",    "Perfil rápido (--profile fast)", "SHA1 de executáveis e detecção pós-deleção não coletados");
            Skip("UserAssist", "Perfil rápido (--profile fast)", "Histórico de execuções via Explorer não coletado");
        }
        else if (_result.IsAdministrator)
        {
            Queue(new AmcacheModule(),    "SHA1 e detecção de executáveis pós-deleção");
            Queue(new UserAssistModule(), "Histórico de execuções via Explorer (NTUSER.DAT)");
        }
        else
        {
            Skip("Amcache",    "Requer Administrador — RegLoadKey negado", "SHA1 de executáveis e detecção pós-deleção indisponíveis");
            Skip("UserAssist", "Requer Administrador — NTUSER.DAT inacessível", "Histórico de execuções via Explorer não coletado");
        }

        // ── Flag-gated modules (Deep profile ignores flags and runs both) ─────
        if (isFast)
        {
            Skip("USN Journal",    "Perfil rápido (--profile fast)", "Operações de arquivo de baixo nível não coletadas");
            Skip("Process Memory", "Perfil rápido (--profile fast)", "Varredura de memória de processos não realizada");
        }
        else if (isDeep && _result.IsAdministrator)
        {
            Queue(new UsnJournalModule(),    "Operações de arquivo de baixo nível (criação/deleção/renomeação)");
            Queue(new ProcessMemoryModule(), "Strings suspeitas em memória de processos");
        }
        else if (isDeep)
        {
            Skip("USN Journal",    "Requer Administrador (perfil deep)", "Operações de arquivo de baixo nível não coletadas");
            Skip("Process Memory", "Requer Administrador (perfil deep)", "Strings suspeitas em memória não varridas");
        }
        else
        {
            if (_config.RunUsnJournal && _result.IsAdministrator)
                Queue(new UsnJournalModule(), "Operações de arquivo de baixo nível (criação/deleção/renomeação)");
            else if (_config.RunUsnJournal)
                Skip("USN Journal", "Requer Administrador", "Operações de arquivo de baixo nível não coletadas");
            else
                Skip("USN Journal", "Desativado (--no-usn)", "Operações de arquivo de baixo nível não coletadas");

            if (_config.DeepMemoryScan && _result.IsAdministrator)
                Queue(new ProcessMemoryModule(), "Strings suspeitas em memória de processos");
            else if (_config.DeepMemoryScan)
                Skip("Process Memory", "Requer Administrador", "Strings suspeitas em memória não varridas");
            else
                Skip("Process Memory", "Desativado (--no-memory)", "Varredura de memória de processos não realizada");
        }

        return list;
    }

    private static void ApplyExternalRules(ScanResult result, ExternalRules rules)
    {
        if (rules.CheatHashes.Count == 0 && rules.CheatNames.Count == 0) return;

        var hashSet = new HashSet<string>(rules.CheatHashes, StringComparer.OrdinalIgnoreCase);
        var nameSet = rules.CheatNames
            .Select(n => n.ToLowerInvariant())
            .ToHashSet();

        foreach (var f in result.Findings)
        {
            var entity = (f.Entity ?? f.Title ?? "").ToLowerInvariant();

            // Hash match → Critical + Confirmed (strongest possible signal)
            if (hashSet.Count > 0 && f.Evidence != null && hashSet.Contains(f.Evidence.Trim()))
            {
                f.Risk = RiskLevel.Critical;
                f.ValidationHint = "Hash externo confirmado via rules/cheat_hashes.json";
                f.ScoreEligible  = true;
                continue;
            }

            // Name match → at least High + re-enable score
            if (nameSet.Count > 0 && nameSet.Any(n => entity.Contains(n)))
            {
                if (f.Risk < RiskLevel.High) f.Risk = RiskLevel.High;
                f.ScoreEligible = true;
                f.ValidationHint = (f.ValidationHint != null ? f.ValidationHint + " | " : "")
                    + "Nome externo confirmado via rules/cheat_names.json";
            }
        }
    }

    private static RiskLevel ParseRisk(string s, RiskLevel fallback) =>
        Enum.TryParse<RiskLevel>(s, ignoreCase: true, out var v) ? v : fallback;

    private static Confidence ParseConf(string s, Confidence fallback) =>
        Enum.TryParse<Confidence>(s, ignoreCase: true, out var v) ? v : fallback;

    private static void ApplyFlorenceElevation(ScanResult result)
    {
        // Build entity → contributing-modules map, excluding already-strong evidence
        var entityModules = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in result.Findings)
        {
            if (f.Confidence == Confidence.Confirmed) continue;
            if (f.RuleId?.StartsWith("CORR_") == true) continue;
            var key = (f.Entity ?? f.Title).ToLowerInvariant().Trim();
            if (!entityModules.TryGetValue(key, out var mods))
                entityModules[key] = mods = [];
            mods.Add(f.Module);
        }

        // Downgrade High/Critical with only one source module
        foreach (var f in result.Findings)
        {
            if (f.Risk < RiskLevel.High) continue;
            if (f.Confidence == Confidence.Confirmed) continue;
            if (f.RuleId?.StartsWith("CORR_") == true) continue;
            var key = (f.Entity ?? f.Title).ToLowerInvariant().Trim();
            if (entityModules.TryGetValue(key, out var mods) && mods.Count < 2)
            {
                f.Risk = RiskLevel.Medium;
                f.ValidationHint = (f.ValidationHint != null ? f.ValidationHint + " | " : "")
                    + "Florence: fonte única — corroborar com segundo módulo antes de concluir";
                f.ScoreEligible = false;
            }
        }
    }

    private static bool IsAdmin()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
