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
            IsAdministrator = IsAdmin()
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

            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var findings = await module.RunAsync(_config, cancellationToken);
                sw.Stop();

                _result.Findings.AddRange(findings);
                _result.ModulesRun.Add(module.Name);
                _result.ModuleDurations[module.Name] = sw.Elapsed;

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

        // Build artifact dossiers — group cheat findings by file, enrich with paths/hashes/bypass
        var bundles = EvidenceEnricher.Enrich(_result.Findings);
        _result.EvidenceBundles.AddRange(bundles);

        // Run correlation engine
        cancellationToken.ThrowIfCancellationRequested();
        Report(new ScanProgressUpdate(
            ScanProgressKind.CorrelationStarted,
            "Analisando padrões entre módulos."));

        Correlator.Correlate(_result);

        Report(new ScanProgressUpdate(
            ScanProgressKind.CorrelationCompleted,
            "Correlação concluída."));

        Report(new ScanProgressUpdate(
            ScanProgressKind.ResultReady,
            "Resultado de varredura pronto.",
            Result: _result));

        // Generate report
        if (_config.SaveReport)
        {
            var reportPath = Path.Combine(_config.ReportOutputPath, _config.ReportFileName + ".html");
            var txtPath = Path.Combine(_config.ReportOutputPath, _config.ReportFileName + ".txt");

            Report(new ScanProgressUpdate(
                ScanProgressKind.ReportStarted,
                "Exportando relatório.",
                HtmlReportPath: reportPath,
                TextReportPath: txtPath,
                Result: _result));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                Directory.CreateDirectory(_config.ReportOutputPath);
                ReportGenerator.GenerateHtml(_result, _config, reportPath);
                ReportGenerator.GenerateTxt(_result, _config, txtPath);

                Report(new ScanProgressUpdate(
                    ScanProgressKind.ReportGenerated,
                    "Relatório exportado.",
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
        var list = new List<BaseModule>
        {
            new SystemInfoModule(),
            new BamDamModule(),
            new PrefetchModule(),
            new RegistryArtifactsModule(),
            new EventViewerModule(),
            new DefenderModule(),
            new KnownCheatsModule(),
            new FileSystemModule(),
            new NetworkModule(),
            new ServiceCheckModule(),
        };

        if (_config.RunUsnJournal && _result.IsAdministrator)
            list.Add(new UsnJournalModule());

        if (_config.DeepMemoryScan && _result.IsAdministrator)
            list.Add(new ProcessMemoryModule());

        return list;
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
