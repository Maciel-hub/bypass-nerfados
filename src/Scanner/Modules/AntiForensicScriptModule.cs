using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Detecta scripts de limpeza anti-forense: padrões do anti-echo.py, BatchGotAdmin,
/// domains C2 conhecidos e artefatos de DriverBooster loader em scripts do usuário.
/// </summary>
public class AntiForensicScriptModule : BaseModule
{
    public override string Name        => "Anti-Forensic Scripts";
    public override string Description => "Scripts de limpeza anti-forense — anti-echo.py, BatchGotAdmin UAC, domains C2 e DriverBooster artifacts";

    private static readonly string[] ScriptExtensions = [".py", ".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".js", ".cfg"];

    private static IEnumerable<string> GetScanRoots()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        yield return Path.GetTempPath();
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    // Token groups for anti-echo cleanup script scoring.
    // 3+ groups → Critical, 2 → High, 1 → Medium (not score-eligible).
    // Each group represents an independent evidence category — multiple groups = coordinated cleanup.
    private static readonly string[][] AntiEchoTokenGroups =
    [
        // Group 0: Event log manipulation
        ["wevtutil", ".evtx", "clear-log", "cl security", "cl system", "cl application"],
        // Group 1: Prefetch / Recent / JumpList artifacts
        ["prefetch", "recent", "automaticdestinations", "customdestinations", "appdata\\roaming\\microsoft\\windows\\recent"],
        // Group 2: Registry history wipe (BAM, UserAssist, AppCompat, ShimCache)
        ["reg delete", "bam", "userassist", "appcompatcache", "shimcache", "runmru", "recentdocs"],
        // Group 3: Browser track clearing
        ["clearmytracksbyprocess", "inetcpl.cpl", "rundll32", "clearmytracks"],
        // Group 4: DriverBooster / loader artifact references
        ["driverbooster", "driver booster", "loader.dll", "loader.cfg"],
        // Group 5: Python anti-echo / brembo references
        ["anti-echo", "antiecho", "brembo", "echo_nerfados", "echonerfados", "bypass_echo"],
    ];

    // BatchGotAdmin UAC stub indicators
    private static readonly string[] BatchGotAdminTokens =
    [
        "getadmin.vbs",
        "shell.application",
        "shellexecute",
        "runas",
        "cacls.exe",
        "net localgroup administrators",
        "batchgotadmin",
    ];

    // Known C2 domains used by FiveM bypass infrastructure
    private static readonly string[] KnownC2Domains =
    [
        "api.tzproject.com",
        "lmarket.fr",
        "ovix.one",
    ];

    // DriverBooster loader artifact paths (Steam common path + known filenames)
    private static readonly string[] DriverBoosterArtifacts =
    [
        "driverbooster",
        "driver booster",
        @"steamapps\common\driverbooster",
        "loader.dll",
        "loader.cfg",
        "driverbooster.dll",
        "driverbooster.cfg",
    ];

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            foreach (var root in GetScanRoots())
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                try
                {
                    var opts = new EnumerationOptions
                    {
                        RecurseSubdirectories = true,
                        MaxRecursionDepth     = 3,
                        IgnoreInaccessible    = true,
                    };

                    foreach (var file in Directory.EnumerateFiles(root, "*", opts))
                    {
                        ct.ThrowIfCancellationRequested();
                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (!ScriptExtensions.Contains(ext)) continue;
                        if (IsOwnProcess(file)) continue;

                        AnalyzeFile(file, findings);
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { LogPartialError($"AntiForensicScriptModule — raiz '{root}' inacessível", ex); }
            }
        }, ct);

        return findings;
    }

    private void AnalyzeFile(string filePath, List<Finding> findings)
    {
        string content;
        try
        {
            content = File.ReadAllText(filePath);
        }
        catch (IOException)                 { return; }
        catch (UnauthorizedAccessException) { return; }
        catch (Exception ex)
        {
            LogPartialError($"AntiForensicScriptModule — leitura de '{filePath}' falhou", ex);
            return;
        }

        var lower   = content.ToLowerInvariant();
        var info    = new FileInfo(filePath);
        var sha256  = GetFileHash(filePath) ?? "N/A";
        var baseName = Path.GetFileName(filePath);

        // ── Anti-echo cleanup script (token group scoring) ─────────────────────
        var matchedGroups = AntiEchoTokenGroups
            .Select((group, idx) => (idx, matched: group.Any(t => lower.Contains(t))))
            .Where(x => x.matched)
            .Select(x => x.idx)
            .ToList();

        if (matchedGroups.Count >= 1)
        {
            RiskLevel risk;
            bool scoreEligible;
            string groupLabel;

            if (matchedGroups.Count >= 3)
            {
                risk          = RiskLevel.Critical;
                scoreEligible = true;
                groupLabel    = $"{matchedGroups.Count} grupos de evidência — limpeza coordenada";
            }
            else if (matchedGroups.Count == 2)
            {
                risk          = RiskLevel.High;
                scoreEligible = true;
                groupLabel    = "2 grupos de evidência — múltiplas trilhas alvo";
            }
            else
            {
                risk          = RiskLevel.Medium;
                scoreEligible = false;
                groupLabel    = "1 grupo de evidência — indicador isolado";
            }

            var groupNames = matchedGroups.Select(g => g switch
            {
                0 => "event-log-wipe",
                1 => "prefetch-recent-jumplists",
                2 => "registry-history",
                3 => "browser-tracks",
                4 => "driverbooster-loader",
                5 => "anti-echo-python",
                _ => $"group-{g}"
            });

            var finding = new Finding(
                risk,
                FindingCategory.AntiForensics,
                Name,
                $"SCRIPT ANTI-FORENSE DETECTADO: {baseName}",
                $"Script contém padrões de limpeza anti-forense ({groupLabel}).\n" +
                $"Grupos atingidos: {string.Join(", ", groupNames)}\n" +
                $"Arquivo: {filePath}\nSHA256: {sha256}",
                $"SHA256: {sha256} | Tamanho: {info.Length} bytes | Modificado: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: matchedGroups.Count >= 3 ? Confidence.High : Confidence.Medium,
                ruleId: "ANTI_ECHO_CLEANUP_SCRIPT",
                entity: filePath
            );
            finding.ScoreEligible = scoreEligible;
            findings.Add(finding);
        }

        // ── BatchGotAdmin UAC stub ─────────────────────────────────────────────
        var uacMatches = BatchGotAdminTokens.Where(t => lower.Contains(t)).ToList();
        if (uacMatches.Count >= 2)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.SystemTampering,
                Name,
                $"SCRIPT UAC BATCHGOTADMIN: {baseName}",
                $"Script contém padrão de autoelevação UAC (BatchGotAdmin).\n" +
                $"Tokens encontrados: {string.Join(", ", uacMatches)}\n" +
                $"Arquivo: {filePath}\nSHA256: {sha256}",
                $"SHA256: {sha256} | Tamanho: {info.Length} bytes | Modificado: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: Confidence.Medium,
                ruleId: "SCRIPT_BATCHGOTADMIN_UAC_STUB",
                entity: filePath
            ));
        }

        // ── Known C2 domains ───────────────────────────────────────────────────
        foreach (var domain in KnownC2Domains)
        {
            if (!lower.Contains(domain)) continue;

            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.AntiForensics,
                Name,
                $"DOMÍNIO C2 CONHECIDO EM SCRIPT: {domain}",
                $"Script referencia domínio de infraestrutura bypass FiveM conhecida.\n" +
                $"Domínio: {domain}\nArquivo: {filePath}\nSHA256: {sha256}",
                $"Domínio: {domain} | SHA256: {sha256} | Modificado: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: Confidence.High,
                ruleId: "ANTI_ECHO_KNOWN_C2_DOMAIN",
                entity: domain
            ));
        }

        // ── DriverBooster loader artifact references ───────────────────────────
        var dbMatches = DriverBoosterArtifacts.Where(t => lower.Contains(t)).ToList();
        if (dbMatches.Count >= 2)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                Name,
                $"ARTEFATO DRIVERBOOSTER LOADER EM SCRIPT: {baseName}",
                $"Script referencia artefatos de DriverBooster loader — padrão de bypass via driver vulnerável.\n" +
                $"Tokens: {string.Join(", ", dbMatches)}\nArquivo: {filePath}\nSHA256: {sha256}",
                $"SHA256: {sha256} | Tamanho: {info.Length} bytes | Modificado: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: Confidence.Medium,
                ruleId: "ANTIECHO_DRIVERBOOSTER_LOADER_ARTIFACT",
                entity: filePath
            ));
        }
    }
}
