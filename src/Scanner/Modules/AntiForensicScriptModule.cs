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

    // Executable script types — C2 domain in these = Critical; in .js/.cfg = High only
    private static readonly HashSet<string> ExecutableExts = new(StringComparer.OrdinalIgnoreCase)
        { ".py", ".bat", ".cmd", ".ps1", ".vbs", ".wsf" };

    // Max file size to avoid reading large transpiled bundles / log dumps
    private const long MaxFileSizeBytes = 1 * 1024 * 1024; // 1 MB

    // Directory name segments that disqualify a file from scanning
    private static readonly HashSet<string> SkippedDirSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules", ".nuget", "npm", "pip", "pip-cache",
        "Packages",         // UWP sandbox
        "INetCache",
    };

    // Path substrings that disqualify a file (handles versioned browser user-data dirs)
    private static readonly string[] SkippedPathSubstrings =
    [
        @"\Microsoft\Edge\User Data\",
        @"\Google\Chrome\User Data\",
        @"\BraveSoftware\Brave-Browser\User Data\",
        @"\Microsoft\Windows\INetCache\",
        @"\Microsoft\Windows\Temporary Internet Files\",
        @"\AppData\Local\Packages\",
        @"\AppData\Local\Microsoft\OneDrive\",
        @"\npm-cache\",
        @"\pip\http\",
    ];

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
    // Each group is an independent evidence category — multiple groups = coordinated cleanup.
    private static readonly string[][] AntiEchoTokenGroups =
    [
        // Group 0: Event log manipulation (all terms are highly specific to admin log ops)
        ["wevtutil", ".evtx", "clear-log", "cl security", "cl system", "cl application"],
        // Group 1: Prefetch / JumpList path references (specific file extensions/paths)
        ["automaticdestinations-ms", "customdestinations-ms", "appdata\\roaming\\microsoft\\windows\\recent",
         "c:\\windows\\prefetch", "\\prefetch\\"],
        // Group 2: Registry history wipe commands
        ["reg delete", "remove-item hklm", "remove-item hkcu", "userassist",
         "appcompatcache", "shimcache", "runmru", "recentdocs"],
        // Group 3: Track clearing via rundll32 (requires the specific API name)
        ["clearmytracksbyprocess", "clearmytracks", "inetcpl.cpl"],
        // Group 4: DriverBooster loader artifacts
        ["driverbooster", "driver booster", "loader.dll", "loader.cfg"],
        // Group 5: Anti-echo / brembo identity strings (very specific)
        ["anti-echo", "antiecho", "brembo", "echo_nerfados", "echonerfados", "bypass_echo"],
    ];

    // BatchGotAdmin UAC stub indicators (require 2+ to reduce noise from vbs snippets)
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

    // DriverBooster loader-specific filenames (must appear in the script to flag)
    private static readonly string[] DriverBoosterLoaderTokens =
    [
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

                int readFailures = 0;

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
                        if (IsInSkippedDirectory(file)) continue;

                        try
                        {
                            var size = new FileInfo(file).Length;
                            if (size > MaxFileSizeBytes) continue;
                        }
                        catch { continue; }

                        if (!AnalyzeFile(file, ext, findings))
                            readFailures++;
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { LogPartialError($"AntiForensicScriptModule — raiz '{root}' inacessível", ex); }

                if (readFailures > 0)
                    LogPartialError($"AntiForensicScriptModule — {readFailures} arquivo(s) em '{root}' não puderam ser lidos (acesso negado ou lock)", null!);
            }
        }, ct);

        return findings;
    }

    // Returns false if the file could not be read
    private bool AnalyzeFile(string filePath, string ext, List<Finding> findings)
    {
        string content;
        try
        {
            content = File.ReadAllText(filePath);
        }
        catch (IOException)                 { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (Exception ex)
        {
            LogPartialError($"AntiForensicScriptModule — leitura de '{Path.GetFileName(filePath)}' falhou", ex);
            return true; // not a simple read failure — still counted as processed
        }

        var lower    = content.ToLowerInvariant();
        var info     = new FileInfo(filePath);
        var sha256   = GetFileHash(filePath) ?? "N/A";
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
                1 => "prefetch-jumplists",
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
                $"Grupos: {string.Join(", ", groupNames)}\n" +
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
                $"Tokens: {string.Join(", ", uacMatches)}\nArquivo: {filePath}\nSHA256: {sha256}",
                $"SHA256: {sha256} | Tamanho: {info.Length} bytes | Modificado: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: Confidence.Medium,
                ruleId: "SCRIPT_BATCHGOTADMIN_UAC_STUB",
                entity: filePath
            ));
        }

        // ── Known C2 domains ───────────────────────────────────────────────────
        // Critical only for executable script types; High+hint for .js/.cfg
        foreach (var domain in KnownC2Domains)
        {
            if (!lower.Contains(domain)) continue;

            bool isExecScript = ExecutableExts.Contains(ext);
            findings.Add(new Finding(
                isExecScript ? RiskLevel.Critical : RiskLevel.High,
                FindingCategory.AntiForensics,
                Name,
                $"DOMÍNIO C2 CONHECIDO EM SCRIPT: {domain}",
                $"Script referencia domínio de infraestrutura bypass FiveM conhecida.\n" +
                $"Domínio: {domain}\nArquivo: {filePath}\nSHA256: {sha256}",
                $"Domínio: {domain} | SHA256: {sha256} | Modificado: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: isExecScript ? Confidence.High : Confidence.Medium,
                ruleId: "ANTI_ECHO_KNOWN_C2_DOMAIN",
                entity: domain,
                validationHint: isExecScript ? null
                    : $"Domínio encontrado em {ext} — confirmar contexto de execução antes de concluir"
            ));
        }

        // ── DriverBooster loader artifact references ───────────────────────────
        // Require specific loader artifact filenames, not just "driverbooster" generically
        var loaderMatches = DriverBoosterLoaderTokens.Where(t => lower.Contains(t)).ToList();
        bool hasDriverBoosterName = lower.Contains("driverbooster") || lower.Contains("driver booster");

        if (loaderMatches.Count >= 1)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                Name,
                $"ARTEFATO DRIVERBOOSTER LOADER EM SCRIPT: {baseName}",
                $"Script referencia artefato de loader de driver vulnerável.\n" +
                $"Tokens: {string.Join(", ", loaderMatches)}\nArquivo: {filePath}\nSHA256: {sha256}",
                $"SHA256: {sha256} | Tamanho: {info.Length} bytes | Modificado: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: Confidence.Medium,
                ruleId: "ANTIECHO_DRIVERBOOSTER_LOADER_ARTIFACT",
                entity: filePath
            ));
        }
        else if (hasDriverBoosterName)
        {
            // Generic DriverBooster mention without specific loader artifacts — low signal
            findings.Add(new Finding(
                RiskLevel.Low,
                FindingCategory.AntiForensics,
                Name,
                $"Referência a DriverBooster em script: {baseName}",
                $"Script menciona DriverBooster sem artefato de loader específico — pode ser uninstall/update legítimo.\n" +
                $"Arquivo: {filePath}\nSHA256: {sha256}",
                $"SHA256: {sha256} | Modificado: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: Confidence.Low,
                ruleId: "ANTIECHO_DRIVERBOOSTER_LOADER_ARTIFACT",
                entity: filePath,
                validationHint: "Confirmar ausência de loader.dll/loader.cfg e correlacionar com Driver & Kernel module"
            ));
        }

        return true;
    }

    private static bool IsInSkippedDirectory(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath) ?? "";
        foreach (var segment in dir.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            if (SkippedDirSegments.Contains(segment)) return true;
        }
        foreach (var sub in SkippedPathSubstrings)
        {
            if (filePath.Contains(sub, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
