using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using System.Text;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Scans Windows Jump List files (AutomaticDestinations and CustomDestinations) for
/// recently accessed file paths. Jump Lists are per-application OLE Compound Document
/// files that embed LNK (Shell Link) entries for recently opened items. Because the
/// records survive the deletion of the referenced files, they provide forensic evidence
/// of access to suspicious executables and cheat-related directories.
///
/// Full OLE/LNK parsing is skipped in favour of a binary string extraction approach:
/// UTF-16LE path-like runs are pulled from the raw bytes and evaluated against
/// CheatDatabase.
/// </summary>
public class JumpListsModule : BaseModule
{
    public override string Name        => "Jump Lists";
    public override string Description => "Histórico de acesso recente por aplicação (AutomaticDestinations/CustomDestinations) — detecta acesso a arquivos suspeitos";

    // Hard cap on total findings emitted by this module
    private const int FindingCap = 60;

    // Minimum character length for an extracted string to be considered a path
    private const int MinPathLength = 6;

    // Windows drive-letter pattern prefix (e.g. "C:\")
    private const char DriveSeparator = ':';

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var seen     = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Resolve %APPDATA% for the current user
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // AutomaticDestinations — updated automatically by Windows
        var autoDestDir = Path.Combine(
            appData,
            @"Microsoft\Windows\Recent\AutomaticDestinations");

        try
        {
            if (Directory.Exists(autoDestDir))
            {
                foreach (var file in Directory.EnumerateFiles(
                             autoDestDir, "*.automaticDestinations-ms"))
                {
                    ct.ThrowIfCancellationRequested();
                    if (findings.Count >= FindingCap) break;

                    try { AnalyzeDestinationFile(file, findings, seen, ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { /* silently skip corrupt or inaccessible files */ }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            LogPartialError("Jump Lists — erro ao enumerar AutomaticDestinations", ex);
        }

        // CustomDestinations — populated by applications via ICustomDestinationList
        var customDestDir = Path.Combine(
            appData,
            @"Microsoft\Windows\Recent\CustomDestinations");

        try
        {
            if (Directory.Exists(customDestDir))
            {
                foreach (var file in Directory.EnumerateFiles(
                             customDestDir, "*.customDestinations-ms"))
                {
                    ct.ThrowIfCancellationRequested();
                    if (findings.Count >= FindingCap) break;

                    try { AnalyzeDestinationFile(file, findings, seen, ct); }
                    catch (OperationCanceledException) { throw; }
                    catch { /* silently skip corrupt or inaccessible files */ }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            LogPartialError("Jump Lists — erro ao enumerar CustomDestinations", ex);
        }

        return Task.FromResult(findings);
    }

    /// <summary>
    /// Reads a single .automaticDestinations-ms or .customDestinations-ms file,
    /// extracts path-like strings from its raw bytes, and emits findings for any
    /// path that matches CheatDatabase signals.
    ///
    /// The file is copied to a temp location before reading because Jump List files
    /// may be exclusively locked by the shell while Windows is running.
    /// </summary>
    private void AnalyzeDestinationFile(
        string filePath,
        List<Finding> findings,
        HashSet<string> seen,
        CancellationToken ct)
    {
        var sourceFileName = Path.GetFileName(filePath);

        // Copy locked file to temp path so we can read it safely
        var tempPath = CopyLockedFile(filePath);
        if (tempPath == null) return;

        try
        {
            var data = File.ReadAllBytes(tempPath);

            foreach (var extractedPath in ExtractPathsFromBinary(data))
            {
                ct.ThrowIfCancellationRequested();
                if (findings.Count >= FindingCap) return;

                // Deduplicate by normalised (lowercased) path
                if (!seen.Add(extractedPath.ToLowerInvariant())) continue;

                // Minimum plausible path length
                if (extractedPath.Length < 10) continue;

                // Must look like a Windows absolute path: drive letter + colon, or UNC (\\)
                if (!IsWindowsPath(extractedPath)) continue;

                if (IsOwnProcess(extractedPath)) continue;
                if (CheatDatabase.IsKnownLegitimate(extractedPath)) continue;

                var fileName = Path.GetFileName(extractedPath).ToLowerInvariant();
                if (string.IsNullOrEmpty(fileName)) continue;

                EvaluatePath(extractedPath, fileName, sourceFileName, findings);
            }
        }
        finally
        {
            // Always clean up the temp copy
            try { File.Delete(tempPath); } catch { }
        }
    }

    /// <summary>
    /// Evaluates a single extracted path against CheatDatabase and emits the
    /// appropriate finding when a signal is detected.
    /// </summary>
    private static void EvaluatePath(
        string path,
        string fileName,
        string sourceFileName,
        List<Finding> findings)
    {
        // Tier 1 — credible cheat match (name + path confirmation)
        var cheat = CheatDatabase.TryGetCredibleCheat(fileName, path);
        if (cheat != null)
        {
            var ruleId = $"JUMPLIST_CHEAT_{fileName.ToUpperInvariant().Replace('.', '_')}";
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.Cheat,
                "Jump Lists",
                $"JUMP LIST — CHEAT: {cheat.Name} ({fileName})",
                $"Jump List registra acesso recente a executável cheat. " +
                $"Origem: {sourceFileName}\n{cheat.Description}",
                evidence: $"Caminho: {path} | Arquivo: {sourceFileName}",
                confidence: Confidence.High,
                ruleId: ruleId,
                entity: path,
                validationHint: "Jump Lists registram acesso mesmo após deleção — correlacionar com Prefetch e Amcache"
            ));
            return;
        }

        // Tier 2 — suspicious keyword in file name
        if (CheatDatabase.HasSuspiciousKeyword(fileName))
        {
            var ruleId = $"JUMPLIST_SUSPICIOUS_{StringHash8(fileName + path)}";
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.SuspiciousExecution,
                "Jump Lists",
                $"Jump List — executável suspeito: {fileName}",
                $"Jump List registra acesso recente a um arquivo com nome suspeito. " +
                $"Origem: {sourceFileName}",
                evidence: $"Caminho: {path} | Arquivo: {sourceFileName}",
                confidence: Confidence.Medium,
                ruleId: ruleId,
                entity: path,
                validationHint: "Jump Lists registram acesso mesmo após deleção — correlacionar com Prefetch e Amcache"
            ));
            return;
        }

        // Tier 3 — suspicious install/run path with risky extension
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        if (CheatDatabase.IsSuspiciousPath(path.ToLowerInvariant()) &&
            ext is ".exe" or ".dll" or ".bat" or ".ps1" or ".cmd")
        {
            var ruleId = $"JUMPLIST_PATH_{StringHash8(fileName + path)}";
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.FileSystem,
                "Jump Lists",
                $"Jump List — arquivo em caminho suspeito: {fileName}",
                $"Jump List registra acesso a um arquivo localizado em caminho suspeito. " +
                $"Origem: {sourceFileName}",
                evidence: $"Caminho: {path} | Arquivo: {sourceFileName}",
                confidence: Confidence.Low,
                ruleId: ruleId,
                entity: path,
                validationHint: "Jump Lists registram acesso mesmo após deleção — correlacionar com Prefetch e Amcache"
            ));
        }
    }

    /// <summary>
    /// Extracts path-like string runs from raw binary data using UTF-16LE detection.
    /// Scans byte pairs; a valid UTF-16LE printable ASCII character requires the high
    /// byte to be 0x00 and the low byte to be in range 0x20–0x7E. Runs of at least
    /// <paramref name="minLength"/> chars that contain a backslash (path separator)
    /// are returned.
    /// </summary>
    private static List<string> ExtractPathsFromBinary(byte[] data, int minLength = 6)
    {
        var results = new List<string>();
        var run     = new StringBuilder();

        for (var i = 0; i + 1 < data.Length; i += 2)
        {
            var lo = data[i];
            var hi = data[i + 1];

            if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E)
            {
                run.Append((char)lo);
            }
            else
            {
                FlushRun(run, minLength, results);
                run.Clear();
            }
        }
        FlushRun(run, minLength, results);

        return results;
    }

    /// <summary>
    /// Appends the contents of <paramref name="run"/> to <paramref name="results"/>
    /// when the run meets the minimum length and contains a path separator.
    /// </summary>
    private static void FlushRun(StringBuilder run, int minLength, List<string> results)
    {
        if (run.Length >= minLength)
        {
            var s = run.ToString();
            if (s.Contains('\\'))
                results.Add(s);
        }
    }

    /// <summary>
    /// Returns true when the string looks like a Windows absolute path:
    /// either a drive-letter path (e.g. "C:\foo") or a UNC path ("\\server\share").
    /// </summary>
    private static bool IsWindowsPath(string s)
    {
        if (s.Length < 3) return false;

        // UNC path: \\server\share
        if (s[0] == '\\' && s[1] == '\\') return true;

        // Drive-letter path: X:\...
        if (char.IsLetter(s[0]) && s[1] == DriveSeparator && s[2] == '\\') return true;

        return false;
    }

    /// <summary>
    /// Returns the first 8 uppercase hex characters of the SHA-256 hash of
    /// <paramref name="value"/> (UTF-8 encoded). Used to produce stable, compact
    /// ruleId suffixes.
    /// </summary>
    private static string StringHash8(string value) =>
        Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                Encoding.UTF8.GetBytes(value)))[..8];
}
