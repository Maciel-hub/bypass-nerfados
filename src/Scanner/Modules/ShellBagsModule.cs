using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Win32;
using System.Text;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Examines ShellBags registry keys from HKCU, which record every folder the user
/// browsed via Explorer. Because ShellBags persist even after the target folder is
/// deleted, they are forensically valuable for detecting access to cheat directories
/// that no longer exist on disk.
///
/// Binary ShellItemID parsing is prohibitively complex; instead, printable string
/// runs (UTF-16LE and UTF-8) are extracted from each REG_BINARY value and the
/// resulting path fragments are evaluated against CheatDatabase.
/// </summary>
public class ShellBagsModule : BaseModule
{
    public override string Name        => "ShellBags";
    public override string Description => "Histórico de navegação de pastas (ShellBags) — detecta acesso a diretórios suspeitos";

    // Primary BagMRU path (Windows 8+)
    private const string BagMruPath =
        @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU";

    // Fallback path for older Windows versions
    private const string BagMruPathLegacy =
        @"Software\Microsoft\Windows\Shell\BagMRU";

    // Maximum recursion depth when walking the BagMRU subkey tree
    private const int MaxDepth = 8;

    // Hard cap on total findings emitted by this module
    private const int FindingCap = 50;

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var seen     = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            // Try primary path first, then fall back to legacy location
            using var bagMru =
                Registry.CurrentUser.OpenSubKey(BagMruPath) ??
                Registry.CurrentUser.OpenSubKey(BagMruPathLegacy);

            if (bagMru == null) return Task.FromResult(findings);

            ScanBagMruKey(bagMru, BagMruPath, findings, seen, 0, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            LogPartialError("ShellBags — erro ao ler BagMRU", ex);
        }

        return Task.FromResult(findings);
    }

    /// <summary>
    /// Recursively walks the BagMRU subkey tree (max <see cref="MaxDepth"/> levels).
    /// For each key, all REG_BINARY values are scanned for embedded path strings via
    /// <see cref="ExtractStringsFromBinary"/>. Extracted strings that contain a path
    /// separator are evaluated against CheatDatabase.
    /// </summary>
    private void ScanBagMruKey(
        RegistryKey key,
        string path,
        List<Finding> findings,
        HashSet<string> seen,
        int depth,
        CancellationToken ct)
    {
        if (depth > MaxDepth) return;
        ct.ThrowIfCancellationRequested();

        // Process binary values in the current key
        try
        {
            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (findings.Count >= FindingCap) return;

                // Only inspect REG_BINARY values; skip MRUListEx and other integers
                if (key.GetValueKind(valueName) != RegistryValueKind.Binary) continue;

                var data = key.GetValue(valueName) as byte[];
                if (data == null || data.Length == 0) continue;

                foreach (var extracted in ExtractStringsFromBinary(data))
                {
                    if (findings.Count >= FindingCap) return;

                    // Only consider strings that look like paths (contain backslash)
                    if (!extracted.Contains('\\')) continue;

                    EvaluateExtractedPath(extracted, findings, seen);
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            LogPartialError($"ShellBags — erro ao ler valores de {path}", ex);
        }

        // Recurse into subkeys (each represents a subfolder level in the MRU tree)
        try
        {
            foreach (var subKeyName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                if (findings.Count >= FindingCap) return;

                try
                {
                    using var sub = key.OpenSubKey(subKeyName);
                    if (sub == null) continue;
                    ScanBagMruKey(sub, $@"{path}\{subKeyName}", findings, seen, depth + 1, ct);
                }
                catch (OperationCanceledException) { throw; }
                catch { /* skip inaccessible subkey */ }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            LogPartialError($"ShellBags — erro ao enumerar subkeys de {path}", ex);
        }
    }

    /// <summary>
    /// Evaluates a single extracted path string against CheatDatabase and emits a
    /// Finding when a suspicious signal is detected. Uses <paramref name="seen"/> to
    /// deduplicate by ruleId so the same path is not reported multiple times.
    /// </summary>
    private static void EvaluateExtractedPath(
        string extractedPath,
        List<Finding> findings,
        HashSet<string> seen)
    {
        if (string.IsNullOrWhiteSpace(extractedPath)) return;
        if (IsOwnProcess(extractedPath)) return;
        if (CheatDatabase.IsKnownLegitimate(extractedPath)) return;

        // Compute a short hash for stable ruleId generation
        var hash8 = PathHash8(extractedPath);

        if (CheatDatabase.HasSuspiciousKeyword(extractedPath) &&
            !CheatDatabase.IsKnownLegitimate(extractedPath))
        {
            var ruleId = $"SHELLBAG_SUSPICIOUS_{hash8}";
            if (!seen.Add(ruleId)) return;

            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.RegistryArtifact,
                "ShellBags",
                $"ShellBag — pasta suspeita navegada: {Path.GetFileName(extractedPath)}",
                $"O Explorer registrou navegação para uma pasta com nome/palavra-chave suspeita. " +
                $"ShellBags persistem mesmo após a deleção da pasta.\nCaminho: {extractedPath}",
                evidence: extractedPath,
                confidence: Confidence.Medium,
                ruleId: ruleId,
                entity: extractedPath,
                validationHint: "ShellBags registram navegação mesmo após deleção da pasta — correlacionar com USN Journal e Prefetch"
            ));
            return;
        }

        if (CheatDatabase.IsSuspiciousPath(extractedPath.ToLowerInvariant()) &&
            extractedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            var ruleId = $"SHELLBAG_PATH_{hash8}";
            if (!seen.Add(ruleId)) return;

            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.RegistryArtifact,
                "ShellBags",
                $"ShellBag — caminho suspeito navegado: {Path.GetFileName(extractedPath)}",
                $"O Explorer registrou navegação para um caminho classificado como suspeito. " +
                $"ShellBags persistem mesmo após a deleção da pasta.\nCaminho: {extractedPath}",
                evidence: extractedPath,
                confidence: Confidence.Low,
                ruleId: ruleId,
                entity: extractedPath,
                validationHint: "ShellBags registram navegação mesmo após deleção da pasta — correlacionar com USN Journal e Prefetch"
            ));
        }
    }

    /// <summary>
    /// Extracts printable string runs from raw binary data using two strategies:
    /// <list type="bullet">
    ///   <item>UTF-16LE: scans with a 2-byte stride, collects runs where the high byte
    ///   is 0x00 and the low byte is a printable ASCII character (0x20–0x7E).</item>
    ///   <item>UTF-8 / Latin-1: collects runs of printable bytes (0x20–0x7E).</item>
    /// </list>
    /// Both strategies yield strings of at least <paramref name="minLength"/> characters.
    /// Results are deduplicated before being returned.
    /// </summary>
    private static IEnumerable<string> ExtractStringsFromBinary(byte[] data, int minLength = 5)
    {
        var results = new HashSet<string>(StringComparer.Ordinal);

        // --- UTF-16LE extraction ---
        // Walk the buffer two bytes at a time. Accumulate chars where the high byte is
        // 0x00 and the low byte falls in the printable ASCII range.
        var run16 = new StringBuilder();
        for (var i = 0; i + 1 < data.Length; i += 2)
        {
            var lo = data[i];
            var hi = data[i + 1];

            if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E)
            {
                run16.Append((char)lo);
            }
            else
            {
                if (run16.Length >= minLength)
                    results.Add(run16.ToString());
                run16.Clear();
            }
        }
        if (run16.Length >= minLength)
            results.Add(run16.ToString());

        // --- UTF-8 / Latin-1 extraction (byte-by-byte) ---
        var run8 = new StringBuilder();
        foreach (var b in data)
        {
            if (b >= 0x20 && b <= 0x7E)
            {
                run8.Append((char)b);
            }
            else
            {
                if (run8.Length >= minLength)
                    results.Add(run8.ToString());
                run8.Clear();
            }
        }
        if (run8.Length >= minLength)
            results.Add(run8.ToString());

        return results;
    }

    /// <summary>
    /// Computes the first 8 hex characters of the SHA-256 hash of the given string
    /// (UTF-8 encoded). Used to generate stable, compact ruleId suffixes.
    /// </summary>
    private static string PathHash8(string value) =>
        Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                Encoding.UTF8.GetBytes(value)))[..8];
}
