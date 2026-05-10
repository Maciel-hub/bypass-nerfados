using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Win32;

namespace BypassNerfados.Scanner.Modules;

// ShimCache (AppCompatCache) is populated by the kernel when a PE is loaded for execution.
// It records the file path + last write time of every executable that ran since last boot,
// surviving across reboots until the cache wraps. Requires no user interaction.
public class ShimCacheModule : BaseModule
{
    public override string Name        => "ShimCache";
    public override string Description => "Histórico de carregamento de executáveis pelo kernel (AppCompatCache)";

    private const string RegPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
    private const string RegValue = "AppCompatCache";

    // Windows 10+ 64-bit entry signature
    private static readonly byte[] Win10EntryMagic = [0x30, 0x31, 0x74, 0x73]; // "01ts"

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        byte[]? raw;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            raw = key?.GetValue(RegValue) as byte[];
        }
        catch (Exception ex)
        {
            LogPartialError("ShimCache/AppCompatCache inacessível via registry", ex);
            return Task.FromResult(findings);
        }

        if (raw == null || raw.Length < 128) return Task.FromResult(findings);

        var paths = ParseShimCache(raw);

        foreach (var (path, lastWrite) in paths)
        {
            ct.ThrowIfCancellationRequested();

            if (IsOwnProcess(path)) continue;
            if (CheatDatabase.IsKnownLegitimate(path)) continue;

            var fileName = Path.GetFileName(path).ToLowerInvariant();
            var (risk, confidence, label) = ClassifyEntry(fileName, path);
            if (risk < RiskLevel.Medium) continue;

            findings.Add(new Finding(
                risk,
                FindingCategory.Cheat,
                "ShimCache",
                $"SHIMCACHE: {label ?? fileName} — indício de carregamento/presença",
                "Executável registrado no AppCompatCache — indício de carregamento/presença no sistema. " +
                "Não confirma execução isoladamente; correlacionar com Prefetch, BAM/DAM ou UserAssist.",
                $"Caminho: {path}",
                timestamp: lastWrite,
                confidence: confidence,
                entity: path,
                ruleId: $"SHIM_{fileName.ToUpperInvariant().Replace('.', '_')}"
            ));
        }

        return Task.FromResult(findings);
    }

    private static List<(string Path, DateTime? LastWrite)> ParseShimCache(byte[] data)
    {
        var results = new List<(string, DateTime?)>();

        // Try Windows 10/11 format: header magic "10ts" at offset 0 (little-endian 0x73743130)
        // Entries follow after 128-byte header, each starting with "10ts" (0x73743130)
        if (data.Length >= 4 &&
            data[0] == 0x73 && data[1] == 0x74 && data[2] == 0x31 && data[3] == 0x30)
        {
            ParseWin10Format(data, results);
        }
        else
        {
            // Unknown format — fall back to UTF-16 path extraction
            ExtractUtf16Paths(data, results);
        }

        return results;
    }

    private static void ParseWin10Format(byte[] data, List<(string, DateTime?)> results)
    {
        // Skip 128-byte header
        var offset = 128;
        while (offset + 12 <= data.Length)
        {
            // Entry signature: "10ts" = 0x73 0x74 0x31 0x30
            if (data[offset]     != 0x73 || data[offset + 1] != 0x74 ||
                data[offset + 2] != 0x31 || data[offset + 3] != 0x30) break;

            if (offset + 12 > data.Length) break;
            var dataLen  = BitConverter.ToInt32(data, offset + 8);
            var pathLen  = BitConverter.ToInt16(data, offset + 12);

            if (dataLen <= 0 || pathLen <= 0 || offset + 14 + pathLen + 8 > data.Length) break;

            var rawPath = System.Text.Encoding.Unicode.GetString(data, offset + 14, pathLen);
            var path    = SanitizePath(rawPath);

            var ftOffset = offset + 14 + pathLen;
            DateTime? lastWrite = null;
            if (ftOffset + 8 <= data.Length)
            {
                var ft = BitConverter.ToInt64(data, ftOffset);
                lastWrite = FileTimeToDateTime(ft);
            }

            if (path != null)
                results.Add((path, lastWrite));

            // Advance: 4 (sig) + 4 (unk) + 4 (datalen) + 2 (pathlen) + pathlen + datalen remainder
            offset += 14 + dataLen;
            if (offset <= 0) break; // guard against overflow
        }
    }

    // Fallback: scan for UTF-16 Windows paths in unknown binary formats.
    // Less precise but handles version variants without crashing.
    private static void ExtractUtf16Paths(byte[] data, List<(string, DateTime?)> results)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var i = 0;
        while (i < data.Length - 6)
        {
            // Look for '\' (0x5C 0x00) in UTF-16LE — start of a path segment
            if (data[i] != 0x5C || data[i + 1] != 0x00) { i++; continue; }

            // Scan backwards for drive letter (e.g. 'C' 0x00)
            var start = i;
            while (start >= 4 &&
                   (data[start - 2] != 0x00 || data[start - 1] != 0x00))
                start -= 2;

            var chars = new List<char>();
            var j = start;
            while (j + 1 < data.Length && !(data[j] == 0 && data[j + 1] == 0 && chars.Count > 3))
            {
                chars.Add((char)(data[j] | (data[j + 1] << 8)));
                j += 2;
            }

            var candidate = SanitizePath(new string([.. chars]));
            if (candidate != null && seen.Add(candidate))
                results.Add((candidate, null));

            i = j > i ? j : i + 2;
        }
    }

    private static (RiskLevel, Confidence, string?) ClassifyEntry(string fileName, string path)
    {
        var cheat = CheatDatabase.TryGetCredibleCheat(fileName, path);
        if (cheat != null)
        {
            var wasGeneric = CheatDatabase.KnownExecutables[fileName].IsGenericName;
            return wasGeneric
                ? (RiskLevel.Medium, Confidence.Low, cheat.Name)
                : (RiskLevel.High, Confidence.High, cheat.Name);
        }
        if (CheatDatabase.IsKnownCheatExecutable(fileName))
            return (RiskLevel.Info, Confidence.Low, null); // generic name, wrong path — suppress

        if (CheatDatabase.IsKnownCheatDll(fileName))
        {
            var e = CheatDatabase.KnownDlls[fileName];
            return (RiskLevel.High, Confidence.High, e.Name);
        }
        if (CheatDatabase.HasSuspiciousKeyword(fileName))
            return (RiskLevel.Medium, Confidence.Medium, null);
        if (CheatDatabase.IsSuspiciousPath(path.ToLowerInvariant()))
            return (RiskLevel.Medium, Confidence.Low, null);
        return (RiskLevel.Info, Confidence.Low, null);
    }

    // Strips leading garbage before the drive letter and trailing non-printable chars.
    // ShimCache binary parsers can misalign and produce paths like "hC:\..." or
    // "C:\foo.exe[garbage]"; this normalizes them or rejects obviously corrupt entries.
    private static string? SanitizePath(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return null;

        // Find first valid drive letter followed by ":\"
        var start = -1;
        for (var i = 0; i < raw.Length - 2; i++)
        {
            if ((raw[i] is >= 'A' and <= 'Z' or >= 'a' and <= 'z')
                && raw[i + 1] == ':' && raw[i + 2] == '\\')
            {
                start = i;
                break;
            }
        }
        if (start < 0) return null;

        var path = raw[start..];

        // Strip null terminators embedded in the string
        var nullIdx = path.IndexOf('\0');
        if (nullIdx >= 0) path = path[..nullIdx];

        // Trim trailing control characters (common in fallback UTF-16 extraction)
        var trimLen = path.Length;
        while (trimLen > 0 && path[trimLen - 1] < ' ')
            trimLen--;
        path = path[..trimLen];

        return path.Length >= 4 ? path : null; // at minimum "C:\x"
    }
}
