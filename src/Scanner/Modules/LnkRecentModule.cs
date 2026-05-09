using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using System.Text;
using System.Text.RegularExpressions;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Reads Windows LNK (Shell Link) files from each user's Recent folder.
/// Parses the binary LNK format to extract the target path, then checks
/// against CheatDatabase. Also scans AutomaticDestinations JumpList files
/// (raw byte scan) for known cheat executable names.
/// </summary>
public class LnkRecentModule : BaseModule
{
    public override string Name        => "LNK Recent";
    public override string Description => "Arquivos LNK recentes — rastreia execução de cheats pelos atalhos do Windows";

    // LNK magic bytes: 0x4C at offset 0 (little-endian GUID follows)
    private const uint LnkMagic = 0x4C;

    // LNK header is always 76 bytes
    private const int LnkHeaderSize = 76;

    // Regex for fallback ASCII path extraction from raw LNK bytes
    private static readonly Regex PathRegex = new(
        @"[A-Za-z]:\\[^\x00-\x1F]{5,}",
        RegexOptions.Compiled);

    // Regex to extract .exe names from AutomaticDestinations raw bytes
    private static readonly Regex ExeNameRegex = new(
        @"[A-Za-z0-9_\-]{2,}\.exe",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        foreach (var userDir in EnumerateUserDirectories())
        {
            ct.ThrowIfCancellationRequested();
            ScanRecentFolder(userDir, findings, ct);
            ScanAutomaticDestinations(userDir, findings, ct);
        }

        return Task.FromResult(findings);
    }

    /// <summary>
    /// Enumerates profile directories under C:\Users, skipping built-in accounts.
    /// </summary>
    private static IEnumerable<string> EnumerateUserDirectories()
    {
        var usersRoot = @"C:\Users";
        if (!Directory.Exists(usersRoot)) yield break;

        // Skip well-known non-user directories
        var skipNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Default", "Default User", "Public", "All Users", "defaultuser0"
        };

        foreach (var dir in Directory.EnumerateDirectories(usersRoot))
        {
            var name = Path.GetFileName(dir);
            if (skipNames.Contains(name ?? "")) continue;
            yield return dir;
        }
    }

    /// <summary>
    /// Scans *.lnk files in %USERPROFILE%\AppData\Microsoft\Windows\Recent.
    /// </summary>
    private static void ScanRecentFolder(string userDir, List<Finding> findings, CancellationToken ct)
    {
        var recentPath = Path.Combine(userDir, @"AppData\Roaming\Microsoft\Windows\Recent");
        if (!Directory.Exists(recentPath)) return;

        foreach (var lnkPath in Directory.EnumerateFiles(recentPath, "*.lnk", SearchOption.TopDirectoryOnly))
        {
            ct.ThrowIfCancellationRequested();
            ProcessLnkFile(lnkPath, findings);
        }
    }

    /// <summary>
    /// Scans AutomaticDestinations JumpList files for known cheat exe names via raw byte regex.
    /// OLE structured storage parsing is skipped — a raw text scan is sufficient for name extraction.
    /// </summary>
    private static void ScanAutomaticDestinations(string userDir, List<Finding> findings, CancellationToken ct)
    {
        var destPath = Path.Combine(
            userDir,
            @"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations");

        if (!Directory.Exists(destPath)) return;

        foreach (var file in Directory.EnumerateFiles(destPath, "*.automaticDestinations-ms"))
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var raw = File.ReadAllBytes(file);
                // Decode as Latin-1 so raw bytes are preserved as printable chars
                var text = Encoding.Latin1.GetString(raw);

                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (Match m in ExeNameRegex.Matches(text))
                {
                    var exeName = m.Value.ToLowerInvariant();
                    if (!seen.Add(exeName)) continue;
                    if (IsOwnProcess(exeName)) continue;
                    if (CheatDatabase.IsKnownLegitimate(exeName)) continue;

                    if (CheatDatabase.IsKnownCheatExecutable(exeName))
                    {
                        var cheat = CheatDatabase.KnownExecutables[exeName];
                        findings.Add(new Finding(
                            cheat.IsGenericName ? RiskLevel.Medium : RiskLevel.High,
                            FindingCategory.Cheat,
                            "LNK Recent",
                            $"JUMPLISTS: {cheat.Name} ({exeName})",
                            $"Nome de executável cheat encontrado nos JumpLists do Windows (AutomaticDestinations).\n{cheat.Description}",
                            $"Arquivo: {Path.GetFileName(file)} | Executável: {exeName}",
                            confidence: cheat.IsGenericName ? Confidence.Low : Confidence.Medium,
                            ruleId: $"LNK_DEST_{exeName.ToUpperInvariant().Replace('.', '_')}",
                            entity: exeName,
                            validationHint: cheat.IsGenericName ? "Confirmar por hash ou caminho típico" : null
                        ));
                    }
                    else if (CheatDatabase.HasSuspiciousKeyword(exeName))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Medium,
                            FindingCategory.SuspiciousExecution,
                            "LNK Recent",
                            $"JumpList — executável suspeito: {exeName}",
                            $"Nome suspeito encontrado nos JumpLists do Windows.",
                            $"Arquivo: {Path.GetFileName(file)} | Executável: {exeName}",
                            confidence: Confidence.Low,
                            entity: exeName
                        ));
                    }
                }
            }
            catch { /* acesso negado ou arquivo corrompido */ }
        }
    }

    /// <summary>
    /// Parses a single LNK file to extract its target path, then evaluates against CheatDatabase.
    /// Falls back to raw-byte regex scanning if the binary parse fails or yields no path.
    /// </summary>
    private static void ProcessLnkFile(string lnkPath, List<Finding> findings)
    {
        try
        {
            var data = File.ReadAllBytes(lnkPath);
            if (data.Length < LnkHeaderSize) return;

            // Verify magic: first 4 bytes must be 0x4C 0x00 0x00 0x00
            if (data[0] != LnkMagic || data[1] != 0 || data[2] != 0 || data[3] != 0) return;

            var timestamp = new FileInfo(lnkPath).LastWriteTimeUtc.ToLocalTime();

            // LinkFlags is a 4-byte LE uint at offset 20
            var linkFlags = BitConverter.ToUInt32(data, 20);
            var hasTargetIdList = (linkFlags & 0x01) != 0;
            var hasLinkInfo     = (linkFlags & 0x02) != 0;

            var offset = LnkHeaderSize;

            // Skip IDList block if present
            if (hasTargetIdList && offset + 2 <= data.Length)
            {
                var idListSize = BitConverter.ToUInt16(data, offset);
                offset += 2 + idListSize;
            }

            string? targetPath = null;

            // Parse LinkInfo block
            if (hasLinkInfo && offset + 28 <= data.Length)
            {
                var linkInfoStart  = offset;
                var linkInfoSize   = BitConverter.ToInt32(data, linkInfoStart);
                var linkInfoFlags  = BitConverter.ToInt32(data, linkInfoStart + 8);
                var localBasePathOffset = BitConverter.ToInt32(data, linkInfoStart + 16);

                // bit 0 of LinkInfoFlags = VolumeIDAndLocalBasePath present
                if ((linkInfoFlags & 0x01) != 0 &&
                    linkInfoStart + localBasePathOffset < data.Length)
                {
                    // LocalBasePath is a null-terminated ASCII string
                    var pathStart = linkInfoStart + localBasePathOffset;
                    var end = Array.IndexOf(data, (byte)0, pathStart);
                    if (end > pathStart)
                    {
                        targetPath = Encoding.ASCII.GetString(data, pathStart, end - pathStart);
                    }
                }

                // Advance past this block regardless
                if (linkInfoStart + linkInfoSize <= data.Length)
                    offset = linkInfoStart + linkInfoSize;
            }

            // Fallback: scan raw bytes for ASCII Windows paths (C:\...)
            if (string.IsNullOrEmpty(targetPath))
            {
                var rawText = Encoding.Latin1.GetString(data);
                var match = PathRegex.Match(rawText);
                if (match.Success)
                    targetPath = match.Value.TrimEnd('\0', ' ', '\t');
            }

            if (string.IsNullOrEmpty(targetPath)) return;

            EvaluateLnkTarget(lnkPath, targetPath, timestamp, findings);
        }
        catch { /* lnk corrompido ou acesso negado */ }
    }

    /// <summary>
    /// Checks the extracted target path against CheatDatabase and emits findings.
    /// </summary>
    private static void EvaluateLnkTarget(
        string lnkPath, string targetPath, DateTime timestamp, List<Finding> findings)
    {
        var fileName = Path.GetFileName(targetPath).ToLowerInvariant();

        if (IsOwnProcess(fileName) || IsOwnProcess(targetPath)) return;
        if (CheatDatabase.IsKnownLegitimate(targetPath)) return;

        if (CheatDatabase.IsKnownCheatExecutable(fileName))
        {
            var cheat = CheatDatabase.KnownExecutables[fileName];
            findings.Add(new Finding(
                cheat.IsGenericName ? RiskLevel.Medium : RiskLevel.High,
                FindingCategory.Cheat,
                "LNK Recent",
                cheat.IsGenericName
                    ? $"LNK aponta para cheat (baixa confiança): {fileName}"
                    : $"LNK RECENTE — CHEAT: {cheat.Name} ({fileName})",
                $"Arquivo LNK recente aponta para executável cheat.\n{cheat.Description}",
                $"LNK: {Path.GetFileName(lnkPath)} | Alvo: {targetPath}",
                timestamp: timestamp,
                confidence: cheat.IsGenericName ? Confidence.Low : Confidence.Medium,
                ruleId: $"LNK_{cheat.Name.ToUpperInvariant().Replace(' ', '_')}",
                entity: targetPath,
                validationHint: cheat.IsGenericName ? "Confirmar por hash ou caminho típico do GOSTH" : null
            ));
            return;
        }

        if (CheatDatabase.IsKnownCheatDll(fileName))
        {
            var cheat = CheatDatabase.KnownDlls[fileName];
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.Cheat,
                "LNK Recent",
                $"LNK RECENTE — DLL CHEAT: {cheat.Name} ({fileName})",
                $"Arquivo LNK recente aponta para DLL cheat.\n{cheat.Description}",
                $"LNK: {Path.GetFileName(lnkPath)} | Alvo: {targetPath}",
                timestamp: timestamp,
                confidence: Confidence.Medium,
                ruleId: $"LNK_DLL_{fileName.ToUpperInvariant().Replace('.', '_')}",
                entity: targetPath
            ));
            return;
        }

        if (CheatDatabase.HasSuspiciousKeyword(fileName) || CheatDatabase.IsSuspiciousPath(targetPath))
        {
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.SuspiciousExecution,
                "LNK Recent",
                $"LNK suspeito: {fileName}",
                $"Arquivo LNK recente aponta para caminho ou executável suspeito.",
                $"LNK: {Path.GetFileName(lnkPath)} | Alvo: {targetPath}",
                timestamp: timestamp,
                confidence: Confidence.Low,
                entity: targetPath
            ));
        }
    }
}
