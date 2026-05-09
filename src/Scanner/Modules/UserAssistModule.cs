using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Win32;

namespace BypassNerfados.Scanner.Modules;

// UserAssist tracks every GUI application the user launched from the Windows shell.
// The key is in each user's NTUSER.DAT — entries are ROT-13 encoded and include
// run count + last execution FILETIME. Survives file deletion.
public class UserAssistModule : BaseModule
{
    public override string Name        => "UserAssist";
    public override string Description => "Execuções de GUI por usuário — contagem + último horário (NTUSER.DAT)";

    // Application-launch GUIDs (Windows 7+)
    private static readonly string[] AssistGuids =
    [
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", // Applications
        "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"  // Shortcuts/Links
    ];

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        // Current user's hive is live — read directly from HKCU
        ScanUserHive(Registry.CurrentUser, Environment.UserName, findings, ct);

        if (!config.ScanAllUsers) return Task.FromResult(findings);

        // Other users: load NTUSER.DAT offline for each profile
        var profilesRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "..");
        if (!Directory.Exists(profilesRoot)) return Task.FromResult(findings);

        foreach (var profileDir in Directory.GetDirectories(profilesRoot))
        {
            ct.ThrowIfCancellationRequested();

            var userName = Path.GetFileName(profileDir);
            if (string.Equals(userName, Environment.UserName, StringComparison.OrdinalIgnoreCase)) continue;
            if (userName is "All Users" or "Default" or "Default User" or "Public") continue;

            var hivePath = Path.Combine(profileDir, "NTUSER.DAT");
            if (!File.Exists(hivePath)) continue;

            var tempKey = $"ECHO_UA_{Guid.NewGuid():N}";
            var hive = LoadOfflineHive(hivePath, tempKey, out var tempFile);
            if (hive == null)
            {
                LogPartialError($"NTUSER.DAT de {userName} — não foi possível carregar (acesso negado ou arquivo em uso)");
                continue;
            }

            try { ScanUserHive(hive, userName, findings, ct); }
            finally { hive.Dispose(); UnloadOfflineHive(tempKey, tempFile); }
        }

        return Task.FromResult(findings);
    }

    private static void ScanUserHive(RegistryKey hiveRoot, string userName, List<Finding> findings, CancellationToken ct)
    {
        foreach (var guid in AssistGuids)
        {
            ct.ThrowIfCancellationRequested();

            using var countKey = hiveRoot.OpenSubKey(
                $@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count");
            if (countKey == null) continue;

            foreach (var valueName in countKey.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();

                var decoded = Rot13(valueName);
                if (!decoded.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !decoded.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) continue;

                if (IsOwnProcess(decoded)) continue;
                if (CheatDatabase.IsKnownLegitimate(decoded)) continue;

                var fileName = Path.GetFileName(decoded).ToLowerInvariant();
                if (decoded.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    fileName = Path.GetFileNameWithoutExtension(decoded).ToLowerInvariant() + ".exe";

                var (risk, confidence, label) = ClassifyEntry(fileName, decoded);
                if (risk < RiskLevel.Medium) continue;

                var (runCount, lastRun) = ParseUserAssistData(countKey.GetValue(valueName) as byte[]);
                var ts = lastRun.HasValue ? lastRun.Value : (DateTime?)null;

                findings.Add(new Finding(
                    risk,
                    FindingCategory.Cheat,
                    "UserAssist",
                    $"USERASSIST: {label ?? fileName} — executado pelo usuário {userName}",
                    $"Execução confirmada via UserAssist (shell do Windows). " +
                    $"Execuções: {(runCount > 0 ? runCount.ToString() : "?")} | Usuário: {userName}",
                    $"Caminho: {decoded}",
                    timestamp: ts,
                    confidence: confidence,
                    entity: decoded,
                    ruleId: $"UA_{fileName.ToUpperInvariant().Replace('.', '_')}_{userName.ToUpperInvariant()}"
                ));
            }
        }
    }

    private static (RiskLevel, Confidence, string?) ClassifyEntry(string fileName, string fullPath)
    {
        if (CheatDatabase.IsKnownCheatExecutable(fileName))
        {
            var e = CheatDatabase.KnownExecutables[fileName];
            return (RiskLevel.High, Confidence.High, e.Name);
        }
        if (CheatDatabase.HasSuspiciousKeyword(fileName))
            return (RiskLevel.Medium, Confidence.Medium, null);
        if (CheatDatabase.IsSuspiciousPath(fullPath.ToLowerInvariant()))
            return (RiskLevel.Medium, Confidence.Low, null);
        return (RiskLevel.Info, Confidence.Low, null);
    }

    private static (int runCount, DateTime? lastRun) ParseUserAssistData(byte[]? data)
    {
        if (data == null || data.Length < 72) return (0, null);
        var runCount = BitConverter.ToInt32(data, 4);
        var ft       = BitConverter.ToInt64(data, 60);
        return (runCount, FileTimeToDateTime(ft));
    }

    // ROT-13 decodes the UserAssist value names (Windows obfuscation)
    private static string Rot13(string input)
    {
        return new string(input.Select(c =>
            c >= 'a' && c <= 'z' ? (char)((c - 'a' + 13) % 26 + 'a') :
            c >= 'A' && c <= 'Z' ? (char)((c - 'A' + 13) % 26 + 'A') : c).ToArray());
    }
}
