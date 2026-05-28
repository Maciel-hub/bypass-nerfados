using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;

namespace BypassNerfados.Scanner.Core;

/// <summary>
/// Identifies suspicious loader co-processes near FiveM sessions.
/// A suspicious co-process is an executable that:
///   - Lives in a user-writable path (Downloads, Temp, AppData\Local\Temp)
///   - Has a random-looking name (6–14 alphanumeric chars, low vowel ratio or mixed case)
///     OR is a known cheat process name (e.g. "Astrix External.exe")
///   - Optionally carries a -cf <payload>.exe command-line argument (RedENGINE loader)
///   - Optionally has external connections on non-standard ports (e.g. port 10001)
/// Results feed RedEngineArtifactsModule, AstrixArtifactsModule, and memory modules.
/// Results are cached for 60 seconds to avoid repeated WMI queries across sequential modules.
/// </summary>
public static class SuspiciousCoProcessResolver
{
    public sealed record SuspiciousCoProcess(
        int Pid,
        string ProcessName,
        string ExePath,
        string? CommandLine,
        string? PayloadPath,
        bool HasNumericPayload,
        List<string> ExternalConnections,
        DateTime? StartTime)
    {
        public bool HasExternalConnection => ExternalConnections.Count > 0;

        public bool IsRedEngineLoader =>
            PayloadPath != null ||
            ExternalConnections.Any(c => c.EndsWith(":10001"));

        public bool IsAstrixProcess =>
            System.IO.Path.GetFileName(ExePath)
                .Equals("Astrix External.exe", StringComparison.OrdinalIgnoreCase) ||
            ProcessName.Equals("Astrix External", StringComparison.OrdinalIgnoreCase);
    }

    private static (DateTime CachedAt, List<SuspiciousCoProcess> Result)? _cache;
    private static readonly object _lock = new();

    public static List<SuspiciousCoProcess> Resolve()
    {
        lock (_lock)
        {
            if (_cache is { } c && (DateTime.UtcNow - c.CachedAt).TotalSeconds < 60)
                return c.Result;
            var result = ResolveInternal();
            _cache = (DateTime.UtcNow, result);
            return result;
        }
    }

    private static List<SuspiciousCoProcess> ResolveInternal()
    {
        var result  = new List<SuspiciousCoProcess>();
        var tcpMap  = BuildTcpConnectionMap();
        var wmiMap  = BuildWmiCommandLineMap();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                string exePath = "";
                try { exePath = proc.MainModule?.FileName ?? ""; } catch { }

                if (string.IsNullOrEmpty(exePath) &&
                    wmiMap.TryGetValue(proc.Id, out var wmiEntry))
                    exePath = wmiEntry.ExecutablePath ?? "";

                if (string.IsNullOrEmpty(exePath)) continue;
                if (!IsUserWritablePath(exePath)) continue;

                var stem = System.IO.Path.GetFileNameWithoutExtension(exePath);

                bool isAstrix = System.IO.Path.GetFileName(exePath)
                    .Equals("Astrix External.exe", StringComparison.OrdinalIgnoreCase);

                if (!isAstrix && !IsRandomName(stem)) continue;

                string? cmdLine = wmiMap.TryGetValue(proc.Id, out var entry)
                    ? entry.CommandLine : null;

                string? payloadPath = ExtractCfPayload(cmdLine);
                bool hasNumericPayload = payloadPath != null && IsNumericStem(payloadPath);

                var conns = tcpMap.TryGetValue(proc.Id, out var list)
                    ? list.Where(c => !IsLocalAddress(c)).ToList()
                    : [];

                DateTime? startTime = null;
                try { startTime = proc.StartTime; } catch { }

                result.Add(new SuspiciousCoProcess(
                    Pid:               proc.Id,
                    ProcessName:       proc.ProcessName,
                    ExePath:           exePath,
                    CommandLine:       cmdLine,
                    PayloadPath:       payloadPath,
                    HasNumericPayload: hasNumericPayload,
                    ExternalConnections: conns,
                    StartTime:         startTime));
            }
            catch { }
        }

        return result;
    }

    // Random name heuristic: low vowel ratio or mixed case with no common-word feel.
    // Specifically tuned for RedENGINE patterns like "nkhDWzGn" (all consonants, mixed case).
    public static bool IsRandomName(string name)
    {
        if (name.Length is < 6 or > 14) return false;
        if (!name.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_')) return false;
        if (s_knownSafe.Contains(name.ToLowerInvariant())) return false;

        var lc = name.ToLowerInvariant();

        // Purely numeric stems → numeric payload EXE (e.g. 1234.exe)
        if (lc.All(char.IsDigit)) return true;

        int letters = lc.Count(char.IsLetter);
        if (letters == 0) return false;

        int vowels = lc.Count(c => c is 'a' or 'e' or 'i' or 'o' or 'u');
        double vowelRatio = (double)vowels / letters;

        // Very few/no vowels → likely random (e.g. nkhDWzGn = 0%, xR7pQmNs = 0%)
        if (vowelRatio < 0.15) return true;

        // Mixed case with both 2+ uppercase and 2+ lowercase → random-looking
        int upperCount = name.Count(char.IsUpper);
        int lowerCount = name.Count(char.IsLower);
        if (upperCount >= 2 && lowerCount >= 2) return true;

        return false;
    }

    // User-writable: not under Windows, Program Files, known game install dirs, or Microsoft app dirs.
    public static bool IsUserWritablePath(string path)
    {
        var lower = path.ToLowerInvariant();
        if (lower.StartsWith(@"c:\windows\")) return false;
        if (lower.StartsWith(@"c:\program files\")) return false;
        if (lower.StartsWith(@"c:\program files (x86)\")) return false;
        if (lower.Contains(@"\steamapps\")) return false;
        if (lower.Contains(@"\epic games\")) return false;
        if (lower.Contains(@"\rockstar games\")) return false;
        if (lower.Contains(@"\microsoft\onedrive\")) return false;
        if (lower.Contains(@"\windowsapps\")) return false;
        return true;
    }

    // Extracts the -cf <path> argument from a command line string.
    public static string? ExtractCfPayload(string? cmdLine)
    {
        if (cmdLine == null) return null;

        var idx = cmdLine.IndexOf("-cf ", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        var rest = cmdLine[(idx + 4)..].TrimStart();

        if (rest.Length > 0 && (rest[0] == '\'' || rest[0] == '"'))
        {
            var quote = rest[0];
            var end   = rest.IndexOf(quote, 1);
            return end > 0 ? rest[1..end] : null;
        }

        var spaceIdx = rest.IndexOf(' ');
        return spaceIdx > 0 ? rest[..spaceIdx] : rest;
    }

    private static bool IsNumericStem(string path)
    {
        var stem = System.IO.Path.GetFileNameWithoutExtension(path);
        return !string.IsNullOrEmpty(stem) && stem.All(char.IsDigit);
    }

    private static bool IsLocalAddress(string addrPort)
    {
        var ip = addrPort.Split(':')[0];
        if (ip.StartsWith("127.") || ip.StartsWith("0.0.") || ip == "::1") return true;
        if (ip.StartsWith("192.168.") || ip.StartsWith("10.")) return true;
        if (ip.StartsWith("172."))
        {
            var parts = ip.Split('.');
            if (parts.Length >= 2 && int.TryParse(parts[1], out var seg))
                return seg is >= 16 and <= 31;
        }
        return false;
    }

    private static Dictionary<int, List<string>> BuildTcpConnectionMap()
    {
        var map = new Dictionary<int, List<string>>();
        try
        {
            int bufSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufSize, true, 2, 5);
            var buf = Marshal.AllocHGlobal(bufSize);
            try
            {
                if (GetExtendedTcpTable(buf, ref bufSize, true, 2, 5) != 0) return map;
                var num = Marshal.ReadInt32(buf);
                var ptr = IntPtr.Add(buf, 4);
                var sz  = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < num; i++)
                {
                    var row  = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(ptr);
                    var ip   = $"{row.remoteAddr & 0xFF}.{(row.remoteAddr >> 8) & 0xFF}.{(row.remoteAddr >> 16) & 0xFF}.{(row.remoteAddr >> 24) & 0xFF}";
                    var port = (ushort)((row.remotePort >> 8) | ((row.remotePort & 0xFF) << 8));
                    if (!map.TryGetValue(row.owningPid, out var list2))
                        map[row.owningPid] = list2 = [];
                    list2.Add($"{ip}:{port}");
                    ptr = IntPtr.Add(ptr, sz);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { }
        return map;
    }

    private sealed record WmiEntry(string? ExecutablePath, string? CommandLine);

    private static Dictionary<int, WmiEntry> BuildWmiCommandLineMap()
    {
        var map = new Dictionary<int, WmiEntry>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                try
                {
                    var pid = Convert.ToInt32(obj["ProcessId"]);
                    var exe = obj["ExecutablePath"]?.ToString();
                    var cmd = obj["CommandLine"]?.ToString();
                    map[pid] = new WmiEntry(exe, cmd);
                }
                catch { }
            }
        }
        catch { }
        return map;
    }

    private static readonly HashSet<string> s_knownSafe = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam", "chrome", "firefox", "discord", "node", "java", "python",
        "winrar", "7zfm", "vlc", "obs64", "obs32", "code", "git", "curl",
        "wget", "ping", "cmd", "powershell", "pwsh", "explorer", "fivem",
        "gta5", "gtav", "cfx", "rockstar", "launcher", "installer", "setup",
        // Microsoft system / OneDrive / Office processes with mixed-case names
        "filecoauth", "onedrive", "onedrivesetup", "microsoftedge",
        "searchhost", "searchindexer", "runtimebroker", "sihost",
        "textinputhost", "startmenuexperiencehost", "lockapp",
        "applicationframehost", "shellexperiencehost",
        "teams", "outlook", "winword", "excel", "powerpnt",
        "crashpad", "crashpad_handler", "msedgewebview2",
        // Own scanner processes — never flag the scanner itself as suspicious
        "echonerfados", "bypassnerfados", "memoryharness", "ecoharness",
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state, localAddr, localPort, remoteAddr, remotePort;
        public int owningPid;
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tableClass, int reserved = 0);
}
