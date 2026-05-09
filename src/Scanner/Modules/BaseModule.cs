using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;
using BypassNerfados.Scanner.Data;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Text;

namespace BypassNerfados.Scanner.Modules;

public abstract class BaseModule
{
    public abstract string Name { get; }
    public abstract string Description { get; }

    private readonly List<string> _partialErrors = [];

    protected void LogPartialError(string context, Exception? ex = null) =>
        _partialErrors.Add(ex != null ? $"{context}: {ex.Message}" : context);

    public bool HasPartialErrors => _partialErrors.Count > 0;
    public IReadOnlyList<string> GetPartialErrors() => _partialErrors;

    public async Task<List<Finding>> RunAsync(ScanConfig config, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _partialErrors.Clear();

        try
        {
            var findings = await ExecuteAsync(config, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            // Surface partial errors as Info findings so they appear in the report
            foreach (var err in _partialErrors)
                findings.Add(new Finding(RiskLevel.Info, FindingCategory.LogCoverage, Name,
                    $"Coleta parcial — {Name}", err, confidence: Confidence.Low));

            return findings;
        }
        catch (OperationCanceledException) { throw; }
        catch (UnauthorizedAccessException ex)
        {
            LogPartialError("Acesso negado ao módulo", ex);
            return [new Finding(RiskLevel.Info, FindingCategory.SystemTampering, Name,
                "Acesso negado", "Módulo requer privilégios de Administrador.")];
        }
    }

    protected abstract Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken);

    // Self-exclusion: never flag the scanner's own process or its build/run directory
    private static readonly string _selfExeName =
        Path.GetFileName(Environment.ProcessPath ?? "echonerfados.exe").ToLowerInvariant();
    private static readonly string _selfDirLower =
        (Path.GetDirectoryName(Environment.ProcessPath) ?? "").ToLowerInvariant();

    protected static bool IsOwnProcess(string nameOrPath)
    {
        var lower = nameOrPath.ToLowerInvariant();
        return lower == _selfExeName
            || lower.EndsWith(Path.DirectorySeparatorChar + _selfExeName)
            || (!string.IsNullOrEmpty(_selfDirLower) && lower.StartsWith(_selfDirLower));
    }

    protected static string ConvertDevicePath(string devicePath)
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            var letter = drive.Name.TrimEnd('\\');
            var sb = new StringBuilder(256);
            if (QueryDosDevice(letter, sb, (uint)sb.Capacity) > 0)
            {
                var dev = sb.ToString();
                if (devicePath.StartsWith(dev, StringComparison.OrdinalIgnoreCase))
                    return letter + devicePath[dev.Length..];
            }
        }
        return devicePath;
    }

    protected static RiskLevel ClassifyExecutablePath(string path)
    {
        var lower = path.ToLowerInvariant();
        if (CheatDatabase.IsSuspiciousPath(lower)) return RiskLevel.Medium;
        if (CheatDatabase.HasSuspiciousKeyword(Path.GetFileName(lower))) return RiskLevel.Medium;
        return RiskLevel.Info;
    }

    // P0.4 fix: async reads of stdout AND stderr to avoid deadlock; explicit kill on timeout
    protected static async Task<string> RunCmdAsync(string command, string arguments, int timeoutMs = 30000,
        CancellationToken cancellationToken = default)
    {
        using var timeoutCts = new CancellationTokenSource(timeoutMs);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, cancellationToken);
        using var proc = new System.Diagnostics.Process();
        proc.StartInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = command,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        try
        {
            proc.Start();

            // Read both streams concurrently to avoid buffer-full deadlock
            var stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
            var stderrTask = proc.StandardError.ReadToEndAsync(cts.Token);

            await Task.WhenAll(stdoutTask, stderrTask).WaitAsync(cts.Token);
            await proc.WaitForExitAsync(cts.Token);

            return await stdoutTask;
        }
        catch (OperationCanceledException)
        {
            try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { }
            cancellationToken.ThrowIfCancellationRequested();
            return string.Empty;
        }
        catch { return string.Empty; }
    }

    // Sync wrapper kept for simple callers — internally uses the async version
    protected static string RunCmd(string command, string arguments, int timeoutMs = 30000,
        CancellationToken cancellationToken = default) =>
        RunCmdAsync(command, arguments, timeoutMs, cancellationToken).GetAwaiter().GetResult();

    // P0.6 fix: SHA256 as primary hash
    protected static string? GetFileHash(string path)
    {
        try
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            using var stream = File.OpenRead(path);
            var hash = sha256.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch { return null; }
    }

    // P0.6: SHA1 kept as secondary for backward compat with known cheat hashes (stored as SHA1)
    protected static string? GetFileSha1(string path)
    {
        try
        {
            using var sha1 = System.Security.Cryptography.SHA1.Create();
            using var stream = File.OpenRead(path);
            var hash = sha1.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch { return null; }
    }

    // P0.6: Normalize executable name — strips .exe suffix to canonical lowercase key
    protected static string NormalizeExeName(string rawName)
    {
        var name = Path.GetFileName(rawName).ToLowerInvariant();
        return name.EndsWith(".exe") ? name : name + ".exe";
    }

    // ── Offline registry hive helpers (Amcache, UserAssist, ShimCache) ─────────────

    // Copies a locked system file (e.g. Amcache.hve, NTUSER.DAT) to a temp path
    // using FILE_SHARE_READ|WRITE|DELETE so the OS doesn't block the copy.
    protected static string? CopyLockedFile(string sourcePath)
    {
        var temp = Path.Combine(Path.GetTempPath(), $"echo_scan_{Guid.NewGuid():N}.tmp");
        try
        {
            using var src = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var dst = File.Create(temp);
            src.CopyTo(dst);
            return temp;
        }
        catch { try { File.Delete(temp); } catch { } return null; }
    }

    // Loads an offline hive copy under HKLM\<tempKeyName>. Returns the RegistryKey
    // (caller must dispose it before calling UnloadOfflineHive).
    // RegLoadKey requires SeBackupPrivilege and SeRestorePrivilege to be explicitly
    // enabled in the process token — being an Administrator is not sufficient.
    protected static RegistryKey? LoadOfflineHive(string hivePath, string tempKeyName, out string tempFile)
    {
        tempFile = string.Empty;
        var copy = CopyLockedFile(hivePath);
        if (copy == null) return null;
        tempFile = copy;

        EnablePrivilege("SeBackupPrivilege");
        EnablePrivilege("SeRestorePrivilege");

        if (RegLoadKey(HklmHandle, tempKeyName, copy) != 0)
        {
            try { File.Delete(copy); } catch { }
            return null;
        }
        return Registry.LocalMachine.OpenSubKey(tempKeyName);
    }

    protected static void UnloadOfflineHive(string tempKeyName, string tempFile)
    {
        // Force GC to release any cached RegistryKey handles before unloading
        GC.Collect(); GC.WaitForPendingFinalizers();
        RegUnLoadKey(HklmHandle, tempKeyName);
        if (!string.IsNullOrEmpty(tempFile)) try { File.Delete(tempFile); } catch { }
    }

    // Converts a Windows FILETIME (100-ns intervals since 1601-01-01) to DateTime?
    protected static DateTime? FileTimeToDateTime(long ft) =>
        ft > 0 ? DateTime.FromFileTimeUtc(ft).ToLocalTime() : null;

    // ── Privilege management (AdjustTokenPrivileges) ──────────────────────────────

    private const uint   SePrivilegeEnabled    = 0x00000002;
    private const int    TokenAdjustPrivileges = 0x0020;
    private const int    TokenQuery            = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes { public Luid Luid; public uint Attributes; }

    // Single-entry variant of TOKEN_PRIVILEGES (variable-length struct from Win32)
    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges1 { public uint PrivilegeCount; public LuidAndAttributes Privilege; }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAll, ref TokenPrivileges1 newState,
        uint bufLen, IntPtr prev, IntPtr retLen);

    // Enables a named privilege in the current process token.
    // Best-effort — silently returns if any step fails (e.g. privilege not held).
    protected static void EnablePrivilege(string privilegeName)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            return;
        try
        {
            if (!LookupPrivilegeValue(null, privilegeName, out var luid)) return;
            var tp = new TokenPrivileges1
            {
                PrivilegeCount = 1,
                Privilege = new LuidAndAttributes { Luid = luid, Attributes = SePrivilegeEnabled }
            };
            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally { CloseHandle(token); }
    }

    // ──────────────────────────────────────────────────────────────────────────────

    private static readonly IntPtr HklmHandle = new IntPtr(unchecked((int)0x80000002));

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    protected static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    protected static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);
}
