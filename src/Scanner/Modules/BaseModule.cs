using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;
using BypassNerfados.Scanner.Data;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Text;
using System.Management;

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

    // ── Self-exclusion ────────────────────────────────────────────────────────────
    //
    // Covers the current running process, all historical exe names (across rebrands),
    // build-tree path fragments, and — via IsOwnToolArtifact — PE metadata such as
    // Publisher / ProductName (used by modules that have that data, e.g. Amcache).

    private static readonly string _selfExeName =
        Path.GetFileName(Environment.ProcessPath ?? "echonerfados.exe").ToLowerInvariant();
    private static readonly string _selfDirLower =
        (Path.GetDirectoryName(Environment.ProcessPath) ?? "").ToLowerInvariant();

    // All known EXE names for this tool (current + historical rebranding)
    private static readonly HashSet<string> _selfExeAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        "echonerfados.exe",
        "bypassnerfados.exe",
    };

    // Path fragments unique to this tool's source/build/publish tree
    private static readonly string[] _selfPathFragments =
    [
        @"\bypassnerfados\",
        @"\echonerfados\",
        @"\echo nerfados\",
    ];

    // Publisher / ProductName keywords (lowercase) — for metadata-rich modules
    private static readonly string[] _selfPublisherKeywords =
    [
        "echonerfados", "bypassnerfados",
        "echo nerfados", "bypass nerfados",
        "echo nerfados shield",
    ];

    // Checks whether a given name or path belongs to this scanner (current run or
    // historical build). Covers: current process name, known alias exe names, and
    // paths containing a known build-tree segment (e.g. \BypassNerfados\).
    protected static bool IsOwnProcess(string nameOrPath)
    {
        if (string.IsNullOrEmpty(nameOrPath)) return false;
        var lower    = nameOrPath.ToLowerInvariant();
        var fileName = Path.GetFileName(lower);

        // Current running process — exact name or same directory
        if (lower == _selfExeName ||
            lower.EndsWith(Path.DirectorySeparatorChar + _selfExeName) ||
            (!string.IsNullOrEmpty(_selfDirLower) && lower.StartsWith(_selfDirLower)))
            return true;

        // Historical / alternative exe names (rebranding across development)
        if (_selfExeAliases.Contains(fileName)) return true;

        // Project / build tree path fragments
        // Normalize to include trailing backslash so bare directory paths like
        // "D:\BypassNerfados" (no trailing slash) still match "\bypassnerfados\"
        var lowerSlash = lower.EndsWith('\\') ? lower : lower + '\\';
        foreach (var frag in _selfPathFragments)
            if (lowerSlash.Contains(frag)) return true;

        return false;
    }

    // Extended self-exclusion for modules with PE metadata (Publisher, ProductName).
    // Combines path/name signals with publisher keywords for defence-in-depth:
    // a file renamed to bypassnerfados.exe but published by an unrelated vendor
    // is NOT excluded — multiple signals must align.
    protected static bool IsOwnToolArtifact(
        string path, string? publisher = null, string? productName = null)
    {
        if (IsOwnProcess(path)) return true;

        foreach (var meta in new[] { publisher, productName })
        {
            if (string.IsNullOrEmpty(meta)) continue;
            var m = meta.ToLowerInvariant();
            foreach (var kw in _selfPublisherKeywords)
                if (m.Contains(kw)) return true;
        }

        return false;
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

    // Copies a locked system file using FILE_SHARE_READ|WRITE|DELETE; returns true on success.
    private static bool TryCopyLocked(string src, string dst)
    {
        try
        {
            using var s = new FileStream(src, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var d = File.Create(dst);
            s.CopyTo(d);
            return true;
        }
        catch { return false; }
    }

    // Kept for callers that still use the single-file copy path.
    protected static string? CopyLockedFile(string sourcePath)
    {
        var temp = Path.Combine(Path.GetTempPath(), $"echo_scan_{Guid.NewGuid():N}.tmp");
        return TryCopyLocked(sourcePath, temp) ? temp : null;
    }

    // Like CopyLockedFile but falls back to VSS when the ESE engine holds an exclusive lock
    // (e.g. SRUDB.dat — the SRUM service holds an exclusive write lock even with FileShare).
    protected static string? CopyLockedFileWithVss(string sourcePath)
    {
        var temp = Path.Combine(Path.GetTempPath(), $"echo_scan_{Guid.NewGuid():N}.tmp");
        if (TryCopyLocked(sourcePath, temp)) return temp;
        try { File.Delete(temp); } catch { }

        var root = Path.GetPathRoot(sourcePath) ?? @"C:\";
        var (shadowId, device) = CreateVssShadow(root);
        if (device == null) return null;

        try
        {
            var rel     = sourcePath[root.Length..];
            var vssPath = device.TrimEnd('\\') + "\\" + rel;
            temp = Path.Combine(Path.GetTempPath(), $"echo_scan_{Guid.NewGuid():N}.tmp");
            if (TryCopyLocked(vssPath, temp)) return temp;
            try { File.Delete(temp); } catch { }
            return null;
        }
        finally { TryDeleteVssShadow(shadowId!); }
    }

    // Loads an offline hive under HKLM\<tempKeyName>. Returns the RegistryKey on success;
    // caller must dispose the key then call UnloadOfflineHive(tempKeyName, tempFile).
    //
    // Strategy:
    // 1. Copies the hive + .LOG1/.LOG2 into a dedicated temp directory.
    //    RegLoadKey replays dirty transactions via the log files — without them the
    //    load fails when the OS hasn't flushed the hive to disk yet.
    // 2. Direct copy (FileShare.ReadWrite|Delete) is tried first.
    //    If the hive is exclusively locked (e.g. Amcache.hve held by the registry
    //    subsystem), falls back to a VSS (Volume Shadow Copy) snapshot.
    // 3. SeBackupPrivilege + SeRestorePrivilege must be explicitly enabled in the token
    //    before RegLoadKey — being an Administrator is not sufficient by itself.
    // 4. tempFile is the temp DIRECTORY; UnloadOfflineHive deletes it recursively.
    // onVssCleanupFail: called when VSS cleanup cannot be verified after maxAttempts.
    // Callers that have a LogPartialError context should pass it so the failure is surfaced.
    protected static RegistryKey? LoadOfflineHive(
        string hivePath, string tempKeyName, out string tempFile,
        Action<string>? onVssCleanupFail = null)
    {
        tempFile = string.Empty;

        var tempDir = Path.Combine(Path.GetTempPath(), $"echo_hive_{Guid.NewGuid():N}");
        try { Directory.CreateDirectory(tempDir); }
        catch { return null; }

        var hiveName = Path.GetFileName(hivePath);
        var hiveRoot = Path.GetPathRoot(hivePath) ?? @"C:\";
        var destHive = Path.Combine(tempDir, hiveName);

        // Step 1: direct copy — works when OS shares the file with read access
        bool hiveOk = TryCopyLocked(hivePath, destHive);

        string? vssId = null, vssDev = null;

        // Step 2: VSS fallback — creates a volume snapshot to read exclusively-locked files
        if (!hiveOk)
        {
            (vssId, vssDev) = CreateVssShadow(hiveRoot);
            if (vssDev != null)
            {
                var rel = hivePath.Substring(hiveRoot.Length);
                hiveOk = TryCopyLocked(vssDev.TrimEnd('\\') + "\\" + rel, destHive);
            }
        }

        if (!hiveOk)
        {
            CleanupVss(vssId, onVssCleanupFail);
            try { Directory.Delete(tempDir, true); } catch { }
            return null;
        }

        // Copy transaction logs — live path first, then VSS path (best-effort)
        foreach (var ext in new[] { ".LOG1", ".LOG2", ".LOG" })
        {
            if (!TryCopyLocked(hivePath + ext, destHive + ext) && vssDev != null)
            {
                var rel = (hivePath + ext).Substring(hiveRoot.Length);
                TryCopyLocked(vssDev.TrimEnd('\\') + "\\" + rel, destHive + ext);
            }
        }

        // Shadow copy no longer needed once all files are copied
        CleanupVss(vssId, onVssCleanupFail);

        tempFile = tempDir;

        EnablePrivilege("SeBackupPrivilege");
        EnablePrivilege("SeRestorePrivilege");

        if (RegLoadKey(HklmHandle, tempKeyName, destHive) != 0)
        {
            try { Directory.Delete(tempDir, true); } catch { }
            tempFile = string.Empty;
            return null;
        }

        return Registry.LocalMachine.OpenSubKey(tempKeyName);
    }

    // Centralizes VSS cleanup with retry + verification. Invokes onFail if the shadow copy
    // cannot be confirmed deleted so the caller can surface it as a PartialError.
    private static void CleanupVss(string? shadowId, Action<string>? onFail)
    {
        if (shadowId == null) return;
        if (!TryDeleteVssShadow(shadowId))
            onFail?.Invoke(
                $"Shadow copy VSS {shadowId} não pôde ser removido automaticamente. " +
                $"Remover manualmente: vssadmin delete shadows /shadow={shadowId} /quiet");
    }

    protected static void UnloadOfflineHive(string tempKeyName, string tempFile)
    {
        // Force GC to release any cached RegistryKey handles before unloading
        GC.Collect(); GC.WaitForPendingFinalizers();
        RegUnLoadKey(HklmHandle, tempKeyName);
        // tempFile is the temp directory created by LoadOfflineHive
        if (!string.IsNullOrEmpty(tempFile))
            try { Directory.Delete(tempFile, recursive: true); } catch { }
    }

    // Converts a Windows FILETIME (100-ns intervals since 1601-01-01) to DateTime?
    protected static DateTime? FileTimeToDateTime(long ft) =>
        ft > 0 ? DateTime.FromFileTimeUtc(ft).ToLocalTime() : null;

    // ── VSS (Volume Shadow Copy) helpers — WMI-based ─────────────────────────────
    //
    // Uses Win32_ShadowCopy.Create via System.Management (no vssadmin.exe dependency).
    // vssadmin create shadow is not available on all Windows client editions.

    // Creates a VSS snapshot for the given volume root (e.g. @"C:\") using WMI.
    // Returns (shadowId, devicePath) on success; (null, null) on any failure.
    // Requires administrator privileges.
    private static (string? id, string? device) CreateVssShadow(string volumeRoot)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();

            using var cls = new ManagementClass(scope, new ManagementPath("Win32_ShadowCopy"), null);
            using var inParams = cls.GetMethodParameters("Create");
            inParams["Volume"]  = volumeRoot;
            inParams["Context"] = "ClientAccessible";

            using var outParams = cls.InvokeMethod("Create", inParams, null);
            if (Convert.ToUInt32(outParams["ReturnValue"]) != 0) return (null, null);

            var shadowId = outParams["ShadowID"]?.ToString();
            if (string.IsNullOrEmpty(shadowId)) return (null, null);

            // DeviceObject from Create output is not always populated — query separately
            var wql = $"SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID = '{shadowId}'";
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
            using var results  = searcher.Get();

            string? device = null;
            foreach (ManagementObject obj in results)
                using (obj) { device = obj["DeviceObject"]?.ToString(); break; }

            return (shadowId, device);
        }
        catch { return (null, null); }
    }

    // Returns true when the shadow copy with the given ID still exists in WMI.
    private static bool VssShadowExists(string shadowId)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            var wql = $"SELECT ID FROM Win32_ShadowCopy WHERE ID = '{shadowId}'";
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
            using var results  = searcher.Get();
            foreach (ManagementObject obj in results)
                using (obj) { return true; }
            return false;
        }
        catch { return false; } // treat query failure as "not found"
    }

    // Deletes a VSS shadow copy by WMI ID.
    // Retries up to maxAttempts times with a short delay, then verifies via WMI query.
    // Returns true when the shadow copy is confirmed gone (or was never found).
    private static bool TryDeleteVssShadow(string shadowId, int maxAttempts = 3)
    {
        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            if (attempt > 0) Thread.Sleep(600);

            try
            {
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var wql = $"SELECT * FROM Win32_ShadowCopy WHERE ID = '{shadowId}'";
                using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
                using var results  = searcher.Get();

                var found = false;
                foreach (ManagementObject obj in results)
                {
                    found = true;
                    using (obj) { obj.Delete(); }
                    break;
                }

                if (!found) return true; // already gone
            }
            catch { /* retry on exception */ }

            // Brief pause so WMI reflects the deletion before verifying
            Thread.Sleep(300);
            if (!VssShadowExists(shadowId)) return true;
        }

        return !VssShadowExists(shadowId);
    }

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
