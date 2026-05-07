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

    public async Task<List<Finding>> RunAsync(ScanConfig config)
    {
        try
        {
            return await ExecuteAsync(config);
        }
        catch (UnauthorizedAccessException)
        {
            return [new Finding(RiskLevel.Info, FindingCategory.SystemTampering, Name,
                "Acesso negado", "Módulo requer privilégios de Administrador.")];
        }
    }

    protected abstract Task<List<Finding>> ExecuteAsync(ScanConfig config);

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
    protected static async Task<string> RunCmdAsync(string command, string arguments, int timeoutMs = 30000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
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
            return string.Empty;
        }
        catch { return string.Empty; }
    }

    // Sync wrapper kept for simple callers — internally uses the async version
    protected static string RunCmd(string command, string arguments, int timeoutMs = 30000) =>
        RunCmdAsync(command, arguments, timeoutMs).GetAwaiter().GetResult();

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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);
}
