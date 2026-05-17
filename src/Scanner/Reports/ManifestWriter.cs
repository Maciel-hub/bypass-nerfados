using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Reports;

public static class ManifestWriter
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static void Write(ScanResult result, ScanConfig config, string runFolder)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var version  = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion
            ?? assembly.GetName().Version?.ToString()
            ?? "1.0.0";

        var processPath  = Environment.ProcessPath;
        var assemblyLoc  = assembly.Location;
        // For single-file publish assemblyLocation is empty — fall back to processPath
        if (string.IsNullOrEmpty(assemblyLoc)) assemblyLoc = processPath;

        var files = new Dictionary<string, FileManifestEntry>();
        foreach (var file in Directory.EnumerateFiles(runFolder).OrderBy(f => f))
        {
            var name = Path.GetFileName(file);
            if (name is "manifest.json" or "manifest.sha256") continue;
            files[name] = new FileManifestEntry
            {
                Sha256    = Sha256Of(file),
                SizeBytes = new FileInfo(file).Length
            };
        }

        var args = Environment.GetCommandLineArgs();
        var manifest = new ManifestDto
        {
            Scanner       = "Echo Nerfados Shield XDR",
            Version       = version,
            ScanStarted   = result.ScanTime,
            ScanCompleted = result.ScanCompleted ?? DateTime.Now,
            Machine       = result.MachineName,
            User          = result.CurrentUser,
            MachineId     = result.MachineId,
            IsElevated    = result.IsAdministrator,
            ProcessId     = Environment.ProcessId,
            CommandLine   = Environment.CommandLine,
            Arguments     = args.Length > 1 ? args[1..] : [],
            WorkingDirectory = Environment.CurrentDirectory,
            OsVersion     = RuntimeInformation.OSDescription,
            Timezone      = TimeZoneInfo.Local.Id,
            LookbackDays  = (int)config.EventWindowLookback.TotalDays,
            TotalScore    = result.TotalScore,
            OverallRisk   = result.OverallRiskLabel,
            License       = result.License is { } lic ? new LicenseManifestEntry
            {
                CustomerId        = lic.CustomerId,
                LicenseMachineId  = lic.LicenseMachineId,
                EffectiveMachineId = lic.EffectiveMachineId,
                IsWildcard        = lic.IsWildcard,
                ExpiresAt         = lic.ExpiresAt,
                Features          = lic.Features,
            } : null,
            Files         = files,
            ScannerExecutable = new ExecutableManifestEntry
            {
                ProcessPath         = processPath,
                ProcessPathSha256   = processPath != null && File.Exists(processPath) ? Sha256Of(processPath) : null,
                AssemblyLocation    = assemblyLoc != processPath ? assemblyLoc : null,
                AssemblyLocationSha256 = assemblyLoc != processPath && assemblyLoc != null && File.Exists(assemblyLoc)
                    ? Sha256Of(assemblyLoc) : null
            }
        };

        var manifestPath = Path.Combine(runFolder, "manifest.json");
        File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, Opts), System.Text.Encoding.UTF8);

        // manifest.sha256 — sha256sum-compatible format, verifiable by third parties:
        // sha256sum -c manifest.sha256
        var manifestHash = Sha256Of(manifestPath);
        File.WriteAllText(
            Path.Combine(runFolder, "manifest.sha256"),
            $"{manifestHash}  manifest.json{Environment.NewLine}",
            System.Text.Encoding.UTF8);

        // manifest.sig — ECDSA P-256 signature of SHA256(manifest.json).
        // Written only if echo_manifest_priv.pem is found beside the EXE.
        ManifestSigner.TrySign(manifestPath);
    }

    private static string Sha256Of(string filePath)
    {
        using var sha = SHA256.Create();
        using var fs  = File.OpenRead(filePath);
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }
}

file sealed class ManifestDto
{
    public string   Scanner          { get; init; } = "";
    public string   Version          { get; init; } = "";
    public DateTime ScanStarted      { get; init; }
    public DateTime ScanCompleted    { get; init; }
    public string   Machine          { get; init; } = "";
    public string   User             { get; init; } = "";
    public string   MachineId        { get; init; } = "";
    public bool     IsElevated       { get; init; }
    public int      ProcessId        { get; init; }
    public string   CommandLine      { get; init; } = "";
    public string[] Arguments        { get; init; } = [];
    public string   WorkingDirectory { get; init; } = "";
    public string   OsVersion        { get; init; } = "";
    public string   Timezone         { get; init; } = "";
    public int      LookbackDays     { get; init; }
    public int      TotalScore       { get; init; }
    public string   OverallRisk      { get; init; } = "";
    public LicenseManifestEntry? License { get; init; }
    public Dictionary<string, FileManifestEntry> Files { get; init; } = new();
    public ExecutableManifestEntry ScannerExecutable   { get; init; } = new();
}

file sealed class LicenseManifestEntry
{
    public string          CustomerId         { get; init; } = "";
    public string          LicenseMachineId   { get; init; } = "";
    public string          EffectiveMachineId { get; init; } = "";
    public bool            IsWildcard         { get; init; }
    public DateTimeOffset  ExpiresAt          { get; init; }
    public string[]        Features           { get; init; } = [];
}

file sealed class FileManifestEntry
{
    public string Sha256    { get; init; } = "";
    public long   SizeBytes { get; init; }
}

file sealed class ExecutableManifestEntry
{
    public string?  ProcessPath            { get; init; }
    public string?  ProcessPathSha256      { get; init; }
    public string?  AssemblyLocation       { get; init; }
    public string?  AssemblyLocationSha256 { get; init; }
}
