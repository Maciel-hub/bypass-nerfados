using System.Reflection;
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

        var exePath  = Environment.ProcessPath;
        var exeHash  = exePath != null && File.Exists(exePath) ? Sha256(exePath) : null;

        var files = new Dictionary<string, FileManifestEntry>();
        foreach (var file in Directory.EnumerateFiles(runFolder))
        {
            var name = Path.GetFileName(file);
            if (name == "manifest.json") continue; // skip self
            files[name] = new FileManifestEntry
            {
                Sha256     = Sha256(file),
                SizeBytes  = new FileInfo(file).Length
            };
        }

        var manifest = new ManifestDto
        {
            Scanner      = "Bypass Nerfados Shield XDR",
            Version      = version,
            ScanStarted  = result.ScanTime,
            ScanCompleted = result.ScanCompleted ?? DateTime.Now,
            Machine      = result.MachineName,
            User         = result.CurrentUser,
            RunAsAdmin   = result.IsAdministrator,
            LookbackDays = (int)config.EventWindowLookback.TotalDays,
            TotalScore   = result.TotalScore,
            OverallRisk  = result.OverallRiskLabel,
            Files        = files,
            ScannerExecutable = exePath != null ? new ExecutableManifestEntry
            {
                Path   = exePath,
                Sha256 = exeHash
            } : null
        };

        var path = Path.Combine(runFolder, "manifest.json");
        File.WriteAllText(path, JsonSerializer.Serialize(manifest, Opts), System.Text.Encoding.UTF8);
    }

    private static string Sha256(string filePath)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        using var fs  = File.OpenRead(filePath);
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }
}

file sealed class ManifestDto
{
    public string    Scanner       { get; init; } = "";
    public string    Version       { get; init; } = "";
    public DateTime  ScanStarted   { get; init; }
    public DateTime  ScanCompleted { get; init; }
    public string    Machine       { get; init; } = "";
    public string    User          { get; init; } = "";
    public bool      RunAsAdmin    { get; init; }
    public int       LookbackDays  { get; init; }
    public int       TotalScore    { get; init; }
    public string    OverallRisk   { get; init; } = "";
    public Dictionary<string, FileManifestEntry> Files { get; init; } = new();
    public ExecutableManifestEntry? ScannerExecutable { get; init; }
}

file sealed class FileManifestEntry
{
    public string Sha256    { get; init; } = "";
    public long   SizeBytes { get; init; }
}

file sealed class ExecutableManifestEntry
{
    public string  Path   { get; init; } = "";
    public string? Sha256 { get; init; }
}
