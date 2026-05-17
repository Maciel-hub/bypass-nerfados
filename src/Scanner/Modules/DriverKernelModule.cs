using System.Diagnostics.Eventing.Reader;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class DriverKernelModule : BaseModule
{
    public override string Name => "Driver & Kernel";
    public override string Description => "Drivers de kernel — não assinados, caminhos suspeitos, instalados recentemente";

    // Windows Driver Service Type values
    private const int KernelDriver     = 1;
    private const int FileSystemDriver = 2;

    // Paths where legitimate Windows drivers live (lowercase fragments)
    private static readonly string[] LegitDriverPathFragments =
    [
        @"\windows\system32\drivers\",
        @"\systemroot\system32\drivers\",
        @"\system32\drivers\",
    ];

    // User-writable locations where .sys files have no business being
    private static readonly string[] SuspectedUserPaths =
    [
        Path.GetTempPath(),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    ];

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        // Run concurrently — independent data sources
        await Task.WhenAll(
            ScanKernelServicesAsync(findings, config, ct),
            ScanSysFilesInUserPathsAsync(findings, ct),
            ScanDriverEventsAsync(findings, config, ct)
        );

        return findings;
    }

    // Enumerate HKLM\SYSTEM\CurrentControlSet\Services where Type = KernelDriver or FileSystemDriver.
    // Flags drivers installed outside of the standard Windows driver directory.
    private async Task ScanKernelServicesAsync(List<Finding> findings, ScanConfig config, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            try
            {
                using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (services == null) return;

                var cutoff = DateTime.UtcNow - config.EventWindowLookback;

                foreach (var name in services.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try { InspectService(name, services, cutoff, findings); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) { LogPartialError($"Serviço '{name}' inacessível", ex); }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError("Enumeração de serviços de kernel falhou", ex); }
        }, ct);
    }

    private void InspectService(string name, RegistryKey parent, DateTime cutoff, List<Finding> findings)
    {
        using var key = parent.OpenSubKey(name);
        if (key == null) return;

        var type = key.GetValue("Type") as int?;
        if (type != KernelDriver && type != FileSystemDriver) return;

        var imagePath = key.GetValue("ImagePath")?.ToString() ?? "";
        if (string.IsNullOrWhiteSpace(imagePath)) return;

        var expanded = Environment.ExpandEnvironmentVariables(
            imagePath.Replace(@"\SystemRoot\", Environment.GetEnvironmentVariable("SystemRoot") + @"\",
                StringComparison.OrdinalIgnoreCase));

        // Strip NT path prefix (\??\) and kernel-mode device path syntax
        expanded = expanded.TrimStart().TrimStart('\\').TrimStart('?').TrimStart('\\');

        var lowerPath = expanded.ToLowerInvariant();
        bool isLegitPath = LegitDriverPathFragments.Any(f => lowerPath.Contains(f));

        if (isLegitPath) return; // Standard Windows driver location — skip

        // Outside of standard driver path: check if the file exists and its age
        var sysPath = ResolveSysPath(expanded);
        if (sysPath == null || !File.Exists(sysPath)) return;

        var writeTime = File.GetLastWriteTimeUtc(sysPath);
        var isRecent = writeTime > cutoff;
        var isSuspiciousUserPath = SuspectedUserPaths.Any(p =>
            sysPath.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        var isSigned = TryGetSignatureStatus(sysPath);
        var typeLabel = type == KernelDriver ? "Kernel" : "FileSystem";
        var startLabel = StartLabel(key.GetValue("Start") as int?);

        // Known cheat driver name
        if (CheatDatabase.KnownExecutables.TryGetValue(
            Path.GetFileName(sysPath).ToLowerInvariant(), out var cheat))
        {
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.KernelArtifact,
                Name,
                $"DRIVER DE CHEAT REGISTRADO: {cheat.Name}",
                $"Driver de kernel com nome de cheat conhecido registrado no sistema.\n" +
                $"{cheat.Description}\nPath: {sysPath}",
                sysPath,
                writeTime.ToLocalTime(),
                confidence: Confidence.High,
                ruleId: $"DRV_CHEAT_{name.ToLowerInvariant()}",
                entity: name.ToLowerInvariant()
            ));
            return;
        }

        // Driver in a user-writable path (Temp, Downloads, AppData…)
        if (isSuspiciousUserPath)
        {
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.KernelArtifact,
                Name,
                $"Driver de kernel em caminho de usuário: {name}",
                $"Driver ({typeLabel}) registrado em caminho de escrita de usuário — alto risco.\n" +
                $"Start: {startLabel} | Assinado: {SignLabel(isSigned)}\nPath: {sysPath}",
                sysPath,
                writeTime.ToLocalTime(),
                confidence: Confidence.High,
                ruleId: $"DRV_USERPATH_{name.ToLowerInvariant()}",
                entity: name.ToLowerInvariant()
            ));
            return;
        }

        // Unsigned driver outside standard location
        if (isSigned == false)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.KernelArtifact,
                Name,
                $"Driver de kernel SEM ASSINATURA: {name}",
                $"Driver ({typeLabel}) sem Authenticode — não deveria existir em Windows 10+ com Secure Boot.\n" +
                $"Start: {startLabel}\nPath: {sysPath}",
                sysPath,
                writeTime.ToLocalTime(),
                confidence: Confidence.High,
                ruleId: $"DRV_UNSIGNED_{name.ToLowerInvariant()}",
                entity: name.ToLowerInvariant()
            ));
            return;
        }

        // Signed driver outside standard location but recently written (within lookback)
        if (isRecent)
        {
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.KernelArtifact,
                Name,
                $"Driver de kernel recente fora de System32: {name}",
                $"Driver ({typeLabel}) instalado dentro da janela de análise.\n" +
                $"Start: {startLabel} | Assinado: {SignLabel(isSigned)}\nPath: {sysPath}",
                sysPath,
                writeTime.ToLocalTime(),
                confidence: Confidence.Medium,
                ruleId: $"DRV_RECENT_{name.ToLowerInvariant()}",
                entity: name.ToLowerInvariant()
            ));
        }
    }

    // Scan user-writable directories (top-level only) for .sys files.
    // A .sys file in Downloads or Temp has essentially no legitimate use case.
    private async Task ScanSysFilesInUserPathsAsync(List<Finding> findings, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            foreach (var basePath in SuspectedUserPaths)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(basePath)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(basePath, "*.sys", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var writeTime = File.GetLastWriteTime(file);
                        var isSigned = TryGetSignatureStatus(file);

                        findings.Add(new Finding(
                            isSigned == true ? RiskLevel.Medium : RiskLevel.High,
                            FindingCategory.KernelArtifact,
                            Name,
                            $"Arquivo .sys em local suspeito: {Path.GetFileName(file)}",
                            $"Driver (.sys) encontrado fora de System32\\drivers\\.\n" +
                            $"Assinado: {SignLabel(isSigned)} | Modificado: {writeTime:dd/MM/yyyy HH:mm}",
                            file,
                            writeTime,
                            confidence: isSigned == false ? Confidence.High : Confidence.Medium,
                            ruleId: $"DRV_SYSFILE_{Path.GetFileName(file).ToLowerInvariant()}",
                            entity: Path.GetFileName(file).ToLowerInvariant()
                        ));
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { LogPartialError($"Varredura .sys falhou em {basePath}", ex); }
            }
        }, ct);
    }

    // Query System Event Log for Event ID 219 (Kernel-PnP: driver failed to start).
    // ID 7045 driver entries are already partially covered by EventViewerModule;
    // 219 is kernel-specific and not covered anywhere else.
    private async Task ScanDriverEventsAsync(List<Finding> findings, ScanConfig config, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var since = DateTime.UtcNow - config.EventWindowLookback;
            var sinceStr = since.ToString("yyyy-MM-ddTHH:mm:ss.000Z");

            // 219 = Kernel-PnP driver load failure; Windows blocks these for unsigned or incompatible drivers
            // 7045 filtered to .sys only (supplements EventViewerModule's keyword filter)
            var specs = new (int Id, RiskLevel Risk, string Label)[]
            {
                (219,  RiskLevel.High,   "Driver de kernel falhou ao carregar (219)"),
                (7045, RiskLevel.Medium, "Novo driver/serviço instalado (7045)"),
            };

            foreach (var spec in specs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var xpath = $"*[System[EventID={spec.Id} and TimeCreated[@SystemTime>='{sinceStr}']]]";
                    var query = new EventLogQuery("System", PathType.LogName, xpath)
                    { ReverseDirection = true };

                    using var reader = new EventLogReader(query);
                    int count = 0;
                    EventRecord? record;

                    while ((record = reader.ReadEvent()) != null && count < 15)
                    {
                        ct.ThrowIfCancellationRequested();
                        count++;
                        using (record)
                        {
                            string desc;
                            try { desc = record.FormatDescription() ?? ""; }
                            catch { desc = $"EventID {spec.Id}"; }

                            // For 7045: only report if it looks like a driver (has .sys or says "kernel")
                            if (spec.Id == 7045)
                            {
                                var lower = desc.ToLowerInvariant();
                                if (!lower.Contains(".sys") && !lower.Contains("kernel driver")) continue;
                            }

                            var detail = desc.Length > 400 ? desc[..400] : desc;
                            findings.Add(new Finding(
                                spec.Risk,
                                FindingCategory.KernelArtifact,
                                Name,
                                spec.Label,
                                detail,
                                $"Log: System | Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                                record.TimeCreated,
                                ruleId: $"DRV_EVENT_{spec.Id}_{record.TimeCreated:yyyyMMddHH}",
                                entity: $"event-{spec.Id}"
                            ));
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { LogPartialError($"Eventos de driver ({spec.Id}) inacessíveis", ex); }
            }
        }, ct);
    }

    // Checks for an embedded Authenticode signature in the file.
    // Returns true = signed, false = unsigned, null = indeterminate (file locked, I/O error, etc.)
    // Note: does NOT verify the certificate chain — presence of any cert is enough for this triage.
    private static bool? TryGetSignatureStatus(string path)
    {
        try
        {
            X509Certificate.CreateFromSignedFile(path);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch
        {
            return null;
        }
    }

    private static string? ResolveSysPath(string imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return null;

        var path = imagePath.Trim();

        // Strip arguments (drivers with "-p param" notation)
        if (path.StartsWith('"') && path.Length > 1)
        {
            var end = path.IndexOf('"', 1);
            path = end > 1 ? path[1..end] : path[1..];
        }

        path = Environment.ExpandEnvironmentVariables(path);

        if (!path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) &&
            !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            path += ".sys";

        return path;
    }

    private static string StartLabel(int? start) => start switch
    {
        0 => "Boot",
        1 => "System",
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => "?"
    };

    private static string SignLabel(bool? signed) => signed switch
    {
        true  => "Sim",
        false => "NÃO",
        null  => "indeterminado"
    };
}
