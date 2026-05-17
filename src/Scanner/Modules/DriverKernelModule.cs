using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class DriverKernelModule : BaseModule
{
    public override string Name => "Driver & Kernel";
    public override string Description => "Drivers de kernel — não assinados, caminhos suspeitos, instalados recentemente";

    private const int KernelDriver     = 1;
    private const int FileSystemDriver = 2;

    // Paths where legitimate Windows drivers live (lowercase fragments).
    // DriverStore is Windows-managed — drivers there were placed by Windows Update or
    // an official INF installer and are implicitly trusted regardless of signature check.
    private static readonly string[] LegitDriverPathFragments =
    [
        @"\windows\system32\drivers\",
        @"\systemroot\system32\drivers\",
        @"\system32\drivers\",
        @"\windows\system32\driverstore\",
        @"\system32\driverstore\",
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
        // Each task owns its own list — no shared mutable state across threads
        var t1 = ScanKernelServicesAsync(config, ct);
        var t2 = ScanSysFilesInUserPathsAsync(ct);
        var t3 = ScanDriverEventsAsync(config, ct);
        await Task.WhenAll(t1, t2, t3);

        var findings = new List<Finding>();
        findings.AddRange(t1.Result);
        findings.AddRange(t2.Result);
        findings.AddRange(t3.Result);
        return findings;
    }

    private async Task<List<Finding>> ScanKernelServicesAsync(ScanConfig config, CancellationToken ct)
    {
        var local = new List<Finding>();
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
                    try { InspectService(name, services, cutoff, local); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) { LogPartialError($"Serviço '{name}' inacessível", ex); }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError("Enumeração de serviços de kernel falhou", ex); }
        }, ct);
        return local;
    }

    private void InspectService(string name, RegistryKey parent, DateTime cutoff, List<Finding> local)
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
        expanded = expanded.TrimStart().TrimStart('\\').TrimStart('?').TrimStart('\\');

        var lowerPath = expanded.ToLowerInvariant();
        bool isLegitPath = LegitDriverPathFragments.Any(f => lowerPath.Contains(f));

        var sysPath = ResolveSysPath(expanded);
        if (sysPath == null || !File.Exists(sysPath)) return;

        var fileName = Path.GetFileName(sysPath).ToLowerInvariant();

        // Known cheat driver — always report, even if path looks legitimate (disguise)
        if (CheatDatabase.KnownExecutables.TryGetValue(fileName, out var cheat))
        {
            var wt = File.GetLastWriteTimeUtc(sysPath);
            local.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.KernelArtifact,
                Name,
                $"DRIVER DE CHEAT REGISTRADO: {cheat.Name}",
                $"Driver de kernel com nome de cheat conhecido registrado no sistema.\n" +
                $"{cheat.Description}\nPath: {sysPath}",
                sysPath,
                wt.ToLocalTime(),
                confidence: Confidence.High,
                ruleId: $"DRV_CHEAT_{name.ToLowerInvariant()}",
                entity: name.ToLowerInvariant()
            ));
            return;
        }

        if (isLegitPath) return;

        var writeTime = File.GetLastWriteTimeUtc(sysPath);
        var isRecent = writeTime > cutoff;
        var isSuspiciousUserPath = SuspectedUserPaths.Any(p =>
            sysPath.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        var sigStatus = VerifyAuthenticode(sysPath);
        var typeLabel = type == KernelDriver ? "Kernel" : "FileSystem";
        var startLabel = StartLabel(key.GetValue("Start") as int?);

        if (isSuspiciousUserPath)
        {
            local.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.KernelArtifact,
                Name,
                $"Driver de kernel em caminho de usuário: {name}",
                $"Driver ({typeLabel}) registrado em caminho de escrita de usuário — alto risco.\n" +
                $"Start: {startLabel} | Assinado: {SignLabel(sigStatus)}\nPath: {sysPath}",
                sysPath,
                writeTime.ToLocalTime(),
                confidence: Confidence.High,
                ruleId: $"DRV_USERPATH_{name.ToLowerInvariant()}",
                entity: name.ToLowerInvariant()
            ));
            return;
        }

        if (sigStatus is SignatureStatus.Unsigned or SignatureStatus.Invalid)
        {
            local.Add(new Finding(
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

        if (isRecent)
        {
            local.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.KernelArtifact,
                Name,
                $"Driver de kernel recente fora de System32: {name}",
                $"Driver ({typeLabel}) instalado dentro da janela de análise.\n" +
                $"Start: {startLabel} | Assinado: {SignLabel(sigStatus)}\nPath: {sysPath}",
                sysPath,
                writeTime.ToLocalTime(),
                confidence: Confidence.Medium,
                ruleId: $"DRV_RECENT_{name.ToLowerInvariant()}",
                entity: name.ToLowerInvariant()
            ));
        }
    }

    private async Task<List<Finding>> ScanSysFilesInUserPathsAsync(CancellationToken ct)
    {
        var local = new List<Finding>();
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
                        var sigStatus = VerifyAuthenticode(file);

                        local.Add(new Finding(
                            sigStatus == SignatureStatus.Valid ? RiskLevel.Medium : RiskLevel.High,
                            FindingCategory.KernelArtifact,
                            Name,
                            $"Arquivo .sys em local suspeito: {Path.GetFileName(file)}",
                            $"Driver (.sys) encontrado fora de System32\\drivers\\.\n" +
                            $"Assinado: {SignLabel(sigStatus)} | Modificado: {writeTime:dd/MM/yyyy HH:mm}",
                            file,
                            writeTime,
                            confidence: sigStatus == SignatureStatus.Valid ? Confidence.Medium : Confidence.High,
                            ruleId: $"DRV_SYSFILE_{Path.GetFileName(file).ToLowerInvariant()}",
                            entity: Path.GetFileName(file).ToLowerInvariant()
                        ));
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { LogPartialError($"Varredura .sys falhou em {basePath}", ex); }
            }
        }, ct);
        return local;
    }

    // Query System Event Log for Event IDs 219 and 7045 driver entries.
    // 219 = Kernel-PnP driver load failure (not covered elsewhere).
    // 7045 = new service installed, filtered to .sys only.
    private async Task<List<Finding>> ScanDriverEventsAsync(ScanConfig config, CancellationToken ct)
    {
        var local = new List<Finding>();
        await Task.Run(() =>
        {
            var since = DateTime.UtcNow - config.EventWindowLookback;
            var sinceStr = since.ToString("yyyy-MM-ddTHH:mm:ss.000Z");

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
                        using (record)
                        {
                            string desc;
                            try { desc = record.FormatDescription() ?? ""; }
                            catch { desc = $"EventID {spec.Id}"; }

                            // For 7045: only report if it looks like a driver (.sys/kernel driver)
                            if (spec.Id == 7045)
                            {
                                var lower = desc.ToLowerInvariant();
                                if (!lower.Contains(".sys") && !lower.Contains("kernel driver")) continue;
                            }

                            count++; // increment only after passing the filter
                            var detail = desc.Length > 400 ? desc[..400] : desc;
                            local.Add(new Finding(
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
        return local;
    }

    // WinVerifyTrust P/Invoke — validates Authenticode (embedded cert + catalog signatures)
    private enum SignatureStatus { Valid, Unsigned, Invalid, Unknown }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint   StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint   StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SIPClientData;
        public uint   UIChoice;          // 2 = WTD_UI_NONE
        public uint   RevocationChecks;  // 0 = WTD_REVOKE_NONE
        public uint   UnionChoice;       // 1 = WTD_CHOICE_FILE
        public IntPtr FileInfoPtr;
        public uint   StateAction;       // 1 = VERIFY, 2 = CLOSE
        public IntPtr StateData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? URLReference;
        public uint   ProvFlags;
        public uint   UIContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WinTrustData data);

    private static readonly Guid WintrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private static SignatureStatus VerifyAuthenticode(string filePath)
    {
        var filePathPtr = Marshal.StringToHGlobalUni(filePath);
        var fileInfo = new WinTrustFileInfo
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath   = filePathPtr,
        };
        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

        var data = new WinTrustData
        {
            StructSize      = (uint)Marshal.SizeOf<WinTrustData>(),
            UIChoice        = 2,
            RevocationChecks = 0,
            UnionChoice     = 1,
            FileInfoPtr     = fileInfoPtr,
            StateAction     = 1,
        };
        var actionId = WintrustActionGenericVerifyV2;

        uint result;
        try
        {
            result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);
        }
        finally
        {
            data.StateAction = 2;
            WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);
            Marshal.FreeHGlobal(filePathPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
        }

        return result switch
        {
            0          => SignatureStatus.Valid,
            0x800B0100 => SignatureStatus.Unsigned, // TRUST_E_NOSIGNATURE
            0x80092003 => SignatureStatus.Unsigned, // CRYPT_E_FILE_ERROR
            0x800B0101 => SignatureStatus.Invalid,  // TRUST_E_EXPLICIT_DISTRUST
            0x800B010C => SignatureStatus.Invalid,  // CERT_E_CHAINING
            0x80096010 => SignatureStatus.Invalid,  // TRUST_E_BAD_DIGEST (file modified)
            _          => SignatureStatus.Unknown,
        };
    }

    private static string? ResolveSysPath(string imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return null;

        var path = imagePath.Trim();

        // Strip arguments: "C:\path\drv.sys" -param → C:\path\drv.sys
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

    private static string SignLabel(SignatureStatus status) => status switch
    {
        SignatureStatus.Valid    => "Sim",
        SignatureStatus.Unsigned => "NÃO",
        SignatureStatus.Invalid  => "NÃO (inválido)",
        _                       => "indeterminado"
    };
}
