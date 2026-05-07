using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class BamDamModule : BaseModule
{
    public override string Name => "BAM/DAM";
    public override string Description => "Background/Desktop Activity Moderator — histórico de execução";

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var svcName in new[] { "bam", "dam" })
        {
            cancellationToken.ThrowIfCancellationRequested();

            var hivePath = $@"SYSTEM\CurrentControlSet\Services\{svcName}\State\UserSettings";
            using var hive = Registry.LocalMachine.OpenSubKey(hivePath);
            if (hive == null) continue;

            foreach (var sid in hive.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var userKey = hive.OpenSubKey(sid);
                if (userKey == null) continue;

                foreach (var valueName in userKey.GetValueNames())
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (string.IsNullOrEmpty(valueName) || valueName == "Version" || valueName == "SequenceNumber")
                        continue;

                    var data = userKey.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                    DateTime? lastRun = null;

                    if (data != null && data.Length >= 8)
                    {
                        var fileTime = BitConverter.ToInt64(data, 0);
                        if (fileTime > 0)
                        {
                            try { lastRun = DateTime.FromFileTime(fileTime); }
                            catch { /* ignore invalid timestamps */ }
                        }
                    }

                    var exePath = ConvertDevicePath(valueName);
                    var fileName = Path.GetFileName(exePath);
                    var bamRef = $"[{svcName.ToUpper()}] {(lastRun.HasValue ? lastRun.Value.ToString("!yyyy/MM/dd:HH:mm:ss") : "data desconhecida")}";

                    // Check against known cheats database
                    if (CheatDatabase.KnownExecutables.TryGetValue(fileName, out var cheatInfo))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.Cheat,
                            Name,
                            $"CHEAT DETECTADO: {cheatInfo.Name} ({fileName})",
                            $"Executável: {exePath}\n{cheatInfo.Description}",
                            bamRef,
                            lastRun
                        ));
                        continue;
                    }

                    // Check for suspicious keywords in name
                    if (CheatDatabase.HasSuspiciousKeyword(fileName))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.SuspiciousExecution,
                            Name,
                            $"Execução suspeita: {fileName}",
                            $"Nome contém palavra-chave de cheat/hack.\nCaminho: {exePath}",
                            bamRef,
                            lastRun
                        ));
                        continue;
                    }

                    // Check for suspicious paths
                    var pathRisk = ClassifyExecutablePath(exePath);
                    if (pathRisk >= RiskLevel.High)
                    {
                        findings.Add(new Finding(
                            RiskLevel.Medium,
                            FindingCategory.SuspiciousExecution,
                            Name,
                            $"Execução em caminho suspeito: {fileName}",
                            $"Caminho incomum para executável: {exePath}",
                            bamRef,
                            lastRun
                        ));
                    }
                }
            }
        }

        return Task.FromResult(findings);
    }
}
