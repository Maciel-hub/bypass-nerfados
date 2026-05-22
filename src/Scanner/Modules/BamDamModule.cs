using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class BamDamModule : BaseModule
{
    public override string Name => "BAM/DAM";
    public override string Description => "Background/Desktop Activity Moderator — histórico de execução e co-execução com FiveM/Steam";

    private record ExecEntry(string FileName, string ExePath, DateTime? RunTime);

    private static readonly HashSet<string> GameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "fivem.exe", "gta5.exe", "gtav.exe", "steam.exe", "epicgameslauncher.exe",
        "rockstargameslauncher.exe", "fivem_b2802_dmp.exe", "fivem_gtanative_x64.exe"
    };

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var timeline = new List<ExecEntry>();

        foreach (var svcName in new[] { "bam", "dam" })
        {
            cancellationToken.ThrowIfCancellationRequested();

            var hivePath = $@"SYSTEM\CurrentControlSet\Services\{svcName}\State\UserSettings";
            try
            {
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

                        var exePath  = ConvertDevicePath(valueName);
                        var fileName = Path.GetFileName(exePath);
                        var bamRef   = $"[{svcName.ToUpper()}] {(lastRun.HasValue ? lastRun.Value.ToString("!yyyy/MM/dd:HH:mm:ss") : "data desconhecida")}";

                        timeline.Add(new ExecEntry(fileName, exePath, lastRun));

                        // Skip game / launcher processes for individual suspicious findings
                        if (GameProcesses.Contains(fileName)) continue;

                        // Use TryGetCredibleCheat for IsGenericName entries (spotify.exe, launcher.exe, dxsetup.exe)
                        // so that spotify.exe at AppData\Roaming\Spotify\ is NOT flagged
                        var credibleCheat = CheatDatabase.TryGetCredibleCheat(fileName, exePath);
                        if (credibleCheat != null)
                        {
                            var isGeneric = CheatDatabase.KnownExecutables[fileName].IsGenericName;
                            findings.Add(new Finding(
                                isGeneric ? RiskLevel.High : RiskLevel.Critical,
                                FindingCategory.Cheat,
                                Name,
                                isGeneric
                                    ? $"CHEAT (nome genérico, caminho suspeito): {credibleCheat.Name} ({fileName})"
                                    : $"CHEAT DETECTADO: {credibleCheat.Name} ({fileName})",
                                $"Executável: {exePath}\n{credibleCheat.Description}",
                                bamRef,
                                lastRun,
                                confidence: isGeneric ? Confidence.Medium : Confidence.High,
                                ruleId: $"BAM_CHEAT_{credibleCheat.Name.ToUpperInvariant().Replace(" ", "_")}_{fileName.ToUpperInvariant().Replace('.', '_')}",
                                entity: exePath
                            ));
                            continue;
                        }

                        // Generic name at wrong path — record in timeline but don't emit individual finding;
                        // it may still be caught by co-execution correlation below.
                        if (CheatDatabase.IsKnownCheatExecutable(fileName)) continue;

                        // Suspicious keywords in name
                        if (CheatDatabase.HasSuspiciousKeyword(fileName))
                        {
                            findings.Add(new Finding(
                                RiskLevel.High,
                                FindingCategory.SuspiciousExecution,
                                Name,
                                $"Execução suspeita: {fileName}",
                                $"Nome contém palavra-chave de cheat/hack.\nCaminho: {exePath}",
                                bamRef,
                                lastRun,
                                ruleId: $"BAM_KEYWORD_{fileName.ToUpperInvariant().Replace('.', '_')}",
                                entity: exePath
                            ));
                            continue;
                        }

                        // Suspicious paths — skip known-legitimate software at unusual locations
                        if (CheatDatabase.IsKnownLegitimate(exePath)) continue;
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
                                lastRun,
                                ruleId: $"BAM_PATH_{fileName.ToUpperInvariant().Replace('.', '_')}",
                                entity: exePath
                            ));
                        }
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (System.Security.SecurityException)
            {
                LogPartialError($"{svcName.ToUpper()}: acesso ao registro negado — requer Administrador");
            }
            catch (UnauthorizedAccessException)
            {
                LogPartialError($"{svcName.ToUpper()}: acesso não autorizado — requer Administrador");
            }
            catch (Exception ex)
            {
                LogPartialError($"{svcName.ToUpper()}: erro ao ler registro BAM/DAM", ex);
            }
        }

        // ── Co-execution correlation ─────────────────────────────────────────────────
        // Find any suspicious process that ran within ±15 min of a FiveM/GTA5 session.
        // This is the strongest behavioral signal: cheat loader running alongside the game.
        CorrelateCoExecution(timeline, findings, cancellationToken);

        return Task.FromResult(findings);
    }

    private static void CorrelateCoExecution(
        List<ExecEntry> timeline,
        List<Finding>   findings,
        CancellationToken cancellationToken)
    {
        var gameSessions = timeline
            .Where(e => e.RunTime.HasValue &&
                        (e.FileName.Equals("fivem.exe", StringComparison.OrdinalIgnoreCase) ||
                         e.FileName.Equals("gta5.exe",  StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(e => e.RunTime)
            .ToList();

        if (gameSessions.Count == 0) return;

        // Build set of already-flagged executables so we don't double-report
        var alreadyFlagged = new HashSet<string>(
            findings.Where(f => f.Entity != null).Select(f => f.Entity!),
            StringComparer.OrdinalIgnoreCase);

        foreach (var session in gameSessions)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var windowStart = session.RunTime!.Value.AddMinutes(-15);
            var windowEnd   = session.RunTime!.Value.AddMinutes(15);

            var coRunning = timeline
                .Where(e => e.RunTime.HasValue &&
                            e.RunTime.Value >= windowStart &&
                            e.RunTime.Value <= windowEnd &&
                            !GameProcesses.Contains(e.FileName) &&
                            !CheatDatabase.IsKnownLegitimate(e.ExePath) &&
                            (CheatDatabase.TryGetCredibleCheat(e.FileName, e.ExePath) != null ||
                             CheatDatabase.HasSuspiciousKeyword(e.FileName) ||
                             CheatDatabase.IsSuspiciousPath(e.ExePath)))
                .ToList();

            foreach (var co in coRunning)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var ruleId = $"BAM_COEXEC_{session.RunTime:yyyyMMddHHmm}_{co.FileName.ToUpperInvariant().Replace('.', '_')}";
                if (findings.Any(f => f.RuleId == ruleId)) continue;

                var lagMin  = (co.RunTime!.Value - session.RunTime.Value).TotalMinutes;
                var lagStr  = $"{lagMin:+0.0;-0.0} min em relação à sessão";

                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.Cheat,
                    "BAM/DAM",
                    $"CO-EXECUÇÃO CHEAT+FIVEM: {co.FileName}",
                    $"Processo suspeito rodou na janela de ±15 min da sessão {session.FileName}.\n" +
                    $"Sessão FiveM/GTA5 : {session.ExePath}\n" +
                    $"                    @ {session.RunTime:dd/MM/yyyy HH:mm:ss}\n" +
                    $"Processo suspeito  : {co.ExePath}\n" +
                    $"                    @ {co.RunTime:dd/MM/yyyy HH:mm:ss}  ({lagStr})",
                    $"Sessão: {session.RunTime:HH:mm:ss} | Suspeito: {co.RunTime:HH:mm:ss} | Lag: {lagStr}",
                    session.RunTime,
                    confidence: alreadyFlagged.Contains(co.ExePath) ? Confidence.High : Confidence.Medium,
                    ruleId: ruleId,
                    entity: co.ExePath
                ));
            }
        }
    }
}
