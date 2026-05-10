using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;
using Microsoft.Win32;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Detecta reinstalação, reset e restauração do Windows — indica possível perda de cobertura forense.
/// Verifica: data de instalação do OS, diretórios residuais de reset, logs do Panther e
/// operações de renomeação pendentes relacionadas ao setup.
/// </summary>
public class SystemResetRestoreModule : BaseModule
{
    public override string Name        => "System Reset/Restore";
    public override string Description => "Detecta reinstalação, reset e restauração do Windows — indica possível perda de cobertura forense";

    // Number of days within which an OS install is considered forensically recent
    private const int RecentInstallDays = 60;

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        CheckWindowsInstallDate(findings);
        cancellationToken.ThrowIfCancellationRequested();

        CheckWindowsOldDirectory(findings);
        cancellationToken.ThrowIfCancellationRequested();

        CheckPantherLogs(findings);
        cancellationToken.ThrowIfCancellationRequested();

        CheckSysResetPending(findings);

        return Task.FromResult(findings);
    }

    // ── Check 1: Windows install date ─────────────────────────────────────────

    /// <summary>
    /// Reads InstallDate (Unix epoch int32) from the CurrentVersion key.
    /// If the OS was installed within the last 60 days, emits a High/AntiForensics finding.
    /// </summary>
    private void CheckWindowsInstallDate(List<Finding> findings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");

            if (key == null) return;

            var raw = key.GetValue("InstallDate");
            if (raw == null) return;

            // InstallDate is stored as a REG_DWORD (int in C#) representing Unix epoch seconds
            int epochSeconds = Convert.ToInt32(raw);
            var installDate  = DateTimeOffset.FromUnixTimeSeconds(epochSeconds).LocalDateTime;
            var age          = DateTime.Now - installDate;

            if (age.TotalDays <= RecentInstallDays)
            {
                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.AntiForensics,
                    Name,
                    "Windows instalado recentemente — possível reset forense",
                    $"Data de instalação do Windows: {installDate:yyyy-MM-dd HH:mm:ss} " +
                    $"({(int)age.TotalDays} dia(s) atrás). " +
                    $"Reinstalações recentes do sistema operacional indicam possível perda de cobertura forense.",
                    $"InstallDate (Unix epoch): {epochSeconds} → {installDate:yyyy-MM-dd}",
                    timestamp: installDate,
                    confidence: Confidence.High,
                    ruleId: "SYSRESET_INSTALL_RECENT"
                ));
            }
        }
        catch (Exception ex) { LogPartialError("CheckWindowsInstallDate falhou", ex); }
    }

    // ── Check 2: Windows.old / reset residual directories ─────────────────────

    /// <summary>
    /// Checks for directories left behind by Windows reset or in-place upgrade.
    /// Each found directory generates a separate High/AntiForensics finding.
    /// </summary>
    private void CheckWindowsOldDirectory(List<Finding> findings)
    {
        var resetDirs = new[]
        {
            @"C:\Windows.old",
            @"C:\$WINDOWS.~BT",
            @"C:\$SysReset",
        };

        foreach (var dir in resetDirs)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;

                var info      = new DirectoryInfo(dir);
                var lastWrite = info.LastWriteTime;
                var dirName   = info.Name.TrimStart('$').Replace('.', '_').Replace('~', '_');

                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.AntiForensics,
                    Name,
                    $"Diretório de reset/reinstalação encontrado: {info.Name}",
                    $"Diretório '{dir}' presente no sistema — indica que o Windows foi resetado ou " +
                    $"atualizado recentemente. Cobertura forense anterior pode estar perdida.",
                    $"Caminho: {dir} | Última modificação: {lastWrite:yyyy-MM-dd HH:mm:ss}",
                    timestamp: lastWrite,
                    confidence: Confidence.High,
                    ruleId: $"SYSRESET_DIR_{dirName.ToUpperInvariant()}"
                ));
            }
            catch (Exception ex) { LogPartialError($"Verificação do diretório '{dir}' falhou", ex); }
        }
    }

    // ── Check 3: Panther setup logs ───────────────────────────────────────────

    /// <summary>
    /// Checks Windows Panther setup logs. If modified within 60 days, the system
    /// was recently set up or reset, which reduces forensic coverage.
    /// </summary>
    private void CheckPantherLogs(List<Finding> findings)
    {
        var pantherFiles = new[]
        {
            @"C:\Windows\Panther\setupact.log",
            @"C:\Windows\Panther\setuperr.log",
        };

        foreach (var logPath in pantherFiles)
        {
            try
            {
                if (!File.Exists(logPath)) continue;

                var info      = new FileInfo(logPath);
                var lastWrite = info.LastWriteTime;
                var age       = DateTime.Now - lastWrite;

                if (age.TotalDays > RecentInstallDays) continue;

                var fileName  = Path.GetFileName(logPath).ToUpperInvariant().Replace('.', '_');

                findings.Add(new Finding(
                    RiskLevel.Medium,
                    FindingCategory.AntiForensics,
                    Name,
                    $"Log de setup do Windows modificado recentemente: {Path.GetFileName(logPath)}",
                    $"O arquivo '{logPath}' foi modificado há {(int)age.TotalDays} dia(s). " +
                    $"Logs Panther recentes indicam setup ou reset do Windows executado nos últimos {RecentInstallDays} dias.",
                    $"Caminho: {logPath} | Última modificação: {lastWrite:yyyy-MM-dd HH:mm:ss} | Tamanho: {info.Length} bytes",
                    timestamp: lastWrite,
                    confidence: Confidence.Medium,
                    ruleId: $"SYSRESET_PANTHER_{fileName}"
                ));
            }
            catch (Exception ex) { LogPartialError($"Verificação do log Panther '{logPath}' falhou", ex); }
        }
    }

    // ── Check 4: PendingFileRenameOperations ──────────────────────────────────

    /// <summary>
    /// Reads PendingFileRenameOperations from Session Manager. If any entry references
    /// "windows" or "setup", it may indicate a pending reset or upgrade operation.
    /// </summary>
    private void CheckSysResetPending(List<Finding> findings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager");

            if (key == null) return;

            var raw = key.GetValue("PendingFileRenameOperations");
            if (raw == null) return;

            // REG_MULTI_SZ is returned as string[] by the registry API
            var entries = raw as string[];
            if (entries == null || entries.Length == 0) return;

            // Look for any entry that mentions windows or setup
            var matched = entries
                .Where(e => !string.IsNullOrEmpty(e) &&
                            (e.IndexOf("windows", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             e.IndexOf("setup",   StringComparison.OrdinalIgnoreCase) >= 0))
                .ToList();

            if (matched.Count == 0) return;

            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.SystemTampering,
                Name,
                "Operações de renomeação pendentes relacionadas ao Windows/Setup",
                $"PendingFileRenameOperations contém {matched.Count} entrada(s) que referenciam 'windows' ou 'setup'. " +
                $"Isso pode indicar uma atualização ou reset do Windows pendente.",
                $"Entradas suspeitas ({matched.Count}): {string.Join("; ", matched.Take(5))}",
                confidence: Confidence.Low,
                ruleId: "SYSRESET_PENDING_RENAME"
            ));
        }
        catch (Exception ex) { LogPartialError("CheckSysResetPending falhou", ex); }
    }
}
