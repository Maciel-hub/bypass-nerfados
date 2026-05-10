using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Win32;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Detecta bypass de requisitos do Windows (LabConfig/MoSetup), scripts de elevação UAC
/// e BatchGotAdmin. Cobre chaves de registro que desabilitam verificações de hardware e
/// scripts que contêm padrões de escalação de privilégios conhecidos.
/// </summary>
public class SystemTamperingModule : BaseModule
{
    public override string Name        => "System Tampering";
    public override string Description => "Deteta bypass de requisitos do Windows (LabConfig/MoSetup), scripts de elevação UAC e BatchGotAdmin";

    // Script file extensions to inspect for tampering indicators
    private static readonly string[] ScriptExtensions = [".bat", ".cmd", ".ps1", ".vbs", ".wsf"];

    // Root folders to scan for scripts (MaxRecursionDepth = 2)
    private static IEnumerable<string> GetScriptRoots()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        yield return Path.GetTempPath();
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    }

    // Case-insensitive indicators that flag a script as tampering-related
    private static readonly string[] TamperingIndicators =
    [
        "batchgotadmin",
        "getadmin.vbs",
        "shell.application",
        "bypasscpucheck",
        "bypasstpmcheck",
        "bypassstoragecheck",   // correct Windows spelling
        "bypasstaoragecheck",   // known typo variant found in bypass scripts
        "bypassramcheck",
        "bypasssecurebootcheck",
        "allowupgradeswithunsupportedtpmorcpu",
        "labconfig",
        "foxee69",
        "echo-bypass-fivem",
        "cacls.exe",
        "windows 11 requirements bypass",
    ];

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        CheckLabConfigKeys(findings);
        cancellationToken.ThrowIfCancellationRequested();

        CheckMoSetupKeys(findings);
        cancellationToken.ThrowIfCancellationRequested();

        CheckGetAdminVbs(findings);
        cancellationToken.ThrowIfCancellationRequested();

        await ScanScriptFiles(findings, cancellationToken);

        return findings;
    }

    // ── Check 1: LabConfig bypass keys ────────────────────────────────────────

    /// <summary>
    /// Reads HKLM\SYSTEM\Setup\LabConfig. If any bypass value equals 1,
    /// emits a single consolidated High/SystemTampering finding.
    /// </summary>
    private void CheckLabConfigKeys(List<Finding> findings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup\LabConfig");
            if (key == null) return;

            var bypassValues = new[]
            {
                "BypassCPUCheck",
                "BypassStorageCheck",
                "BypassRAMCheck",
                "BypassTPMCheck",
                "BypassSecureBootCheck",
            };

            var active = bypassValues
                .Where(name =>
                {
                    var raw = key.GetValue(name);
                    return raw != null && Convert.ToInt32(raw) == 1;
                })
                .ToList();

            if (active.Count == 0) return;

            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.SystemTampering,
                Name,
                $"Bypass de requisitos do Windows 11 via LabConfig ({active.Count} chave(s))",
                $"As seguintes chaves de bypass do Windows 11 estão ativas em HKLM\\SYSTEM\\Setup\\LabConfig: " +
                $"{string.Join(", ", active)}. " +
                $"Essas chaves permitem instalação/atualização do Windows sem atender aos requisitos mínimos de hardware.",
                $"Chaves ativas: {string.Join(", ", active)} | Caminho: HKLM\\SYSTEM\\Setup\\LabConfig",
                confidence: Confidence.High,
                ruleId: "TAMPER_LABCONFIG_BYPASS",
                validationHint: "Correlacionar com Downloads do browser, Prefetch de cmd.exe/reg.exe/wscript.exe e PSReadLine"
            ));
        }
        catch (Exception ex) { LogPartialError("CheckLabConfigKeys falhou", ex); }
    }

    // ── Check 2: MoSetup bypass key ───────────────────────────────────────────

    /// <summary>
    /// Reads HKLM\SYSTEM\Setup\MoSetup. If AllowUpgradesWithUnsupportedTPMOrCPU == 1,
    /// emits a High/SystemTampering finding.
    /// </summary>
    private void CheckMoSetupKeys(List<Finding> findings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup\MoSetup");
            if (key == null) return;

            var raw = key.GetValue("AllowUpgradesWithUnsupportedTPMOrCPU");
            if (raw == null || Convert.ToInt32(raw) != 1) return;

            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.SystemTampering,
                Name,
                "Bypass de TPM/CPU para upgrade do Windows via MoSetup",
                "A chave AllowUpgradesWithUnsupportedTPMOrCPU está definida como 1 em " +
                "HKLM\\SYSTEM\\Setup\\MoSetup. Isso permite atualizar o Windows 11 em hardware " +
                "não suportado, contornando verificações de segurança.",
                "HKLM\\SYSTEM\\Setup\\MoSetup\\AllowUpgradesWithUnsupportedTPMOrCPU = 1",
                confidence: Confidence.High,
                ruleId: "TAMPER_MOSETUP_BYPASS"
            ));
        }
        catch (Exception ex) { LogPartialError("CheckMoSetupKeys falhou", ex); }
    }

    // ── Check 3: getadmin.vbs in Temp ─────────────────────────────────────────

    /// <summary>
    /// Checks for the BatchGotAdmin VBScript artifact in the system Temp directory.
    /// Its presence indicates UAC elevation bypass was attempted via script.
    /// </summary>
    private void CheckGetAdminVbs(List<Finding> findings)
    {
        try
        {
            var path = Path.Combine(Path.GetTempPath(), "getadmin.vbs");
            if (!File.Exists(path)) return;

            var info = new FileInfo(path);

            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.SystemTampering,
                Name,
                "SCRIPT BATCHGOTADMIN PRESENTE: getadmin.vbs no Temp",
                $"O arquivo 'getadmin.vbs' foi encontrado na pasta Temp do sistema. " +
                $"Esse script é gerado pelo padrão BatchGotAdmin e é usado para escalar " +
                $"privilégios via UAC sem conhecimento do usuário.",
                $"Caminho: {path} | Tamanho: {info.Length} bytes | " +
                $"Última modificação: {info.LastWriteTime:yyyy-MM-dd HH:mm:ss}",
                timestamp: info.LastWriteTime,
                confidence: Confidence.High,
                ruleId: "SCRIPT_BATCHGOTADMIN_PRESENT",
                entity: path
            ));
        }
        catch (Exception ex) { LogPartialError("CheckGetAdminVbs falhou", ex); }
    }

    // ── Check 4: Script file content scan ─────────────────────────────────────

    /// <summary>
    /// Enumerates .bat, .cmd, .ps1, .vbs, .wsf files in well-known user directories
    /// (Desktop, Downloads, Temp, AppData) up to depth 2. For each file whose content
    /// matches any tampering indicator, emits a Critical or High/SystemTampering finding.
    /// </summary>
    private async Task ScanScriptFiles(List<Finding> findings, CancellationToken cancellationToken)
    {
        await Task.Run(() =>
        {
            foreach (var root in GetScriptRoots())
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!Directory.Exists(root)) continue;

                try
                {
                    // Enumerate all script extensions with limited recursion depth
                    var options = new EnumerationOptions
                    {
                        RecurseSubdirectories = true,
                        MaxRecursionDepth     = 2,
                        IgnoreInaccessible    = true,
                    };

                    foreach (var file in Directory.EnumerateFiles(root, "*", options))
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (!ScriptExtensions.Contains(ext)) continue;

                        // Skip the scanner's own files
                        if (IsOwnProcess(file)) continue;

                        AnalyzeScriptFile(file, findings);
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { LogPartialError($"ScanScriptFiles — raiz '{root}' inacessível", ex); }
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Reads a single script file and checks its content against all tampering indicators.
    /// Emits a finding if any indicator matches.
    /// </summary>
    private void AnalyzeScriptFile(string filePath, List<Finding> findings)
    {
        string content;

        try
        {
            content = File.ReadAllText(filePath);
        }
        catch (IOException)            { return; }
        catch (UnauthorizedAccessException) { return; }
        catch (Exception ex)
        {
            LogPartialError($"Leitura do script '{filePath}' falhou", ex);
            return;
        }

        var contentLower = content.ToLowerInvariant();

        // Collect all matched indicators for this file
        var matched = TamperingIndicators
            .Where(ind => contentLower.Contains(ind))
            .ToList();

        if (matched.Count == 0) return;

        // BatchGotAdmin pattern: contains the UAC elevation dropper keywords
        var isBatchGotAdmin = contentLower.Contains("batchgotadmin") ||
                              contentLower.Contains("getadmin.vbs");

        var info      = new FileInfo(filePath);
        var sha256    = GetFileHash(filePath) ?? "N/A";
        var fileSize  = info.Length;
        var lastWrite = info.LastWriteTime;

        var detail = isBatchGotAdmin
            ? $"Script contém padrão BatchGotAdmin — eleva privilégios via UAC sem consentimento.\n" +
              $"Arquivo: {filePath}\nIndicadores: {string.Join(", ", matched)}\n" +
              $"SHA256: {sha256} | Tamanho: {fileSize} bytes"
            : $"Script contém indicadores de adulteração do sistema.\n" +
              $"Arquivo: {filePath}\nIndicadores: {string.Join(", ", matched)}\n" +
              $"SHA256: {sha256} | Tamanho: {fileSize} bytes";

        findings.Add(new Finding(
            isBatchGotAdmin ? RiskLevel.Critical : RiskLevel.High,
            FindingCategory.SystemTampering,
            Name,
            isBatchGotAdmin
                ? $"BATCHGOTADMIN DETECTADO: {Path.GetFileName(filePath)}"
                : $"Script com indicadores de adulteração: {Path.GetFileName(filePath)}",
            detail,
            $"SHA256: {sha256} | Tamanho: {fileSize} bytes | " +
            $"Modificado: {lastWrite:yyyy-MM-dd HH:mm:ss}",
            timestamp: lastWrite,
            confidence: isBatchGotAdmin ? Confidence.High : Confidence.Medium,
            ruleId: isBatchGotAdmin ? "SCRIPT_BATCHGOTADMIN_PRESENT" : "SCRIPT_TAMPERING_DETECTED",
            entity: filePath
        ));
    }
}
