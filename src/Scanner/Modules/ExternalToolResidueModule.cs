using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Detecta rastros de ferramentas de investigação, análise de processo e tampering.
/// A presença isolada dessas ferramentas não constitui prova de cheat — é um indício
/// que deve ser correlacionado com outras evidências (loaders, DLLs suspeitas,
/// Prefetch FiveM, etc.).
/// </summary>
public class ExternalToolResidueModule : BaseModule
{
    public override string Name        => "External Tool Residue";
    public override string Description => "Detecta rastros de ferramentas de investigação, análise de processo e tampering — sozinho é indício, correlacionar com evidências de cheat";

    private const string ValidationHintText =
        "Sozinho não é prova de cheat — verificar se há execução próxima de FiveM, loaders ou DLLs suspeitas";

    // Conjunto de nomes base (sem extensão, sem hash de prefetch) de ferramentas suspeitas
    // mantido como HashSet para lookup O(1).
    private static readonly HashSet<string> SuspiciousPrefetchNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "PROCESSHACKER", "PROCESSHACKER2", "SYSTEMINFORMER", "SYSTEMINFORMER64",
            "X64DBG", "X32DBG", "OLLYDBG", "WINDBG",
            "CHEATENGINE", "CHEATENGINE-X86_64", "CHEATENGINE-I386",
            "EVERYTHING", "EVERYTHING64",
            "WIRESHARK", "RAWCAP", "NETWORKMINER",
            "REGSHOT", "REGSHOT64", "REGSHOT-X64",
            "PROCEXP", "PROCEXP64", "PROCMON", "PROCMON64",
            "AUTORUNS", "AUTORUNSC",
            "PESTUDIO", "EXEINFOPE", "PEID", "DIEC",
            "HXDSETUP", "HXDPORTABLE", "010EDITOR",
            "DUMPCAP", "TSHARK",
            "MEMORIZE", "RAMMAP64", "VMMAP64",
            "USBDEVIEW", "NIRSOFT",
            // Nirsoft forensic viewers
            "LASTACTIVITYVIEW", "WINPREFETCHVIEW", "SHELLBAGSVIEW",
            "BROWSINGHISTORYVIEW", "USBLOGVIEW", "VOLUMESSHADOWCOPYVIEW",
            "JUMPLISTSVIEW", "RECENTFILESVIEW",
            // Journal / BAM parsers
            "JOURNALTRACE", "BAMPARSER", "BAMVIEW",
            // Path analysis
            "PATHPARSER", "PATHANALYZER",
        };

    // Executáveis cujos caminhos de disco são inspecionados em locais sensíveis
    private static readonly string[] DiskCheckExecutables =
    [
        "processhacker.exe",
        "systeminformer.exe",
        "systeminformer64.exe",
        "cheatengine-x86_64.exe",
        "cheatengine-i386.exe",
        "everything.exe",
        "everything64.exe",
    ];

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        CheckPrefetchForTools(findings, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        CheckDirectPaths(findings, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        CheckRegistryEvidence(findings);

        return Task.FromResult(findings);
    }

    // ── Prefetch ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Varre a pasta Prefetch em busca de .pf cujos nomes de executável (antes do
    /// traço-hash) correspondam a ferramentas de análise conhecidas.
    /// </summary>
    private void CheckPrefetchForTools(List<Finding> findings, CancellationToken ct)
    {
        var prefetchPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchPath)) return;

        IEnumerable<string> pfFiles;
        try
        {
            pfFiles = Directory.EnumerateFiles(prefetchPath, "*.pf",
                new EnumerationOptions { IgnoreInaccessible = true });
        }
        catch (Exception ex)
        {
            LogPartialError("ExternalToolResidue — acesso à pasta Prefetch negado", ex);
            return;
        }

        foreach (var pfFile in pfFiles)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var baseName = Path.GetFileNameWithoutExtension(pfFile); // e.g. PROCEXP64-A1B2C3D4
                var dashIdx  = baseName.LastIndexOf('-');
                var toolName = dashIdx > 0 ? baseName[..dashIdx] : baseName; // e.g. PROCEXP64

                if (!SuspiciousPrefetchNames.Contains(toolName)) continue;
                if (IsOwnProcess(toolName)) continue;

                var lastWrite = File.GetLastWriteTime(pfFile);

                findings.Add(new Finding(
                    RiskLevel.Medium,
                    FindingCategory.SuspiciousExecution,
                    Name,
                    $"Ferramenta de análise detectada no Prefetch: {toolName}",
                    "Ferramenta de análise de processo/memória encontrada no histórico de execuções. " +
                    "Sozinha é indício — correlacionar com evidências de cheat e timestamps.",
                    evidence:       $"Arquivo Prefetch: {Path.GetFileName(pfFile)} | LastWriteTime: {lastWrite:dd/MM/yyyy HH:mm:ss}",
                    timestamp:      lastWrite,
                    confidence:     Confidence.Low,
                    ruleId:         $"EXTOOL_PREFETCH_{toolName.ToUpperInvariant()}",
                    entity:         toolName,
                    validationHint: ValidationHintText
                ));
            }
            catch (Exception ex)
            {
                LogPartialError($"ExternalToolResidue — falha ao processar Prefetch {pfFile}", ex);
            }
        }
    }

    // ── Disco ─────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Verifica se executáveis de ferramentas de análise existem em locais
    /// sensíveis do perfil do usuário atual (Desktop, Downloads, AppData, Temp).
    /// </summary>
    private void CheckDirectPaths(List<Finding> findings, CancellationToken ct)
    {
        // Locais sensíveis a verificar
        var searchRoots = new List<string>();

        TryAddDirectory(searchRoots, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        TryAddDirectory(searchRoots, Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
        TryAddDirectory(searchRoots, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        TryAddDirectory(searchRoots, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        TryAddDirectory(searchRoots, Path.GetTempPath());

        foreach (var exe in DiskCheckExecutables)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var root in searchRoots)
            {
                var fullPath = Path.Combine(root, exe);
                try
                {
                    if (!File.Exists(fullPath)) continue;
                    if (IsOwnProcess(fullPath)) continue;

                    var hash = GetFileHash(fullPath);
                    findings.Add(new Finding(
                        RiskLevel.Medium,
                        FindingCategory.SuspiciousExecution,
                        Name,
                        $"Ferramenta de análise em disco: {exe}",
                        "Executável de ferramenta de análise de processo/memória encontrado em local sensível do usuário. " +
                        "Sozinho é indício — correlacionar com evidências de cheat.",
                        evidence:       $"Caminho: {fullPath}" +
                                        (hash != null ? $" | SHA256: {hash}" : ""),
                        confidence:     Confidence.Medium,
                        ruleId:         $"EXTOOL_DISK_{Path.GetFileNameWithoutExtension(exe).ToUpperInvariant()}",
                        entity:         fullPath,
                        validationHint: ValidationHintText
                    ));
                }
                catch (Exception ex)
                {
                    LogPartialError($"ExternalToolResidue — falha ao verificar {fullPath}", ex);
                }
            }
        }
    }

    // ── Registro ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Verifica chaves de registro criadas por ferramentas de análise.
    /// A presença indica uso prévio da ferramenta nesta conta de usuário.
    /// </summary>
    private void CheckRegistryEvidence(List<Finding> findings)
    {
        // Cada entrada: (subkey relativa a HKCU, nome da ferramenta, nível de risco, ruleId)
        var entries = new (string SubKey, string ToolName, RiskLevel Risk, string RuleId)[]
        {
            (
                @"Software\ProcessHacker",
                "Process Hacker",
                RiskLevel.High,
                "EXTOOL_REG_PROCESSHACKER"
            ),
            (
                @"Software\Sysinternals\Process Explorer",
                "Process Explorer (Sysinternals)",
                RiskLevel.Medium,
                "EXTOOL_REG_PROCEXP"
            ),
            (
                @"Software\Sysinternals\Autoruns",
                "Autoruns (Sysinternals)",
                RiskLevel.Medium,
                "EXTOOL_REG_AUTORUNS"
            ),
            (
                @"Software\voidtools\Everything",
                "Everything",
                RiskLevel.Medium,
                "EXTOOL_REG_EVERYTHING"
            ),
        };

        foreach (var (subKey, toolName, risk, ruleId) in entries)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(subKey);
                if (key == null) continue;

                findings.Add(new Finding(
                    risk,
                    FindingCategory.SuspiciousExecution,
                    Name,
                    $"Registro de ferramenta de análise: {toolName}",
                    $"Chave de registro criada por ferramenta de análise encontrada em HKCU\\{subKey}. " +
                    "Indica uso prévio da ferramenta nesta conta. " +
                    "Sozinho é indício — correlacionar com evidências de cheat.",
                    evidence:       $@"HKCU\{subKey}",
                    confidence:     Confidence.Low,
                    ruleId:         ruleId,
                    entity:         subKey,
                    validationHint: ValidationHintText
                ));
            }
            catch (Exception ex)
            {
                LogPartialError($"ExternalToolResidue — falha ao verificar registro {subKey}", ex);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────

    private static void TryAddDirectory(List<string> list, string path)
    {
        if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
            list.Add(path);
    }
}
