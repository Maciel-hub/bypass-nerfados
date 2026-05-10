using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class KnownCheatsModule : BaseModule
{
    public override string Name => "Known Cheats";
    public override string Description => "Busca direta por executáveis e DLLs de cheats conhecidos no disco";

    private static readonly string[] SearchRoots =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM"),
    ];

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        // Search for known cheat executables
        await Task.Run(() =>
        {
            foreach (var root in SearchRoots)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;
                SearchDirectory(root, findings, cancellationToken);
            }

            // Specific path checks from the document
            CheckSpecificPaths(findings, cancellationToken);
        }, cancellationToken);

        // Check GOSTH pattern: random 8-10 char filename in System32
        CheckGosthPattern(findings, cancellationToken);

        // Check d3d10.dll in FiveM Plugins
        CheckFiveMPlugins(findings, cancellationToken);

        // Check PSReadLine history
        CheckPsReadLine(findings, cancellationToken);

        return findings;
    }

    private void SearchDirectory(string root, List<Finding> findings, CancellationToken cancellationToken)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(root, "*.exe",
                new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
            {
                cancellationToken.ThrowIfCancellationRequested();

                var fileName = Path.GetFileName(file).ToLowerInvariant();

                if (CheatDatabase.KnownExecutables.TryGetValue(fileName, out var cheat))
                {
                    var sha256 = GetFileHash(file);
                    var sha1   = GetFileSha1(file);

                    bool hashMatch = cheat.Hashes?.Contains(sha1 ?? "", StringComparer.OrdinalIgnoreCase) == true;
                    bool pathMatch = cheat.KnownPaths.Any(p =>
                        file.Contains(p, StringComparison.OrdinalIgnoreCase));

                    Confidence confidence;
                    RiskLevel risk;
                    string? validationHint = null;

                    if (hashMatch)
                    {
                        confidence = Confidence.Confirmed;
                        risk = RiskLevel.Critical;
                    }
                    else if (pathMatch)
                    {
                        confidence = Confidence.High;
                        risk = RiskLevel.Critical;
                    }
                    else if (cheat.IsGenericName)
                    {
                        // Generic filename (launcher.exe, dxsetup.exe) — needs path or hash to be credible
                        confidence = Confidence.Low;
                        risk = RiskLevel.Medium;
                        validationHint = "Nome genérico associado a cheats — confirmar por hash, assinatura, caminho típico da família ou correlação com Prefetch/MuiCache/BAM/UserAssist";
                    }
                    else
                    {
                        // Unique cheat name (farinhafree.exe, whatsapp installer.exe) — name alone is credible
                        confidence = Confidence.Medium;
                        risk = RiskLevel.High;
                        validationHint = null;
                    }

                    var ruleId = hashMatch  ? $"CHEAT_HASH_{cheat.Name.ToUpperInvariant().Replace(" ", "_")}"
                               : pathMatch  ? $"CHEAT_PATH_{cheat.Name.ToUpperInvariant().Replace(" ", "_")}"
                               : cheat.IsGenericName ? $"CHEAT_NAME_GENERIC_{fileName.ToUpperInvariant().Replace('.', '_')}"
                               :                       $"CHEAT_NAME_{cheat.Name.ToUpperInvariant().Replace(" ", "_")}";

                    findings.Add(new Finding(
                        risk,
                        FindingCategory.Cheat,
                        "Known Cheats",
                        risk == RiskLevel.Critical
                            ? $"CHEAT ENCONTRADO: {cheat.Name} ({fileName})"
                            : $"Executável com nome de cheat (baixa confiança): {fileName}",
                        $"Arquivo: {file}\n{cheat.Description}",
                        $"SHA256: {sha256 ?? "N/A"} | Tamanho: {new FileInfo(file).Length} bytes",
                        confidence: confidence,
                        ruleId: ruleId,
                        entity: file,
                        validationHint: validationHint
                    ));
                }
            }

            // Skip DLL scan entirely inside C:\Windows — d3d10.dll exists legitimately in System32,
            // WinSxS, servicing, and hundreds of other subdirectories. The cheat variant is only
            // relevant in FiveM Plugins and is handled by CheckFiveMPlugins.
            var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!root.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase))
            foreach (var file in Directory.EnumerateFiles(root, "*.dll",
                new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
            {
                cancellationToken.ThrowIfCancellationRequested();

                var fileName = Path.GetFileName(file).ToLowerInvariant();
                if (CheatDatabase.KnownDlls.TryGetValue(fileName, out var cheat))
                {
                    var info = new FileInfo(file);
                    var sizeKb = info.Length / 1024;
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        "Known Cheats",
                        $"CHEAT DLL ENCONTRADA: {cheat.Name} ({fileName})",
                        $"Arquivo: {file}\n{cheat.Description}",
                        $"Tamanho: {sizeKb} KB | SHA256: {GetFileHash(file) ?? "N/A"}"
                    ));
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Diretório inacessível na varredura de cheats conhecidos", ex); }
    }

    private static void CheckSpecificPaths(List<Finding> findings, CancellationToken cancellationToken)
    {
        // WhatsApp Installer falso em System32\WinBioDatabase
        cancellationToken.ThrowIfCancellationRequested();

        var fakeWhatsApp = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WinBioDatabase", "WhatsApp Installer.exe");

        if (File.Exists(fakeWhatsApp))
        {
            var sha256 = GetFileHash(fakeWhatsApp);
            var sha1   = GetFileSha1(fakeWhatsApp);
            var hashMatch = string.Equals(sha1, "a7d04fdbc41fe2165a4cbc8e0657052ec3fb334f",
                StringComparison.OrdinalIgnoreCase);
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.Cheat,
                "Known Cheats",
                hashMatch
                    ? "GOSTH LOADER CONFIRMADO: WhatsApp Installer.exe em System32"
                    : "WhatsApp Installer.exe suspeito em System32\\WinBioDatabase",
                "Executável malicioso disfarçado de WhatsApp Installer encontrado em System32\\WinBioDatabase.",
                $"Caminho: {fakeWhatsApp} | SHA256: {sha256 ?? "N/A"}",
                confidence: hashMatch ? Confidence.Confirmed : Confidence.High,
                ruleId: hashMatch ? "CHEAT_HASH_GOSTH_WHATSAPP" : "CHEAT_PATH_GOSTH_WHATSAPP",
                entity: fakeWhatsApp
            ));
        }

        // GOSTH: AppData\Local\Programs\Common\dxsetup
        var dxsetupPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs", "Common");

        if (Directory.Exists(dxsetupPath))
        {
            var enumOpts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
            foreach (var file in Directory.EnumerateFiles(dxsetupPath, "*", enumOpts))
            {
                cancellationToken.ThrowIfCancellationRequested();

                var lower = Path.GetFileName(file).ToLowerInvariant();
                if (lower.Contains("dxsetup") || lower.Contains("launcher"))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        "Known Cheats",
                        $"GOSTH LOADER: {Path.GetFileName(file)} em AppData\\Programs\\Common",
                        $"Caminho típico do loader GOSTH detectado.\nArquivo: {file}",
                        $"SHA256: {GetFileHash(file) ?? "N/A"}",
                        confidence: Confidence.High,
                        ruleId: "CHEAT_PATH_GOSTH_DXSETUP",
                        entity: file
                    ));
                }
            }
        }
    }

    private void CheckGosthPattern(List<Finding> findings, CancellationToken cancellationToken)
    {
        // GOSTH gera arquivo de 8-10 chars aleatórios (apenas letras/números) na System32
        // e um arquivo com 8-10 dígitos numéricos com 0 KB
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var files = Directory.GetFiles(system32, "*")
                .Where(f =>
                {
                    var name = Path.GetFileNameWithoutExtension(f);
                    var ext  = Path.GetExtension(f).ToLowerInvariant();

                    // GOSTH drops extensionless files or .exe — DLLs, SYS, DAT etc. are Windows artifacts
                    if (ext is not ("" or ".exe")) return false;

                    bool isSmall      = new FileInfo(f).Length == 0;
                    bool isNumeric    = name.Length is >= 8 and <= 10 && name.All(char.IsDigit);
                    bool isRandomAlph = name.Length is >= 8 and <= 10 && name.All(char.IsLetterOrDigit) && !isNumeric;

                    // Both patterns require 0 KB — legitimate extensionless System32 files are never empty
                    return isSmall && (isNumeric || isRandomAlph);
                })
                .ToList();

            if (files.Count > 0)
            {
                foreach (var f in files)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var size = new FileInfo(f).Length;
                    findings.Add(new Finding(
                        RiskLevel.Medium,
                        FindingCategory.Cheat,
                        "Known Cheats",
                        $"POSSÍVEL PADRÃO GOSTH em System32: {Path.GetFileName(f)}",
                        $"Arquivo 0 KB com nome de 8-10 chars alfanuméricos na System32 — padrão do GOSTH.\nCaminho: {f}\nValidar com Prefetch de launcher.exe e hash SHA1 conhecido.",
                        $"Tamanho: {size} bytes",
                        confidence: Confidence.Low,
                        ruleId: "GOSTH_PATTERN_SYSTEM32",
                        entity: f,
                        validationHint: "Confirmar com Prefetch de launcher.exe ou hash SHA1 do GOSTH"
                    ));
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Varredura de padrão GOSTH no System32 falhou", ex); }
    }

    private static void CheckFiveMPlugins(List<Finding> findings, CancellationToken cancellationToken)
    {
        var fivemData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FiveM", "FiveM Application Data", "Plugins");

        if (!Directory.Exists(fivemData)) return;

        foreach (var file in Directory.GetFiles(fivemData, "*.dll", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var info = new FileInfo(file);
            var sizeKb = info.Length / 1024;

            // d3d10.dll ~1MB is the known cheat
            if (string.Equals(Path.GetFileName(file), "d3d10.dll", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.Cheat,
                    "Known Cheats",
                    $"CHEAT DLL FiveM: d3d10.dll nos Plugins ({sizeKb} KB)",
                    $"DLL de cheat encontrada na pasta de Plugins do FiveM. Tamanho típico: ~1MB.\nArquivo: {file}",
                    $"SHA256: {GetFileHash(file) ?? "N/A"} | Tamanho: {sizeKb} KB"
                ));
                continue;
            }

            // Any unsigned DLL in FiveM plugins is suspicious
            if (sizeKb > 100)
            {
                findings.Add(new Finding(
                    RiskLevel.Medium,
                    FindingCategory.SuspiciousExecution,
                    "Known Cheats",
                    $"DLL suspeita nos Plugins do FiveM: {Path.GetFileName(file)}",
                    $"DLL não padrão encontrada na pasta de Plugins do FiveM.\nArquivo: {file}",
                    $"Tamanho: {sizeKb} KB"
                ));
            }
        }
    }

    private void CheckPsReadLine(List<Finding> findings, CancellationToken cancellationToken)
    {
        var psHistory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "PowerShell", "PSReadline", "ConsoleHost_history.txt");

        if (!File.Exists(psHistory)) return;

        try
        {
            var lines = File.ReadAllLines(psHistory);
            foreach (var line in lines)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var lower = line.ToLowerInvariant();

                if (lower.Contains("wevtutil") && (lower.Contains(" cl ") || lower.Contains("clear-log")))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.AntiForensics,
                        "Known Cheats",
                        "PSReadLine: Limpeza de logs via wevtutil",
                        $"Comando encontrado no histórico PowerShell: {line.Trim()}",
                        $"Arquivo: {psHistory}"
                    ));
                }
                else if (lower.Contains("fsutil") && lower.Contains("usn"))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.AntiForensics,
                        "Known Cheats",
                        "PSReadLine: Manipulação do USN Journal",
                        $"Comando encontrado no histórico PowerShell: {line.Trim()}",
                        $"Arquivo: {psHistory}"
                    ));
                }
                // Guard with IsKnownLegitimate before keyword match: commands like
                // "git clone github.com/citizenfx/..." contain "citizen" as a substring
                // of "citizenfx" and would otherwise generate false High findings.
                else if (CheatDatabase.HasSuspiciousKeyword(lower) &&
                         !CheatDatabase.IsKnownLegitimate(lower))
                {
                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.SuspiciousExecution,
                        "Known Cheats",
                        "PSReadLine: Comando suspeito no histórico PowerShell",
                        $"Comando: {line.Trim()}",
                        $"Arquivo: {psHistory}"
                    ));
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Histórico do PSReadLine inacessível", ex); }
    }
}
