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

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config)
    {
        var findings = new List<Finding>();

        // Search for known cheat executables
        await Task.Run(() =>
        {
            foreach (var root in SearchRoots)
            {
                if (!Directory.Exists(root)) continue;
                SearchDirectory(root, findings);
            }

            // Specific path checks from the document
            CheckSpecificPaths(findings);
        });

        // Check GOSTH pattern: random 8-10 char filename in System32
        CheckGosthPattern(findings);

        // Check d3d10.dll in FiveM Plugins
        CheckFiveMPlugins(findings);

        // Check PSReadLine history
        CheckPsReadLine(findings);

        return findings;
    }

    private static void SearchDirectory(string root, List<Finding> findings)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(root, "*.exe",
                new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
            {
                var fileName = Path.GetFileName(file).ToLowerInvariant();

                if (CheatDatabase.KnownExecutables.TryGetValue(fileName, out var cheat))
                {
                    var hash = GetFileHash(file);
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        "Known Cheats",
                        $"CHEAT ENCONTRADO NO DISCO: {cheat.Name}",
                        $"Arquivo: {file}\n{cheat.Description}",
                        $"SHA1: {hash ?? "N/A"} | Tamanho: {new FileInfo(file).Length} bytes"
                    ));
                }
            }

            // Search DLLs in FiveM plugins
            foreach (var file in Directory.EnumerateFiles(root, "*.dll",
                new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
            {
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
                        $"Tamanho: {sizeKb} KB | SHA1: {GetFileHash(file) ?? "N/A"}"
                    ));
                }
            }
        }
        catch { }
    }

    private static void CheckSpecificPaths(List<Finding> findings)
    {
        // WhatsApp Installer falso em System32\WinBioDatabase
        var fakeWhatsApp = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WinBioDatabase", "WhatsApp Installer.exe");

        if (File.Exists(fakeWhatsApp))
        {
            var hash = GetFileHash(fakeWhatsApp);
            var isConfirmed = string.Equals(hash, "a7d04fdbc41fe2165a4cbc8e0657052ec3fb334f",
                StringComparison.OrdinalIgnoreCase);
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.Cheat,
                "Known Cheats",
                isConfirmed
                    ? "GOSTH LOADER CONFIRMADO: WhatsApp Installer.exe em System32"
                    : "WhatsApp Installer.exe suspeito em System32\\WinBioDatabase",
                "Executável malicioso disfarçado de WhatsApp Installer encontrado em System32\\WinBioDatabase.",
                $"Caminho: {fakeWhatsApp} | SHA1: {hash ?? "N/A"}"
            ));
        }

        // GOSTH: AppData\Local\Programs\Common\dxsetup
        var dxsetupPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs", "Common");

        if (Directory.Exists(dxsetupPath))
        {
            foreach (var file in Directory.GetFiles(dxsetupPath, "*", SearchOption.AllDirectories))
            {
                var lower = Path.GetFileName(file).ToLowerInvariant();
                if (lower.Contains("dxsetup") || lower.Contains("launcher"))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        "Known Cheats",
                        $"GOSTH LOADER: {Path.GetFileName(file)} em AppData\\Programs\\Common",
                        $"Caminho típico do loader GOSTH detectado.\nArquivo: {file}",
                        $"SHA1: {GetFileHash(file) ?? "N/A"}"
                    ));
                }
            }
        }
    }

    private static void CheckGosthPattern(List<Finding> findings)
    {
        // GOSTH gera arquivo de 8-10 chars aleatórios (apenas letras/números) na System32
        // e um arquivo com 8-10 dígitos numéricos com 0 KB
        try
        {
            var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var files = Directory.GetFiles(system32, "*")
                .Where(f =>
                {
                    var name = Path.GetFileNameWithoutExtension(f);
                    var ext = Path.GetExtension(f);
                    // Match 8-10 random alphanum chars, no extension or .exe
                    bool isRandomName = name.Length is >= 8 and <= 10 &&
                                        name.All(char.IsLetterOrDigit);
                    bool isNumericName = name.Length is >= 8 and <= 10 &&
                                         name.All(char.IsDigit);
                    bool isSmall = new FileInfo(f).Length == 0;
                    return (isRandomName || (isNumericName && isSmall)) &&
                           !string.Equals(ext, ".mui", StringComparison.OrdinalIgnoreCase);
                })
                .ToList();

            if (files.Count > 0)
            {
                foreach (var f in files)
                {
                    var size = new FileInfo(f).Length;
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        "Known Cheats",
                        $"PADRÃO GOSTH em System32: {Path.GetFileName(f)}",
                        $"Arquivo com nome aleatório de 8-10 chars na System32 — padrão característico do GOSTH.\nCaminho: {f}",
                        $"Tamanho: {size} bytes | SHA1: {(size > 0 ? GetFileHash(f) ?? "N/A" : "vazio")}"
                    ));
                }
            }
        }
        catch { }
    }

    private static void CheckFiveMPlugins(List<Finding> findings)
    {
        var fivemData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FiveM", "FiveM Application Data", "Plugins");

        if (!Directory.Exists(fivemData)) return;

        foreach (var file in Directory.GetFiles(fivemData, "*.dll", SearchOption.AllDirectories))
        {
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
                    $"SHA1: {GetFileHash(file) ?? "N/A"} | Tamanho: {sizeKb} KB"
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

    private static void CheckPsReadLine(List<Finding> findings)
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
                else if (CheatDatabase.HasSuspiciousKeyword(lower))
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
        catch { }
    }
}
