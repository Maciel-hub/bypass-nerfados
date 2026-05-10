using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class PrefetchModule : BaseModule
{
    public override string Name => "Prefetch";
    public override string Description => "Histórico de programas executados via arquivos .pf";

    private static readonly string PrefetchPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        if (!Directory.Exists(PrefetchPath))
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                Name,
                "Pasta Prefetch não encontrada",
                "A pasta C:\\Windows\\Prefetch foi removida ou o Prefetch está desabilitado. " +
                "Isso pode indicar tentativa de ocultar histórico de execução.",
                PrefetchPath
            ));
            return Task.FromResult(findings);
        }

        var pfFiles = Directory.GetFiles(PrefetchPath, "*.pf");

        if (pfFiles.Length == 0)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.AntiForensics,
                Name,
                "Pasta Prefetch está vazia",
                "Nenhum arquivo .pf encontrado. O Prefetch pode ter sido limpo manualmente.",
                PrefetchPath
            ));
            return Task.FromResult(findings);
        }

        foreach (var pfFile in pfFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var fileName = Path.GetFileNameWithoutExtension(pfFile);
            // Prefetch format: EXENAME-HASH.pf — extract executable name
            // P0.5 fix: fileName may be "LAUNCHER.EXE-A1B2C3D4"; after splitting we get "LAUNCHER.EXE"
            // NormalizeExeName ensures we always have exactly "name.exe" (lowercase, no double extension)
            var dashIdx = fileName.LastIndexOf('-');
            var rawName = dashIdx > 0 ? fileName[..dashIdx] : fileName;
            var exeName = NormalizeExeName(rawName); // always "name.exe" lowercase

            var lastWriteTime = File.GetLastWriteTime(pfFile);

            // Never flag the scanner itself
            if (IsOwnProcess(exeName)) continue;

            // Known cheat executables — apply same confidence logic as KnownCheatsModule
            if (CheatDatabase.KnownExecutables.TryGetValue(exeName, out var cheatInfo))
            {
                var confidence = cheatInfo.IsGenericName ? Confidence.Low : Confidence.Medium;
                var risk       = cheatInfo.IsGenericName ? RiskLevel.Medium : RiskLevel.High;
                findings.Add(new Finding(
                    risk,
                    FindingCategory.Cheat,
                    Name,
                    cheatInfo.IsGenericName
                        ? $"Executável com nome de cheat no Prefetch (baixa confiança): {exeName}"
                        : $"CHEAT NO PREFETCH: {cheatInfo.Name} ({exeName})",
                    $"Arquivo Prefetch confirma execução.\n{cheatInfo.Description}",
                    $"Prefetch: {Path.GetFileName(pfFile)} | Última execução: {lastWriteTime:dd/MM/yyyy HH:mm:ss}",
                    lastWriteTime,
                    confidence: confidence,
                    ruleId: cheatInfo.IsGenericName
                        ? $"PREFETCH_GENERIC_{exeName.ToUpperInvariant().Replace('.', '_')}"
                        : $"PREFETCH_{cheatInfo.Name.ToUpperInvariant().Replace(' ', '_')}",
                    entity: exeName,
                    validationHint: cheatInfo.IsGenericName
                        ? "Confirmar caminho e hash — nome genérico pode ser launcher legítimo"
                        : null
                ));
                continue;
            }

            // Suspicious keywords in name
            if (CheatDatabase.HasSuspiciousKeyword(exeName))
            {
                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.SuspiciousExecution,
                    Name,
                    $"Execução suspeita no Prefetch: {exeName}",
                    $"Nome do executável contém indicador de cheat/hack.",
                    $"Arquivo: {Path.GetFileName(pfFile)} | Última execução: {lastWriteTime:dd/MM/yyyy HH:mm:ss}",
                    lastWriteTime
                ));
                continue;
            }

            // Known bypass/hack tools
            if (IsKnownHackTool(exeName))
            {
                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.SuspiciousExecution,
                    Name,
                    $"Ferramenta suspeita no Prefetch: {exeName}.exe",
                    "Ferramenta conhecida de manipulação de processos ou memória.",
                    $"Arquivo: {Path.GetFileName(pfFile)} | Última execução: {lastWriteTime:dd/MM/yyyy HH:mm:ss}",
                    lastWriteTime
                ));
            }
        }

        return Task.FromResult(findings);
    }

    private static bool IsKnownHackTool(string exeName)
    {
        // exeName comes normalized from NormalizeExeName — always has .exe
        var nameNoExt = Path.GetFileNameWithoutExtension(exeName).ToLowerInvariant();
        var tools = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cheatengine", "cheatengine-x86_64", "cheatengine-i386",
            "processhacker", "processhacker2", "systeminformer",
            "x64dbg", "x32dbg", "ollydbg",
            "injector", "xenos", "extreme injector",
            "maphack", "multihack", "speedhack"
            // Note: wireshark/fiddler/charlesproxy are dual-use — not flagged here
        };
        return tools.Contains(nameNoExt);
    }
}
