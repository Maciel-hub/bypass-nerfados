using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class FileSystemModule : BaseModule
{
    public override string Name => "File System";
    public override string Description => "Lixeira, Temp, Downloads, CrashDumps e arquivos suspeitos";

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        ScanRecycleBin(findings, cancellationToken);
        ScanTempFolders(findings, cancellationToken);
        ScanDownloads(findings, cancellationToken);
        ScanCrashDumps(findings, cancellationToken);
        ScanAppDataSuspicious(findings, cancellationToken);

        return Task.FromResult(findings);
    }

    private void ScanRecycleBin(List<Finding> findings, CancellationToken cancellationToken)
    {
        var recyclePath = @"C:\$Recycle.Bin";
        if (!Directory.Exists(recyclePath)) return;

        try
        {
            foreach (var userDir in Directory.GetDirectories(recyclePath))
            {
                cancellationToken.ThrowIfCancellationRequested();

                foreach (var file in Directory.EnumerateFiles(userDir, "$I*",
                    new EnumerationOptions { IgnoreInaccessible = true }))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        // $I files contain original path info
                        var bytes = File.ReadAllBytes(file);
                        if (bytes.Length < 28) continue;

                        // Original path starts at offset 28 in $I files (Unicode)
                        var originalPath = System.Text.Encoding.Unicode
                            .GetString(bytes, 28, bytes.Length - 28)
                            .TrimEnd('\0');

                        var fileName = Path.GetFileName(originalPath).ToLowerInvariant();

                        if (CheatDatabase.KnownExecutables.TryGetValue(fileName, out var cheat))
                        {
                            findings.Add(new Finding(
                                RiskLevel.Critical,
                                FindingCategory.Cheat,
                                "File System",
                                $"CHEAT NA LIXEIRA: {cheat.Name}",
                                $"Executável de cheat encontrado na Lixeira. Jogador tentou excluir após uso.\nCaminho original: {originalPath}",
                                $"Arquivo $I: {file}"
                            ));
                            continue;
                        }

                        // Only flag executable-type files on keyword match — .lnk, .log, .sql etc.
                        // are benign even when found in AppData or Downloads paths
                        var origExt = Path.GetExtension(originalPath).ToLowerInvariant();
                        if (origExt is ".exe" or ".dll" or ".bat" or ".ps1" or ".vbs" or ".cmd" or ".scr")
                        {
                            if (CheatDatabase.HasSuspiciousKeyword(fileName) &&
                                !CheatDatabase.IsKnownLegitimate(fileName))
                            {
                                findings.Add(new Finding(
                                    RiskLevel.Medium,
                                    FindingCategory.FileSystem,
                                    "File System",
                                    $"Arquivo suspeito na Lixeira: {fileName}",
                                    $"Caminho original: {originalPath}"
                                ));
                            }
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Lixeira inacessível", ex); }
    }

    private static void ScanTempFolders(List<Finding> findings, CancellationToken cancellationToken)
    {
        var tempPaths = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        foreach (var temp in tempPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Directory.Exists(temp)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(temp, "*.exe",
                    new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 2 }))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var name = Path.GetFileName(file).ToLowerInvariant();

                    if (CheatDatabase.KnownExecutables.TryGetValue(name, out var cheat))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.Cheat,
                            "File System",
                            $"CHEAT NA PASTA TEMP: {cheat.Name}",
                            $"Executável de cheat na pasta temporária.\nArquivo: {file}",
                            $"SHA256: {GetFileHash(file) ?? "N/A"}"
                        ));
                        continue;
                    }

                    if (CheatDatabase.HasSuspiciousKeyword(name) && !IsOwnProcess(name))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.FileSystem,
                            "File System",
                            $"Executável suspeito na Temp: {name}",
                            $"Arquivo: {file}"
                        ));
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }

    private void ScanDownloads(List<Finding> findings, CancellationToken cancellationToken)
    {
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        if (!Directory.Exists(downloads)) return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(downloads, "*",
                new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 2 }))
            {
                cancellationToken.ThrowIfCancellationRequested();

                var ext = Path.GetExtension(file).ToLowerInvariant();
                var name = Path.GetFileName(file).ToLowerInvariant();

                if (ext is not (".exe" or ".dll" or ".zip" or ".rar" or ".7z")) continue;

                if (CheatDatabase.KnownExecutables.TryGetValue(name, out var cheat))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        "File System",
                        $"CHEAT NOS DOWNLOADS: {cheat.Name}",
                        $"Arquivo de cheat encontrado na pasta de Downloads.\nArquivo: {file}",
                        $"SHA256: {GetFileHash(file) ?? "N/A"}"
                    ));
                    continue;
                }

                if (CheatDatabase.HasSuspiciousKeyword(name) && !IsOwnProcess(name))
                {
                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.FileSystem,
                        "File System",
                        $"Arquivo suspeito nos Downloads: {name}",
                        $"Arquivo: {file}"
                    ));
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Pasta Downloads inacessível", ex); }
    }

    private static void ScanCrashDumps(List<Finding> findings, CancellationToken cancellationToken)
    {
        var crashDumps = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CrashDumps");

        if (!Directory.Exists(crashDumps))
        {
            // Absence of CrashDumps may indicate cleanup
            findings.Add(new Finding(
                RiskLevel.Low,
                FindingCategory.FileSystem,
                "File System",
                "Pasta CrashDumps não encontrada",
                "Pode indicar limpeza da pasta ou sistema sem crashs históricos. Verificar contexto."
            ));
            return;
        }

        var dmpFiles = Directory.GetFiles(crashDumps, "*.dmp", SearchOption.AllDirectories);
        foreach (var dmp in dmpFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var name = Path.GetFileName(dmp);
            var lower = name.ToLowerInvariant();

            if (lower.Contains("fivem") || lower.Contains("gta"))
            {
                var info = new FileInfo(dmp);
                findings.Add(new Finding(
                    RiskLevel.Medium,
                    FindingCategory.FileSystem,
                    "File System",
                    $"CrashDump do FiveM/GTA: {name}",
                    $"Crash registrado — pode conter informações sobre módulos ativos no momento do crash.\nData: {info.LastWriteTime:dd/MM/yyyy HH:mm:ss}",
                    $"Arquivo: {dmp} | Tamanho: {info.Length / 1024} KB",
                    info.LastWriteTime
                ));
            }
        }
    }

    private static void ScanAppDataSuspicious(List<Finding> findings, CancellationToken cancellationToken)
    {
        var appDataPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var root in appDataPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.exe",
                    new EnumerationOptions { IgnoreInaccessible = true, MaxRecursionDepth = 4, RecurseSubdirectories = true }))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var name = Path.GetFileName(file).ToLowerInvariant();

                    if (CheatDatabase.KnownExecutables.TryGetValue(name, out var cheat))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.Cheat,
                            "File System",
                            $"CHEAT NO APPDATA: {cheat.Name}",
                            $"Executável de cheat em AppData.\nArquivo: {file}"
                        ));
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }
}
