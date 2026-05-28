using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

// Stan Menu is a FiveM cheat loader distributed as loader.exe with a .credentials file
// for subscriber authentication. It downloads from redengine.net/customer-area/orders
// and leaves a forensic chain: Loader-*.zip → loader.exe → f0686phud.credentials → BAM/Prefetch.
//
// Privacy constraint: .credentials file content MUST NEVER appear in any Finding.
// Log only: path, SHA256 hash, file size, timestamp, and whether known fields exist.
public class StanArtifactsModule : BaseModule
{
    public override string Name        => "Stan Artifacts";
    public override string Description => "Artefatos do loader Stan/genérico (loader.exe, .credentials, Loader-*.zip, Prefetch, BAM)";

    // Archive filename patterns used by Stan/RedENGINE distribution
    private static readonly string[] LoaderArchivePatterns =
        ["Loader-*.zip", "Loader-*.rar", "Executor*V*.zip", "*spoofer*.zip", "*Spoofer*.zip"];

    private static string[] UserSearchRoots()
    {
        var profile   = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return
        [
            Path.Combine(profile, "Downloads"),
            Path.Combine(profile, "Desktop"),
            Path.Combine(profile, "Documents"),
            Path.GetTempPath(),
            Path.Combine(localData, "Temp"),
        ];
    }

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        ScanLoaderExeOnDisk(findings, ct);
        ScanCredentialsFiles(findings, ct);
        ScanLoaderArchives(findings, ct);
        ScanPrefetchBam(findings, ct);

        return Task.FromResult(findings);
    }

    // Detect loader.exe in user-accessible paths.
    // Alone it is Medium — context (credentials co-located, downloads, FiveM proximity) escalates it.
    private void ScanLoaderExeOnDisk(List<Finding> findings, CancellationToken ct)
    {
        foreach (var root in UserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "loader.exe",
                    new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
                {
                    ct.ThrowIfCancellationRequested();

                    var modified  = File.GetLastWriteTime(file);
                    var sizeBytes = new FileInfo(file).Length;
                    var dir       = Path.GetDirectoryName(file) ?? "";

                    // Check if .credentials exists in same directory (stronger co-location signal)
                    bool hasCredential = Directory.GetFiles(dir, "*.credentials", SearchOption.TopDirectoryOnly).Length > 0;

                    var risk  = hasCredential ? RiskLevel.High   : RiskLevel.Medium;
                    var conf  = hasCredential ? Confidence.High  : Confidence.Medium;
                    var ruleId = hasCredential ? "STAN_LOADER_WITH_CREDENTIAL" : "STAN_LOADER_EXE";

                    findings.Add(new Finding(
                        risk,
                        FindingCategory.Cheat,
                        Name,
                        hasCredential
                            ? "STAN LOADER: loader.exe + .credentials no mesmo diretório"
                            : "STAN LOADER: loader.exe encontrado em caminho de usuário",
                        $"loader.exe detectado em localização de usuário.\n" +
                        (hasCredential
                            ? "Arquivo .credentials co-localizado — indicativo de loader com autenticação de assinante.\n"
                            : "Sozinho é insuficiente — correlacionar com download de portal e sessão FiveM.\n") +
                        $"Caminho: {file}",
                        $"Tamanho: {sizeBytes} bytes | Modificado: {modified:dd/MM/yyyy HH:mm:ss}" +
                        (hasCredential ? " | .credentials co-localizado" : ""),
                        timestamp: modified,
                        confidence: conf,
                        ruleId: ruleId,
                        entity: file,
                        validationHint: hasCredential
                            ? "Correlacionar com download de redengine.net e sessão FiveM"
                            : "Sozinho é inconclusivo — exige download de portal cheat, Prefetch próximo ao FiveM e/ou .credentials"
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"Stan: varredura de loader.exe em {root} falhou", ex); }
        }
    }

    // Detect *.credentials files in user paths.
    // Pattern: random-hex name + .credentials extension (e.g. f0686phud.credentials).
    // PRIVACY: file content NEVER logged. Only path, SHA256, size, timestamp.
    private void ScanCredentialsFiles(List<Finding> findings, CancellationToken ct)
    {
        foreach (var root in UserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.credentials",
                    new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
                {
                    ct.ThrowIfCancellationRequested();

                    var modified  = File.GetLastWriteTime(file);
                    var sizeBytes = new FileInfo(file).Length;
                    var stem      = Path.GetFileNameWithoutExtension(file);
                    var dir       = Path.GetDirectoryName(file) ?? "";

                    // Compute SHA256 for integrity — never log content
                    string sha256 = "erro";
                    try { sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))).ToLowerInvariant(); } catch { }

                    bool hasLoader = File.Exists(Path.Combine(dir, "loader.exe"))
                                  || File.Exists(Path.Combine(dir, "Loader.exe"));

                    bool stemLooksRandom = SuspiciousCoProcessResolver.IsRandomName(stem) ||
                                          (stem.Length >= 6 && stem.All(c => char.IsLetterOrDigit(c)));

                    var risk  = (hasLoader || stemLooksRandom) ? RiskLevel.High   : RiskLevel.Medium;
                    var conf  = hasLoader                      ? Confidence.High  : Confidence.Medium;
                    var ruleId = hasLoader ? "STAN_CREDENTIALS_NEAR_LOADER" : "STAN_RANDOM_CREDENTIAL_FILE";

                    findings.Add(new Finding(
                        risk,
                        FindingCategory.Cheat,
                        Name,
                        hasLoader
                            ? $"STAN CREDENTIAL: .credentials co-localizado com loader.exe — {stem}.credentials"
                            : $"STAN CREDENTIAL: arquivo .credentials com nome aleatório — {stem}.credentials",
                        $"Arquivo de credencial de cheat detectado em caminho de usuário.\n" +
                        "Padrão: nome aleatório + extensão .credentials (ex: f0686phud.credentials).\n" +
                        (hasLoader ? "loader.exe encontrado no mesmo diretório — cadeia de entrega confirmada.\n" : "") +
                        $"Caminho: {file}\n" +
                        $"(Conteúdo nunca registrado — apenas hash e metadados.)",
                        $"SHA256: {sha256} | Tamanho: {sizeBytes} bytes | Modificado: {modified:dd/MM/yyyy HH:mm:ss}",
                        timestamp: modified,
                        confidence: conf,
                        ruleId: ruleId,
                        entity: file,
                        validationHint: "Correlacionar com download de portal cheat, Prefetch de loader.exe e sessão FiveM"
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"Stan: varredura de .credentials em {root} falhou", ex); }
        }
    }

    // Detect loader/executor ZIP archives in user paths.
    // Pattern: Loader-<hash>.zip, Executor V*.zip, *spoofer*.zip
    private void ScanLoaderArchives(List<Finding> findings, CancellationToken ct)
    {
        foreach (var root in UserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            foreach (var pattern in LoaderArchivePatterns)
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(root, pattern,
                        new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 4 }))
                    {
                        ct.ThrowIfCancellationRequested();

                        var modified  = File.GetLastWriteTime(file);
                        var sizeBytes = new FileInfo(file).Length;

                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.Cheat,
                            Name,
                            $"STAN ARCHIVE: arquivo de loader/executor encontrado — {Path.GetFileName(file)}",
                            $"Arquivo compactado de loader/executor cheat encontrado em localização de usuário.\n" +
                            $"Padrão: Loader-<hash>.zip, Executor V*.zip ou arquivo spoofer compactado.\n" +
                            $"Caminho: {file}",
                            $"Tamanho: {sizeBytes} bytes | Modificado: {modified:dd/MM/yyyy HH:mm:ss}",
                            timestamp: modified,
                            confidence: Confidence.Medium,
                            ruleId: "STAN_LOADER_ARCHIVE",
                            entity: file,
                            validationHint: "Correlacionar com download de redengine.net, Prefetch de loader.exe e sessão FiveM"
                        ));
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }
    }

    // Check Prefetch for LOADER.EXE* and BAM for loader paths.
    private void ScanPrefetchBam(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (Directory.Exists(prefetchDir))
        {
            try
            {
                foreach (var pf in Directory.GetFiles(prefetchDir, "LOADER.EXE*"))
                {
                    ct.ThrowIfCancellationRequested();
                    var modified = File.GetLastWriteTime(pf);
                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.Cheat,
                        Name,
                        $"STAN EXECUTADO: rastro Prefetch — {Path.GetFileName(pf)}",
                        $"Prefetch de loader.exe indica execução anterior do loader Stan/genérico.\n" +
                        $"Caminho Prefetch: {pf}",
                        $"Última execução: {modified:dd/MM/yyyy HH:mm:ss}",
                        timestamp: modified,
                        confidence: Confidence.High,
                        ruleId: "STAN_PREFETCH_EXECUTED",
                        entity: pf
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError("Stan: varredura Prefetch falhou", ex); }
        }

        foreach (var svc in new[] { "bam", "dam" })
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var hive = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svc}\State\UserSettings");
                if (hive == null) continue;

                foreach (var sid in hive.GetSubKeyNames())
                {
                    using var key = hive.OpenSubKey(sid);
                    if (key == null) continue;

                    foreach (var vname in key.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(vname)) continue;
                        var lower = vname.ToLowerInvariant();
                        // Match loader.exe in a user-writable path (Downloads, Temp, AppData)
                        if (!lower.EndsWith("\\loader.exe")) continue;
                        if (!SuspiciousCoProcessResolver.IsUserWritablePath(vname)) continue;

                        var data = key.GetValue(vname, null,
                            RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                        if (data?.Length < 8) continue;
                        var ft = BitConverter.ToInt64(data!, 0);
                        DateTime ts;
                        try { ts = DateTime.FromFileTime(ft); } catch { continue; }

                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.Cheat,
                            Name,
                            $"STAN BAM: loader.exe registrado no Background Activity Monitor",
                            $"BAM ({svc.ToUpperInvariant()}) registrou execução de loader.exe em caminho de usuário.\n" +
                            $"Chave: {vname}",
                            $"Timestamp BAM: {ts:dd/MM/yyyy HH:mm:ss}",
                            timestamp: ts,
                            confidence: Confidence.High,
                            ruleId: "STAN_BAM_EXECUTED",
                            entity: Path.GetFileName(vname)
                        ));
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"Stan: varredura BAM/{svc} falhou", ex); }
        }
    }
}
