using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

// Astrix External is a FiveM cheat sold as "Astrix External.exe".
// It reads a config file (config.astrix) containing subscriber credentials.
// Privacy constraint: values inside config.astrix (username, password, etc.)
// MUST NEVER appear in any Finding. Log only: field existence, SHA256 hash,
// file size in bytes, and last-modified timestamp.
public class AstrixArtifactsModule : BaseModule
{
    public override string Name        => "Astrix Artifacts";
    public override string Description => "Artefatos do cheat FiveM Astrix External (exe, config, Prefetch, BAM)";

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

        ScanAstrixExeOnDisk(findings, ct);
        ScanConfigAstrix(findings, ct);
        ScanPrefetchBam(findings, ct);
        ScanActiveProcess(findings, ct);

        return Task.FromResult(findings);
    }

    // Detect "Astrix External.exe" on disk in user-accessible locations.
    private void ScanAstrixExeOnDisk(List<Finding> findings, CancellationToken ct)
    {
        foreach (var root in UserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "Astrix External.exe",
                    new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
                {
                    ct.ThrowIfCancellationRequested();

                    var modified  = File.GetLastWriteTime(file);
                    var sizeBytes = new FileInfo(file).Length;

                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        Name,
                        "ASTRIX EXTERNO: executável encontrado no disco",
                        $"Astrix External.exe detectado em localização de usuário.\n" +
                        $"Astrix é um cheat FiveM externo com aimbot, ESP e anti-detecção.\n" +
                        $"Caminho: {file}",
                        $"Tamanho: {sizeBytes} bytes | Modificado: {modified:dd/MM/yyyy HH:mm:ss}",
                        timestamp: modified,
                        confidence: Confidence.Confirmed,
                        ruleId: "ASTRIX_EXE_USERPATH",
                        entity: file
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"Astrix: varredura de exe em {root} falhou", ex); }
        }
    }

    // Detect config.astrix — the subscriber credential config written by Astrix External.
    // PRIVACY: parse JSON only to detect field existence; never log values.
    // Log: field names present (bool), SHA256 hash, file size, last-modified timestamp.
    private void ScanConfigAstrix(List<Finding> findings, CancellationToken ct)
    {
        foreach (var root in UserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "config.astrix",
                    new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
                {
                    ct.ThrowIfCancellationRequested();

                    var modified  = File.GetLastWriteTime(file);
                    var sizeBytes = new FileInfo(file).Length;

                    // Privacy-safe field detection — read once, then discard content
                    bool hasUsername = false;
                    bool hasPassword = false;
                    string? sha256   = null;
                    int fieldCount   = 0;

                    try
                    {
                        var bytes = File.ReadAllBytes(file);
                        sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

                        using var doc = JsonDocument.Parse(bytes);
                        foreach (var prop in doc.RootElement.EnumerateObject())
                        {
                            fieldCount++;
                            var name = prop.Name.ToLowerInvariant();
                            if (name == "username") hasUsername = true;
                            if (name == "password") hasPassword = true;
                        }
                    }
                    catch { }

                    var fieldSummary = new System.Text.StringBuilder();
                    if (hasUsername) fieldSummary.Append("username:presente ");
                    if (hasPassword) fieldSummary.Append("password:presente ");
                    if (fieldCount > 0 && !hasUsername && !hasPassword)
                        fieldSummary.Append($"{fieldCount} campo(s) ");

                    var risk = (hasUsername || hasPassword) ? RiskLevel.Critical : RiskLevel.High;
                    var conf = (hasUsername || hasPassword) ? Confidence.Confirmed : Confidence.High;

                    findings.Add(new Finding(
                        risk,
                        FindingCategory.Cheat,
                        Name,
                        (hasUsername || hasPassword)
                            ? "ASTRIX CONFIG: config.astrix com credenciais detectadas"
                            : "ASTRIX CONFIG: config.astrix encontrado",
                        $"Arquivo de configuração do Astrix External detectado.\n" +
                        $"Campos presentes: {fieldSummary.ToString().Trim()}\n" +
                        $"Caminho: {file}\n" +
                        $"(Valores de credencial nunca são registrados — apenas existência e hash.)",
                        $"SHA256: {sha256 ?? "erro"} | Tamanho: {sizeBytes} bytes | Modificado: {modified:dd/MM/yyyy HH:mm:ss}",
                        timestamp: modified,
                        confidence: conf,
                        ruleId: "ASTRIX_CONFIG_FILE",
                        entity: file
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"Astrix: varredura de config.astrix em {root} falhou", ex); }
        }
    }

    // Check Prefetch for ASTRIX EXTERNAL*.PF execution traces.
    private void ScanPrefetchBam(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Prefetch
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (Directory.Exists(prefetchDir))
        {
            try
            {
                foreach (var pf in Directory.GetFiles(prefetchDir, "ASTRIX*"))
                {
                    ct.ThrowIfCancellationRequested();
                    var modified = File.GetLastWriteTime(pf);
                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.Cheat,
                        Name,
                        $"ASTRIX EXECUTADO: rastro Prefetch — {Path.GetFileName(pf)}",
                        $"Prefetch de Astrix External indica execução anterior do cheat.\n" +
                        $"Caminho Prefetch: {pf}",
                        $"Última execução: {modified:dd/MM/yyyy HH:mm:ss}",
                        timestamp: modified,
                        confidence: Confidence.High,
                        ruleId: "ASTRIX_PREFETCH_EXECUTED",
                        entity: pf
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError("Astrix: varredura Prefetch falhou", ex); }
        }

        // BAM/DAM — look for "astrix external" execution timestamps
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
                        if (!vname.ToLowerInvariant().Contains("astrix")) continue;

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
                            $"ASTRIX BAM: execução registrada no Background Activity Monitor",
                            $"BAM ({svc.ToUpperInvariant()}) registrou execução do Astrix External.\n" +
                            $"Chave: {vname}",
                            $"Timestamp BAM: {ts:dd/MM/yyyy HH:mm:ss}",
                            timestamp: ts,
                            confidence: Confidence.High,
                            ruleId: "ASTRIX_BAM_EXECUTED",
                            entity: Path.GetFileName(vname)
                        ));
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"Astrix: varredura BAM/{svc} falhou", ex); }
        }
    }

    // Detect Astrix External.exe currently running via SuspiciousCoProcessResolver.
    private void ScanActiveProcess(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        List<SuspiciousCoProcessResolver.SuspiciousCoProcess> coProcs;
        try { coProcs = SuspiciousCoProcessResolver.Resolve(); }
        catch (Exception ex) { LogPartialError("Astrix: SuspiciousCoProcessResolver falhou", ex); return; }

        foreach (var proc in coProcs.Where(p => p.IsAstrixProcess))
        {
            ct.ThrowIfCancellationRequested();
            var connStr = proc.HasExternalConnection
                ? $" | Conexões: {string.Join(", ", proc.ExternalConnections.Take(3))}"
                : "";

            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.Cheat,
                Name,
                $"ASTRIX EM EXECUÇÃO: Astrix External ativo (PID {proc.Pid})",
                $"Astrix External.exe detectado em execução no momento da varredura.\n" +
                $"Caminho: {proc.ExePath}",
                $"PID: {proc.Pid}{connStr}",
                timestamp: proc.StartTime,
                confidence: Confidence.Confirmed,
                ruleId: "ASTRIX_ACTIVE_PROCESS",
                entity: proc.ExePath
            ));
        }
    }
}
