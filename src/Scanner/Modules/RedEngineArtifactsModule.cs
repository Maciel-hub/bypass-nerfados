using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

// RedENGINE is a FiveM Lua executor with aimbot/ESP/no-recoil.
// v1 artifacts: settings.cock, *.lua menus, imgui.ini, WinRAR temp dirs.
// v2 runtime artifacts: random-name loader (-cf <numeric>.exe), cfg.dat, port 10001 C2.
public class RedEngineArtifactsModule : BaseModule
{
    public override string Name        => "RedENGINE Artifacts";
    public override string Description => "Artefatos do executor FiveM RedENGINE (settings.cock, menus .lua, imgui.ini, WinRAR, loader, cfg.dat, porta C2)";

    // Menu .lua filenames bundled with or downloaded for RedENGINE loaders
    private static readonly HashSet<string> MenuLuaNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "absolute.lua", "lumia.lua", "phaze.lua", "nexus.lua",
        "strata.lua", "lynx.lua", "insec.lua", "hoax.lua",
        "tiagomenu.lua", "skidmenu.lua", "lydia.lua",
    };

    // GTA V install paths to search for imgui.ini
    private static string[] GtaDirs()
    {
        var pf   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        return
        [
            Path.Combine(pf,    "Rockstar Games", "Grand Theft Auto V"),
            Path.Combine(pfx86, "Steam", "steamapps", "common", "Grand Theft Auto V"),
            Path.Combine(pfx86, "Epic Games", "GTAV"),
        ];
    }

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        // v1: static artifacts on disk
        ScanSettingsCock(findings, ct);
        ScanMenuLuaFiles(findings, ct);
        ScanImguiIni(findings, ct);
        ScanWinRarTemps(findings, ct);

        // v2: runtime loader pattern (random loader + cfg.dat + -cf payload + C2 port)
        ScanRandomLoaderWithCfgDat(findings, ct);
        ScanActiveLoaderProcess(findings, ct);

        return Task.FromResult(findings);
    }

    // "settings.cock" is a unique config file dropped by RedENGINE.
    // No legitimate software uses this name — any occurrence is a strong signal.
    private void ScanSettingsCock(List<Finding> findings, CancellationToken ct)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            @"C:\",
        };

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "settings.cock",
                    new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 6 }))
                {
                    ct.ThrowIfCancellationRequested();

                    var dir = Path.GetDirectoryName(file) ?? "";
                    var modified = File.GetLastWriteTime(file);
                    var sizeBytes = new FileInfo(file).Length;

                    // Check if redengine.exe is in the same directory (strongest signal)
                    bool hasLoader = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly)
                        .Any(f => Path.GetFileName(f).Equals("redengine.exe", StringComparison.OrdinalIgnoreCase));

                    // settings.cock alone → High/Medium (unique name, but single-source)
                    // settings.cock + redengine.exe co-located → Critical/High (two artifacts)
                    var risk       = hasLoader ? RiskLevel.Critical : RiskLevel.High;
                    var confidence = hasLoader ? Confidence.High    : Confidence.Medium;
                    var ruleId     = hasLoader ? "REDENGINE_SETTINGS_COCK_WITH_LOADER"
                                               : "REDENGINE_SETTINGS_COCK";

                    findings.Add(new Finding(
                        risk,
                        FindingCategory.Cheat,
                        Name,
                        hasLoader
                            ? "REDENGINE CONFIRMADO: settings.cock + redengine.exe co-localizados"
                            : "REDENGINE FORTE INDÍCIO: settings.cock encontrado",
                        $"Arquivo de configuração exclusivo do RedENGINE detectado.\n" +
                        $"Nenhum software legítimo usa este nome de arquivo.\n" +
                        (hasLoader ? "redengine.exe encontrado no mesmo diretório — dois artefatos distintos confirmam a ferramenta.\n" : "") +
                        $"Caminho: {file}",
                        $"Tamanho: {sizeBytes} bytes | Modificado: {modified:dd/MM/yyyy HH:mm:ss}",
                        timestamp: modified,
                        confidence: confidence,
                        ruleId: ruleId,
                        entity: file,
                        validationHint: hasLoader ? null
                            : "Correlacionar com Prefetch/BAM de redengine.exe e sessão FiveM para confirmar"
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"RedENGINE: varredura de settings.cock em {root} falhou", ex); }
        }
    }

    // Known menu .lua scripts distributed with RedENGINE.
    // Search in user-accessible locations — menus are usually extracted there before injection.
    private void ScanMenuLuaFiles(List<Finding> findings, CancellationToken ct)
    {
        var roots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua",
                    new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 5 }))
                {
                    ct.ThrowIfCancellationRequested();

                    var name = Path.GetFileName(file);
                    if (!MenuLuaNames.Contains(name)) continue;

                    var modified = File.GetLastWriteTime(file);

                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.Cheat,
                        Name,
                        $"REDENGINE MENU: {name} encontrado",
                        $"Script de menu associado ao RedENGINE encontrado em localização de risco.\n" +
                        $"Estes menus são injetados via executor Lua do RedENGINE no FiveM.\n" +
                        $"Caminho: {file}",
                        $"Modificado: {modified:dd/MM/yyyy HH:mm:ss}",
                        timestamp: modified,
                        confidence: Confidence.Medium,
                        ruleId: $"REDENGINE_MENU_LUA_{name.ToUpperInvariant().Replace('.', '_')}",
                        entity: file,
                        validationHint: "Correlacionar com Prefetch de redengine.exe e sessão FiveM para confirmar execução"
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"RedENGINE: varredura de menus .lua em {root} falhou", ex); }
        }
    }

    // RedENGINE uses ImGui for its overlay UI. The docs instruct users to delete imgui.ini
    // from the GTA V directory when the overlay fails to appear — confirming this is where
    // RedENGINE writes its ImGui config during injection.
    private void ScanImguiIni(List<Finding> findings, CancellationToken ct)
    {
        foreach (var gtaDir in GtaDirs())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(gtaDir)) continue;

            var imguiPath = Path.Combine(gtaDir, "imgui.ini");
            if (!File.Exists(imguiPath)) continue;

            var modified  = File.GetLastWriteTime(imguiPath);
            var age       = DateTime.Now - modified;
            var sizeBytes = new FileInfo(imguiPath).Length;

            // imgui.ini in GTA V dir is suspicious — GTA V does not use ImGui.
            // However, overlays and mod tools (e.g. reshade, mod menus) also write imgui.ini.
            // Alone it is at most Medium/Low; escalation requires correlation in the Correlator.
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.SuspiciousExecution,
                Name,
                $"imgui.ini no diretório do GTA V — possível indicativo de RedENGINE",
                $"O GTA V não usa ImGui internamente. A documentação do RedENGINE instrui\n" +
                $"usuários a deletar este arquivo quando o overlay falha ao aparecer, confirmando\n" +
                $"que o RedENGINE o grava neste diretório durante a injeção.\n" +
                $"Nota: overlays e mod tools legítimos também podem gerar este arquivo.\n" +
                $"Caminho: {imguiPath}\nÚltima modificação: {modified:dd/MM/yyyy HH:mm:ss} ({(int)age.TotalDays} dias atrás)",
                $"Tamanho: {sizeBytes} bytes | Idade: {(int)age.TotalDays} dias",
                timestamp: modified,
                confidence: Confidence.Low,
                ruleId: "REDENGINE_IMGUI_INI",
                entity: imguiPath,
                validationHint: "Correlacionar timestamp com sessão FiveM (BAM/Prefetch), Prefetch de redengine.exe, settings.cock ou menu .lua para escalar risco"
            ));
        }
    }

    // v2: Scan user-writable directories for random-name EXEs co-located with cfg.dat.
    // cfg.dat in the same folder as a random loader is a strong RedENGINE signal:
    // nkhDWzGn.exe + cfg.dat in Downloads → REDENGINE_CFG_DAT_NEAR_LOADER.
    private void ScanRandomLoaderWithCfgDat(List<Finding> findings, CancellationToken ct)
    {
        var roots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                // Look for cfg.dat files — they are the RedENGINE loader config anchor
                foreach (var cfgDat in Directory.EnumerateFiles(root, "cfg.dat",
                    new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 4 }))
                {
                    ct.ThrowIfCancellationRequested();

                    var dir = Path.GetDirectoryName(cfgDat) ?? "";

                    // Find random-name EXEs in the same directory
                    var randomExes = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly)
                        .Where(f => SuspiciousCoProcessResolver.IsRandomName(
                            Path.GetFileNameWithoutExtension(f)))
                        .ToList();

                    var cfgModified = File.GetLastWriteTime(cfgDat);

                    if (randomExes.Count > 0)
                    {
                        // Strongest pattern: cfg.dat + random loader EXE co-located
                        var loaderName = Path.GetFileName(randomExes[0]);
                        var loaderModified = File.GetLastWriteTime(randomExes[0]);
                        var loaderSize = new FileInfo(randomExes[0]).Length;

                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.Cheat,
                            Name,
                            $"REDENGINE LOADER: cfg.dat + loader de nome aleatório co-localizados",
                            $"Arquivo de configuração cfg.dat encontrado junto a executável de nome aleatório.\n" +
                            $"Padrão característico do loader RedENGINE (ex: nkhDWzGn.exe + cfg.dat).\n" +
                            $"Loader: {randomExes[0]}\n" +
                            $"cfg.dat: {cfgDat}",
                            $"Loader: {loaderName} ({loaderSize} bytes, {loaderModified:dd/MM/yyyy HH:mm})" +
                            $" | cfg.dat: {cfgModified:dd/MM/yyyy HH:mm}",
                            timestamp: cfgModified > loaderModified ? cfgModified : loaderModified,
                            confidence: Confidence.High,
                            ruleId: "REDENGINE_CFG_DAT_NEAR_LOADER",
                            entity: randomExes[0]
                        ));
                    }
                    else
                    {
                        // cfg.dat alone in user path — weaker signal, corroboration needed
                        var cfgSize = new FileInfo(cfgDat).Length;
                        findings.Add(new Finding(
                            RiskLevel.Medium,
                            FindingCategory.SuspiciousExecution,
                            Name,
                            $"cfg.dat em caminho de usuário — possível artefato de loader RedENGINE",
                            $"Arquivo cfg.dat encontrado em localização de usuário.\n" +
                            $"Quando co-localizado com loader RedENGINE, é o arquivo de configuração do executor.\n" +
                            $"Caminho: {cfgDat}",
                            $"Tamanho: {cfgSize} bytes | Modificado: {cfgModified:dd/MM/yyyy HH:mm}",
                            timestamp: cfgModified,
                            confidence: Confidence.Low,
                            ruleId: "REDENGINE_CFG_DAT_STANDALONE",
                            entity: cfgDat,
                            validationHint: "Correlacionar com Prefetch de loader de nome aleatório e sessão FiveM"
                        ));
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"RedENGINE v2: varredura de cfg.dat em {root} falhou", ex); }
        }
    }

    // v2: Detect actively running RedENGINE loaders via SuspiciousCoProcessResolver.
    // Covers: random loader with -cf payload, numeric payload, port 10001 C2 connection.
    private void ScanActiveLoaderProcess(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        List<SuspiciousCoProcessResolver.SuspiciousCoProcess> coProcs;
        try { coProcs = SuspiciousCoProcessResolver.Resolve(); }
        catch (Exception ex) { LogPartialError("RedENGINE v2: SuspiciousCoProcessResolver falhou", ex); return; }

        foreach (var proc in coProcs)
        {
            ct.ThrowIfCancellationRequested();
            if (proc.IsAstrixProcess) continue; // handled by AstrixArtifactsModule

            if (proc.PayloadPath != null)
            {
                // Loader with -cf <payload>.exe → REDENGINE_CMDLINE_CF_PAYLOAD
                var risk = proc.HasNumericPayload ? RiskLevel.Critical : RiskLevel.High;
                var conf = proc.HasNumericPayload ? Confidence.High    : Confidence.Medium;
                var ruleId = proc.HasNumericPayload
                    ? "REDENGINE_NUMERIC_PAYLOAD_EXECUTED"
                    : "REDENGINE_CMDLINE_CF_PAYLOAD";

                findings.Add(new Finding(
                    risk,
                    FindingCategory.Cheat,
                    Name,
                    proc.HasNumericPayload
                        ? $"REDENGINE ATIVO: loader com payload numérico (-cf {Path.GetFileName(proc.PayloadPath)})"
                        : $"REDENGINE LOADER: argumento -cf com payload detectado",
                    $"Loader RedENGINE ativo com argumento de payload na linha de comando.\n" +
                    $"Padrão: <loader>.exe -cf <payload>.exe\n" +
                    $"Loader: {proc.ExePath}\n" +
                    $"Payload: {proc.PayloadPath}\n" +
                    $"Linha de comando: {TruncateCmd(proc.CommandLine)}",
                    $"PID: {proc.Pid} | Payload: {Path.GetFileName(proc.PayloadPath)}" +
                    (proc.HasExternalConnection ? $" | Conexões: {string.Join(", ", proc.ExternalConnections.Take(2))}" : ""),
                    timestamp: proc.StartTime,
                    confidence: conf,
                    ruleId: ruleId,
                    entity: proc.ExePath
                ));
            }

            if (proc.ExternalConnections.Any(c => c.EndsWith(":10001")))
            {
                // Active C2 connection on port 10001 (RedENGINE licensing/C2 server)
                var c2Conns = proc.ExternalConnections.Where(c => c.EndsWith(":10001")).ToList();
                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.Cheat,
                    Name,
                    $"REDENGINE C2 ATIVO: conexão na porta 10001 ({proc.ProcessName})",
                    $"Processo com nome aleatório conectado à porta 10001 — porta C2/licenciamento do RedENGINE.\n" +
                    $"Processo: {proc.ExePath}",
                    $"PID: {proc.Pid} | Destinos: {string.Join(", ", c2Conns)}",
                    timestamp: proc.StartTime,
                    confidence: Confidence.High,
                    ruleId: "REDENGINE_ACTIVE_C2_PORT",
                    entity: proc.ExePath
                ));
            }
            else if (proc.HasExternalConnection && !proc.IsRedEngineLoader && proc.PayloadPath == null)
            {
                // Random-name EXE in user path with external connection but no -cf → suspicious loader
                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.SuspiciousExecution,
                    Name,
                    $"Loader de nome aleatório com conexão externa ativa: {proc.ProcessName}",
                    $"Executável com nome aleatório em caminho de usuário com conexão de rede ativa.\n" +
                    $"Padrão associado a loaders RedENGINE e similares.\n" +
                    $"Caminho: {proc.ExePath}",
                    $"PID: {proc.Pid} | Conexões: {string.Join(", ", proc.ExternalConnections.Take(3))}",
                    timestamp: proc.StartTime,
                    confidence: Confidence.Medium,
                    ruleId: "REDENGINE_RANDOM_LOADER_NET",
                    entity: proc.ExePath,
                    validationHint: "Confirmar com cfg.dat no mesmo diretório, Prefetch e sessão FiveM"
                ));
            }
        }
    }

    private static string TruncateCmd(string? cmd, int max = 120) =>
        cmd == null ? "" : cmd.Length <= max ? cmd : cmd[..max] + "…";

    // RedENGINE is typically distributed as a ZIP/RAR archive. WinRAR extraction
    // leaves temporary directories (Rar$EXa* / Rar$DIa*) in %TEMP% that may
    // contain redengine.exe or settings.cock before the user moves them.
    private void ScanWinRarTemps(List<Finding> findings, CancellationToken ct)
    {
        var temp = Path.GetTempPath();
        if (!Directory.Exists(temp)) return;

        try
        {
            foreach (var dir in Directory.GetDirectories(temp, "Rar$*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();

                bool foundRedEngine = false;
                bool foundSettings  = false;
                var suspiciousFiles = new List<string>();

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*",
                        new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 4 }))
                    {
                        ct.ThrowIfCancellationRequested();
                        var name = Path.GetFileName(file).ToLowerInvariant();

                        if (name == "redengine.exe")    { foundRedEngine = true; suspiciousFiles.Add(file); }
                        if (name == "settings.cock")    { foundSettings  = true; suspiciousFiles.Add(file); }
                        if (MenuLuaNames.Contains(name))                          suspiciousFiles.Add(file);
                        if (CheatDatabase.HasSuspiciousKeyword(Path.GetFileNameWithoutExtension(name)))
                            suspiciousFiles.Add(file);
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }

                if (suspiciousFiles.Count == 0) continue;

                var dirModified = Directory.GetLastWriteTime(dir);
                var risk = (foundRedEngine || foundSettings) ? RiskLevel.Critical : RiskLevel.High;
                var title = foundRedEngine ? "WinRAR temp com redengine.exe detectado"
                          : foundSettings  ? "WinRAR temp com settings.cock detectado"
                          :                  "WinRAR temp com arquivos RedENGINE suspeitos";

                findings.Add(new Finding(
                    risk,
                    FindingCategory.Cheat,
                    Name,
                    $"REDENGINE: {title}",
                    $"Diretório temporário do WinRAR com artefatos do RedENGINE.\n" +
                    $"Dir: {dir}\nArquivos: {string.Join(", ", suspiciousFiles.Select(Path.GetFileName).Distinct().Take(5))}",
                    $"Modificado: {dirModified:dd/MM/yyyy HH:mm:ss} | {suspiciousFiles.Count} arquivo(s) suspeito(s)",
                    timestamp: dirModified,
                    confidence: foundRedEngine || foundSettings ? Confidence.High : Confidence.Medium,
                    ruleId: "REDENGINE_WINRAR_TEMP",
                    entity: dir
                ));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("RedENGINE: varredura de diretórios WinRAR falhou", ex); }
    }
}
