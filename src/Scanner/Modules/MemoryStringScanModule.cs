using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

// Scans FiveM/GTA process memory for branded cheat family strings.
// Complements MemoryDllTraceModule (structural anomalies) by detecting cheat identity at the string level.
// Critical constraint: generic tokens (lua, executor, imgui, license, auth) NEVER trigger high-risk
// findings alone — evasion/behavior only escalates when a branded family token is co-located in the same
// memory region. Enforced by the EmitPack logic: familyTerm == null → skip all escalation.
public class MemoryStringScanModule : BaseModule
{
    public override string Name        => "Memory String Scan";
    public override string Description => "Strings de famílias de cheat em memória de processos FiveM/GTA";

    private static readonly string[] CoreTargetNames = ["fivem", "gta5", "redengine"];
    private static readonly string[] FiveMPrefixes   = ["fivem_b", "fivem_gt", "fivem_rgl"];

    private const int MinStringLen = 8;
    private const int ChunkSize    = 64 * 1024;        //  64 KB per read attempt
    private const int MaxPerRegion = 4 * 1024 * 1024;  //   4 MB total per region

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        // Load rule packs — emit diagnostics for any load failure, never fail silently
        var (globalPack, brPack) = LoadRulePacks(config);
        if (globalPack.Error != null) findings.Add(MakePackDiagnostic(globalPack.Error));
        if (brPack.Error    != null) findings.Add(MakePackDiagnostic(brPack.Error));

        bool allPacksFailed = globalPack.Families.Length == 0 && brPack.Families.Length == 0;
        if (allPacksFailed)
        {
            LogPartialError("Ambos os packs de regras de strings falharam — varredura de famílias de cheat comprometida");
            return Task.FromResult(findings);
        }

        var targets = CollectTargetProcesses();
        if (targets.Count == 0)
        {
            var f = new Finding(
                RiskLevel.Info, FindingCategory.LogCoverage, Name,
                "Memory String Scan — nenhum processo alvo ativo",
                "Nenhum processo FiveM/GTA/RedENGINE encontrado. Varredura de strings de cheat não realizada.",
                confidence: Confidence.Confirmed,
                ruleId: "MEMSTR_NO_TARGET_PROCESS");
            f.ScoreEligible = false;
            findings.Add(f);
            return Task.FromResult(findings);
        }

        foreach (var proc in targets)
        {
            ct.ThrowIfCancellationRequested();
            try { AnalyzeProcess(proc, globalPack, brPack, findings, ct); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                LogPartialError($"MemoryStringScan: falha ao analisar {proc.ProcessName} PID {proc.Id}", ex);
            }
        }

        return Task.FromResult(findings);
    }

    // ── Target collection ──────────────────────────────────────────────────────

    private static List<Process> CollectTargetProcesses()
    {
        var seen   = new HashSet<int>();
        var result = new List<Process>();

        void Add(Process p) { if (seen.Add(p.Id)) result.Add(p); }

        foreach (var name in CoreTargetNames)
            foreach (var p in Process.GetProcessesByName(name)) Add(p);

        foreach (var p in Process.GetProcesses())
        {
            var lower = p.ProcessName.ToLowerInvariant();
            if (FiveMPrefixes.Any(pfx => lower.StartsWith(pfx))) Add(p);
        }

        // Also scan suspicious co-processes discovered by SuspiciousCoProcessResolver.
        try
        {
            foreach (var coProc in SuspiciousCoProcessResolver.Resolve())
            {
                if (!seen.Contains(coProc.Pid))
                {
                    try
                    {
                        var p = Process.GetProcessById(coProc.Pid);
                        Add(p);
                    }
                    catch { }
                }
            }
        }
        catch { }

        return result;
    }

    // ── Per-process analysis ───────────────────────────────────────────────────

    private void AnalyzeProcess(Process proc, CheatFamilyPack globalPack, CheatFamilyPack brPack,
        List<Finding> findings, CancellationToken ct)
    {
        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, (uint)proc.Id);
        if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE)
        {
            LogPartialError($"MemoryStringScan: acesso negado ao processo {proc.ProcessName} PID {proc.Id}");
            return;
        }

        // Per-process dedup: one finding per "familyName|ruleId" pair regardless of region
        var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            // Phase 1: suspicious loaded modules
            foreach (var mod in EnumModules((uint)proc.Id))
            {
                ct.ThrowIfCancellationRequested();
                if (!ShouldScanModule(mod.Path)) continue;

                var corpus = ReadAndBuildCorpus(handle, mod.Base, mod.Size);
                if (corpus == null) continue;

                MatchAndEmit(proc, globalPack, brPack, corpus, "module",
                    mod.Base, mod.Size, mod.Path, emitted, findings);
            }

            // Phase 2: MEM_PRIVATE executable regions
            IntPtr addr = IntPtr.Zero;
            while (VirtualQueryEx(handle, addr, out var mbi,
                   (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) > 0)
            {
                ct.ThrowIfCancellationRequested();
                var regionBase = mbi.BaseAddress.ToInt64();
                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    IsExecutable(mbi.Protect) && regionSize > 0x1000)
                {
                    var corpus = ReadAndBuildCorpus(handle, regionBase, regionSize);
                    if (corpus != null)
                        MatchAndEmit(proc, globalPack, brPack, corpus, "private_exec",
                            regionBase, regionSize, null, emitted, findings);
                }

                addr = new IntPtr(regionBase + regionSize);
            }
        }
        finally { CloseHandle(handle); }
    }

    // ── Module filter ──────────────────────────────────────────────────────────

    private static bool ShouldScanModule(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase)) return false;

        if (path.StartsWith(@"C:\Program Files\",      StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"C:\Program Files (x86)\", StringComparison.OrdinalIgnoreCase))
            return !IsAuthenticodeSigned(path);

        return true;
    }

    // ── Chunked memory read + string extraction ────────────────────────────────

    // Reads up to MaxPerRegion bytes in ChunkSize chunks, continuing on partial failures.
    // Partial reads (some pages unreadable) yield whatever bytes were accessible.
    private static string? ReadAndBuildCorpus(IntPtr hProcess, long baseAddr, long regionSize)
    {
        long   remaining = Math.Min(regionSize, MaxPerRegion);
        long   offset    = 0;
        var    buf       = new byte[ChunkSize];
        var    sb        = new System.Text.StringBuilder();
        bool   anyRead   = false;

        while (remaining > 0)
        {
            int toRead = (int)Math.Min(remaining, ChunkSize);
            ReadProcessMemory(hProcess, new IntPtr(baseAddr + offset), buf, toRead, out int read);

            if (read > 0)
            {
                var strings = ExtractStrings(buf, read);
                if (strings.Count > 0)
                {
                    if (sb.Length > 0) sb.Append('\0');
                    sb.AppendJoin('\0', strings);
                    anyRead = true;
                }
            }

            // Always advance by at least toRead to avoid infinite loop on unreadable pages
            long advance = read > 0 ? read : toRead;
            offset    += advance;
            remaining -= advance;
        }

        return anyRead ? sb.ToString() : null;
    }

    private static List<string> ExtractStrings(byte[] buf, int len)
    {
        var result = new List<string>();

        // ASCII printable strings ≥ MinStringLen
        int start = -1;
        for (int i = 0; i < len; i++)
        {
            byte b = buf[i];
            if (b >= 0x20 && b < 0x7F)
            {
                if (start < 0) start = i;
            }
            else
            {
                if (start >= 0 && i - start >= MinStringLen)
                    result.Add(Encoding.ASCII.GetString(buf, start, i - start));
                start = -1;
            }
        }
        // Flush ASCII tail at end of buffer
        if (start >= 0 && len - start >= MinStringLen)
            result.Add(Encoding.ASCII.GetString(buf, start, len - start));

        // UTF-16LE printable strings ≥ MinStringLen chars
        start = -1;
        for (int i = 0; i + 1 < len; i += 2)
        {
            char c = (char)(buf[i] | (buf[i + 1] << 8));
            if (c >= 0x20 && c < 0x7F)
            {
                if (start < 0) start = i;
            }
            else
            {
                int chars = (i - start) / 2;
                if (start >= 0 && chars >= MinStringLen)
                    result.Add(Encoding.Unicode.GetString(buf, start, i - start));
                start = -1;
            }
        }
        // Flush UTF-16LE tail at end of buffer
        if (start >= 0 && (len - start) / 2 >= MinStringLen)
            result.Add(Encoding.Unicode.GetString(buf, start, len - start));

        return result;
    }

    // ── Family matching and finding emission ───────────────────────────────────

    private static void MatchAndEmit(Process proc, CheatFamilyPack globalPack, CheatFamilyPack brPack,
        string corpus, string scope, long baseAddr, long regionSize, string? modulePath,
        HashSet<string> emitted, List<Finding> findings)
    {
        EmitPack(proc, globalPack, corpus, scope, baseAddr, regionSize, modulePath, emitted, findings, isBr: false);
        EmitPack(proc, brPack,     corpus, scope, baseAddr, regionSize, modulePath, emitted, findings, isBr: true);
    }

    private static void EmitPack(Process proc, CheatFamilyPack pack, string corpus, string scope,
        long baseAddr, long regionSize, string? modulePath,
        HashSet<string> emitted, List<Finding> findings, bool isBr)
    {
        foreach (var fam in pack.Families)
        {
            var familyTerm = FirstMatch(corpus, fam.FamilyTokens);
            if (familyTerm == null) continue; // no family identity → no escalation, no finding

            var evidenceBase =
                $"family: {fam.Name} | matchedTerm: {familyTerm} | scope: {scope}\n" +
                $"process: {proc.ProcessName} (PID {proc.Id}) | " +
                $"baseAddress: 0x{baseAddr:X} | regionSize: {regionSize / 1024} KB" +
                (modulePath != null ? $"\nmodule: {modulePath}" : "");

            string scopeLabel = scope == "module"
                ? $"módulo suspeito: {Path.GetFileName(modulePath ?? "")}"
                : "região de memória privada executável";

            // ─ MEMSTR_CHEAT_FAMILY_TOKEN / MEMSTR_BR_CHEAT_FAMILY
            string famRule = isBr ? "MEMSTR_BR_CHEAT_FAMILY" : "MEMSTR_CHEAT_FAMILY_TOKEN";
            if (emitted.Add($"{fam.Name}|{famRule}"))
            {
                findings.Add(new Finding(
                    RiskLevel.Medium, FindingCategory.MemoryAnomaly, "Memory String Scan",
                    $"{famRule} — {fam.Name} [{fam.Priority.ToUpper()}] em {proc.ProcessName} (PID {proc.Id})",
                    $"String de identificação da família de cheat {fam.Name} encontrada em {scopeLabel}.\n" +
                    $"Por si só é indicativo — correlacionar com KnownCheats, Prefetch e BAM/DAM para confirmar.",
                    evidenceBase,
                    confidence: Confidence.Medium,
                    ruleId: famRule,
                    entity: $"{proc.ProcessName}:{fam.Name}",
                    validationHint: "Correlacionar com artefatos de disco antes de concluir"
                ));
            }

            // ─ MEMSTR_EXECUTOR_BEHAVIOR / MEMSTR_BR_EXECUTOR_BEHAVIOR
            // Shared behavior tokens complement per-family ones; still requires familyHit (above).
            var behavTerm = FirstMatch(corpus, Merge(fam.BehaviorTokens, pack.SharedBehaviorTokens));
            if (behavTerm != null)
            {
                string behavRule = isBr ? "MEMSTR_BR_EXECUTOR_BEHAVIOR" : "MEMSTR_EXECUTOR_BEHAVIOR";
                if (emitted.Add($"{fam.Name}|{behavRule}"))
                {
                    findings.Add(new Finding(
                        RiskLevel.High, FindingCategory.MemoryAnomaly, "Memory String Scan",
                        $"{behavRule} — {fam.Name} [{fam.Priority.ToUpper()}] padrão executor em {proc.ProcessName} (PID {proc.Id})",
                        $"Strings de família + comportamento de executor encontradas na mesma região de memória.\n" +
                        $"Indica executor ativo ou DLL de cheat carregada e em uso.",
                        evidenceBase + $"\nbehaviorMatch: {behavTerm}",
                        confidence: Confidence.High,
                        ruleId: behavRule,
                        entity: $"{proc.ProcessName}:{fam.Name}",
                        validationHint: "Correlacionar com MEMDLL_PRIVATE_EXEC_PE ou MEMDLL_KNOWN_CHEAT_DLL_LOADED"
                    ));
                }
            }

            // ─ MEMSTR_ANTICHEAT_EVASION / MEMSTR_BR_ANTICHEAT_BYPASS
            var evasionTerm = FirstMatch(corpus, Merge(fam.EvasionTokens, pack.SharedEvasionTokens));
            if (evasionTerm != null)
            {
                string evasionRule = isBr ? "MEMSTR_BR_ANTICHEAT_BYPASS" : "MEMSTR_ANTICHEAT_EVASION";
                if (emitted.Add($"{fam.Name}|{evasionRule}"))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical, FindingCategory.MemoryAnomaly, "Memory String Scan",
                        $"{evasionRule} — {fam.Name} [{fam.Priority.ToUpper()}] evasão anti-cheat em {proc.ProcessName} (PID {proc.Id})",
                        $"Strings de família + técnicas de evasão de anti-cheat co-localizadas na mesma região.\n" +
                        $"Artefato forense forte — indica cheat com mecanismo ativo de bypass de anti-cheat.",
                        evidenceBase + $"\nevasionMatch: {evasionTerm}",
                        confidence: Confidence.High,
                        ruleId: evasionRule,
                        entity: $"{proc.ProcessName}:{fam.Name}",
                        validationHint: "Família + evasão co-localizadas é evidência forense de alta confiança"
                    ));
                }
            }

            // ─ MEMSTR_SPOOFER_PRIVACY (global only)
            if (!isBr)
            {
                var spooferTerm = FirstMatch(corpus, fam.SpooferTokens);
                if (spooferTerm != null && emitted.Add($"{fam.Name}|MEMSTR_SPOOFER_PRIVACY"))
                {
                    findings.Add(new Finding(
                        RiskLevel.High, FindingCategory.MemoryAnomaly, "Memory String Scan",
                        $"MEMSTR_SPOOFER_PRIVACY — {fam.Name} [{fam.Priority.ToUpper()}] strings de spoofer em {proc.ProcessName} (PID {proc.Id})",
                        $"Strings de HWID spoofer da família {fam.Name} co-localizadas com família de cheat.\n" +
                        $"Sugere tentativa ativa de evadir ban permanente por HWID.",
                        evidenceBase + $"\nspooferMatch: {spooferTerm}",
                        confidence: Confidence.Medium,
                        ruleId: "MEMSTR_SPOOFER_PRIVACY",
                        entity: $"{proc.ProcessName}:{fam.Name}",
                        validationHint: "Correlacionar com histórico de bans e device IDs no relatório"
                    ));
                }
            }

            // ─ MEMSTR_BR_SERVER_ABUSE (BR only)
            if (isBr)
            {
                var abuseTerm = FirstMatch(corpus, Merge(fam.AbuseTokens, pack.SharedAbuseTokens));
                if (abuseTerm != null && emitted.Add($"{fam.Name}|MEMSTR_BR_SERVER_ABUSE"))
                {
                    findings.Add(new Finding(
                        RiskLevel.High, FindingCategory.MemoryAnomaly, "Memory String Scan",
                        $"MEMSTR_BR_SERVER_ABUSE — {fam.Name} [{fam.Priority.ToUpper()}] abuso de servidor em {proc.ProcessName} (PID {proc.Id})",
                        $"Strings de crash/kick de servidor co-localizadas com família de cheat BR {fam.Name}.\n" +
                        $"Indica ferramentas ativas de disruption contra o servidor FiveM.",
                        evidenceBase + $"\nabuseMatch: {abuseTerm}",
                        confidence: Confidence.High,
                        ruleId: "MEMSTR_BR_SERVER_ABUSE",
                        entity: $"{proc.ProcessName}:{fam.Name}",
                        validationHint: "Strings de abuso de servidor evidenciam intenção de disruption ativo"
                    ));
                }
            }

            // ─ MEMSTR_LICENSE_BEACON (both packs)
            var licenseTerm = FirstMatch(corpus, Merge(fam.LicenseTokens, pack.SharedLicenseTokens));
            if (licenseTerm != null && emitted.Add($"{fam.Name}|MEMSTR_LICENSE_BEACON"))
            {
                var licRisk = fam.Priority == "p0" ? RiskLevel.High : RiskLevel.Medium;
                findings.Add(new Finding(
                    licRisk, FindingCategory.MemoryAnomaly, "Memory String Scan",
                    $"MEMSTR_LICENSE_BEACON — {fam.Name} [{fam.Priority.ToUpper()}] beacon de licença em {proc.ProcessName} (PID {proc.Id})",
                    $"Strings de autenticação/licença do cheat {fam.Name} detectadas na memória.\n" +
                    $"Indica comunicação de licença ativa ou chave de acesso presente em memória.",
                    evidenceBase + $"\nlicenseMatch: {licenseTerm}",
                    confidence: Confidence.Medium,
                    ruleId: "MEMSTR_LICENSE_BEACON",
                    entity: $"{proc.ProcessName}:{fam.Name}"
                ));
            }

            // ─ MEMSTR_MENU_UI (both packs)
            var menuTerm = FirstMatch(corpus, Merge(fam.MenuTokens, pack.SharedMenuTokens));
            if (menuTerm != null && emitted.Add($"{fam.Name}|MEMSTR_MENU_UI"))
            {
                findings.Add(new Finding(
                    RiskLevel.Medium, FindingCategory.MemoryAnomaly, "Memory String Scan",
                    $"MEMSTR_MENU_UI — {fam.Name} [{fam.Priority.ToUpper()}] UI de menu em {proc.ProcessName} (PID {proc.Id})",
                    $"Strings de interface de menu do cheat {fam.Name} detectadas na memória.\n" +
                    $"Indica menu de cheat ativo ou renderizado no processo.",
                    evidenceBase + $"\nmenuMatch: {menuTerm}",
                    confidence: Confidence.Medium,
                    ruleId: "MEMSTR_MENU_UI",
                    entity: $"{proc.ProcessName}:{fam.Name}"
                ));
            }
        }
    }

    // ── Rule pack loading ──────────────────────────────────────────────────────

    private static (CheatFamilyPack global, CheatFamilyPack br) LoadRulePacks(ScanConfig config)
    {
        var dir    = Path.Combine(AppContext.BaseDirectory, "rules");
        var global = LoadPack(dir, "memory_strings.json");
        // BR pack requires the 'br_pack' license feature
        var br = config.LicenseFeatures.Contains("br_pack")
            ? LoadPack(dir, "memory_strings_br.json")
            : new CheatFamilyPack { Families = [], Error = null };
        return (global, br);
    }

    private static CheatFamilyPack LoadPack(string dir, string file)
    {
        var path = Path.Combine(dir, file);

        if (!File.Exists(path))
            return new CheatFamilyPack { Error = $"MEMSTR_RULE_PACK_MISSING: {file} não encontrado em {dir}" };

        try
        {
            var opts = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip
            };
            var pack = JsonSerializer.Deserialize<CheatFamilyPack>(File.ReadAllText(path), opts);

            if (pack == null || pack.Families.Length == 0)
                return new CheatFamilyPack { Error = $"MEMSTR_RULE_PACK_INVALID: {file} — pack vazio ou inválido" };

            return pack;
        }
        catch (Exception ex)
        {
            return new CheatFamilyPack { Error = $"MEMSTR_RULE_PACK_INVALID: {file} — {ex.Message}" };
        }
    }

    private static Finding MakePackDiagnostic(string error)
    {
        bool missing = error.StartsWith("MEMSTR_RULE_PACK_MISSING");
        var f = new Finding(
            RiskLevel.Info, FindingCategory.LogCoverage, "Memory String Scan",
            missing ? "MEMSTR_RULE_PACK_MISSING — pack de regras de strings ausente"
                    : "MEMSTR_RULE_PACK_INVALID — pack de regras de strings inválido",
            $"O pack de regras de strings de cheat não pôde ser carregado.\n{error}",
            confidence: Confidence.Confirmed,
            ruleId: missing ? "MEMSTR_RULE_PACK_MISSING" : "MEMSTR_RULE_PACK_INVALID");
        f.ScoreEligible = false;
        return f;
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static string? FirstMatch(string corpus, string[] tokens)
    {
        foreach (var t in tokens)
            if (corpus.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0)
                return t;
        return null;
    }

    // Merges two token arrays without allocation when one is empty
    private static string[] Merge(string[] a, string[] b) =>
        a.Length == 0 ? b : b.Length == 0 ? a : [..a, ..b];

    private static bool IsExecutable(uint p) =>
        (p & 0xFF) is 0x10 or 0x20 or 0x40 or 0x80;

    // Authenticode check — same approach as MemoryDllTraceModule
    private static bool IsAuthenticodeSigned(string path)
    {
        if (!File.Exists(path)) return false;
        try
        {
            var pathPtr = Marshal.StringToHGlobalUni(path);
            var fiSize  = Marshal.SizeOf<WINTRUST_FILE_INFO>();
            var fiPtr   = Marshal.AllocHGlobal(fiSize);
            try
            {
                Marshal.StructureToPtr(new WINTRUST_FILE_INFO
                {
                    cbStruct      = (uint)fiSize,
                    pcwszFilePath = pathPtr,
                    hFile         = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                }, fiPtr, false);

                var td = new WINTRUST_DATA
                {
                    cbStruct            = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData      = IntPtr.Zero,
                    dwUIChoice          = 2,
                    fdwRevocationChecks = 0,
                    dwUnionChoice       = 1,
                    pFile               = fiPtr,
                    dwStateAction       = 1,
                    hWVTStateData       = IntPtr.Zero,
                    pwszURLReference    = IntPtr.Zero,
                    dwProvFlags         = 0x00001000,
                    dwUIContext         = 0,
                    pSignatureSettings  = IntPtr.Zero
                };
                var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
                uint res   = WinVerifyTrust(IntPtr.Zero, ref action, ref td);
                td.dwStateAction = 2;
                WinVerifyTrust(IntPtr.Zero, ref action, ref td);
                return res == 0;
            }
            finally { Marshal.FreeHGlobal(fiPtr); Marshal.FreeHGlobal(pathPtr); }
        }
        catch { return false; }
    }

    // ── Module enumeration ─────────────────────────────────────────────────────

    private static List<ModInfo> EnumModules(uint pid)
    {
        var result   = new List<ModInfo>();
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE) return result;

        try
        {
            var entry = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };
            if (!Module32FirstW(snapshot, ref entry)) return result;
            do
            {
                result.Add(new ModInfo(
                    entry.modBaseAddr.ToInt64(),
                    Math.Max(entry.modBaseSize, 0x1000),
                    entry.szExePath ?? ""));
            }
            while (Module32NextW(snapshot, ref entry));
        }
        catch { }
        finally { CloseHandle(snapshot); }

        return result;
    }

    // ── Win32 constants ────────────────────────────────────────────────────────

    private const uint MEM_COMMIT  = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;

    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    private const uint TH32CS_SNAPMODULE   = 0x00000008;
    private const uint TH32CS_SNAPMODULE32 = 0x00000010;

    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    // ── Structs ────────────────────────────────────────────────────────────────

    private sealed record ModInfo(long Base, long Size, string Path);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MODULEENTRY32W
    {
        public uint   dwSize;
        public uint   th32ModuleID;
        public uint   th32ProcessID;
        public uint   GlblcntUsage;
        public uint   ProccntUsage;
        public IntPtr modBaseAddr;
        public uint   modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint   cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint   cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint   dwUIChoice;
        public uint   fdwRevocationChecks;
        public uint   dwUnionChoice;
        public IntPtr pFile;
        public uint   dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint   dwProvFlags;
        public uint   dwUIContext;
        public IntPtr pSignatureSettings;
    }

    // ── P/Invoke ───────────────────────────────────────────────────────────────

    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, uint dwPid);
    [DllImport("kernel32.dll")] private static extern bool   CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] private static extern int    VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [DllImport("kernel32.dll")] private static extern bool   ReadProcessMemory(IntPtr hProcess, IntPtr lpBase, byte[] lpBuf, int nSize, out int lpRead);
    [DllImport("kernel32.dll")] private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Module32FirstW(IntPtr hSnap, ref MODULEENTRY32W lpme);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Module32NextW(IntPtr hSnap, ref MODULEENTRY32W lpme);
    [DllImport("wintrust.dll", SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    // ── JSON model (nested — avoids CS9051 file-local type restrictions) ───────

    private sealed class CheatFamilyPack
    {
        [JsonPropertyName("families")]              public CheatFamily[] Families             { get; set; } = [];
        [JsonPropertyName("sharedBehaviorTokens")] public string[]      SharedBehaviorTokens { get; set; } = [];
        [JsonPropertyName("sharedEvasionTokens")]  public string[]      SharedEvasionTokens  { get; set; } = [];
        [JsonPropertyName("sharedAbuseTokens")]    public string[]      SharedAbuseTokens    { get; set; } = [];
        [JsonPropertyName("sharedMenuTokens")]     public string[]      SharedMenuTokens     { get; set; } = [];
        [JsonPropertyName("sharedLicenseTokens")]  public string[]      SharedLicenseTokens  { get; set; } = [];
        public string? Error { get; set; }
    }

    private sealed class CheatFamily
    {
        [JsonPropertyName("name")]           public string   Name           { get; set; } = "";
        [JsonPropertyName("priority")]       public string   Priority       { get; set; } = "p2";
        [JsonPropertyName("familyTokens")]   public string[] FamilyTokens   { get; set; } = [];
        [JsonPropertyName("behaviorTokens")] public string[] BehaviorTokens { get; set; } = [];
        [JsonPropertyName("evasionTokens")]  public string[] EvasionTokens  { get; set; } = [];
        [JsonPropertyName("spooferTokens")]  public string[] SpooferTokens  { get; set; } = [];
        [JsonPropertyName("abuseTokens")]    public string[] AbuseTokens    { get; set; } = [];
        [JsonPropertyName("licenseTokens")]  public string[] LicenseTokens  { get; set; } = [];
        [JsonPropertyName("menuTokens")]     public string[] MenuTokens     { get; set; } = [];
    }
}
