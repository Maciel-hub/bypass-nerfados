using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

// Deep memory forensics for FiveM/GTA processes.
// Complements ProcessMemoryModule (anonymous exec regions) by adding:
//   - loaded module validation (known cheat DLLs, deleted-on-disk, suspicious path + Authenticode)
//   - unlinked image detection (MEM_IMAGE not in Toolhelp module list)
//   - MZ/PE header check in MEM_PRIVATE exec regions (manual map / reflective DLL)
//   - thread start address correlation with private exec regions
public class MemoryDllTraceModule : BaseModule
{
    public override string Name        => "Memory DLL Trace";
    public override string Description => "DLLs carregadas, módulos ocultos/manual map e regiões executáveis em processos FiveM/GTA";

    // Only these process families are scanned — scanning all processes produces noise and is slow.
    private static readonly string[] CoreTargetNames = ["fivem", "gta5", "redengine"];

    // FiveM spawns versioned child processes (e.g. FiveM_b3095_GTAProcess); match by prefix.
    private static readonly string[] FiveMPrefixes = ["fivem_b", "fivem_gt", "fivem_rgl"];

    // Standard system paths — DLLs here are unconditionally trusted without signature check.
    private static readonly string[] SystemPathPrefixes =
    [
        @"C:\Windows\",
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
    ];

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var targets  = CollectTargetProcesses();

        if (targets.Count == 0)
        {
            // Emit diagnostic so investigator knows module ran but had no targets to scan.
            var f = new Finding(
                RiskLevel.Info, FindingCategory.LogCoverage, Name,
                "Memory DLL Trace — nenhum processo alvo ativo",
                "Nenhum processo FiveM/GTA/RedENGINE encontrado em execução.\n" +
                "O módulo não pode varrer memória sem processo alvo.",
                confidence: Confidence.Confirmed,
                ruleId: "MEMDLL_NO_TARGET_PROCESS");
            f.ScoreEligible = false;
            findings.Add(f);
            return Task.FromResult(findings);
        }

        foreach (var proc in targets)
        {
            ct.ThrowIfCancellationRequested();
            try { AnalyzeProcess(proc, findings, ct); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { LogPartialError($"MemoryDllTrace: falha ao analisar {proc.ProcessName} PID {proc.Id}", ex); }
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

        return result;
    }

    // ── Per-process analysis ───────────────────────────────────────────────────

    private void AnalyzeProcess(Process proc, List<Finding> findings, CancellationToken ct)
    {
        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, (uint)proc.Id);
        if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE)
        {
            LogPartialError($"MemoryDllTrace: acesso negado ao processo {proc.ProcessName} PID {proc.Id}");
            return;
        }

        try
        {
            // Module enumeration — must succeed before unlinked-image detection is safe
            var modules = EnumModules((uint)proc.Id, out bool moduleEnumOk);
            if (!moduleEnumOk)
            {
                var f = new Finding(
                    RiskLevel.Info, FindingCategory.LogCoverage, Name,
                    $"MemoryDllTrace: enumeração de módulos falhou em {proc.ProcessName} (PID {proc.Id})",
                    "Toolhelp32 não conseguiu listar os módulos carregados.\n" +
                    "MEMDLL_UNLINKED_IMAGE não será emitido — lista parcial causaria falsos positivos.\n" +
                    "Demais detecções (RWX, PE privado, thread start) permanecem ativas.",
                    confidence: Confidence.Confirmed,
                    ruleId: "MEMDLL_MODULE_ENUM_FAILED");
                f.ScoreEligible = false;
                findings.Add(f);
            }

            var moduleBaseSet = new HashSet<long>(modules.Select(m => m.Base));

            var privateExecRegions = new List<(long Base, long Size)>();
            WalkMemory(handle, proc, moduleBaseSet, moduleEnumOk, privateExecRegions, findings, ct);

            foreach (var mod in modules)
            {
                ct.ThrowIfCancellationRequested();
                ValidateModule(proc, mod, findings);
            }

            if (privateExecRegions.Count > 0)
                CheckThreads(proc, privateExecRegions, findings, ct);
        }
        finally { CloseHandle(handle); }
    }

    // ── Memory walk ────────────────────────────────────────────────────────────

    private void WalkMemory(IntPtr handle, Process proc,
        HashSet<long> moduleBaseSet, bool moduleEnumOk,
        List<(long Base, long Size)> privateExecRegions,
        List<Finding> findings, CancellationToken ct)
    {
        IntPtr addr  = IntPtr.Zero;
        int rwxCount = 0;

        while (VirtualQueryEx(handle, addr, out var mbi,
               (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) > 0)
        {
            ct.ThrowIfCancellationRequested();

            var regionBase = mbi.BaseAddress.ToInt64();
            var regionSize = mbi.RegionSize.ToInt64();
            if (regionSize <= 0) break;

            if (mbi.State == MEM_COMMIT)
            {
                bool isExec    = IsExecutable(mbi.Protect);
                bool isPrivate = mbi.Type == MEM_PRIVATE;
                bool isImage   = mbi.Type == MEM_IMAGE;

                if (isPrivate && isExec && regionSize > 0x1000)
                    privateExecRegions.Add((regionBase, regionSize));

                if (isPrivate && (mbi.Protect & 0xFF) == PAGE_EXECUTE_READWRITE)
                {
                    rwxCount++;
                    if (rwxCount <= 3)
                    {
                        var risk = regionSize > 0x10000 ? RiskLevel.Critical : RiskLevel.High;
                        findings.Add(new Finding(
                            risk, FindingCategory.MemoryAnomaly, Name,
                            $"MEMDLL_RWX_REGION — PAGE_EXECUTE_READWRITE em {proc.ProcessName} (PID {proc.Id})",
                            $"Região PAGE_EXECUTE_READWRITE privada em processo FiveM/GTA.\n" +
                            $"Padrão clássico de injector: aloca RWX, copia payload, executa.",
                            $"Base: 0x{regionBase:X} | Tamanho: {regionSize / 1024} KB",
                            confidence: Confidence.High,
                            ruleId: "MEMDLL_RWX_REGION",
                            entity: $"{proc.ProcessName}:0x{regionBase:X}"
                        ));
                    }
                }
                else if (isPrivate && isExec && regionSize > 0x4000)
                {
                    bool hasMz = ReadHasMzHeader(handle, mbi.BaseAddress);
                    if (hasMz)
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical, FindingCategory.MemoryAnomaly, Name,
                            $"MEMDLL_PRIVATE_EXEC_PE — PE em memória privada: {proc.ProcessName} (PID {proc.Id})",
                            $"Região MEM_PRIVATE executável contém header MZ/PE sem arquivo mapeado em disco.\n" +
                            $"Indica manual map ou reflective DLL injection — artefato forense forte.",
                            $"Base: 0x{regionBase:X} | Tamanho: {regionSize / 1024} KB",
                            confidence: Confidence.High,
                            ruleId: "MEMDLL_PRIVATE_EXEC_PE",
                            entity: $"{proc.ProcessName}:0x{regionBase:X}"
                        ));
                    }
                    else if (regionSize > 0x10000)
                    {
                        // Only flag large anonymous exec regions to suppress JIT compiler thunks
                        findings.Add(new Finding(
                            RiskLevel.High, FindingCategory.MemoryAnomaly, Name,
                            $"MEMDLL_PRIVATE_EXEC_NO_PE — Executável anônimo grande em {proc.ProcessName} (PID {proc.Id})",
                            $"Região MEM_PRIVATE executável sem header PE e sem módulo associado.\n" +
                            $"Possível shellcode ou trampolim de injeção.",
                            $"Base: 0x{regionBase:X} | Tamanho: {regionSize / 1024} KB | Protect: {ProtectName(mbi.Protect)}",
                            confidence: Confidence.Medium,
                            ruleId: "MEMDLL_PRIVATE_EXEC_NO_PE",
                            entity: $"{proc.ProcessName}:0x{regionBase:X}",
                            validationHint: "Correlacionar com thread start address; descartar se processo é .NET/runtime JIT"
                        ));
                    }
                }
                // Only detect unlinked images when module enumeration succeeded.
                // An empty/partial module list would cause every MEM_IMAGE to appear unlinked.
                else if (isImage && isExec && moduleEnumOk && moduleBaseSet.Count > 0)
                {
                    var allocBase = mbi.AllocationBase.ToInt64();
                    if (!moduleBaseSet.Contains(allocBase))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical, FindingCategory.MemoryAnomaly, Name,
                            $"MEMDLL_UNLINKED_IMAGE — Módulo deslinkado em {proc.ProcessName} (PID {proc.Id})",
                            $"Região MEM_IMAGE executável sem correspondência na lista de módulos carregados.\n" +
                            $"Indica DLL injetada e removida do PEB para ocultar presença.",
                            $"Base: 0x{regionBase:X} | AllocBase: 0x{allocBase:X} | Tamanho: {regionSize / 1024} KB",
                            confidence: Confidence.High,
                            ruleId: "MEMDLL_UNLINKED_IMAGE",
                            entity: $"{proc.ProcessName}:0x{allocBase:X}"
                        ));
                    }
                }
            }

            addr = new IntPtr(regionBase + regionSize);
        }

        if (rwxCount > 3)
        {
            findings.Add(new Finding(
                RiskLevel.Critical, FindingCategory.MemoryAnomaly, Name,
                $"MEMDLL_RWX_REGION — {rwxCount} regiões RWX em {proc.ProcessName} (PID {proc.Id})",
                $"Volume elevado de regiões PAGE_EXECUTE_READWRITE ({rwxCount} regiões).\n" +
                $"Fortemente indicativo de hook framework ou injector ativo.",
                $"Total RWX: {rwxCount}",
                confidence: Confidence.High,
                ruleId: "MEMDLL_RWX_REGION_MASS",
                entity: proc.ProcessName
            ));
        }
    }

    // ── Module validation ──────────────────────────────────────────────────────

    private void ValidateModule(Process proc, ModuleInfo mod, List<Finding> findings)
    {
        var path  = mod.Path;
        var name  = Path.GetFileName(path);
        var lower = name.ToLowerInvariant();

        if (string.IsNullOrWhiteSpace(path) || IsOwnProcess(path)) return;

        // KnownDlls always checked first — a cheat DLL placed under Program Files must not be suppressed.
        if (CheatDatabase.KnownDlls.TryGetValue(lower, out var dllInfo))
        {
            string? sha256 = null;
            if (File.Exists(path)) { try { sha256 = ComputeSha256(path); } catch { } }

            findings.Add(new Finding(
                RiskLevel.Critical, FindingCategory.MemoryAnomaly, Name,
                $"MEMDLL_KNOWN_CHEAT_DLL_LOADED — {dllInfo.Name} em {proc.ProcessName} (PID {proc.Id})",
                $"DLL de cheat conhecida carregada no processo FiveM/GTA.\n{dllInfo.Description}",
                $"DLL: {path}" + (sha256 != null ? $"\nSHA256: {sha256}" : ""),
                confidence: sha256 != null ? Confidence.Confirmed : Confidence.High,
                ruleId: "MEMDLL_KNOWN_CHEAT_DLL_LOADED",
                entity: path
            ));
            return;
        }

        // C:\Windows\ — unconditionally trusted (KnownDlls already won above)
        if (path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase)) return;

        // C:\Program Files\ — trusted only with a valid Authenticode chain.
        // An unsigned DLL under Program Files in a FiveM/GTA process is still suspicious.
        if (path.StartsWith(@"C:\Program Files\",      StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"C:\Program Files (x86)\", StringComparison.OrdinalIgnoreCase))
        {
            if (IsAuthenticodeSigned(path)) return;
            // Fall through — unsigned Program Files DLL warrants inspection
        }

        if (CheatDatabase.IsKnownLegitimate(path)) return;

        // File deleted from disk after load?
        bool exists = File.Exists(path);
        if (!exists)
        {
            findings.Add(new Finding(
                RiskLevel.High, FindingCategory.MemoryAnomaly, Name,
                $"MEMDLL_DELETED_IMAGE_MAPPING — DLL deletada em memória: {proc.ProcessName} (PID {proc.Id})",
                $"Módulo mapeado cujo arquivo não existe mais em disco.\n" +
                $"Técnica usada por loaders para apagar rastros após injeção bem-sucedida.",
                $"DLL: {path} | Base: 0x{mod.Base:X}",
                confidence: Confidence.Medium,
                ruleId: "MEMDLL_DELETED_IMAGE_MAPPING",
                entity: path,
                validationHint: "Correlacionar com Prefetch, Amcache e Recycle Bin para histórico de execução"
            ));
            return;
        }

        // DLL loaded from suspicious path (Temp, Downloads, Desktop, Rar$*, etc.)?
        if (!CheatDatabase.IsSuspiciousPath(path)) return;

        // Use WinVerifyTrust for Authenticode — CompanyName is editable metadata, not trusted.
        // A cheat DLL can set "Microsoft Corporation" in FileVersionInfo.
        bool signed = IsAuthenticodeSigned(path);
        if (signed) return; // valid Authenticode chain → suppress

        string? sha256dll = null;
        try { sha256dll = ComputeSha256(path); } catch { }

        // Collect CompanyName as additional context only, not as trust signal
        string? companyName = null;
        try { companyName = FileVersionInfo.GetVersionInfo(path).CompanyName?.Trim(); } catch { }

        findings.Add(new Finding(
            RiskLevel.High, FindingCategory.MemoryAnomaly, Name,
            $"MEMDLL_UNSIGNED_USER_DLL — DLL sem assinatura em path suspeito: {proc.ProcessName} (PID {proc.Id})",
            $"DLL carregada de localização de risco sem assinatura Authenticode válida.\n" +
            $"DLLs legítimas residem em Program Files ou System32 e são assinadas digitalmente.",
            $"DLL: {path}" +
            (sha256dll    != null ? $"\nSHA256: {sha256dll}"       : "") +
            (companyName  != null ? $"\nCompanyName: {companyName} (metadata não verificado)" : "\nCompanyName: ausente"),
            confidence: Confidence.Medium,
            ruleId: "MEMDLL_UNSIGNED_USER_DLL",
            entity: path,
            validationHint: "Consultar hash em VirusTotal; correlacionar com extração WinRAR/7z ou download recente"
        ));
    }

    // ── Thread start address check ─────────────────────────────────────────────

    private void CheckThreads(Process proc,
        List<(long Base, long Size)> privateExecRegions,
        List<Finding> findings, CancellationToken ct)
    {
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE) return;

        int inaccessibleThreads = 0;
        int ntQueryFailures     = 0;

        try
        {
            var entry = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
            if (!Thread32First(snapshot, ref entry)) return;

            do
            {
                ct.ThrowIfCancellationRequested();
                if (entry.th32OwnerProcessID != (uint)proc.Id) continue;

                var th = OpenThread(THREAD_QUERY_INFORMATION, false, entry.th32ThreadID);
                if (th == IntPtr.Zero) { inaccessibleThreads++; continue; }

                try
                {
                    // NtQueryInformationThread class 9 = ThreadQuerySetWin32StartAddress
                    int ntStatus = NtQueryInformationThread(th, THREAD_WIN32_START_ADDRESS,
                        out var startAddr, IntPtr.Size, out _);

                    if (ntStatus != 0) { ntQueryFailures++; continue; }

                    var sa = startAddr.ToInt64();
                    foreach (var (regBase, regSize) in privateExecRegions)
                    {
                        if (sa < regBase || sa >= regBase + regSize) continue;

                        findings.Add(new Finding(
                            RiskLevel.Critical, FindingCategory.MemoryAnomaly, Name,
                            $"MEMDLL_THREAD_START_PRIVATE_EXEC — Thread em região privada: {proc.ProcessName} (PID {proc.Id})",
                            $"Thread com start address em região MEM_PRIVATE executável.\n" +
                            $"Indica shellcode ou DLL injetada com thread de execução ativa.",
                            $"TID: {entry.th32ThreadID} | Start: 0x{sa:X} | Região: 0x{regBase:X}+{regSize / 1024}KB",
                            confidence: Confidence.High,
                            ruleId: "MEMDLL_THREAD_START_PRIVATE_EXEC",
                            entity: $"{proc.ProcessName}:TID{entry.th32ThreadID}"
                        ));
                        break;
                    }
                }
                finally { CloseHandle(th); }
            }
            while (Thread32Next(snapshot, ref entry));
        }
        finally { CloseHandle(snapshot); }

        // Only warn when failures are forensically relevant (process had suspicious regions)
        if (inaccessibleThreads > 0 || ntQueryFailures > 0)
            LogPartialError(
                $"MemoryDllTrace: {proc.ProcessName} PID {proc.Id} — " +
                $"{inaccessibleThreads} thread(s) inacessível(is), " +
                $"{ntQueryFailures} falha(s) NtQueryInformationThread. " +
                $"Processo tinha {privateExecRegions.Count} região(ões) privada(s) executável(is).");
    }

    // ── Module enumeration ─────────────────────────────────────────────────────

    private static List<ModuleInfo> EnumModules(uint pid, out bool ok)
    {
        var result   = new List<ModuleInfo>();
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

        if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE) { ok = false; return result; }

        try
        {
            var entry = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };
            if (!Module32FirstW(snapshot, ref entry)) { ok = false; return result; }
            do { result.Add(new ModuleInfo(entry.modBaseAddr.ToInt64(), entry.szExePath ?? "")); }
            while (Module32NextW(snapshot, ref entry));
        }
        catch { ok = false; return result; }
        finally { CloseHandle(snapshot); }

        ok = result.Count > 0;
        return result;
    }

    // ── Authenticode (WinVerifyTrust) ──────────────────────────────────────────

    // Returns true if the file carries a valid Authenticode signature trusted by the OS.
    // Uses WTD_CACHE_ONLY_URL_RETRIEVAL to avoid network calls during scan.
    // CompanyName from FileVersionInfo is NOT a trust signal — any cheat can set it.
    private static bool IsAuthenticodeSigned(string path)
    {
        if (!File.Exists(path)) return false;
        try
        {
            var pathPtr      = Marshal.StringToHGlobalUni(path);
            var fileInfoSize = Marshal.SizeOf<WINTRUST_FILE_INFO>();
            var fileInfoPtr  = Marshal.AllocHGlobal(fileInfoSize);
            try
            {
                Marshal.StructureToPtr(new WINTRUST_FILE_INFO
                {
                    cbStruct      = (uint)fileInfoSize,
                    pcwszFilePath = pathPtr,
                    hFile         = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                }, fileInfoPtr, false);

                var trustData = new WINTRUST_DATA
                {
                    cbStruct            = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData      = IntPtr.Zero,
                    dwUIChoice          = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice       = WTD_CHOICE_FILE,
                    pFile               = fileInfoPtr,
                    dwStateAction       = WTD_STATEACTION_VERIFY,
                    hWVTStateData       = IntPtr.Zero,
                    pwszURLReference    = IntPtr.Zero,
                    dwProvFlags         = WTD_CACHE_ONLY_URL_RETRIEVAL,
                    dwUIContext         = 0,
                    pSignatureSettings  = IntPtr.Zero
                };

                var actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                uint result    = WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);

                // Always close the state handle to prevent leaks
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);

                return result == 0; // 0 = ERROR_SUCCESS = signed and trusted
            }
            finally
            {
                Marshal.FreeHGlobal(fileInfoPtr);
                Marshal.FreeHGlobal(pathPtr);
            }
        }
        catch { return false; }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static bool ReadHasMzHeader(IntPtr hProcess, IntPtr baseAddr)
    {
        var buf = new byte[2];
        return ReadProcessMemory(hProcess, baseAddr, buf, 2, out var read)
               && read >= 2
               && buf[0] == 0x4D && buf[1] == 0x5A; // MZ
    }

    private static string ComputeSha256(string path)
    {
        using var sha = SHA256.Create();
        using var fs  = File.OpenRead(path);
        return Convert.ToHexString(sha.ComputeHash(fs));
    }

    // Strip PAGE_GUARD (0x100), PAGE_NOCACHE (0x200), PAGE_WRITECOMBINE (0x400) modifiers
    // before comparing — they can be OR'd into any base protection value.
    private static bool IsExecutable(uint p) =>
        (p & 0xFF) is PAGE_EXECUTE or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;

    private static string ProtectName(uint p)
    {
        var mods = new List<string>();
        if ((p & 0x100) != 0) mods.Add("GUARD");
        if ((p & 0x200) != 0) mods.Add("NOCACHE");
        if ((p & 0x400) != 0) mods.Add("WRITECOMBINE");
        var suffix = mods.Count > 0 ? $"|{string.Join("|", mods)}" : "";
        return ((p & 0xFF) switch
        {
            PAGE_EXECUTE           => "EXECUTE",
            PAGE_EXECUTE_READ      => "EXECUTE_READ",
            PAGE_EXECUTE_READWRITE => "EXECUTE_READWRITE",
            PAGE_EXECUTE_WRITECOPY => "EXECUTE_WRITECOPY",
            _                      => $"0x{p & 0xFF:X}"
        }) + suffix;
    }

    // ── Win32 constants ────────────────────────────────────────────────────────

    private const uint MEM_COMMIT  = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint MEM_IMAGE   = 0x1000000;

    private const uint PAGE_EXECUTE           = 0x10;
    private const uint PAGE_EXECUTE_READ      = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint THREAD_QUERY_INFORMATION  = 0x0040;

    private const uint TH32CS_SNAPMODULE   = 0x00000008;
    private const uint TH32CS_SNAPMODULE32 = 0x00000010;
    private const uint TH32CS_SNAPTHREAD   = 0x00000004;

    private const int THREAD_WIN32_START_ADDRESS = 9;

    // WinVerifyTrust constants
    private const uint WTD_UI_NONE                  = 2;
    private const uint WTD_REVOKE_NONE              = 0;
    private const uint WTD_CHOICE_FILE              = 1;
    private const uint WTD_STATEACTION_VERIFY       = 1;
    private const uint WTD_STATEACTION_CLOSE        = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    // ── Structs ────────────────────────────────────────────────────────────────

    private sealed record ModuleInfo(long Base, string Path);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;        // 4-byte padding on 64-bit absorbs Win10 PartitionId field
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
    private struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int  tpBasePri;
        public int  tpDeltaPri;
        public uint dwFlags;
    }

    // WinVerifyTrust structs — layout must match Win32 64-bit ABI exactly.
    // WINTRUST_FILE_INFO: cbStruct(4)+pad(4)+pcwszFilePath(8)+hFile(8)+pgKnownSubject(8) = 32 bytes
    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint   cbStruct;
        public IntPtr pcwszFilePath; // LPCWSTR — allocated via Marshal.StringToHGlobalUni
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    // WINTRUST_DATA: total 88 bytes on 64-bit (see layout comment in IsAuthenticodeSigned)
    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint   cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint   dwUIChoice;
        public uint   fdwRevocationChecks;
        public uint   dwUnionChoice;
        public IntPtr pFile;               // union — only file variant used
        public uint   dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint   dwProvFlags;
        public uint   dwUIContext;
        public IntPtr pSignatureSettings;
    }

    // ── P/Invoke ───────────────────────────────────────────────────────────────

    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, uint dwPid);
    [DllImport("kernel32.dll")] private static extern IntPtr OpenThread(uint dwAccess, bool bInherit, uint dwTid);
    [DllImport("kernel32.dll")] private static extern bool   CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] private static extern int    VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [DllImport("kernel32.dll")] private static extern bool   ReadProcessMemory(IntPtr hProcess, IntPtr lpBase, byte[] lpBuf, int nSize, out int lpRead);
    [DllImport("kernel32.dll")] private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Module32FirstW(IntPtr hSnap, ref MODULEENTRY32W lpme);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Module32NextW(IntPtr hSnap, ref MODULEENTRY32W lpme);
    [DllImport("kernel32.dll")] private static extern bool Thread32First(IntPtr hSnap, ref THREADENTRY32 lpte);
    [DllImport("kernel32.dll")] private static extern bool Thread32Next(IntPtr hSnap, ref THREADENTRY32 lpte);
    [DllImport("ntdll.dll")]    private static extern int  NtQueryInformationThread(IntPtr hThread, int threadInfoClass, out IntPtr threadInfo, int threadInfoLen, out int returnLen);
    [DllImport("wintrust.dll", SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
}
