using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

// Deep memory forensics for FiveM/GTA processes.
// Complements ProcessMemoryModule (anonymous exec regions) by adding:
//   - loaded module validation (known cheat DLLs, deleted-on-disk, suspicious path)
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

    // Standard system paths — DLLs here are unconditionally trusted.
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
        if (targets.Count == 0) return Task.FromResult(findings);

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
        if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE) return;

        try
        {
            var modules       = EnumModules((uint)proc.Id);
            var moduleBaseSet = new HashSet<long>(modules.Select(m => m.Base));

            var privateExecRegions = new List<(long Base, long Size)>();
            WalkMemory(handle, proc, moduleBaseSet, privateExecRegions, findings, ct);

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
        HashSet<long> moduleBaseSet,
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

                if (isPrivate && mbi.Protect == PAGE_EXECUTE_READWRITE)
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
                else if (isImage && isExec)
                {
                    // MEM_IMAGE region whose AllocationBase is not in the Toolhelp module list
                    // → DLL injected and removed from PEB/loader list to hide its presence
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

        // Suppress standard system directories unconditionally
        if (SystemPathPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase))) return;
        if (CheatDatabase.IsKnownLegitimate(path)) return;

        // Known cheat DLL?
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
        if (CheatDatabase.IsSuspiciousPath(path))
        {
            string? publisher = null;
            try { publisher = FileVersionInfo.GetVersionInfo(path).CompanyName?.Trim(); } catch { }

            if (!string.IsNullOrEmpty(publisher) && CheatDatabase.IsKnownLegitimatePublisher(publisher)) return;

            string? sha256 = null;
            try { sha256 = ComputeSha256(path); } catch { }

            findings.Add(new Finding(
                RiskLevel.High, FindingCategory.MemoryAnomaly, Name,
                $"MEMDLL_UNSIGNED_USER_DLL — DLL em path suspeito: {proc.ProcessName} (PID {proc.Id})",
                $"DLL carregada de localização de risco sem publisher confiável.\n" +
                $"DLLs legítimas residem em Program Files ou System32.",
                $"DLL: {path}" +
                (sha256      != null ? $"\nSHA256: {sha256}"      : "") +
                (publisher   != null ? $"\nPublisher: {publisher}" : "\nPublisher: ausente"),
                confidence: Confidence.Medium,
                ruleId: "MEMDLL_UNSIGNED_USER_DLL",
                entity: path,
                validationHint: "Consultar hash em VirusTotal; correlacionar com extração WinRAR/7z ou download recente"
            ));
        }
    }

    // ── Thread start address check ─────────────────────────────────────────────

    private void CheckThreads(Process proc,
        List<(long Base, long Size)> privateExecRegions,
        List<Finding> findings, CancellationToken ct)
    {
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE) return;

        try
        {
            var entry = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
            if (!Thread32First(snapshot, ref entry)) return;

            do
            {
                ct.ThrowIfCancellationRequested();
                if (entry.th32OwnerProcessID != (uint)proc.Id) continue;

                var th = OpenThread(THREAD_QUERY_INFORMATION, false, entry.th32ThreadID);
                if (th == IntPtr.Zero) continue;

                try
                {
                    // NtQueryInformationThread class 9 = ThreadQuerySetWin32StartAddress
                    if (NtQueryInformationThread(th, THREAD_WIN32_START_ADDRESS,
                            out var startAddr, IntPtr.Size, out _) != 0) continue;

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
    }

    // ── Module enumeration ─────────────────────────────────────────────────────

    private static List<ModuleInfo> EnumModules(uint pid)
    {
        var result   = new List<ModuleInfo>();
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE) return result;

        try
        {
            var entry = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };
            if (!Module32FirstW(snapshot, ref entry)) return result;
            do { result.Add(new ModuleInfo(entry.modBaseAddr.ToInt64(), entry.szExePath)); }
            while (Module32NextW(snapshot, ref entry));
        }
        catch { }
        finally { CloseHandle(snapshot); }

        return result;
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

    private static bool IsExecutable(uint p) =>
        p is PAGE_EXECUTE or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;

    private static string ProtectName(uint p) => p switch
    {
        PAGE_EXECUTE             => "EXECUTE",
        PAGE_EXECUTE_READ        => "EXECUTE_READ",
        PAGE_EXECUTE_READWRITE   => "EXECUTE_READWRITE",
        PAGE_EXECUTE_WRITECOPY   => "EXECUTE_WRITECOPY",
        _                        => $"0x{p:X}"
    };

    // ── Win32 / structs ────────────────────────────────────────────────────────

    private sealed record ModuleInfo(long Base, string Path);

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

    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

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
}
