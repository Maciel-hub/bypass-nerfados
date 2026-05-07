using System.Diagnostics;
using System.Runtime.InteropServices;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class ProcessMemoryModule : BaseModule
{
    public override string Name => "Process Memory";
    public override string Description => "Anomalias de memória: hollowing, injeção de DLL, shellcode, APC";

    private static readonly string[] TargetProcessNames =
        ["fivem", "fivem_b2699", "gta5", "javaw", "minecraft.windows", "valorant"];

    private static readonly string[] SuspiciousParentProcesses =
        ["cmd", "powershell", "wscript", "cscript", "mshta", "regsvr32", "rundll32"];

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        ScanRunningProcesses(findings, cancellationToken);
        ScanMemoryRegions(findings, cancellationToken);
        ScanProcessTree(findings, cancellationToken);

        return Task.FromResult(findings);
    }

    private static void ScanRunningProcesses(List<Finding> findings, CancellationToken cancellationToken)
    {
        foreach (var proc in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var nameLower = proc.ProcessName.ToLowerInvariant();

                // Detect processes with suspicious names
                if (CheatDatabase.HasSuspiciousKeyword(nameLower))
                {
                    string exePath = "desconhecido";
                    try { exePath = proc.MainModule?.FileName ?? "desconhecido"; } catch { }

                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.SuspiciousExecution,
                        "Process Memory",
                        $"Processo suspeito em execução: {proc.ProcessName} (PID {proc.Id})",
                        $"Processo com nome suspeito ativo.\nCaminho: {exePath}"
                    ));
                    continue;
                }

                // Check for known cheat executables running
                if (CheatDatabase.KnownExecutables.ContainsKey(nameLower + ".exe"))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        "Process Memory",
                        $"CHEAT EM EXECUÇÃO: {proc.ProcessName} (PID {proc.Id})",
                        $"Processo de cheat conhecido ativo no sistema."
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }

    private static void ScanMemoryRegions(List<Finding> findings, CancellationToken cancellationToken)
    {
        // Scan FiveM and target game processes for memory anomalies
        foreach (var targetName in TargetProcessNames)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var procs = Process.GetProcessesByName(targetName);
            foreach (var proc in procs)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    ScanProcessMemoryRegions(proc, findings, cancellationToken);
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }
    }

    private static void ScanProcessMemoryRegions(Process proc, List<Finding> findings, CancellationToken cancellationToken)
    {
        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, (uint)proc.Id);
        if (handle == IntPtr.Zero) return;

        try
        {
            IntPtr address = IntPtr.Zero;
            int anomalyCount = 0;

            while (VirtualQueryEx(handle, address, out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Look for executable private memory not backed by a file
                if (mbi.State == MEM_COMMIT &&
                    mbi.Type == MEM_PRIVATE &&
                    (mbi.Protect == PAGE_EXECUTE_READWRITE ||
                     mbi.Protect == PAGE_EXECUTE_READ ||
                     mbi.Protect == PAGE_EXECUTE) &&
                    mbi.RegionSize > 4096)
                {
                    anomalyCount++;

                    if (anomalyCount <= 5) // Report first 5 anomalies
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.MemoryAnomaly,
                            "Process Memory",
                            $"Memória executável anônima em {proc.ProcessName} (PID {proc.Id})",
                            $"Região de memória privada executável sem módulo associado. " +
                            $"Possível injeção de código (DLL reflexiva, shellcode, APC, Hollowing).",
                            $"Endereço: 0x{address.ToInt64():X} | " +
                            $"Tamanho: {mbi.RegionSize / 1024} KB | " +
                            $"Proteção: {ProtectionName(mbi.Protect)}"
                        ));
                    }
                }

                // Detect PAGE_EXECUTE_READWRITE specifically (used by injectors)
                if (mbi.State == MEM_COMMIT &&
                    mbi.Protect == PAGE_EXECUTE_READWRITE &&
                    mbi.Type == MEM_PRIVATE &&
                    mbi.RegionSize > 65536)
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.MemoryAnomaly,
                        "Process Memory",
                        $"EXECUTE+READWRITE em {proc.ProcessName} — indicativo de injeção ativa",
                        $"Região PAGE_EXECUTE_READWRITE privada grande. Padrão forte de injeção de código.",
                        $"Endereço: 0x{address.ToInt64():X} | Tamanho: {mbi.RegionSize / 1024} KB"
                    ));
                }

                // Advance to next region
                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;
                address = new IntPtr(address.ToInt64() + regionSize);
            }

            if (anomalyCount > 5)
            {
                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.MemoryAnomaly,
                    "Process Memory",
                    $"ALTO NÚMERO de regiões anômalas em {proc.ProcessName}: {anomalyCount}",
                    $"Quantidade elevada de regiões de memória executável sem módulo. " +
                    "Fortemente indicativo de injeção de código em execução."
                ));
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static void ScanProcessTree(List<Finding> findings, CancellationToken cancellationToken)
    {
        // Check FiveM parent process — should be FiveM_GTAProcess or similar, not cmd/powershell
        var fivemProcesses = Process.GetProcessesByName("fivem");
        if (fivemProcesses.Length == 0) return;

        foreach (var fivem in fivemProcesses)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var ppid = GetParentProcessId((uint)fivem.Id);
                if (ppid == 0) continue;

                var parent = Process.GetProcessById((int)ppid);
                var parentName = parent.ProcessName.ToLowerInvariant();

                if (SuspiciousParentProcesses.Contains(parentName))
                {
                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.SuspiciousExecution,
                        "Process Memory",
                        $"FiveM iniciado por processo suspeito: {parent.ProcessName}",
                        $"FiveM (PID {fivem.Id}) foi iniciado por {parent.ProcessName} (PID {ppid}). " +
                        "Processo pai incomum — possível launcher de cheat.",
                        $"Parent: {parent.ProcessName} | PID: {ppid}"
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }

    private static uint GetParentProcessId(uint pid)
    {
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero) return 0;

        try
        {
            var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32First(snapshot, ref entry)) return 0;

            do
            {
                if (entry.th32ProcessID == pid)
                    return entry.th32ParentProcessID;
            } while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }
        return 0;
    }

    private static string ProtectionName(uint protect) => protect switch
    {
        PAGE_EXECUTE_READWRITE => "EXECUTE_READWRITE",
        PAGE_EXECUTE_READ      => "EXECUTE_READ",
        PAGE_EXECUTE           => "EXECUTE",
        _                      => $"0x{protect:X}"
    };

    // Win32 constants
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint TH32CS_SNAPPROCESS = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [DllImport("kernel32.dll")] private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
}
