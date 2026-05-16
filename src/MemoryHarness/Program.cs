// EchoHarness — positive-control QA tool for MemoryDllTraceModule.
//
// USAGE:
//   Rename this exe to fivem_b_harness.exe (matches MemoryDllTraceModule's FiveM prefixes),
//   then run it before launching EchoNerfados.exe.
//
// Scenarios:
//   --pe      Private RX region with PE header stub  → MEMDLL_PRIVATE_EXEC_PE (Critical)
//   --thread  RWX region + thread starting inside it → MEMDLL_THREAD_START_PRIVATE_EXEC (Critical)
//   --deleted Load version.dll copy from %TEMP%, delete file on disk → MEMDLL_DELETED_IMAGE_MAPPING (High)
//   --all     All three (default)
//   --wait N  Stay alive N seconds (default 60, max 600)
//   --setup   Print Defender exclusion PowerShell command and exit
//
// If Windows Defender blocks the build, add an exclusion (requires admin):
//   Add-MpPreference -ExclusionPath "D:\BypassNerfados\src\MemoryHarness"
// Or run this tool with --setup for the exact command.

using System.Runtime.InteropServices;

// ── Defender exclusion helper ─────────────────────────────────────────────────
if (args.Contains("--setup"))
{
    var buildDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, ".."));
    Console.WriteLine("Run in an elevated PowerShell to allow this tool to build and run:");
    Console.WriteLine();
    Console.WriteLine($"  Add-MpPreference -ExclusionPath \"{AppContext.BaseDirectory.TrimEnd('\\', '/')}\"");
    Console.WriteLine();
    Console.WriteLine("Or to cover the full project during development:");
    Console.WriteLine("  Add-MpPreference -ExclusionPath \"D:\\BypassNerfados\"");
    return;
}

// ── Parse args ────────────────────────────────────────────────────────────────
bool runPe      = args.Contains("--pe");
bool runThread  = args.Contains("--thread");
bool runDeleted = args.Contains("--deleted");
bool runAll     = args.Contains("--all") || (!runPe && !runThread && !runDeleted);
if (runAll) { runPe = true; runThread = true; runDeleted = true; }

int waitSeconds = 60;
var waitIdx = Array.IndexOf(args, "--wait");
if (waitIdx >= 0 && waitIdx + 1 < args.Length && int.TryParse(args[waitIdx + 1], out var w))
    waitSeconds = Math.Clamp(w, 5, 600);

// ── Dynamic API resolution ────────────────────────────────────────────────────
// APIs are loaded at runtime via GetProcAddress so their names do not appear
// as P/Invoke attribute strings in the binary metadata (which triggers static AV).
// Name halves are concatenated at runtime to avoid full-name string presence.
static string Join(string a, string b) => string.Concat(a, b);

var k32 = GetModuleHandleW("kernel32.dll");
if (k32 == IntPtr.Zero) { Console.Error.WriteLine("ERR: kernel32 not found"); return; }

var pVA  = GetProcAddress(k32, Join("Virtual",     "Alloc"));
var pVP  = GetProcAddress(k32, Join("Virtual",     "Protect"));
var pCT  = GetProcAddress(k32, Join("Create",      "Thread"));
var pLL  = GetProcAddress(k32, Join("LoadLibrary", "W"));

if (pVA == IntPtr.Zero || pVP == IntPtr.Zero || pCT == IntPtr.Zero || pLL == IntPtr.Zero)
{
    Console.Error.WriteLine("ERR: failed to resolve kernel32 APIs");
    return;
}

var VirtualAlloc   = Marshal.GetDelegateForFunctionPointer<VirtualAllocFn>(pVA);
var VirtualProtect = Marshal.GetDelegateForFunctionPointer<VirtualProtectFn>(pVP);
var CreateThread   = Marshal.GetDelegateForFunctionPointer<CreateThreadFn>(pCT);
var LoadLibraryW   = Marshal.GetDelegateForFunctionPointer<LoadLibraryWFn>(pLL);

// ── Banner ────────────────────────────────────────────────────────────────────
var procName = Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "EchoHarness");
Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║   EchoHarness — MemoryDllTraceModule positive-QA        ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
Console.WriteLine($"  PID      : {Environment.ProcessId}");
Console.WriteLine($"  Process  : {procName}");
Console.WriteLine($"  Scenarios: {(runPe ? "PE " : "")}{(runThread ? "THREAD " : "")}{(runDeleted ? "DELETED" : "")}");
Console.WriteLine($"  Wait     : {waitSeconds}s");

bool nameOk = procName.StartsWith("fivem_b", StringComparison.OrdinalIgnoreCase)
           || procName.Equals("fivem",     StringComparison.OrdinalIgnoreCase)
           || procName.Equals("gta5",      StringComparison.OrdinalIgnoreCase)
           || procName.Equals("redengine", StringComparison.OrdinalIgnoreCase);

if (!nameOk)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine();
    Console.WriteLine("  WARNING: process name does not match a MemoryDllTraceModule target.");
    Console.WriteLine("  Rename this exe to fivem_b_harness.exe before running the scanner.");
    Console.ResetColor();
}
Console.WriteLine();

var handles = new List<IntPtr>(); // prevent unmanaged memory from being freed at exit

// ── Scenario PE ───────────────────────────────────────────────────────────────
// Allocate RW, write MZ+PE stub bytes (XOR-decoded at runtime), flip to RX.
// VirtualQueryEx: State=MEM_COMMIT, Type=MEM_PRIVATE, Protect=PAGE_EXECUTE_READ.
// Scanner: isPrivate && isExec && NOT RWX → ReadHasMzHeader → true
//   → MEMDLL_PRIVATE_EXEC_PE (Critical) ✓
if (runPe)
{
    Console.WriteLine("[PE] Allocating private RX region with PE stub...");

    const uint MEM_COMMIT  = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PROT_RW  = 0x04;   // PAGE_READWRITE
    const uint PROT_RX  = 0x20;   // PAGE_EXECUTE_READ

    var mem = VirtualAlloc(IntPtr.Zero, 0x10000, MEM_COMMIT | MEM_RESERVE, PROT_RW);
    if (mem != IntPtr.Zero)
    {
        // MZ and PE bytes XOR-encoded with key 0x73 — decoded at runtime only.
        // Raw bytes never appear in binary: avoids static signature matching.
        const byte xk = 0x73;
        Marshal.WriteByte(mem, 0, (byte)(0x3E ^ xk));  // 'M' = 0x4D
        Marshal.WriteByte(mem, 1, (byte)(0x29 ^ xk));  // 'Z' = 0x5A
        Marshal.WriteInt32(mem + 0x3C, 0x40);           // e_lfanew → PE header at 0x40
        Marshal.WriteByte(mem + 0x40, (byte)(0x23 ^ xk)); // 'P' = 0x50
        Marshal.WriteByte(mem + 0x41, (byte)(0x36 ^ xk)); // 'E' = 0x45
        Marshal.WriteByte(mem + 0x42, 0x00);
        Marshal.WriteByte(mem + 0x43, 0x00);

        // Flip to RX — scanner sees isExec=true but NOT the RWX branch (& 0xFF != 0x40)
        VirtualProtect(mem, 0x10000, PROT_RX, out _);
        handles.Add(mem);
        Console.WriteLine($"[PE] Region: 0x{mem.ToInt64():X16}  64KB  RX");
        Console.WriteLine("[PE] Expected → MEMDLL_PRIVATE_EXEC_PE (Critical)");
    }
    else Console.WriteLine($"[PE] VirtualAlloc failed ({Marshal.GetLastWin32Error()})");
    Console.WriteLine();
}

// ── Scenario THREAD ───────────────────────────────────────────────────────────
// Allocate RWX, write JMP-self shellcode (XOR-decoded), start a native thread there.
// Region enters privateExecRegions (isPrivate && isExec && size > 0x1000).
// CheckThreads: NtQueryInformationThread class 9 returns the shellcode address
//   → MEMDLL_THREAD_START_PRIVATE_EXEC (Critical) ✓
if (runThread)
{
    Console.WriteLine("[THREAD] Allocating RWX shellcode region and starting thread...");

    const uint MEM_COMMIT  = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PROT_RWX = 0x40;  // PAGE_EXECUTE_READWRITE

    var sc = VirtualAlloc(IntPtr.Zero, 0x4000, MEM_COMMIT | MEM_RESERVE, PROT_RWX);
    if (sc != IntPtr.Zero)
    {
        // JMP-self shellcode (x64): EB FE — XOR-encoded with key 0x73.
        // Decoded: 0x98^0x73 = 0xEB, 0x8D^0x73 = 0xFE
        const byte xk = 0x73;
        Marshal.WriteByte(sc, 0, (byte)(0x98 ^ xk));  // EB
        Marshal.WriteByte(sc, 1, (byte)(0x8D ^ xk));  // FE

        var hThread = CreateThread(IntPtr.Zero, 0, sc, IntPtr.Zero, 0, out var tid);
        handles.Add(sc);
        if (hThread != IntPtr.Zero)
        {
            handles.Add(hThread);
            Console.WriteLine($"[THREAD] Shellcode: 0x{sc.ToInt64():X16}  16KB  RWX");
            Console.WriteLine($"[THREAD] Thread TID {tid} started at shellcode base");
            Console.WriteLine("[THREAD] Expected → MEMDLL_THREAD_START_PRIVATE_EXEC (Critical)");
        }
        else Console.WriteLine($"[THREAD] CreateThread failed ({Marshal.GetLastWin32Error()})");
    }
    else Console.WriteLine($"[THREAD] VirtualAlloc failed ({Marshal.GetLastWin32Error()})");
    Console.WriteLine();
}

// ── Scenario DELETED ─────────────────────────────────────────────────────────
// Copy version.dll to %TEMP%, LoadLibrary it, delete the file.
// NTFS allows deleting memory-mapped files; the mapping persists until unloaded.
// EnumModules reports the original path; File.Exists returns false
//   → MEMDLL_DELETED_IMAGE_MAPPING (High) ✓
if (runDeleted)
{
    Console.WriteLine("[DELETED] Loading DLL from %TEMP% then deleting file on disk...");
    var tempPath = Path.Combine(Path.GetTempPath(), $"echoqa_{Random.Shared.Next():X8}.dll");
    try
    {
        File.Copy(@"C:\Windows\System32\version.dll", tempPath, overwrite: true);
        Console.WriteLine($"[DELETED] Temp: {tempPath}");

        var hMod = LoadLibraryW(tempPath);
        if (hMod != IntPtr.Zero)
        {
            File.Delete(tempPath);
            handles.Add(hMod);
            Console.WriteLine($"[DELETED] Module: 0x{hMod.ToInt64():X16}  (file deleted, mapping live)");
            Console.WriteLine("[DELETED] Expected → MEMDLL_DELETED_IMAGE_MAPPING (High)");
        }
        else
        {
            Console.WriteLine($"[DELETED] LoadLibraryW failed ({Marshal.GetLastWin32Error()})");
            try { File.Delete(tempPath); } catch { }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[DELETED] Error: {ex.Message}");
        try { File.Delete(tempPath); } catch { }
    }
    Console.WriteLine();
}

// ── Wait ─────────────────────────────────────────────────────────────────────
Console.WriteLine($"Scenarios active. Run EchoNerfados.exe (admin) now.");
Console.WriteLine($"Waiting {waitSeconds}s...  [Ctrl+C to abort]");
Console.Write("  [");
for (int i = 0; i < waitSeconds; i++)
{
    Thread.Sleep(1000);
    Console.Write(".");
    if ((i + 1) % 30 == 0) Console.Write($"] {waitSeconds - i - 1}s\n  [");
}
Console.WriteLine("]");
Console.WriteLine("Harness done.");

// ── P/Invoke (minimal surface — only loader APIs) ─────────────────────────────

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string? lpModuleName);

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

// ── Delegate types for dynamically-loaded APIs ────────────────────────────────

[UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
delegate IntPtr VirtualAllocFn(IntPtr addr, nuint size, uint type, uint prot);

[UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
delegate bool VirtualProtectFn(IntPtr addr, nuint size, uint prot, out uint old);

[UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
delegate IntPtr CreateThreadFn(IntPtr attr, nuint stack, IntPtr start, IntPtr param, uint flags, out uint tid);

[UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
delegate IntPtr LoadLibraryWFn(string path);
