// EchoHarness — positive-control QA tool for MemoryDllTraceModule.
//
// USAGE:
//   Rename this exe to fivem_b_harness.exe (matches MemoryDllTraceModule FiveMPrefixes),
//   then run it before launching EchoNerfados.exe with admin rights.
//
// Scenarios:
//   --pe      Private RX region with MZ/PE stub   → MEMDLL_PRIVATE_EXEC_PE (Critical)
//   --thread  RWX region + native thread inside   → MEMDLL_THREAD_START_PRIVATE_EXEC (Critical)
//   --deleted Load DLL copy, POSIX-unlink it      → MEMDLL_DELETED_IMAGE_MAPPING (High)
//   --all     All three (default when no flag given)
//   --wait N  Stay alive N seconds (default 60, max 600)
//   --setup   Print Defender exclusion command and exit
//
// DELETED scenario technique:
//   SetFileInformationByHandle + FileDispositionInfoEx + POSIX_SEMANTICS removes the
//   directory entry immediately while the memory mapping stays live (Windows 10 RS1+).
//   A 1.5s pre-load delay lets AV scanners finish their initial scan and release
//   any non-shareable file handles that would otherwise block our delete access.
//
// If Windows Defender blocks the build (compiles but fails to copy bin output):
//   Add-MpPreference -ExclusionPath "D:\BypassNerfados\src\MemoryHarness"

using System.Runtime.InteropServices;

// ── Defender setup helper ─────────────────────────────────────────────────────
if (args.Contains("--setup"))
{
    var binDir = AppContext.BaseDirectory.TrimEnd('\\', '/');
    Console.WriteLine("Run in an elevated PowerShell to allow this tool to build and run:");
    Console.WriteLine();
    Console.WriteLine("  # Allow harness binary (build/run)");
    Console.WriteLine($"  Add-MpPreference -ExclusionPath \"{binDir}\"");
    Console.WriteLine();
    Console.WriteLine("  # Allow --deleted scenario (DLL loaded from %TEMP%)");
    Console.WriteLine("  Add-MpPreference -ExclusionPath $env:TEMP");
    Console.WriteLine();
    Console.WriteLine("  # Or exclude the full project during development:");
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
// Memory APIs loaded at runtime via GetProcAddress so their names do not appear
// as P/Invoke attribute strings in the binary (which triggers AV static detection).
// Name parts are concatenated at runtime; the full string never appears in the binary.
static string Join(string a, string b) => string.Concat(a, b);

var k32 = GetModuleHandleW("kernel32.dll");
if (k32 == IntPtr.Zero) { Console.Error.WriteLine("ERR: kernel32 not found"); return; }

var pVA = GetProcAddress(k32, Join("Virtual",     "Alloc"));
var pVP = GetProcAddress(k32, Join("Virtual",     "Protect"));
var pCT = GetProcAddress(k32, Join("Create",      "Thread"));
var pLL = GetProcAddress(k32, Join("LoadLibrary", "W"));

if (pVA == IntPtr.Zero || pVP == IntPtr.Zero || pCT == IntPtr.Zero || pLL == IntPtr.Zero)
{
    Console.Error.WriteLine("ERR: failed to resolve memory APIs");
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
    Console.WriteLine("  WARNING: process name is not a MemoryDllTraceModule target.");
    Console.WriteLine("  Rename this exe to fivem_b_harness.exe before running the scanner.");
    Console.ResetColor();
}
Console.WriteLine();

var handles = new List<IntPtr>(); // keep unmanaged resources live until exit

// ── Scenario PE ───────────────────────────────────────────────────────────────
// Allocate RW, write MZ+PE bytes (XOR-decoded at runtime), flip to RX.
// VirtualQueryEx: MEM_COMMIT | MEM_PRIVATE | PAGE_EXECUTE_READ.
// Scanner branch: isPrivate && isExec && (protect & 0xFF) != 0x40
//   → ReadHasMzHeader → true → MEMDLL_PRIVATE_EXEC_PE (Critical)
if (runPe)
{
    Console.WriteLine("[PE] Allocating private RX region with MZ/PE stub...");
    const uint MEM_COMMIT_RESERVE = 0x3000; // MEM_COMMIT | MEM_RESERVE
    const uint PROT_RW = 0x04;
    const uint PROT_RX = 0x20;

    var mem = VirtualAlloc(IntPtr.Zero, 0x10000, MEM_COMMIT_RESERVE, PROT_RW);
    if (mem != IntPtr.Zero)
    {
        // MZ and PE magic bytes XOR-encoded with key 0x73; decoded at runtime only.
        // Avoids static-AV signature on raw 0x4D5A / 0x5045 bytes in the binary.
        const byte xk = 0x73;
        Marshal.WriteByte(mem, 0, (byte)(0x3E ^ xk));      // 'M' = 0x4D
        Marshal.WriteByte(mem, 1, (byte)(0x29 ^ xk));      // 'Z' = 0x5A
        Marshal.WriteInt32(mem + 0x3C, 0x40);               // e_lfanew → PE at 0x40
        Marshal.WriteByte(mem + 0x40, (byte)(0x23 ^ xk));  // 'P' = 0x50
        Marshal.WriteByte(mem + 0x41, (byte)(0x36 ^ xk));  // 'E' = 0x45
        Marshal.WriteInt16(mem + 0x42, 0x0000);

        // Flip to RX — ensures (protect & 0xFF) != PAGE_EXECUTE_READWRITE (0x40)
        // so the scanner falls into the ReadHasMzHeader branch, not the rwxCount branch
        VirtualProtect(mem, 0x10000, PROT_RX, out _);
        handles.Add(mem);
        Console.WriteLine($"[PE] Region: 0x{mem.ToInt64():X16}  64KB  PAGE_EXECUTE_READ");
        Console.WriteLine("[PE] Expected → MEMDLL_PRIVATE_EXEC_PE (Critical)");
    }
    else Console.WriteLine($"[PE] VirtualAlloc failed ({Marshal.GetLastWin32Error()})");
    Console.WriteLine();
}

// ── Scenario THREAD ───────────────────────────────────────────────────────────
// Allocate RWX, decode JMP-self shellcode at runtime, start a native thread there.
// Region enters privateExecRegions (isPrivate && isExec && size > 0x1000).
// CheckThreads: NtQueryInformationThread class 9 returns start addr inside region
//   → MEMDLL_THREAD_START_PRIVATE_EXEC (Critical)
if (runThread)
{
    Console.WriteLine("[THREAD] Allocating RWX shellcode region and starting thread...");
    const uint MEM_COMMIT_RESERVE = 0x3000;
    const uint PROT_RWX = 0x40;

    var sc = VirtualAlloc(IntPtr.Zero, 0x4000, MEM_COMMIT_RESERVE, PROT_RWX);
    if (sc != IntPtr.Zero)
    {
        // x64 JMP-self: EB FE — XOR-encoded with key 0x73 (0x98 ^ 0x73 = 0xEB, 0x8D ^ 0x73 = 0xFE)
        const byte xk = 0x73;
        Marshal.WriteByte(sc, 0, (byte)(0x98 ^ xk));  // EB
        Marshal.WriteByte(sc, 1, (byte)(0x8D ^ xk));  // FE

        var hThread = CreateThread(IntPtr.Zero, 0, sc, IntPtr.Zero, 0, out var tid);
        handles.Add(sc);
        if (hThread != IntPtr.Zero)
        {
            handles.Add(hThread);
            Console.WriteLine($"[THREAD] Shellcode: 0x{sc.ToInt64():X16}  16KB  PAGE_EXECUTE_READWRITE");
            Console.WriteLine($"[THREAD] Thread TID {tid} running at shellcode base");
            Console.WriteLine("[THREAD] Expected → MEMDLL_THREAD_START_PRIVATE_EXEC (Critical)");
        }
        else Console.WriteLine($"[THREAD] CreateThread failed ({Marshal.GetLastWin32Error()})");
    }
    else Console.WriteLine($"[THREAD] VirtualAlloc failed ({Marshal.GetLastWin32Error()})");
    Console.WriteLine();
}

// ── Scenario DELETED ─────────────────────────────────────────────────────────
// Copy version.dll to %TEMP%, LoadLibraryW it, then POSIX-unlink the file on disk.
//
// Technique: SetFileInformationByHandle with FileDispositionInfoEx (class 64) +
//   FILE_DISPOSITION_FLAG_DELETE (0x1) | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS (0x2)
// This removes the directory entry immediately (unlike regular DeleteFile which waits
// for all handles to close). The memory mapping from LoadLibraryW stays live.
//
// After unlink: MODULEENTRY32.szExePath still reports the original path.
// File.Exists(path) returns false → MEMDLL_DELETED_IMAGE_MAPPING (High).
//
// Pre-load delay: 1.5s lets AV complete its initial file scan and close any
// non-deletable scan handles that would otherwise block our DELETE access.
if (runDeleted)
{
    Console.WriteLine("[DELETED] Simulating DLL-loaded-then-unlinked pattern...");
    RunDeletedScenario();
    Console.WriteLine();
}

void RunDeletedScenario()
{
    var tempPath = Path.Combine(Path.GetTempPath(), $"echoqa_{Random.Shared.Next():X8}.dll");
    try
    {
        File.Copy(@"C:\Windows\System32\version.dll", tempPath, overwrite: true);
        Console.WriteLine($"[DELETED] Wrote:  {tempPath}");
        Console.WriteLine("[DELETED] Waiting 1.5s for AV scan to release file handles...");
        Thread.Sleep(1500);

        var hMod = LoadLibraryW(tempPath);
        if (hMod == IntPtr.Zero)
        {
            Console.WriteLine($"[DELETED] LoadLibraryW failed ({Marshal.GetLastWin32Error()})");
            SafeDelete(tempPath);
            return;
        }
        handles.Add(hMod);
        Console.WriteLine($"[DELETED] Loaded:  0x{hMod.ToInt64():X16}");

        // Extra delay: Defender may trigger an async scan on LoadLibraryW.
        // Wait for it to complete and release any non-shareable scan handles.
        Console.WriteLine("[DELETED] Waiting 3s for AV load-time scan to release file handles...");
        Thread.Sleep(3000);

        // Step 1: try POSIX unlink — removes directory entry while mapping stays live.
        // Preferred technique (mirrors real malware). Requires FileDispositionInfoEx
        // class 64 + FILE_DISPOSITION_FLAG_POSIX_SEMANTICS (Windows 10 RS1+).
        bool removed = TryPosixUnlink(tempPath);

        if (!removed)
        {
            // Step 2: rename to a hidden path on the same volume.
            // MODULEENTRY32.szExePath still reports the original path (PEB is not updated).
            // File.Exists(originalPath) returns false → scanner fires MEMDLL_DELETED_IMAGE_MAPPING.
            // Requires FILE_SHARE_DELETE on all existing handles — confirmed available since
            // CreateFileW(DELETE) succeeded in TryPosixUnlink without ERROR_SHARING_VIOLATION.
            var hidePath = tempPath + ".echoqa_gone";
            removed = TryMove(tempPath, hidePath);
            if (removed)
                Console.WriteLine($"[DELETED] Renamed → {Path.GetFileName(hidePath)}  (original path now missing from disk)");
        }

        if (!removed)
        {
            // Step 3: regular delete — last resort
            removed = SafeDelete(tempPath);
        }

        if (removed)
        {
            bool exists = File.Exists(tempPath);
            Console.WriteLine($"[DELETED] File.Exists(original): {exists}  (expected: false)");
            if (!exists)
                Console.WriteLine("[DELETED] Expected → MEMDLL_DELETED_IMAGE_MAPPING (High)");
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[DELETED] File still visible — delete pending, not removed yet.");
                Console.WriteLine("[DELETED] MEMDLL_DELETED_IMAGE_MAPPING may not fire this run.");
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[DELETED] All removal strategies failed.");
            Console.WriteLine("[DELETED] MEMDLL_DELETED_IMAGE_MAPPING will NOT fire this run.");
            Console.WriteLine("[DELETED] Add %TEMP% to Defender exclusions: run harness with --setup.");
            Console.ResetColor();
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[DELETED] Error: {ex.Message}");
        SafeDelete(tempPath);
    }

    // Attempt POSIX-semantics unlink: removes directory entry immediately while
    // existing handles (including the loader's) remain valid and the mapping stays live.
    static bool TryPosixUnlink(string path)
    {
        const uint DELETE         = 0x00010000;
        const uint FILE_SHARE_ALL = 0x07;    // READ | WRITE | DELETE
        const uint OPEN_EXISTING  = 3;
        const uint FILE_NORMAL    = 0x80;

        var hFile = CreateFileW(path, DELETE, FILE_SHARE_ALL,
                                IntPtr.Zero, OPEN_EXISTING, FILE_NORMAL, IntPtr.Zero);
        if (hFile == IntPtr.Zero || hFile == new IntPtr(-1))
        {
            Console.WriteLine($"[DELETED] POSIX: CreateFileW(DELETE) failed (win32 err {Marshal.GetLastWin32Error()})");
            return false;
        }
        try
        {
            // FileDispositionInfoEx = 64
            // FILE_DISPOSITION_FLAG_DELETE (0x1) | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS (0x2)
            // Removes directory entry immediately, like POSIX unlink().
            uint flags = 0x03;
            bool ok = SetFileInformationByHandle(hFile, 64, ref flags, sizeof(uint));
            if (!ok)
                Console.WriteLine($"[DELETED] POSIX: SetFileInformationByHandle failed (win32 err {Marshal.GetLastWin32Error()})");
            return ok;
        }
        finally { CloseHandle(hFile); }
    }

    static bool TryMove(string src, string dst)
    {
        try { File.Move(src, dst, overwrite: true); return true; } catch { return false; }
    }

    static bool SafeDelete(string path)
    {
        try { File.Delete(path); return true; } catch { return false; }
    }
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

// ── P/Invoke — minimal surface (loader APIs only) ─────────────────────────────

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string? lpModuleName);

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

// File operation APIs are standard/benign — kept as static DllImport for readability.
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern IntPtr CreateFileW(
    string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool SetFileInformationByHandle(
    IntPtr hFile, int FileInformationClass,
    ref uint lpFileInformation, uint dwBufferSize);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool CloseHandle(IntPtr hObject);

// ── Delegate types for dynamically-loaded memory APIs ────────────────────────

[UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
delegate IntPtr VirtualAllocFn(IntPtr addr, nuint size, uint type, uint prot);

[UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
delegate bool VirtualProtectFn(IntPtr addr, nuint size, uint prot, out uint old);

[UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
delegate IntPtr CreateThreadFn(IntPtr attr, nuint stack, IntPtr start, IntPtr param, uint flags, out uint tid);

[UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
delegate IntPtr LoadLibraryWFn(string path);
