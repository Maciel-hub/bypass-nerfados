using System.Runtime.InteropServices;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class NetworkModule : BaseModule
{
    public override string Name => "Network Usage";
    public override string Description => "Conexões ativas e histórico de uso de dados por executável";

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        ScanActiveTcpConnections(findings, cancellationToken);
        ScanNetworkDataUsage(findings, cancellationToken);

        return Task.FromResult(findings);
    }

    private static void ScanActiveTcpConnections(List<Finding> findings, CancellationToken cancellationToken)
    {
        var connections = GetTcpConnections();
        var processConnections = connections.GroupBy(c => c.ProcessId).ToList();

        foreach (var group in processConnections)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(group.Key);
                var nameLower = proc.ProcessName.ToLowerInvariant();
                string exePath = "desconhecido";
                try { exePath = proc.MainModule?.FileName ?? nameLower; } catch { }

                bool isKnownCheat = CheatDatabase.KnownExecutables.ContainsKey(nameLower + ".exe");
                bool isSuspicious = CheatDatabase.HasSuspiciousKeyword(nameLower) ||
                                    CheatDatabase.IsSuspiciousPath(exePath);

                if (isKnownCheat || isSuspicious)
                {
                    var externalConns = group
                        .Where(c => !IsLocalAddress(c.RemoteAddress))
                        .ToList();

                    if (externalConns.Count > 0)
                    {
                        var remotes = string.Join(", ",
                            externalConns.Take(3).Select(c => $"{c.RemoteAddress}:{c.RemotePort}"));

                        findings.Add(new Finding(
                            isKnownCheat ? RiskLevel.Critical : RiskLevel.High,
                            isKnownCheat ? FindingCategory.Cheat : FindingCategory.NetworkActivity,
                            "Network",
                            isKnownCheat
                                ? $"CHEAT COM CONEXÃO ATIVA: {proc.ProcessName}"
                                : $"Conexão suspeita: {proc.ProcessName} (PID {proc.Id})",
                            $"Executável suspeito com conexões externas ativas.\nCaminho: {exePath}",
                            $"Conexões: {remotes}"
                        ));
                    }
                }

                // Detect suspicious executables connecting to non-standard ports
                foreach (var conn in group.Where(c => !IsLocalAddress(c.RemoteAddress)))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (conn.RemotePort is >= 4444 and <= 9999 &&
                        !IsKnownSafeProcess(nameLower))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Medium,
                            FindingCategory.NetworkActivity,
                            "Network",
                            $"Conexão em porta suspeita: {proc.ProcessName}:{conn.RemotePort}",
                            $"Processo conectando em porta não padrão.\nRemoto: {conn.RemoteAddress}:{conn.RemotePort}",
                            $"PID: {proc.Id} | Caminho: {exePath}"
                        ));
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }

    private static void ScanNetworkDataUsage(List<Finding> findings, CancellationToken cancellationToken)
    {
        // Supplement with netstat output for running connections
        try
        {
            var netstatOutput = RunCmd("cmd.exe", "/c netstat -bno 2>nul", 15000, cancellationToken);
            if (string.IsNullOrEmpty(netstatOutput)) return;

            var lines = netstatOutput.Split('\n');
            string? currentExe = null;

            foreach (var line in lines)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var trimmed = line.Trim();
                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    currentExe = trimmed.Trim('[', ']').ToLowerInvariant();
                    continue;
                }

                if (currentExe == null) continue;

                var exeName = Path.GetFileName(currentExe);
                if (CheatDatabase.KnownExecutables.TryGetValue(exeName, out var cheat) &&
                    trimmed.Contains("ESTABLISHED"))
                {
                    findings.Add(new Finding(
                        RiskLevel.Critical,
                        FindingCategory.Cheat,
                        "Network",
                        $"CHEAT COM TRÁFEGO ATIVO: {cheat.Name} ({exeName})",
                        $"Cheat detectado com conexão de rede estabelecida.\n{cheat.Description}",
                        $"Linha netstat: {trimmed}"
                    ));
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private static List<TcpConnection> GetTcpConnections()
    {
        var result = new List<TcpConnection>();
        var bufferSize = 0;

        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        var buffer = Marshal.AllocHGlobal(bufferSize);

        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0)
                return result;

            var numEntries = Marshal.ReadInt32(buffer);
            var entryPtr = IntPtr.Add(buffer, 4);
            var entrySize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var entry = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(entryPtr);
                result.Add(new TcpConnection(
                    entry.owningPid,
                    FormatIpAddress(entry.remoteAddr),
                    (ushort)((entry.remotePort >> 8) | (entry.remotePort << 8) & 0xFFFF)
                ));
                entryPtr = IntPtr.Add(entryPtr, entrySize);
            }
        }
        catch { }
        finally { Marshal.FreeHGlobal(buffer); }

        return result;
    }

    private static string FormatIpAddress(uint addr)
    {
        return $"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}";
    }

    private static bool IsLocalAddress(string ip) =>
        ip.StartsWith("127.") || ip.StartsWith("0.0.") || ip == "::1" || ip.StartsWith("192.168.") ||
        ip.StartsWith("10.") || ip.StartsWith("172.16.");

    private static bool IsKnownSafeProcess(string name)
    {
        var safe = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "firefox", "msedge", "opera", "brave", "discord",
            "steam", "epicgameslauncher", "origin", "svchost", "system"
        };
        return safe.Contains(name);
    }

    private record TcpConnection(int ProcessId, string RemoteAddress, ushort RemotePort);

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public int owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, int tableClass, int reserved = 0);
}
