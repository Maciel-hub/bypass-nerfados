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

    private void ScanActiveTcpConnections(List<Finding> findings, CancellationToken cancellationToken)
    {
        var connections = GetTcpConnections();
        var processConnections = connections.GroupBy(c => c.ProcessId).ToList();

        var failCount = 0;

        foreach (var group in processConnections)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(group.Key);
                var nameLower = proc.ProcessName.ToLowerInvariant();
                string exePath = "desconhecido";
                try { exePath = proc.MainModule?.FileName ?? nameLower; } catch { }

                string? publisher = null;
                try { publisher = System.Diagnostics.FileVersionInfo.GetVersionInfo(exePath).CompanyName; } catch { }

                // 3-tier classification for generic names (spotify.exe, launcher.exe, dxsetup.exe):
                // Suppressed = legit path or legit publisher → skip.
                // Suspect    = unknown path, no legit signals → Medium with hint.
                // Credible   = known cheat path → Critical.
                // Non-generic names that are in KnownExecutables are always Credible.
                CheatInfo? credibleCheat = null;
                bool isGenericSuspect = false;

                if (CheatDatabase.KnownExecutables.TryGetValue(nameLower + ".exe", out var anyEntry))
                {
                    if (anyEntry.IsGenericName)
                    {
                        var (tier, info) = CheatDatabase.ClassifyGenericProcess(nameLower + ".exe", exePath, publisher);
                        if (tier == CheatDatabase.GenericTier.Suppressed) continue;
                        if (tier == CheatDatabase.GenericTier.Credible) credibleCheat = info;
                        else isGenericSuspect = true;
                    }
                    else
                    {
                        credibleCheat = anyEntry;
                    }
                }

                bool isKnownCheat = credibleCheat != null;
                if (!isKnownCheat && !isGenericSuspect && IsKnownSafeProcess(nameLower)) continue;

                bool isSuspicious = isGenericSuspect ||
                                    CheatDatabase.HasSuspiciousKeyword(nameLower) ||
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

                        if (isKnownCheat)
                        {
                            findings.Add(new Finding(
                                RiskLevel.Critical, FindingCategory.Cheat, Name,
                                $"CHEAT COM CONEXÃO ATIVA: {credibleCheat!.Name} ({proc.ProcessName})",
                                $"Executável suspeito com conexões externas ativas.\nCaminho: {exePath}",
                                $"Conexões: {remotes}",
                                ruleId: "NET_KNOWN_CHEAT_ACTIVE",
                                entity: exePath
                            ));
                        }
                        else if (isGenericSuspect)
                        {
                            findings.Add(new Finding(
                                RiskLevel.Medium, FindingCategory.SuspiciousExecution, Name,
                                $"Processo genérico com nome associado a loader e conexão ativa: {proc.ProcessName}",
                                $"Nome associado a cheats FiveM, path fora de localização legítima conhecida, com rede ativa.\nCaminho: {exePath}",
                                $"Conexões: {remotes} | Publisher: {publisher ?? "ausente"}",
                                confidence: Confidence.Low,
                                ruleId: "NET_SUSPICIOUS_GENERIC_PROCESS",
                                entity: exePath,
                                validationHint: "Verificar hash SHA256, assinatura digital e correlação com Prefetch/BAM/sessão FiveM"
                            ));
                        }
                        else
                        {
                            findings.Add(new Finding(
                                RiskLevel.High, FindingCategory.NetworkActivity, Name,
                                $"Conexão suspeita: {proc.ProcessName} (PID {proc.Id})",
                                $"Executável suspeito com conexões externas ativas.\nCaminho: {exePath}",
                                $"Conexões: {remotes}",
                                ruleId: "NET_SUSPICIOUS_USERPATH_PROCESS",
                                entity: exePath
                            ));
                        }
                    }
                }

                // Detect suspicious executables connecting to non-standard ports
                foreach (var conn in group.Where(c => !IsLocalAddress(c.RemoteAddress)))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    // Port 10001 is the RedENGINE C2/licensing port — flag at High for any process
                    if (conn.RemotePort == 10001 && !IsKnownSafeProcess(nameLower))
                    {
                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.NetworkActivity,
                            Name,
                            $"Conexão na porta 10001 (C2 RedENGINE): {proc.ProcessName}",
                            $"Porta 10001 é usada pelo servidor C2/licenciamento do RedENGINE.\nRemoto: {conn.RemoteAddress}:{conn.RemotePort}\nCaminho: {exePath}",
                            $"PID: {proc.Id}",
                            ruleId: "NET_COPROC_NEAR_FIVEM",
                            entity: exePath
                        ));
                    }
                    else if (conn.RemotePort is >= 4444 and <= 9999 && !IsKnownSafeProcess(nameLower))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Medium,
                            FindingCategory.NetworkActivity,
                            Name,
                            $"Conexão em porta suspeita: {proc.ProcessName}:{conn.RemotePort}",
                            $"Processo conectando em porta não padrão.\nRemoto: {conn.RemoteAddress}:{conn.RemotePort}",
                            $"PID: {proc.Id} | Caminho: {exePath}",
                            ruleId: "NET_NONSTANDARD_PORT",
                            entity: exePath
                        ));
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { failCount++; }
        }

        if (failCount > 0)
            LogPartialError($"{failCount} conexão(ões) sem proprietário identificável");
    }

    private void ScanNetworkDataUsage(List<Finding> findings, CancellationToken cancellationToken)
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
                    if (cheat.IsGenericName)
                    {
                        findings.Add(new Finding(
                            RiskLevel.Medium,
                            FindingCategory.SuspiciousExecution,
                            Name,
                            $"Processo com nome genérico com tráfego ativo: {exeName}",
                            $"Nome genérico associado a cheats FiveM com conexão ativa — confirmar por caminho e hash.\n{cheat.Description}",
                            $"Linha netstat: {trimmed}",
                            confidence: Confidence.Low,
                            validationHint: "Verificar caminho completo do processo e hash SHA256 antes de concluir"
                        ));
                    }
                    else
                    {
                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.Cheat,
                            Name,
                            $"CHEAT COM TRÁFEGO ATIVO: {cheat.Name} ({exeName})",
                            $"Cheat detectado com conexão de rede estabelecida.\n{cheat.Description}",
                            $"Linha netstat: {trimmed}"
                        ));
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Dados de uso de rede inacessíveis", ex); }
    }

    private List<TcpConnection> GetTcpConnections()
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
        catch (Exception ex) { LogPartialError("Conexões TCP inacessíveis via P/Invoke", ex); }
        finally { Marshal.FreeHGlobal(buffer); }

        return result;
    }

    private static string FormatIpAddress(uint addr)
    {
        return $"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}";
    }

    private static bool IsLocalAddress(string ip)
    {
        if (ip.StartsWith("127.") || ip.StartsWith("0.0.") || ip == "::1") return true;
        if (ip.StartsWith("192.168.") || ip.StartsWith("10.")) return true;
        // 172.16.0.0/12 covers 172.16.x.x – 172.31.x.x
        if (ip.StartsWith("172."))
        {
            var parts = ip.Split('.');
            if (parts.Length >= 2 && int.TryParse(parts[1], out var second))
                return second is >= 16 and <= 31;
        }
        return false;
    }

    private static bool IsKnownSafeProcess(string name) => _knownSafe.Contains(name);

    private static readonly HashSet<string> _knownSafe = new(StringComparer.OrdinalIgnoreCase)
    {
        // Browsers
        "chrome", "firefox", "msedge", "opera", "brave", "vivaldi",
        // Communication / media
        "discord", "spotify", "teams", "slack", "zoom", "skype",
        // Game platforms
        "steam", "epicgameslauncher", "origin", "gog galaxy", "battlenet",
        "rockstarlauncher", "upc", "ubisoft connect",
        // Runtimes / dev tools
        "python", "python3", "pythonw", "node", "java", "javaw", "ruby",
        "git", "gh",
        // VS Code and its helper processes (AppData\Local\Programs\Microsoft VS Code\)
        "code", "code-tunnel", "code - oss",
        // Windows system
        "svchost", "system", "lsass", "services", "wininit", "winlogon",
        "searchhost", "runtimebroker", "sihost", "ctfmon", "dwm",
        "taskhostw", "explorer", "onedrive", "microsoftedgeupdate",
        // Updaters / cloud storage
        "dropbox", "onedrive", "googledrivefs", "icloudservices",
    };

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
