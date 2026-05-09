using System.ServiceProcess;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class ServiceCheckModule : BaseModule
{
    public override string Name => "Services";
    public override string Description => "Verificação de serviços críticos de monitoramento do Windows";

    private record ServiceSpec(string Name, string Label, bool CriticalIfStopped);

    private static readonly ServiceSpec[] MonitoringServices =
    [
        new("pcasvc",     "Program Compatibility Assistant (PCA)",     true),
        new("dps",        "Diagnostic Policy Service (DPS)",           true),
        new("diagtrack",  "Diagnostic Tracking Service (DiagTrack)",  false),
        new("sysmain",    "SuperFetch/SysMain",                        false),
        new("eventlog",   "Windows Event Log",                         true),
        new("dusmsvc",    "Data Usage (DUSM)",                         false),
        new("appinfo",    "Application Information Service (UAC)",     false),
        new("bam",        "Background Activity Moderator (BAM)",       true),
        new("wdnissvc",   "Windows Defender Network Inspection",       true),
        new("wscsvc",     "Windows Security Center",                   true),
        new("mpssvc",     "Windows Firewall",                          true),
    ];

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        var noStartTypeCount = 0;
        var inaccessibleCount = 0;

        foreach (var svc in MonitoringServices)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var sc = new ServiceController(svc.Name);
                var status = sc.Status;

                bool isStopped = status == ServiceControllerStatus.Stopped;
                bool isDisabled = false;
                try { isDisabled = sc.StartType == ServiceStartMode.Disabled; }
                catch { noStartTypeCount++; /* StartType unavailable on some services */ }

                bool shouldFlag = isStopped || isDisabled;
                if (shouldFlag)
                {
                    var stateLabel = isDisabled ? "DESABILITADO" : "parado";
                    var risk = svc.CriticalIfStopped ? RiskLevel.Critical : RiskLevel.High;
                    findings.Add(new Finding(
                        risk,
                        FindingCategory.ServiceTampering,
                        "Services",
                        $"Serviço {stateLabel}: {svc.Label}",
                        $"O serviço '{svc.Name}' está {status}" + (isDisabled ? " (Startup: Disabled)" : "") + ". " +
                        "Serviços de monitoramento desativados podem indicar tentativa de bypass.",
                        $"Serviço: {svc.Name} | Status: {status} | Startup: {(isDisabled ? "Disabled" : "Manual/Auto")}"
                    ));
                }
            }
            catch (InvalidOperationException)
            {
                // Service doesn't exist — BAM missing is noteworthy
                if (svc.Name == "bam" || svc.Name == "eventlog")
                {
                    findings.Add(new Finding(
                        RiskLevel.High,
                        FindingCategory.ServiceTampering,
                        "Services",
                        $"Serviço NÃO ENCONTRADO: {svc.Label}",
                        $"O serviço '{svc.Name}' não existe no sistema. Pode ter sido removido ou desabilitado."
                    ));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { inaccessibleCount++; }
        }

        if (noStartTypeCount > 0)
            LogPartialError($"{noStartTypeCount} serviço(s) sem StartType acessível");
        if (inaccessibleCount > 0)
            LogPartialError($"{inaccessibleCount} serviço(s) inacessíveis durante varredura");

        // Check for the UmRdpService (normal to be stopped - as noted in the guide)
        // Do NOT flag UmRdpService as suspicious

        // Check Windows Defender real-time protection
        CheckDefenderRealtime(findings);

        return Task.FromResult(findings);
    }

    private void CheckDefenderRealtime(List<Finding> findings)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
            if (key == null) return;

            var disabled = key.GetValue("DisableRealtimeMonitoring");
            if (disabled is int val && val == 1)
            {
                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.ServiceTampering,
                    "Services",
                    "PROTEÇÃO EM TEMPO REAL DO DEFENDER DESATIVADA",
                    "DisableRealtimeMonitoring = 1 no registro. " +
                    "Proteção em tempo real do Windows Defender está desabilitada.",
                    @"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Status de tempo real do Defender inacessível via registry", ex); }
    }
}
