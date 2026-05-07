using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class SystemInfoModule : BaseModule
{
    public override string Name => "System Info";
    public override string Description => "Informações do sistema, data de instalação e proteção DMA";

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config)
    {
        var findings = new List<Finding>();

        GetSystemInfo(findings);
        CheckInstallDate(findings);
        CheckDmaProtection(findings);
        CheckUnknownPcieDevices(findings);
        CheckVirtualization(findings);

        return Task.FromResult(findings);
    }

    private static void GetSystemInfo(List<Finding> findings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key == null) return;

            var productName = key.GetValue("ProductName")?.ToString() ?? "Desconhecido";
            var buildNumber = key.GetValue("CurrentBuildNumber")?.ToString() ?? "?";
            var ubr = key.GetValue("UBR")?.ToString() ?? "0";

            findings.Add(new Finding(
                RiskLevel.Info,
                FindingCategory.SystemTampering,
                "System Info",
                $"Windows: {productName} Build {buildNumber}.{ubr}",
                $"Versão do sistema operacional identificada.",
                $"Build: {buildNumber} | UBR: {ubr}"
            ));
        }
        catch { }
    }

    private static void CheckInstallDate(List<Finding> findings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key == null) return;

            var installDateRaw = key.GetValue("InstallDate");
            if (installDateRaw == null) return;

            var installTimestamp = Convert.ToInt64(installDateRaw);
            var installDate = DateTimeOffset.FromUnixTimeSeconds(installTimestamp).LocalDateTime;

            findings.Add(new Finding(
                RiskLevel.Info,
                FindingCategory.SystemTampering,
                "System Info",
                $"Data de instalação do Windows: {installDate:dd/MM/yyyy}",
                $"Instalação realizada em {installDate:dd/MM/yyyy HH:mm:ss}. " +
                "Verificar se a data é posterior a algum ban para detectar formatação pós-ban.",
                $"Unix timestamp: {installTimestamp}"
            ));

            // Warn if Windows was installed recently (within 30 days)
            var daysSinceInstall = (DateTime.Now - installDate).TotalDays;
            if (daysSinceInstall < 30)
            {
                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.SystemTampering,
                    "System Info",
                    $"Windows instalado recentemente: {(int)daysSinceInstall} dias atrás",
                    $"Sistema instalado em {installDate:dd/MM/yyyy}. Verificar se há ban anterior à data de instalação.",
                    $"Instalação: {installDate:dd/MM/yyyy}"
                ));
            }
        }
        catch { }
    }

    private static void CheckDmaProtection(List<Finding> findings)
    {
        // Check Kernel DMA Protection status
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\FVE");
            var dmaPolicy = key?.GetValue("DisableExternalDMAUnderLock");

            bool dmaEnabled;
            using var secKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DmaSecurity");
            dmaEnabled = secKey != null;

            if (!dmaEnabled)
            {
                findings.Add(new Finding(
                    RiskLevel.Medium,
                    FindingCategory.DeviceAnomaly,
                    "System Info",
                    "Kernel DMA Protection: status indisponível",
                    "Não foi possível confirmar se a proteção DMA está ativa. " +
                    "Em sistemas sem IOMMU ativo, ferramentas externas (PCIe/Thunderbolt) podem ter acesso direto à memória.",
                    "Verifique UEFI → IOMMU/VT-d/AMD-Vi"
                ));
            }
        }
        catch { }

        // Check IOMMU/VT-d related events in System log
        try
        {
            var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                "System",
                System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[Provider[@Name='iommu'] or Provider[@Name='ACPI']]]");

            using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
            System.Diagnostics.Eventing.Reader.EventRecord? record;
            int count = 0;

            while ((record = reader.ReadEvent()) != null && count < 10)
            {
                using (record)
                {
                    count++;
                    string description;
                    try { description = record.FormatDescription() ?? ""; }
                    catch { description = "Evento IOMMU/ACPI"; }

                    if (description.ToLowerInvariant().Contains("dmar") ||
                        description.ToLowerInvariant().Contains("iommu"))
                    {
                        findings.Add(new Finding(
                            RiskLevel.Medium,
                            FindingCategory.DeviceAnomaly,
                            "System Info",
                            "Evento DMAR/IOMMU detectado no log do sistema",
                            $"Evento relacionado ao sistema DMA detectado. Verificar contexto.\n{description[..Math.Min(200, description.Length)]}",
                            $"Data: {record.TimeCreated:dd/MM/yyyy HH:mm:ss}",
                            record.TimeCreated
                        ));
                    }
                }
            }
        }
        catch { }
    }

    private static void CheckUnknownPcieDevices(List<Finding> findings)
    {
        // Use SetupAPI via WMI to look for unknown or recently added PCIe/Thunderbolt devices
        try
        {
            var output = RunCmd("cmd.exe",
                @"/c pnputil /enum-devices /class Display 2>nul & pnputil /enum-devices /class USB 2>nul",
                10000);

            if (string.IsNullOrEmpty(output)) return;

            var lines = output.Split('\n');
            bool inUnknown = false;

            foreach (var line in lines)
            {
                if (line.Contains("Unknown", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("Desconhecido", StringComparison.OrdinalIgnoreCase))
                {
                    inUnknown = true;
                }

                if (inUnknown && line.Contains("Instance ID", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new Finding(
                        RiskLevel.Medium,
                        FindingCategory.DeviceAnomaly,
                        "System Info",
                        "Dispositivo desconhecido detectado",
                        $"Dispositivo sem driver identificado. Possível hardware DMA (KMBOX, PCIe).\n{line.Trim()}"
                    ));
                    inUnknown = false;
                }
            }
        }
        catch { }
    }

    private static void CheckVirtualization(List<Finding> findings)
    {
        // Check if running in a VM (possible indicator of environment manipulation)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Disk\Enum");
            if (key == null) return;

            var disk0 = key.GetValue("0")?.ToString() ?? "";
            var lower = disk0.ToLowerInvariant();

            bool isVm = lower.Contains("vmware") || lower.Contains("vbox") ||
                        lower.Contains("virtual") || lower.Contains("qemu") ||
                        lower.Contains("hyper-v");

            if (isVm)
            {
                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.SystemTampering,
                    "System Info",
                    $"MÁQUINA VIRTUAL DETECTADA: {disk0}",
                    "O sistema está rodando em ambiente virtualizado. " +
                    "Screen-share em VM pode ser usado para ocultar atividade do host real.",
                    $"Disco: {disk0}"
                ));
            }
        }
        catch { }
    }
}
