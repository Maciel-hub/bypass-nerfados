using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace BypassNerfados.Scanner.Modules;

public class SystemInfoModule : BaseModule
{
    public override string Name => "System Info";
    public override string Description => "Informações do sistema, proteção DMA, hardware FPGA e artefatos de ferramentas DMA";

    // Known FPGA vendor IDs used in commercial DMA cheat hardware
    // Format: VEN_XXXX (case-insensitive match against PCI registry keys)
    private static readonly (string VendorId, string VendorName, string Notes)[] FpgaVendors =
    [
        ("VEN_10EE", "Xilinx",  "Fabricante do FPGA usado no Squirrel DMA, Enigma X1, Kintex-7/Artix-7"),
        ("VEN_1172", "Altera",  "Fabricante FPGA Intel/Altera — presente em placas DMA de alto custo"),
        ("VEN_1204", "Lattice", "Lattice Semiconductor FPGA — usado em versões mais baratas de DMA boards"),
        ("VEN_0BD0", "PLDA",    "PLDA PCIe IP core — encontrado em alguns DMA boards customizados"),
    ];

    // Known specific DMA device combinations (VEN&DEV pairs)
    private static readonly (string Pattern, string Name)[] KnownDmaDevices =
    [
        ("VEN_10EE&DEV_0666", "Squirrel DMA (Xilinx Artix-7 padrão)"),
        ("VEN_10EE&DEV_9022", "Xilinx FPGA DMA — variante DMA cheat"),
        ("VEN_10EE&DEV_6024", "Xilinx Kintex-7 DMA"),
        ("VEN_10EE&DEV_6011", "Xilinx FPGA — board DMA genérico"),
    ];

    // DMA software tools that may leave artifacts on the primary machine
    private static readonly string[] DmaSoftwareNames =
    [
        "pcileech", "memproc", "memprocessfs", "leechcore", "fpga_driver",
        "pcileech.exe", "memprocessfs.exe", "leechcore.dll", "pcileech.sys", "leechcore.sys",
    ];

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        GetSystemInfo(findings);
        cancellationToken.ThrowIfCancellationRequested();
        CheckInstallDate(findings);
        cancellationToken.ThrowIfCancellationRequested();
        CheckDmaProtectionStatus(findings);
        cancellationToken.ThrowIfCancellationRequested();
        CheckFpgaDevicesInRegistry(findings, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        CheckSetupApiLog(findings, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        CheckDmaSoftwareArtifacts(findings, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        CheckUnknownPcieDevices(findings, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        CheckVirtualization(findings);
        cancellationToken.ThrowIfCancellationRequested();
        CheckSteamInstallations(findings);

        return Task.FromResult(findings);
    }

    private void GetSystemInfo(List<Finding> findings)
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
        catch (Exception ex) { LogPartialError("Informações do sistema inacessíveis via registry", ex); }
    }

    private void CheckInstallDate(List<Finding> findings)
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
        catch (Exception ex) { LogPartialError("Data de instalação do Windows inacessível", ex); }
    }

    private void CheckDmaProtectionStatus(List<Finding> findings)
    {
        // ── Kernel DMA Protection (IOMMU/VT-d/AMD-Vi) ─────────────────────────────
        try
        {
            // Primary indicator: DmaSecurity key presence
            using var dmaKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DmaSecurity");
            var dmaEnabled = dmaKey != null;

            if (!dmaEnabled)
            {
                findings.Add(new Finding(
                    RiskLevel.Medium,
                    FindingCategory.DeviceAnomaly,
                    "System Info",
                    "Kernel DMA Protection: desabilitada ou não suportada",
                    "Kernel DMA Protection (baseada em IOMMU/VT-d/AMD-Vi) não está ativa. " +
                    "Sem essa proteção, dispositivos PCIe externos (DMA boards) podem acessar " +
                    "a memória RAM diretamente antes do Windows carregar. " +
                    "Habilitar em: UEFI → VT-d (Intel) ou AMD-Vi, depois reiniciar.",
                    "Verificar: UEFI → VT-d / AMD-Vi / IOMMU"
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Proteção DMA inacessível via registry", ex); }

        // ── Virtualization Based Security (VBS) e HVCI ────────────────────────────
        // DMA cheats que precisam de drivers não-assinados requerem HVCI desligado.
        // HVCI ativo = Memory Integrity = carregamento de drivers kernel não-assinados bloqueado.
        try
        {
            using var vbsKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            var hvciEnabled = vbsKey?.GetValue("Enabled") is int hvciVal && hvciVal == 1;
            var hvciRunning = vbsKey?.GetValue("WasEnabledBy") != null;

            if (!hvciEnabled)
            {
                // HVCI desligado é comum em PCs gamer (impacto de desempenho) — classificado
                // como postura de risco, não evidência direta de cheat.
                findings.Add(new Finding(
                    RiskLevel.Low,
                    FindingCategory.DeviceAnomaly,
                    "System Info",
                    "HVCI (Memory Integrity) desabilitado — postura de risco",
                    "Hypervisor-Protected Code Integrity (HVCI) não está ativo. " +
                    "Isso é comum em PCs gamer por impacto de desempenho, mas permite o carregamento " +
                    "de drivers de kernel não-assinados (usado por DMA loaders e spoofers de HWID). " +
                    "Por si só não indica uso de cheat — relevante apenas em combinação com outros achados.",
                    "HVCI: OFF | Relevante apenas combinado com finding de hardware DMA ou driver suspeito"
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Status HVCI inacessível", ex); }

        // ── Thunderbolt DMA Protection ─────────────────────────────────────────────
        try
        {
            using var tbKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions");
            var tbDmaPolicy = tbKey?.GetValue("AllowDirectAccessToThunderboltPCIe");
            if (tbDmaPolicy is int tbVal && tbVal == 1)
            {
                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.DeviceAnomaly,
                    "System Info",
                    "DMA via Thunderbolt/USB4 permitido por política",
                    "A política do sistema permite acesso DMA direto via Thunderbolt/USB4. " +
                    "Dispositivos DMA conectados por Thunderbolt (alternativa ao PCIe) " +
                    "podem acessar a memória do sistema.",
                    "AllowDirectAccessToThunderboltPCIe = 1"
                ));
            }
        }
        catch { /* chave ausente é o estado normal */ }
    }

    private void CheckFpgaDevicesInRegistry(List<Finding> findings, CancellationToken cancellationToken)
    {
        // The Windows PCI device registry (HKLM\SYSTEM\CurrentControlSet\Enum\PCI\)
        // retains entries for all devices ever plugged in, even after removal.
        // This makes it one of the most reliable DMA indicators — even if the board
        // was unplugged before the investigation, its VEN/DEV entry remains.
        try
        {
            using var pciRoot = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Enum\PCI");
            if (pciRoot == null)
            {
                LogPartialError("Enumeração PCI inacessível — requer Administrador");
                return;
            }

            foreach (var devKey in pciRoot.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var upper = devKey.ToUpperInvariant();

                // Check for known specific DMA device signatures first
                foreach (var (pattern, name) in KnownDmaDevices)
                {
                    if (!upper.Contains(pattern.ToUpperInvariant())) continue;

                    using var devSubKey = pciRoot.OpenSubKey(devKey);
                    var instances = devSubKey?.GetSubKeyNames() ?? [];
                    foreach (var inst in instances)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        using var instKey = devSubKey!.OpenSubKey(inst);
                        var friendlyName = instKey?.GetValue("FriendlyName")?.ToString() ?? "";
                        var desc         = instKey?.GetValue("DeviceDesc")?.ToString() ?? "";

                        findings.Add(new Finding(
                            RiskLevel.Critical,
                            FindingCategory.DeviceAnomaly,
                            "System Info",
                            $"DMA CHEAT HARDWARE DETECTADO: {name}",
                            $"Dispositivo PCIe com assinatura conhecida de hardware DMA cheat encontrado no registro.\n" +
                            $"Chave PCI: {devKey}\\{inst}\n" +
                            $"Nome: {(string.IsNullOrEmpty(friendlyName) ? desc : friendlyName)}\n" +
                            "O registro PCI persiste mesmo após remover a placa, confirmando uso passado.",
                            $"PCI: {devKey} | Nome: {friendlyName}",
                            confidence: Confidence.Confirmed,
                            ruleId: $"DMA_FPGA_KNOWN_{pattern.Replace("&", "_").ToUpperInvariant()}",
                            entity: devKey
                        ));
                    }
                    break; // matched a specific device, don't also flag as generic FPGA
                }

                // Check for FPGA vendor (without matching a known device ID)
                foreach (var (vendorId, vendorName, notes) in FpgaVendors)
                {
                    if (!upper.StartsWith(vendorId.ToUpperInvariant())) continue;

                    // Already flagged above as a known DMA device
                    if (KnownDmaDevices.Any(d => upper.Contains(d.Pattern.ToUpperInvariant()))) break;

                    using var devSubKey = pciRoot.OpenSubKey(devKey);
                    var instances = devSubKey?.GetSubKeyNames() ?? [];
                    foreach (var inst in instances)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        using var instKey = devSubKey!.OpenSubKey(inst);
                        var friendlyName = instKey?.GetValue("FriendlyName")?.ToString() ?? "";
                        var desc         = instKey?.GetValue("DeviceDesc")?.ToString() ?? "";
                        var driver       = instKey?.GetValue("Driver")?.ToString() ?? "";

                        findings.Add(new Finding(
                            RiskLevel.High,
                            FindingCategory.DeviceAnomaly,
                            "System Info",
                            $"FPGA PCIe detectado: {vendorName} ({devKey})",
                            $"Dispositivo PCIe de fabricante de FPGA detectado no registro do sistema.\n" +
                            $"Vendor: {vendorName} — {notes}\n" +
                            $"Chave: {devKey}\\{inst}\n" +
                            $"Nome: {(string.IsNullOrEmpty(friendlyName) ? (string.IsNullOrEmpty(desc) ? "(sem nome)" : desc) : friendlyName)}\n" +
                            $"Driver: {(string.IsNullOrEmpty(driver) ? "(nenhum)" : driver)}\n" +
                            "FPGAs em PCs gamer geralmente indicam hardware DMA cheat. " +
                            "O registro persiste mesmo após remover o dispositivo.",
                            $"PCI: {devKey} | Vendor: {vendorName}",
                            confidence: Confidence.High,
                            ruleId: $"DMA_FPGA_VENDOR_{vendorId.ToUpperInvariant()}",
                            entity: devKey,
                            validationHint: "Verificar se é placa DMA removida: checar SetupAPI.dev.log para data de instalação"
                        ));
                    }
                    break;
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (System.Security.SecurityException)
        {
            LogPartialError("Enumeração PCI: acesso negado — requer Administrador");
        }
        catch (Exception ex) { LogPartialError("Enumeração PCI no registry falhou", ex); }
    }

    private void CheckSetupApiLog(List<Finding> findings, CancellationToken cancellationToken)
    {
        // SetupAPI.dev.log records every device installation, including FPGAs that were
        // plugged in and later removed. It's one of the few artifacts that survive device removal.
        var logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", "setupapi.dev.log");

        if (!File.Exists(logPath)) return;

        try
        {
            // Read last 8000 lines — file can be several MB
            var lines = File.ReadLines(logPath).TakeLast(8000).ToList();
            bool inFpgaSection = false;
            string sectionHeader = "";

            for (int i = 0; i < lines.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var line = lines[i];
                var lower = line.ToLowerInvariant();

                // Detect start of a device installation section
                if (line.StartsWith(">>>"))
                {
                    inFpgaSection = false;
                    sectionHeader = line.Trim();
                }

                // Check if this section involves an FPGA vendor
                foreach (var (vendorId, vendorName, _) in FpgaVendors)
                {
                    if (!lower.Contains(vendorId.ToLowerInvariant())) continue;
                    inFpgaSection = true;
                    break;
                }

                // Also check for known DMA device IDs in the log
                foreach (var (pattern, name) in KnownDmaDevices)
                {
                    if (!lower.Contains(pattern.ToLowerInvariant())) continue;
                    inFpgaSection = true;
                    break;
                }

                // Check for DMA software tool names
                foreach (var tool in DmaSoftwareNames)
                {
                    if (!lower.Contains(tool.ToLowerInvariant())) continue;
                    inFpgaSection = true;
                    break;
                }

                if (!inFpgaSection) continue;

                // Try to extract a timestamp from the section for context
                DateTime? ts = null;
                for (int j = Math.Max(0, i - 5); j <= i; j++)
                {
                    if (DateTime.TryParse(
                            lines[j].TrimStart('[').Split(']')[0],
                            out var parsed))
                    {
                        ts = parsed;
                        break;
                    }
                }

                findings.Add(new Finding(
                    RiskLevel.High,
                    FindingCategory.DeviceAnomaly,
                    "System Info",
                    "SetupAPI: instalação de dispositivo FPGA/DMA registrada",
                    $"O log SetupAPI registrou instalação de dispositivo com assinatura FPGA/DMA.\n" +
                    $"Seção: {sectionHeader}\n" +
                    $"Linha: {line.Trim()[..Math.Min(200, line.Trim().Length)]}\n" +
                    "Este log persiste mesmo após remover o dispositivo, confirmando que um hardware DMA " +
                    "foi conectado a este sistema.",
                    $"Arquivo: {logPath}{(ts.HasValue ? $" | Data estimada: {ts:dd/MM/yyyy}" : "")}",
                    ts,
                    confidence: Confidence.High,
                    ruleId: "DMA_SETUPAPI_FPGA",
                    entity: logPath,
                    validationHint: "Cruzar com data de ban e entradas PCI no registry para confirmar período de uso"
                ));

                inFpgaSection = false; // emit one finding per section
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("SetupAPI.dev.log inacessível", ex); }
    }

    private void CheckDmaSoftwareArtifacts(List<Finding> findings, CancellationToken cancellationToken)
    {
        // PCILeech / MemProcFS are the primary software stacks used to operate DMA boards.
        // They may leave artifacts on the primary machine if the user ran them locally,
        // or on the secondary (attack) machine — but driver residue can appear on the primary.

        // 1. Drivers in System32\drivers\
        var driversDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");

        var dmaDriverNames = new[]
        {
            "pcileech.sys", "leechcore.sys", "fpgadrv.sys", "dmadummy.sys",
            "pcieleech.sys" // common typo variant
        };

        foreach (var driverName in dmaDriverNames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = Path.Combine(driversDir, driverName);
            if (!File.Exists(path)) continue;

            var sha256 = GetFileHash(path);
            findings.Add(new Finding(
                RiskLevel.Critical,
                FindingCategory.DeviceAnomaly,
                "System Info",
                $"DRIVER DMA/PCILeech encontrado: {driverName}",
                $"Driver de kernel associado à plataforma PCILeech/MemProcFS DMA encontrado.\n" +
                $"Caminho: {path}\n" +
                "Este driver é usado para operar hardware DMA cheat diretamente do PC alvo " +
                "ou para forensics — em contexto de suspeita de cheat, é forte indicador.",
                $"SHA256: {sha256 ?? "N/A"}",
                confidence: Confidence.Confirmed,
                ruleId: $"DMA_DRIVER_{driverName.ToUpperInvariant().Replace('.', '_')}",
                entity: path
            ));
        }

        // 2. Software executables in common locations
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };

        var dmaExeNames = new[] { "pcileech.exe", "memprocessfs.exe", "MemProcFS.exe" };

        foreach (var dir in searchDirs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            foreach (var exeName in dmaExeNames)
            {
                var path = Path.Combine(dir, exeName);
                if (!File.Exists(path)) continue;

                var sha256 = GetFileHash(path);
                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.DeviceAnomaly,
                    "System Info",
                    $"SOFTWARE DMA detectado: {exeName}",
                    $"Executável PCILeech/MemProcFS encontrado neste sistema.\n" +
                    $"Caminho: {path}\n" +
                    "PCILeech e MemProcFS são as ferramentas padrão para operar hardware DMA cheat.",
                    $"SHA256: {sha256 ?? "N/A"}",
                    confidence: Confidence.Confirmed,
                    ruleId: $"DMA_SOFTWARE_{exeName.ToUpperInvariant().Replace('.', '_')}",
                    entity: path
                ));
            }
        }

        // 3. Registry service entries for PCILeech driver
        try
        {
            foreach (var svcName in new[] { "pcileech", "leechcore", "fpgadrv" })
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var svcKey = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svcName}");
                if (svcKey == null) continue;

                var imagePath = svcKey.GetValue("ImagePath")?.ToString() ?? "";
                findings.Add(new Finding(
                    RiskLevel.Critical,
                    FindingCategory.DeviceAnomaly,
                    "System Info",
                    $"SERVIÇO DMA registrado: {svcName}",
                    $"Chave de serviço de kernel associada ao PCILeech/MemProcFS encontrada no registro.\n" +
                    $"Serviço: {svcName}\nImagem: {imagePath}",
                    $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                    confidence: Confidence.Confirmed,
                    ruleId: $"DMA_SERVICE_{svcName.ToUpperInvariant()}",
                    entity: $@"HKLM\SERVICES\{svcName}"
                ));
            }
        }
        catch (Exception ex) { LogPartialError("Verificação de serviços DMA falhou", ex); }
    }

    private void CheckUnknownPcieDevices(List<Finding> findings, CancellationToken cancellationToken)
    {
        // Scan ALL PCI device classes (not just Display/USB) for unknown devices.
        // DMA boards without a proper driver show as "Unknown Device" in Device Manager.
        try
        {
            var output = RunCmd("pnputil",
                "/enum-devices /class Unknown",
                15000,
                cancellationToken);

            if (string.IsNullOrWhiteSpace(output)) return;

            var lines = output.Split('\n');
            string? currentInstanceId = null;

            foreach (var line in lines)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var trimmed = line.Trim();
                if (trimmed.StartsWith("Instance ID", StringComparison.OrdinalIgnoreCase))
                {
                    currentInstanceId = trimmed.Split(':', 2).Last().Trim();
                }
                else if (trimmed.StartsWith("Status", StringComparison.OrdinalIgnoreCase) &&
                         currentInstanceId != null)
                {
                    var isPci = currentInstanceId.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase);
                    if (!isPci) { currentInstanceId = null; continue; }

                    findings.Add(new Finding(
                        RiskLevel.Medium,
                        FindingCategory.DeviceAnomaly,
                        "System Info",
                        $"Dispositivo PCIe desconhecido (sem driver): {currentInstanceId}",
                        $"Dispositivo PCIe sem driver identificado no sistema.\n" +
                        $"ID: {currentInstanceId}\n" +
                        "Hardware DMA barato frequentemente aparece como dispositivo desconhecido " +
                        "quando conectado sem driver instalado.",
                        $"Instance: {currentInstanceId}",
                        confidence: Confidence.Low,
                        ruleId: $"DMA_UNKNOWN_PCI_{currentInstanceId.ToUpperInvariant().Replace('\\', '_').Replace('&', '_')[..Math.Min(60, currentInstanceId.Length)]}",
                        entity: currentInstanceId,
                        validationHint: "Cruzar com SetupAPI.dev.log e registro PCI para verificar se é hardware DMA"
                    ));
                    currentInstanceId = null;
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("Enumeração de dispositivos desconhecidos falhou", ex); }
    }

    // VM string fragments matched against BIOS and disk strings (strong indicators)
    private static readonly (string Keyword, string Label)[] VmGuestStrings =
    [
        ("vmware",      "VMware"),
        ("virtualbox",  "VirtualBox"),
        ("vbox",        "VirtualBox"),
        ("qemu",        "QEMU/KVM"),
        ("xen",         "Xen"),
        ("parallels",   "Parallels"),
        ("innotek",     "VirtualBox (innotek)"),
        ("bochs",       "Bochs"),
        // Hyper-V guest BIOS/disk strings — distinct from host capability
        ("microsoft corporation",  "Hyper-V guest (Microsoft Corp)"),
        ("virtual machine",        "Hyper-V guest (Virtual Machine)"),
        ("virtual disk",           "Hyper-V guest (Virtual Disk)"),
        ("msft virtual",           "Hyper-V guest (MSFT)"),
    ];

    private void CheckVirtualization(List<Finding> findings)
    {
        // Scoring approach — prevents false positives on physical hosts with Hyper-V installed.
        // Strong signals (BIOS/disk virtual, guest additions): each worth 2 points.
        // Weak signals (Hyper-V service keys, which exist on physical hosts with Hyper-V feature): 1 point.
        // HIGH finding only when score >= 2.
        // INFO finding when only weak signals present (Hyper-V host capability, not a guest).

        var strongSignals = new List<string>();
        var weakSignals   = new List<string>();

        // 1. Disk enum — strong indicator; VMware/VBox/QEMU disk strings only appear in actual guests
        try
        {
            using var diskKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Disk\Enum");
            var disk0 = diskKey?.GetValue("0")?.ToString() ?? "";
            var lower = disk0.ToLowerInvariant();
            foreach (var (kw, label) in VmGuestStrings)
            {
                if (lower.Contains(kw))
                {
                    strongSignals.Add($"Disco: {label} ({disk0})");
                    break;
                }
            }
        }
        catch (Exception ex) { LogPartialError("CheckVirtualization: leitura do disco falhou", ex); }

        // 2. BIOS manufacturer / product name — strong indicator
        try
        {
            using var biosKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            if (biosKey != null)
            {
                var mfr  = (biosKey.GetValue("SystemManufacturer") ?? biosKey.GetValue("BaseBoardManufacturer"))?.ToString() ?? "";
                var prod = (biosKey.GetValue("SystemProductName")  ?? biosKey.GetValue("BaseBoardProduct"))?.ToString()      ?? "";
                var combined = (mfr + " " + prod).ToLowerInvariant();
                foreach (var (kw, label) in VmGuestStrings)
                {
                    if (combined.Contains(kw))
                    {
                        strongSignals.Add($"BIOS: {label} ({mfr.Trim()} / {prod.Trim()})");
                        break;
                    }
                }
            }
        }
        catch { }

        // 3. Guest additions (VMware Tools / VirtualBox GAs) — strong indicator;
        //    these are installed inside the VM, not on the host.
        var guestAdditions = new[]
        {
            (@"SOFTWARE\VMware, Inc.\VMware Tools",              "VMware Tools (guest)"),
            (@"SOFTWARE\Oracle\VirtualBox Guest Additions",      "VirtualBox Guest Additions"),
            (@"SYSTEM\CurrentControlSet\Services\vmtoolsd",      "Serviço vmtoolsd (guest VMware)"),
            (@"SYSTEM\CurrentControlSet\Services\VBoxService",   "Serviço VBoxService (guest VirtualBox)"),
        };
        foreach (var (regPath, label) in guestAdditions)
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(regPath);
                if (k != null) strongSignals.Add(label);
            }
            catch { }
        }

        // 4. Hyper-V service keys — WEAK indicator.
        //    vmbus and vmicheartbeat exist on physical hosts that have the Hyper-V Windows Feature
        //    installed (even with services Stopped/Manual). Only count as evidence when combined
        //    with a strong signal or when the service is actually running (start type = 1/2/4).
        var hypervKeys = new[]
        {
            (@"SYSTEM\CurrentControlSet\Services\vmbus",         "Hyper-V vmbus"),
            (@"SYSTEM\CurrentControlSet\Services\vmicheartbeat", "Hyper-V vmicheartbeat"),
            (@"SYSTEM\CurrentControlSet\Services\vmicrdv",       "Hyper-V vmicrdv"),
            (@"SYSTEM\CurrentControlSet\Services\vid",           "Hyper-V vid"),
        };
        foreach (var (regPath, label) in hypervKeys)
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(regPath);
                if (k == null) continue;
                // Start type: 0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled
                var startType = k.GetValue("Start") as int?;
                if (startType is 0 or 1 or 2)
                    weakSignals.Add($"{label} (Start={startType} — automático)");
                // else: Manual/Disabled on host machine — ignore as standalone signal
            }
            catch { }
        }

        var score = strongSignals.Count * 2 + weakSignals.Count;

        if (score == 0) return;

        if (score >= 2)
        {
            var allSignals = strongSignals.Concat(weakSignals).ToList();
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.SystemTampering,
                "System Info",
                $"MÁQUINA VIRTUAL DETECTADA ({allSignals.Count} indicador(es))",
                "O sistema está rodando em ambiente virtualizado. " +
                "Screen-share em VM pode ser usado para ocultar atividade do host real. " +
                "DMA cheats também podem ser usados com VM para isolar o processo do cheat.\n" +
                "Indicadores:\n" + string.Join("\n", allSignals.Select(s => $"  • {s}")),
                string.Join(" | ", allSignals)
            ));
        }
        else
        {
            // Only weak signals (e.g. Hyper-V host capability with Start=Auto but no BIOS/disk/guest evidence)
            findings.Add(new Finding(
                RiskLevel.Info,
                FindingCategory.SystemTampering,
                "System Info",
                "Hyper-V: recurso de host detectado (não é VM guest)",
                "Chaves de serviço Hyper-V encontradas com inicialização automática, mas sem indicadores de guest " +
                "(BIOS/disco virtual, VMware Tools, VirtualBox GAs). " +
                "Provavelmente é o recurso Hyper-V do Windows instalado no host físico. " +
                "Sinal fraco isolado — não indica uso de cheat.",
                string.Join(" | ", weakSignals)
            ));
        }
    }

    private void CheckSteamInstallations(List<Finding> findings)
    {
        var steamPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // User-level Steam (most common)
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            var p = key?.GetValue("SteamPath")?.ToString();
            if (!string.IsNullOrEmpty(p)) steamPaths.Add(p);
        }
        catch { }

        // Machine-level Steam (both native and Wow6432Node for 64-bit Windows)
        foreach (var regPath in new[] { @"SOFTWARE\Valve\Steam", @"SOFTWARE\Wow6432Node\Valve\Steam" })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                var p = key?.GetValue("InstallPath")?.ToString();
                if (!string.IsNullOrEmpty(p)) steamPaths.Add(p);
            }
            catch { }
        }

        if (steamPaths.Count == 0) return;

        // Count library folders from libraryfolders.vdf inside each Steam installation
        var libraryCount = 0;
        foreach (var steamPath in steamPaths)
        {
            var vdf = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
            if (!File.Exists(vdf)) continue;
            try
            {
                var content = File.ReadAllText(vdf);
                // vdf format: "path" "<folder_path>" entries — count unique path values
                var matches = System.Text.RegularExpressions.Regex.Matches(
                    content, @"""path""\s+""([^""]+)""",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                libraryCount += matches.Count;
            }
            catch { }
        }

        var summary = steamPaths.Count == 1
            ? steamPaths.First()
            : string.Join("; ", steamPaths);

        findings.Add(new Finding(
            RiskLevel.Info,
            FindingCategory.SystemTampering,
            "System Info",
            $"Steam: {steamPaths.Count} instalação(ões){(libraryCount > 0 ? $", {libraryCount} biblioteca(s)" : "")}",
            $"Instalações Steam encontradas no registro.\nCaminhos: {summary}",
            summary
        ));
    }
}
