using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BypassNerfados.Scanner.Core;

namespace EchoNerfados.App.ViewModels;

public sealed partial class HomeViewModel : ObservableObject
{
    private readonly Action<ScanConfig> _startScan;

    // ── License ───────────────────────────────────────────────────────────────

    public bool   LicenseValid    { get; }
    public string LicenseStatus   { get; }
    public string LicenseCustomer { get; }
    public string LicenseExpiry   { get; }
    public string MachineId       { get; }

    private readonly string[] _licenseFeatures;

    // ── Scan config fields ────────────────────────────────────────────────────

    [ObservableProperty] private string _investigatorName = "";
    [ObservableProperty] private string _suspectName      = "";
    [ObservableProperty] private string _caseId           = "";
    [ObservableProperty] private string _reportOutputPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartScanCommand))]
    private ScanProfileOption _selectedProfile = ScanProfileOption.Profiles[0];

    public static IReadOnlyList<ScanProfileOption> Profiles => ScanProfileOption.Profiles;

    // ── Constructor ───────────────────────────────────────────────────────────

    public HomeViewModel(Action<ScanConfig> startScan)
    {
        _startScan = startScan;

        var lic = BypassNerfados.Scanner.Core.LicenseValidator.Validate();
        LicenseValid    = lic.Success;
        LicenseFeatures = lic.Success ? lic.License!.Features : [];

        if (lic.Success)
        {
            LicenseCustomer = lic.License!.CustomerId;
            LicenseExpiry   = lic.License.ExpiresAt.LocalDateTime.ToString("dd/MM/yyyy");
            LicenseStatus   = $"Válida até {LicenseExpiry}";
            _licenseFeatures = lic.License.Features;
        }
        else
        {
            LicenseCustomer  = "—";
            LicenseExpiry    = "—";
            LicenseStatus    = lic.ErrorMessage;
            _licenseFeatures = [];
        }

        MachineId = LicenseValidator.ComputeMachineId();
    }

    // Internal property exposed only for nullable initializer purposes
    private string[] LicenseFeatures { get; }

    // ── Commands ──────────────────────────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanStartScan))]
    private void StartScan()
    {
        var rules  = BypassNerfados.Scanner.Core.RulesLoader.Load();
        var config = new ScanConfig
        {
            InvestigatorName = string.IsNullOrWhiteSpace(InvestigatorName) ? null : InvestigatorName.Trim(),
            SuspectName      = string.IsNullOrWhiteSpace(SuspectName)      ? null : SuspectName.Trim(),
            CaseId           = string.IsNullOrWhiteSpace(CaseId)           ? null : CaseId.Trim(),
            ReportOutputPath = ReportOutputPath,
            Profile          = SelectedProfile.Profile,
            Rules            = rules,
            LicenseFeatures  = new HashSet<string>(_licenseFeatures, StringComparer.OrdinalIgnoreCase),
        };

        if (!config.LicenseFeatures.Contains("memory"))
            config.DeepMemoryScan = false;
        if (!config.LicenseFeatures.Contains("deep") && config.Profile == ScanProfile.Deep)
            config.Profile = ScanProfile.Default;

        _startScan(config);
    }

    private bool CanStartScan() => LicenseValid;

    [RelayCommand]
    private void CopyMachineId()
    {
        try { Clipboard.SetText(MachineId); }
        catch { /* clipboard may be locked */ }
    }

    [RelayCommand]
    private void BrowseOutputFolder()
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog
        {
            Title            = "Selecione a pasta de saída dos relatórios",
            InitialDirectory = ReportOutputPath,
            Multiselect      = false,
        };
        if (dlg.ShowDialog() == true)
            ReportOutputPath = dlg.FolderName;
    }
}

public sealed record ScanProfileOption(string Label, string Description, ScanProfile Profile)
{
    public static readonly IReadOnlyList<ScanProfileOption> Profiles =
    [
        new("Default",  "Todos os módulos (~2-3 min)",              ScanProfile.Default),
        new("Fast",     "16 módulos essenciais (~30s)",             ScanProfile.Fast),
        new("Deep",     "Todos + USN + Memória",                    ScanProfile.Deep),
        new("FiveM",    "Foco FiveM — timeline por sessão",         ScanProfile.FiveM),
        new("Florence", "Todos + validação de fonte dupla",         ScanProfile.Florence),
    ];
}
