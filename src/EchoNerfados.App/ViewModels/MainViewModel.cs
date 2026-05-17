using CommunityToolkit.Mvvm.ComponentModel;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Models;

namespace EchoNerfados.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private ObservableObject _currentView = null!;

    public MainViewModel()
    {
        NavigateHome();
    }

    public void NavigateHome()
    {
        CurrentView = new HomeViewModel(NavigateToScan);
    }

    public void NavigateToScan(ScanConfig config)
    {
        CurrentView = new ScanViewModel(config, NavigateToResult, NavigateHome);
    }

    public void NavigateToResult(ScanResult result, string? htmlReportPath)
    {
        CurrentView = new ResultViewModel(result, htmlReportPath, NavigateHome);
    }
}
