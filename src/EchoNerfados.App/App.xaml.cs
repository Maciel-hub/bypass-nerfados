using System.Windows;
using EchoNerfados.App.ViewModels;

namespace EchoNerfados.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var mainVm = new MainViewModel();
        var window = new MainWindow { DataContext = mainVm };
        MainWindow = window;
        window.Show();
    }
}
