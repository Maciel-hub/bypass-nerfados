using System.Collections.Specialized;
using System.Windows.Controls;
using EchoNerfados.App.ViewModels;

namespace EchoNerfados.App.Views;

public partial class ScanView : UserControl
{
    public ScanView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => WireLogScroll();
    }

    private void WireLogScroll()
    {
        if (DataContext is ScanViewModel vm)
            ((INotifyCollectionChanged)vm.LogLines).CollectionChanged += (_, _) =>
                LogScroller.ScrollToBottom();
    }
}
