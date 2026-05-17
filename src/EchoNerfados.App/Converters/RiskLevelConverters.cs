using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using BypassNerfados.Scanner.Models;

namespace EchoNerfados.App.Converters;

// Shared frozen-brush cache — avoids allocating a new SolidColorBrush per binding call.
internal static class RiskColors
{
    private static readonly Dictionary<RiskLevel, Brush> _brushes = new()
    {
        [RiskLevel.Critical] = Freeze(new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFFF4040"))),
        [RiskLevel.High]     = Freeze(new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFFF8C00"))),
        [RiskLevel.Medium]   = Freeze(new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFFFD700"))),
        [RiskLevel.Low]      = Freeze(new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF4CAF50"))),
    };

    private static readonly Brush _fallback =
        Freeze(new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF808080")));

    public static Brush Get(RiskLevel risk) =>
        _brushes.TryGetValue(risk, out var b) ? b : _fallback;

    private static Brush Freeze(Brush b) { b.Freeze(); return b; }
}

[ValueConversion(typeof(RiskLevel), typeof(Brush))]
public sealed class RiskLevelToBrushConverter : IValueConverter
{
    public static readonly RiskLevelToBrushConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        RiskColors.Get((RiskLevel)value);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

[ValueConversion(typeof(RiskLevel), typeof(string))]
public sealed class RiskLevelToLabelConverter : IValueConverter
{
    public static readonly RiskLevelToLabelConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        ((RiskLevel)value).ToString().ToUpperInvariant();

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

[ValueConversion(typeof(bool), typeof(string))]
public sealed class BoolToLicenseStatusConverter : IValueConverter
{
    public static readonly BoolToLicenseStatusConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        (bool)value ? "VÁLIDA" : "INVÁLIDA";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

[ValueConversion(typeof(bool), typeof(Brush))]
public sealed class BoolToLicenseColorConverter : IValueConverter
{
    public static readonly BoolToLicenseColorConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var hex = (bool)value ? "#FF4CAF50" : "#FFFF4040";
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
