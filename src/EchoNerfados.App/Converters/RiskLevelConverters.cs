using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using BypassNerfados.Scanner.Models;

namespace EchoNerfados.App.Converters;

[ValueConversion(typeof(RiskLevel), typeof(Brush))]
public sealed class RiskLevelToBrushConverter : IValueConverter
{
    public static readonly RiskLevelToBrushConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var color = (RiskLevel)value switch
        {
            RiskLevel.Critical => "#FFFF4040",
            RiskLevel.High     => "#FFFF8C00",
            RiskLevel.Medium   => "#FFFFD700",
            RiskLevel.Low      => "#FF4CAF50",
            _                  => "#FF808080"
        };
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
    }

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
