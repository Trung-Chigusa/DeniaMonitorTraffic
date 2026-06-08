using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using DdosTriggerAnalyzer.Models;

namespace DdosTriggerAnalyzer.Helpers;

public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var severity = value is AlertSeverity s ? s : AlertSeverity.Normal;
        return severity switch
        {
            AlertSeverity.Low => new SolidColorBrush(Color.FromRgb(238, 203, 85)),
            AlertSeverity.Medium => new SolidColorBrush(Color.FromRgb(255, 139, 45)),
            AlertSeverity.High => new SolidColorBrush(Color.FromRgb(255, 67, 87)),
            AlertSeverity.Critical => new SolidColorBrush(Color.FromRgb(178, 83, 255)),
            _ => new SolidColorBrush(Color.FromRgb(31, 220, 167))
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
