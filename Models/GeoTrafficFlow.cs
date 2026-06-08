namespace DdosTriggerAnalyzer.Models;

public sealed class GeoTrafficFlow
{
    private const double MapWidth = 680;
    private const double MapHeight = 260;

    public string SourceIp { get; init; } = "-";
    public string DestinationIp { get; init; } = "-";
    public string SourceLocation { get; init; } = "Unknown";
    public string DestinationLocation { get; init; } = "Unknown";
    public int PacketCount { get; init; }
    public string Protocol { get; init; } = "Mixed";
    public AlertSeverity Severity { get; init; } = AlertSeverity.Normal;
    public double SourceLatitude { get; init; }
    public double SourceLongitude { get; init; }
    public double DestinationLatitude { get; init; }
    public double DestinationLongitude { get; init; }

    public double SourceX => ProjectX(SourceLongitude);
    public double SourceY => ProjectY(SourceLatitude);
    public double DestinationX => ProjectX(DestinationLongitude);
    public double DestinationY => ProjectY(DestinationLatitude);
    public double StrokeThickness => Math.Clamp(1.4 + Math.Log10(Math.Max(1, PacketCount)), 2, 7);
    public string FlowLabel => $"{SourceLocation} -> {DestinationLocation}";
    public string PacketDisplay => $"{PacketCount:N0} packets / {Protocol}";

    public string ArcPath
    {
        get
        {
            var midX = (SourceX + DestinationX) / 2;
            var midY = Math.Min(SourceY, DestinationY) - Math.Clamp(Math.Abs(SourceX - DestinationX) * 0.22, 18, 70);
            return $"M {SourceX:0.##},{SourceY:0.##} Q {midX:0.##},{midY:0.##} {DestinationX:0.##},{DestinationY:0.##}";
        }
    }

    private static double ProjectX(double longitude) => (longitude + 180) / 360 * MapWidth;
    private static double ProjectY(double latitude) => (90 - latitude) / 180 * MapHeight;
}
