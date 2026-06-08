namespace DdosTriggerAnalyzer.Models;

public sealed class GeoLocationInfo
{
    public string IpAddress { get; init; } = "-";
    public string City { get; init; } = "Unknown";
    public string Region { get; init; } = string.Empty;
    public string Country { get; init; } = "Unknown";
    public double Latitude { get; init; }
    public double Longitude { get; init; }
    public bool IsLocal { get; init; }

    public string DisplayName => IsLocal
        ? "Local Network"
        : string.IsNullOrWhiteSpace(City) || City == "Unknown"
            ? Country
            : $"{City}, {Country}";
}
