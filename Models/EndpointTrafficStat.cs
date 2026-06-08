namespace DdosTriggerAnalyzer.Models;

public sealed class EndpointTrafficStat
{
    public string IpAddress { get; init; } = "-";
    public string Location { get; init; } = "Resolving...";
    public int PacketCount { get; init; }
    public double Share { get; init; }
}
