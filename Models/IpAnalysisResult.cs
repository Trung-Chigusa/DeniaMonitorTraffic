namespace DdosTriggerAnalyzer.Models;

public sealed class IpAnalysisResult
{
    public string SourceIp { get; init; } = "-";
    public int TotalPacketCount { get; init; }
    public double PacketsPerSecond { get; init; }
    public int TcpSynCount { get; init; }
    public int TcpAckCount { get; init; }
    public double SynRatio { get; init; }
    public int UdpCount { get; init; }
    public int IcmpEchoRequestCount { get; init; }
    public int UniqueDestinationPorts { get; init; }
    public int UniqueSourcePorts { get; init; }
    public int UniqueDestinationIps { get; init; }
    public string TopDestinationIp { get; init; } = "-";
    public int? TopDestinationPort { get; init; }
    public int RiskScore { get; init; }
    public AlertSeverity Severity { get; init; } = AlertSeverity.Normal;
    public AttackType AttackType { get; init; } = AttackType.None;
    public string Reason { get; init; } = "No DDoS trigger detected";
}
