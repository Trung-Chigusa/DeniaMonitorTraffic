namespace DdosTriggerAnalyzer.Models;

public sealed class PacketRecord
{
    public DateTime Time { get; init; }
    public string TimeDisplay => Time.ToString("yyyy-MM-dd HH:mm:ss.fff");
    public string SourceIp { get; init; } = "-";
    public string DestinationIp { get; init; } = "-";
    public string Protocol { get; init; } = "Other";
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public string TcpFlags { get; init; } = string.Empty;
    public int Length { get; init; }
    public AlertSeverity Severity { get; set; } = AlertSeverity.Normal;
    public string Reason { get; set; } = "Baseline traffic";

    public bool IsTcpSyn { get; init; }
    public bool IsTcpAck { get; init; }
    public bool IsUdp => Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase);
    public bool IsIcmpEchoRequest { get; init; }
}
