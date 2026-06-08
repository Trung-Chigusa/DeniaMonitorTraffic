namespace DdosTriggerAnalyzer.Models;

public sealed class SocAlert
{
    public DateTime Time { get; init; } = DateTime.Now;
    public AlertSeverity Severity { get; init; } = AlertSeverity.Normal;
    public string Title { get; init; } = "SOC signal";
    public string SourceIp { get; init; } = "-";
    public string Location { get; init; } = "Unknown";
    public string Detail { get; init; } = string.Empty;
    public int RiskScore { get; init; }
    public string TimeDisplay => Time.ToString("HH:mm:ss");
}
