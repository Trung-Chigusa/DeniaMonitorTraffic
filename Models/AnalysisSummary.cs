namespace DdosTriggerAnalyzer.Models;

public sealed class AnalysisSummary
{
    public string SourceFile { get; init; } = string.Empty;
    public DateTime AnalyzedAt { get; init; } = DateTime.Now;
    public int TotalPackets { get; init; }
    public int TotalSourceIps { get; init; }
    public int TotalAlerts { get; init; }
    public string MostSuspiciousIp { get; init; } = "-";
    public string VictimIp { get; init; } = "-";
    public AttackType AttackType { get; init; } = AttackType.None;
    public int RiskScore { get; init; }
    public AlertSeverity Severity { get; init; } = AlertSeverity.Normal;
    public IReadOnlyList<IpAnalysisResult> SuspiciousIps { get; init; } = Array.Empty<IpAnalysisResult>();
}
