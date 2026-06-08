using System.Globalization;
using System.IO;
using System.Text;
using DdosTriggerAnalyzer.Models;

namespace DdosTriggerAnalyzer.Services;

public sealed class ReportExportService
{
    public void ExportText(string filePath, AnalysisSummary summary)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Denia Report");
        builder.AppendLine("============");
        builder.AppendLine($"PCAP file: {summary.SourceFile}");
        builder.AppendLine($"Analyzed at: {summary.AnalyzedAt:yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine($"Total packets: {summary.TotalPackets}");
        builder.AppendLine($"Total source IPs: {summary.TotalSourceIps}");
        builder.AppendLine($"Total alerts: {summary.TotalAlerts}");
        builder.AppendLine($"Most suspicious IP: {summary.MostSuspiciousIp}");
        builder.AppendLine($"Victim IP: {summary.VictimIp}");
        builder.AppendLine($"Attack type: {summary.AttackType}");
        builder.AppendLine($"Risk score: {summary.RiskScore}/100 ({summary.Severity})");
        builder.AppendLine();
        builder.AppendLine("Evidence");
        builder.AppendLine("--------");

        foreach (var ip in summary.SuspiciousIps)
        {
            builder.AppendLine($"Source IP: {ip.SourceIp}");
            builder.AppendLine($"  Reason: {ip.Reason}");
            builder.AppendLine($"  Risk: {ip.RiskScore}/100 ({ip.Severity})");
            builder.AppendLine($"  PPS: {ip.PacketsPerSecond.ToString("0.00", CultureInfo.InvariantCulture)}");
            builder.AppendLine($"  SYN/ACK: {ip.TcpSynCount}/{ip.TcpAckCount}, SYN ratio: {ip.SynRatio:0.00}");
            builder.AppendLine($"  UDP: {ip.UdpCount}, ICMP echo requests: {ip.IcmpEchoRequestCount}");
            builder.AppendLine($"  Unique src ports: {ip.UniqueSourcePorts}, unique dst ports: {ip.UniqueDestinationPorts}");
            builder.AppendLine($"  Top destination: {ip.TopDestinationIp}:{ip.TopDestinationPort?.ToString() ?? "-"}");
        }

        builder.AppendLine();
        builder.AppendLine("Conclusion");
        builder.AppendLine(summary.RiskScore > 70
            ? "High confidence DDoS/flood indicators were found in the offline capture."
            : summary.RiskScore > 30
                ? "Some suspicious flood indicators were found. Review the listed IPs and packet dump."
                : "No strong DDoS trigger was detected with the configured thresholds.");

        File.WriteAllText(filePath, builder.ToString(), Encoding.UTF8);
    }

    public void ExportCsv(string filePath, AnalysisSummary summary)
    {
        var builder = new StringBuilder();
        builder.AppendLine("SourceIp,AttackType,RiskScore,Severity,PacketsPerSecond,TcpSyn,TcpAck,SynRatio,Udp,IcmpEcho,UniqueSourcePorts,UniqueDestinationPorts,TopDestinationIp,TopDestinationPort,Reason");

        foreach (var ip in summary.SuspiciousIps)
        {
            builder.AppendLine(string.Join(',',
                Escape(ip.SourceIp),
                ip.AttackType,
                ip.RiskScore,
                ip.Severity,
                ip.PacketsPerSecond.ToString("0.00", CultureInfo.InvariantCulture),
                ip.TcpSynCount,
                ip.TcpAckCount,
                ip.SynRatio.ToString("0.00", CultureInfo.InvariantCulture),
                ip.UdpCount,
                ip.IcmpEchoRequestCount,
                ip.UniqueSourcePorts,
                ip.UniqueDestinationPorts,
                Escape(ip.TopDestinationIp),
                ip.TopDestinationPort?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                Escape(ip.Reason)));
        }

        File.WriteAllText(filePath, builder.ToString(), Encoding.UTF8);
    }

    private static string Escape(string value)
    {
        if (!value.Contains(',') && !value.Contains('"') && !value.Contains('\n'))
        {
            return value;
        }

        return $"\"{value.Replace("\"", "\"\"")}\"";
    }
}
