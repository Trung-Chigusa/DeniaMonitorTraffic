using DdosTriggerAnalyzer.Helpers;
using DdosTriggerAnalyzer.Models;

namespace DdosTriggerAnalyzer.Services;

public sealed class DdosDetectionService
{
    public AnalysisSummary Analyze(IReadOnlyList<PacketRecord> packets, string sourceFile, DetectionThresholds? thresholds = null)
    {
        thresholds ??= new DetectionThresholds();

        if (packets.Count == 0)
        {
            return new AnalysisSummary
            {
                SourceFile = sourceFile,
                AnalyzedAt = DateTime.Now
            };
        }

        var sourceResults = packets
            .Where(p => p.SourceIp != "-")
            .GroupBy(p => p.SourceIp)
            .AsParallel()
            .WithDegreeOfParallelism(Math.Max(1, Environment.ProcessorCount - 1))
            .Select(group => AnalyzeSource(group.Key, group.OrderBy(p => p.Time).ToList(), thresholds))
            .AsSequential()
            .OrderByDescending(r => r.RiskScore)
            .ThenByDescending(r => r.TotalPacketCount)
            .ToList();

        var suspicious = sourceResults
            .Where(r => r.RiskScore > thresholds.SuspiciousRiskThreshold || r.AttackType != AttackType.None)
            .ToList();

        var suspiciousBySource = suspicious.ToDictionary(r => r.SourceIp, StringComparer.OrdinalIgnoreCase);
        foreach (var packet in packets)
        {
            if (suspiciousBySource.TryGetValue(packet.SourceIp, out var result))
            {
                packet.Severity = result.Severity;
                packet.Reason = result.Reason;
            }
            else
            {
                packet.Severity = AlertSeverity.Normal;
                packet.Reason = "Baseline traffic";
            }
        }

        var victimIp = packets
            .Where(p => p.DestinationIp != "-")
            .GroupBy(p => p.DestinationIp)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault() ?? "-";

        var mainAttack = DetermineMainAttack(suspicious);
        var maxRisk = suspicious.FirstOrDefault()?.RiskScore ?? 0;

        return new AnalysisSummary
        {
            SourceFile = sourceFile,
            AnalyzedAt = DateTime.Now,
            TotalPackets = packets.Count,
            TotalSourceIps = packets.Select(p => p.SourceIp).Where(ip => ip != "-").Distinct().Count(),
            TotalAlerts = suspicious.Count,
            MostSuspiciousIp = suspicious.FirstOrDefault()?.SourceIp ?? "-",
            VictimIp = victimIp,
            AttackType = mainAttack,
            RiskScore = maxRisk,
            Severity = RiskScoreHelper.ToSeverity(maxRisk),
            SuspiciousIps = suspicious
        };
    }

    private static IpAnalysisResult AnalyzeSource(
        string sourceIp,
        IReadOnlyList<PacketRecord> packets,
        DetectionThresholds thresholds)
    {
        var best = BuildResult(sourceIp, packets, thresholds);
        var window = new Queue<PacketRecord>();
        var windowSize = TimeSpan.FromSeconds(thresholds.WindowSeconds);

        foreach (var packet in packets)
        {
            window.Enqueue(packet);
            while (window.Count > 0 && packet.Time - window.Peek().Time > windowSize)
            {
                window.Dequeue();
            }

            var candidate = BuildResult(sourceIp, window.ToList(), thresholds);
            if (candidate.RiskScore > best.RiskScore ||
                candidate.RiskScore == best.RiskScore && candidate.TotalPacketCount > best.TotalPacketCount)
            {
                best = candidate;
            }
        }

        return best;
    }

    private static IpAnalysisResult BuildResult(
        string sourceIp,
        IReadOnlyList<PacketRecord> packets,
        DetectionThresholds thresholds)
    {
        if (packets.Count == 0)
        {
            return new IpAnalysisResult { SourceIp = sourceIp };
        }

        var tcpCount = packets.Count(p => p.Protocol == "TCP");
        var synCount = packets.Count(p => p.IsTcpSyn);
        var ackCount = packets.Count(p => p.IsTcpAck);
        var udpCount = packets.Count(p => p.Protocol == "UDP");
        var icmpEchoCount = packets.Count(p => p.IsIcmpEchoRequest);
        var duration = Math.Max(1.0, (packets[^1].Time - packets[0].Time).TotalSeconds);
        var pps = packets.Count / duration;
        var synRatio = tcpCount == 0 ? 0 : synCount / (double)tcpCount;
        var uniqueDestinationPorts = packets.Where(p => p.DestinationPort.HasValue).Select(p => p.DestinationPort!.Value).Distinct().Count();
        var uniqueDestinationIps = packets.Where(p => p.DestinationIp != "-").Select(p => p.DestinationIp).Distinct().Count();

        var topDestination = packets
            .GroupBy(p => p.DestinationIp)
            .OrderByDescending(g => g.Count())
            .Select(g => new { Ip = g.Key, Count = g.Count() })
            .FirstOrDefault();

        var uniqueSourcePorts = packets.Where(p => p.SourcePort.HasValue).Select(p => p.SourcePort!.Value).Distinct().Count();
        var sameVictim = topDestination is not null && topDestination.Count >= packets.Count * thresholds.SameVictimRatioThreshold;
        var tcpSynFlood = synCount > thresholds.TcpSynCountThreshold &&
                          synRatio > thresholds.TcpSynRatioThreshold &&
                          ackCount < synCount * thresholds.TcpAckRatioMax &&
                          uniqueSourcePorts > thresholds.TcpUniqueSourcePortsThreshold;
        var udpFlood = udpCount > thresholds.UdpCountThreshold && sameVictim && pps >= thresholds.UdpPacketsPerSecondThreshold;
        var icmpFlood = icmpEchoCount > thresholds.IcmpEchoRequestThreshold && sameVictim;
        var portScan = uniqueDestinationPorts >= thresholds.PortScanUniqueDestinationPortsThreshold ||
                       uniqueDestinationIps >= thresholds.DestinationIpFanOutThreshold && uniqueDestinationPorts >= 6;
        var requestBurst = packets.Count >= thresholds.RequestBurstThreshold && sameVictim;

        var score = RiskScoreHelper.Calculate(pps, synRatio, udpFlood, icmpFlood, sameVictim);
        if (tcpSynFlood)
        {
            score = Math.Max(score, 78);
        }
        if (portScan)
        {
            score = Math.Max(score, 72);
        }
        if (requestBurst)
        {
            score = Math.Max(score, 82);
        }

        var attackType = DetermineAttackType(tcpSynFlood, udpFlood, icmpFlood, portScan, requestBurst);
        var severity = RiskScoreHelper.ToSeverity(score);

        return new IpAnalysisResult
        {
            SourceIp = sourceIp,
            TotalPacketCount = packets.Count,
            PacketsPerSecond = Math.Round(pps, 2),
            TcpSynCount = synCount,
            TcpAckCount = ackCount,
            SynRatio = Math.Round(synRatio, 2),
            UdpCount = udpCount,
            IcmpEchoRequestCount = icmpEchoCount,
            UniqueDestinationPorts = uniqueDestinationPorts,
            UniqueSourcePorts = uniqueSourcePorts,
            UniqueDestinationIps = uniqueDestinationIps,
            TopDestinationIp = topDestination?.Ip ?? "-",
            TopDestinationPort = packets
                .Where(p => p.DestinationPort.HasValue)
                .GroupBy(p => p.DestinationPort!.Value)
                .OrderByDescending(g => g.Count())
                .Select(g => (int?)g.Key)
                .FirstOrDefault(),
            RiskScore = score,
            Severity = severity,
            AttackType = attackType,
            Reason = BuildReason(attackType, score)
        };
    }

    private static AttackType DetermineAttackType(bool tcpSynFlood, bool udpFlood, bool icmpFlood, bool portScan, bool requestBurst)
    {
        var count = new[] { tcpSynFlood, udpFlood, icmpFlood, portScan, requestBurst }.Count(Boolean => Boolean);
        if (count > 1)
        {
            return AttackType.MixedDdos;
        }

        if (tcpSynFlood) return AttackType.TcpSynFlood;
        if (udpFlood) return AttackType.UdpFlood;
        if (icmpFlood) return AttackType.IcmpFlood;
        if (portScan) return AttackType.PortScan;
        if (requestBurst) return AttackType.RequestBurst;
        return AttackType.None;
    }

    private static AttackType DetermineMainAttack(IReadOnlyList<IpAnalysisResult> suspicious)
    {
        var attackTypes = suspicious
            .Where(r => r.AttackType != AttackType.None)
            .GroupBy(r => r.AttackType)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .ToList();

        if (attackTypes.Count > 1)
        {
            return AttackType.MixedDdos;
        }

        return attackTypes.FirstOrDefault();
    }

    private static string BuildReason(AttackType attackType, int score) => attackType switch
    {
        AttackType.TcpSynFlood => "Possible TCP SYN Flood",
        AttackType.UdpFlood => "Possible UDP Flood",
        AttackType.IcmpFlood => "Possible ICMP Flood",
        AttackType.PortScan => "Possible port scan or reconnaissance",
        AttackType.RequestBurst => "High request burst against one host",
        AttackType.MixedDdos => "Possible Mixed DDoS",
        _ when score > 30 => "Elevated packet rate or concentrated victim IP",
        _ => "No DDoS trigger detected"
    };
}
