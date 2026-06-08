using DdosTriggerAnalyzer.Models;

namespace DdosTriggerAnalyzer.Helpers;

public static class RiskScoreHelper
{
    public static int Calculate(
        double packetsPerSecond,
        double synRatio,
        bool udpFlood,
        bool icmpFlood,
        bool sameVictim)
    {
        var score = 0;

        if (packetsPerSecond >= 30)
        {
            score += 30;
        }
        else if (packetsPerSecond >= 15)
        {
            score += 18;
        }
        else if (packetsPerSecond >= 8)
        {
            score += 10;
        }

        if (synRatio > 0.7)
        {
            score += 25;
        }
        else if (synRatio > 0.45)
        {
            score += 12;
        }

        if (udpFlood)
        {
            score += 20;
        }

        if (icmpFlood)
        {
            score += 15;
        }

        if (sameVictim)
        {
            score += 10;
        }

        return Math.Clamp(score, 0, 100);
    }

    public static AlertSeverity ToSeverity(int score) => score switch
    {
        <= 30 => AlertSeverity.Normal,
        <= 50 => AlertSeverity.Low,
        <= 70 => AlertSeverity.Medium,
        <= 85 => AlertSeverity.High,
        _ => AlertSeverity.Critical
    };
}
