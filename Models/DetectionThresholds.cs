using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace DdosTriggerAnalyzer.Models;

public sealed class DetectionThresholds : INotifyPropertyChanged
{
    private int _windowSeconds = 10;
    private int _tcpSynCountThreshold = 200;
    private double _tcpSynRatioThreshold = 0.7;
    private double _tcpAckRatioMax = 0.35;
    private int _tcpUniqueSourcePortsThreshold = 50;
    private int _udpCountThreshold = 300;
    private double _udpPacketsPerSecondThreshold = 30;
    private int _icmpEchoRequestThreshold = 100;
    private double _sameVictimRatioThreshold = 0.65;
    private int _suspiciousRiskThreshold = 30;
    private int _portScanUniqueDestinationPortsThreshold = 24;
    private int _destinationIpFanOutThreshold = 12;
    private int _requestBurstThreshold = 600;

    public event PropertyChangedEventHandler? PropertyChanged;

    public int WindowSeconds
    {
        get => _windowSeconds;
        set => SetField(ref _windowSeconds, Math.Clamp(value, 1, 120));
    }

    public int TcpSynCountThreshold
    {
        get => _tcpSynCountThreshold;
        set => SetField(ref _tcpSynCountThreshold, Math.Max(1, value));
    }

    public double TcpSynRatioThreshold
    {
        get => _tcpSynRatioThreshold;
        set => SetField(ref _tcpSynRatioThreshold, Math.Clamp(value, 0, 1));
    }

    public double TcpAckRatioMax
    {
        get => _tcpAckRatioMax;
        set => SetField(ref _tcpAckRatioMax, Math.Clamp(value, 0, 1));
    }

    public int TcpUniqueSourcePortsThreshold
    {
        get => _tcpUniqueSourcePortsThreshold;
        set => SetField(ref _tcpUniqueSourcePortsThreshold, Math.Max(1, value));
    }

    public int UdpCountThreshold
    {
        get => _udpCountThreshold;
        set => SetField(ref _udpCountThreshold, Math.Max(1, value));
    }

    public double UdpPacketsPerSecondThreshold
    {
        get => _udpPacketsPerSecondThreshold;
        set => SetField(ref _udpPacketsPerSecondThreshold, Math.Max(1, value));
    }

    public int IcmpEchoRequestThreshold
    {
        get => _icmpEchoRequestThreshold;
        set => SetField(ref _icmpEchoRequestThreshold, Math.Max(1, value));
    }

    public double SameVictimRatioThreshold
    {
        get => _sameVictimRatioThreshold;
        set => SetField(ref _sameVictimRatioThreshold, Math.Clamp(value, 0, 1));
    }

    public int SuspiciousRiskThreshold
    {
        get => _suspiciousRiskThreshold;
        set => SetField(ref _suspiciousRiskThreshold, Math.Clamp(value, 0, 100));
    }

    public int PortScanUniqueDestinationPortsThreshold
    {
        get => _portScanUniqueDestinationPortsThreshold;
        set => SetField(ref _portScanUniqueDestinationPortsThreshold, Math.Max(3, value));
    }

    public int DestinationIpFanOutThreshold
    {
        get => _destinationIpFanOutThreshold;
        set => SetField(ref _destinationIpFanOutThreshold, Math.Max(2, value));
    }

    public int RequestBurstThreshold
    {
        get => _requestBurstThreshold;
        set => SetField(ref _requestBurstThreshold, Math.Max(10, value));
    }

    public void Reset()
    {
        WindowSeconds = 10;
        TcpSynCountThreshold = 200;
        TcpSynRatioThreshold = 0.7;
        TcpAckRatioMax = 0.35;
        TcpUniqueSourcePortsThreshold = 50;
        UdpCountThreshold = 300;
        UdpPacketsPerSecondThreshold = 30;
        IcmpEchoRequestThreshold = 100;
        SameVictimRatioThreshold = 0.65;
        SuspiciousRiskThreshold = 30;
        PortScanUniqueDestinationPortsThreshold = 24;
        DestinationIpFanOutThreshold = 12;
        RequestBurstThreshold = 600;
    }

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
