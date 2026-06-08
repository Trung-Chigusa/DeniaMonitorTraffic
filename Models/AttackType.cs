namespace DdosTriggerAnalyzer.Models;

public enum AttackType
{
    None,
    TcpSynFlood,
    UdpFlood,
    IcmpFlood,
    PortScan,
    RequestBurst,
    MixedDdos
}
