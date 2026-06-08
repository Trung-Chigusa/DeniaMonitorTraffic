namespace DdosTriggerAnalyzer.Models;

public sealed class HostResourceSnapshot
{
    public double CpuPercent { get; init; }
    public double RamPercent { get; init; }
    public double DiskPercent { get; init; }
    public string DiskName { get; init; } = "-";
    public string RamDisplay { get; init; } = "-";
}
