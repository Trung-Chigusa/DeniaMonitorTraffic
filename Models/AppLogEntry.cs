namespace DdosTriggerAnalyzer.Models;

public sealed class AppLogEntry
{
    public DateTime Time { get; init; } = DateTime.Now;
    public string Level { get; init; } = "INFO";
    public string Message { get; init; } = string.Empty;
    public string TimeDisplay => Time.ToString("HH:mm:ss");
}
