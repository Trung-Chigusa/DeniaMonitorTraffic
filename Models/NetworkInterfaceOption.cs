namespace DdosTriggerAnalyzer.Models;

public sealed class NetworkInterfaceOption
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string DisplayName => string.IsNullOrWhiteSpace(Description)
        ? $"{Id}. {Name}"
        : $"{Id}. {Description}";
}
