using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using DdosTriggerAnalyzer.Models;

namespace DdosTriggerAnalyzer.Services;

public sealed class IpGeoLookupService
{
    private readonly ConcurrentDictionary<string, GeoLocationInfo> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly HttpClient _httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(3)
    };

    public async Task<GeoLocationInfo> LookupAsync(string ipAddress, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ipAddress) || ipAddress == "-")
        {
            return Unknown(ipAddress);
        }

        if (_cache.TryGetValue(ipAddress, out var cached))
        {
            return cached;
        }

        var resolved = IsPrivateOrLocal(ipAddress)
            ? Local(ipAddress)
            : await LookupPublicAsync(ipAddress, cancellationToken);

        _cache[ipAddress] = resolved;
        return resolved;
    }

    private async Task<GeoLocationInfo> LookupPublicAsync(string ipAddress, CancellationToken cancellationToken)
    {
        try
        {
            var url = $"http://ip-api.com/json/{Uri.EscapeDataString(ipAddress)}?fields=status,country,regionName,city,lat,lon,query";
            using var stream = await _httpClient.GetStreamAsync(url, cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            var root = document.RootElement;
            if (!root.TryGetProperty("status", out var status) || status.GetString() != "success")
            {
                return Unknown(ipAddress);
            }

            return new GeoLocationInfo
            {
                IpAddress = ipAddress,
                City = GetString(root, "city"),
                Region = GetString(root, "regionName"),
                Country = GetString(root, "country"),
                Latitude = GetDouble(root, "lat"),
                Longitude = GetDouble(root, "lon")
            };
        }
        catch
        {
            return Unknown(ipAddress);
        }
    }

    private static string GetString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) ? property.GetString() ?? "Unknown" : "Unknown";

    private static double GetDouble(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.TryGetDouble(out var value) ? value : 0;

    private static GeoLocationInfo Local(string ipAddress) => new()
    {
        IpAddress = ipAddress,
        City = "Local Network",
        Country = "Private LAN",
        Latitude = 10.8231,
        Longitude = 106.6297,
        IsLocal = true
    };

    private static GeoLocationInfo Unknown(string ipAddress) => new()
    {
        IpAddress = ipAddress,
        City = "Unknown",
        Country = "Unknown",
        Latitude = 20,
        Longitude = 0
    };

    private static bool IsPrivateOrLocal(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var ip))
        {
            return true;
        }

        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return bytes[0] == 10 ||
                   bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31 ||
                   bytes[0] == 192 && bytes[1] == 168 ||
                   bytes[0] == 169 && bytes[1] == 254;
        }

        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ipAddress.StartsWith("fc", StringComparison.OrdinalIgnoreCase) ||
               ipAddress.StartsWith("fd", StringComparison.OrdinalIgnoreCase);
    }
}
