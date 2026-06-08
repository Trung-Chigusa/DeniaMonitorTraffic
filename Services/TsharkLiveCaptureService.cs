using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using DdosTriggerAnalyzer.Models;

namespace DdosTriggerAnalyzer.Services;

public sealed class TsharkLiveCaptureService
{
    private static readonly Regex InterfaceRegex = new(@"^\s*(\d+)\.\s+(.+?)(?:\s+\((.+)\))?\s*$", RegexOptions.Compiled);
    private Process? _captureProcess;

    public async Task<IReadOnlyList<NetworkInterfaceOption>> GetInterfacesAsync(CancellationToken cancellationToken = default)
    {
        var lines = await RunTsharkAsync("-D", cancellationToken);
        return lines
            .Select(ParseInterface)
            .Where(option => option is not null)
            .Select(option => option!)
            .ToList();
    }

    public async Task StartCaptureAsync(
        NetworkInterfaceOption interfaceOption,
        Func<PacketRecord, Task> onPacket,
        Action<string>? onStatus,
        CancellationToken cancellationToken)
    {
        StopCapture();

        var arguments = string.Join(' ', new[]
        {
            "-n",
            "-l",
            "-Q",
            "-i", interfaceOption.Id,
            "-Y", Quote("ip or ipv6"),
            "-T", "fields",
            "-E", "separator=|",
            "-E", "occurrence=f",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "_ws.col.Protocol",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-e", "tcp.flags.reset",
            "-e", "tcp.flags.fin",
            "-e", "frame.len",
            "-e", "icmp.type",
            "-e", "icmpv6.type"
        });

        var startInfo = CreateStartInfo(arguments);
        _captureProcess = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start tshark.");
        onStatus?.Invoke($"Live capture started on {interfaceOption.DisplayName}");

        _ = Task.Run(async () =>
        {
            try
            {
                while (_captureProcess is { HasExited: false } && !cancellationToken.IsCancellationRequested)
                {
                    var errorLine = await _captureProcess.StandardError.ReadLineAsync(cancellationToken);
                    if (!string.IsNullOrWhiteSpace(errorLine) &&
                        !errorLine.Contains("Capturing on", StringComparison.OrdinalIgnoreCase) &&
                        !errorLine.Contains("File:", StringComparison.OrdinalIgnoreCase))
                    {
                        onStatus?.Invoke(errorLine.Trim());
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch
            {
            }
        }, cancellationToken);

        try
        {
            var rawLineCount = 0;
            var parsedPacketCount = 0;

            while (_captureProcess is { HasExited: false } && !cancellationToken.IsCancellationRequested)
            {
                var line = await _captureProcess.StandardOutput.ReadLineAsync(cancellationToken);
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                rawLineCount++;
                var packet = ParsePacketLine(line);
                if (packet is not null)
                {
                    parsedPacketCount++;
                    if (parsedPacketCount % 500 == 0)
                    {
                        onStatus?.Invoke($"Parsed {parsedPacketCount} live IP packets from TShark.");
                    }

                    await onPacket(packet);
                }
                else if (rawLineCount % 500 == 0)
                {
                    onStatus?.Invoke($"TShark output received ({rawLineCount} lines), but parser skipped them. Check selected NIC/filter.");
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            StopCapture();
            onStatus?.Invoke("Live capture stopped.");
        }
    }

    public void StopCapture()
    {
        try
        {
            if (_captureProcess is { HasExited: false })
            {
                _captureProcess.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best effort cleanup for an external capture process.
        }
        finally
        {
            _captureProcess?.Dispose();
            _captureProcess = null;
        }
    }

    private static async Task<IReadOnlyList<string>> RunTsharkAsync(string arguments, CancellationToken cancellationToken)
    {
        using var process = Process.Start(CreateStartInfo(arguments))
            ?? throw new InvalidOperationException("Unable to start tshark.");

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(error)
                ? "tshark returned an error."
                : error.Trim());
        }

        return output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
    }

    private static ProcessStartInfo CreateStartInfo(string arguments) => new()
    {
        FileName = ResolveTsharkPath(),
        Arguments = arguments,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };

    private static string ResolveTsharkPath()
    {
        var baseDirectory = AppContext.BaseDirectory;
        var candidates = new List<string>
        {
            Path.Combine(baseDirectory, "Tools", "Wireshark", "tshark.exe"),
            Path.Combine(baseDirectory, "Tools", "TShark", "tshark.exe"),
            Path.Combine(baseDirectory, "tshark.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", "tshark.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Wireshark", "tshark.exe")
        };

        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        candidates.AddRange(path
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(folder => Path.Combine(folder.Trim(), "tshark.exe")));

        return candidates.FirstOrDefault(File.Exists) ?? "tshark";
    }

    private static NetworkInterfaceOption? ParseInterface(string line)
    {
        var match = InterfaceRegex.Match(line);
        if (!match.Success)
        {
            return null;
        }

        var rawName = match.Groups[2].Value.Trim();
        var description = match.Groups[3].Success ? match.Groups[3].Value.Trim() : rawName;
        return new NetworkInterfaceOption
        {
            Id = match.Groups[1].Value,
            Name = rawName,
            Description = description
        };
    }

    private static PacketRecord? ParsePacketLine(string line)
    {
        var fields = line.Split('|');
        if (fields.Length < 17)
        {
            return null;
        }

        var sourceIp = FirstValue(Get(fields, 1), Get(fields, 3));
        var destinationIp = FirstValue(Get(fields, 2), Get(fields, 4));
        if (string.IsNullOrWhiteSpace(sourceIp) || string.IsNullOrWhiteSpace(destinationIp))
        {
            return null;
        }

        var protocol = NormalizeProtocol(Get(fields, 5));
        var sourcePort = ParsePort(Get(fields, 6)) ?? ParsePort(Get(fields, 8));
        var destinationPort = ParsePort(Get(fields, 7)) ?? ParsePort(Get(fields, 9));
        var isSyn = IsTrue(Get(fields, 10));
        var isAck = IsTrue(Get(fields, 11));
        var isRst = IsTrue(Get(fields, 12));
        var isFin = IsTrue(Get(fields, 13));
        var frameLength = ParsePort(Get(fields, 14)) ?? 0;
        var icmpType = Get(fields, 15);
        var icmpV6Type = Get(fields, 16);

        return new PacketRecord
        {
            Time = ParseEpoch(Get(fields, 0)),
            SourceIp = sourceIp,
            DestinationIp = destinationIp,
            Protocol = protocol,
            SourcePort = sourcePort,
            DestinationPort = destinationPort,
            TcpFlags = BuildTcpFlags(isSyn, isAck, isRst, isFin),
            Length = frameLength,
            IsTcpSyn = isSyn,
            IsTcpAck = isAck,
            IsIcmpEchoRequest = protocol == "ICMP" && icmpType == "8" || protocol == "ICMPv6" && icmpV6Type == "128"
        };
    }

    private static DateTime ParseEpoch(string value)
    {
        if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var epoch))
        {
            return DateTimeOffset.FromUnixTimeMilliseconds((long)(epoch * 1000)).LocalDateTime;
        }

        return DateTime.Now;
    }

    private static string NormalizeProtocol(string value)
    {
        if (value.Contains("TCP", StringComparison.OrdinalIgnoreCase)) return "TCP";
        if (value.Contains("UDP", StringComparison.OrdinalIgnoreCase)) return "UDP";
        if (value.Contains("ICMPv6", StringComparison.OrdinalIgnoreCase)) return "ICMPv6";
        if (value.Contains("ICMP", StringComparison.OrdinalIgnoreCase)) return "ICMP";
        return string.IsNullOrWhiteSpace(value) ? "Other" : value.Trim();
    }

    private static int? ParsePort(string value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) ? port : null;

    private static bool IsTrue(string value) => value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase);

    private static string BuildTcpFlags(bool syn, bool ack, bool rst, bool fin)
    {
        var flags = new List<string>(4);
        if (syn) flags.Add("SYN");
        if (ack) flags.Add("ACK");
        if (rst) flags.Add("RST");
        if (fin) flags.Add("FIN");
        return string.Join(",", flags);
    }

    private static string Get(string[] fields, int index) => index < fields.Length ? fields[index].Trim() : string.Empty;

    private static string FirstValue(params string[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static string Quote(string value) => $"\"{value}\"";
}
