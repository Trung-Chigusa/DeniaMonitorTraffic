using DdosTriggerAnalyzer.Models;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.IO;

namespace DdosTriggerAnalyzer.Services;

public sealed class PcapReaderService
{
    public Task<IReadOnlyList<PacketRecord>> ReadAsync(
        string filePath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("PCAP file not found.", filePath);
            }

            var records = new List<PacketRecord>();
            using var device = new CaptureFileReaderDevice(filePath);
            device.Open();

            var fileLength = Math.Max(1L, new FileInfo(filePath).Length);
            long estimatedBytesRead = 0;
            while (device.GetNextPacket(out var packetCapture) == GetPacketStatus.PacketRead)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var rawCapture = packetCapture.GetPacket();
                estimatedBytesRead += Math.Max(1, rawCapture.Data.Length);
                var record = TryParsePacket(rawCapture);
                if (record is not null)
                {
                    records.Add(record);
                }

                if (records.Count % 250 == 0)
                {
                    // CaptureFileReaderDevice does not expose a reliable byte offset across all formats,
                    // so this bounded estimate keeps the UI alive for large captures.
                    var estimated = Math.Min(95.0, estimatedBytesRead * 100.0 / fileLength);
                    progress?.Report(estimated);
                }
            }

            progress?.Report(100);
            return (IReadOnlyList<PacketRecord>)records.OrderBy(p => p.Time).ToList();
        }, cancellationToken);
    }

    private static PacketRecord? TryParsePacket(RawCapture rawCapture)
    {
        try
        {
            var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket is null)
            {
                return null;
            }

            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();
            var icmpPacket = packet.Extract<IcmpV4Packet>();

            var protocol = "Other";
            int? sourcePort = null;
            int? destinationPort = null;
            var tcpFlags = string.Empty;
            var isSyn = false;
            var isAck = false;
            var isIcmpEchoRequest = false;

            if (tcpPacket is not null)
            {
                protocol = "TCP";
                sourcePort = tcpPacket.SourcePort;
                destinationPort = tcpPacket.DestinationPort;
                isSyn = tcpPacket.Synchronize;
                isAck = tcpPacket.Acknowledgment;
                tcpFlags = BuildTcpFlags(tcpPacket);
            }
            else if (udpPacket is not null)
            {
                protocol = "UDP";
                sourcePort = udpPacket.SourcePort;
                destinationPort = udpPacket.DestinationPort;
            }
            else if (icmpPacket is not null)
            {
                protocol = "ICMP";
                isIcmpEchoRequest = icmpPacket.TypeCode.ToString().Contains("EchoRequest", StringComparison.OrdinalIgnoreCase);
            }

            return new PacketRecord
            {
                Time = rawCapture.Timeval.Date.ToLocalTime(),
                SourceIp = ipPacket.SourceAddress?.ToString() ?? "-",
                DestinationIp = ipPacket.DestinationAddress?.ToString() ?? "-",
                Protocol = protocol,
                SourcePort = sourcePort,
                DestinationPort = destinationPort,
                TcpFlags = tcpFlags,
                Length = rawCapture.Data.Length,
                IsTcpSyn = isSyn,
                IsTcpAck = isAck,
                IsIcmpEchoRequest = isIcmpEchoRequest
            };
        }
        catch
        {
            return null;
        }
    }

    private static string BuildTcpFlags(TcpPacket packet)
    {
        var flags = new List<string>(8);
        if (packet.Synchronize) flags.Add("SYN");
        if (packet.Acknowledgment) flags.Add("ACK");
        if (packet.Reset) flags.Add("RST");
        if (packet.Finished) flags.Add("FIN");
        if (packet.Push) flags.Add("PSH");
        if (packet.Urgent) flags.Add("URG");
        return string.Join(",", flags);
    }
}
