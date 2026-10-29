using SharpTrace.Core.Models;
using SharpTrace.Core.Parsers.Application;
using SharpTrace.Core.Parsers.Internet;
using SharpTrace.Core.Parsers.Link;
using SharpTrace.Core.Parsers.Transport;

namespace SharpTrace.Core.Parsers;

public static class PacketDecoder
{
    public static PacketModel Decode(byte[] rawBytes, int packetNumber, DateTime timestamp, double relativeSeconds)
    {
        var packet = new PacketModel
        {
            Number = packetNumber,
            Timestamp = timestamp,
            RelativeTimeSeconds = relativeSeconds,
            Length = rawBytes.Length,
            RawBytes = rawBytes,
            Protocol = "Unknown",
            Info = $"Frame ({rawBytes.Length} bytes)"
        };

        packet.SetFilterField("frame.number", packetNumber);
        packet.SetFilterField("frame.len", rawBytes.Length);
        packet.SetFilterField("frame.time_relative", relativeSeconds);

        var span = rawBytes.AsSpan();

        // 1. Frame pseudo-header
        var frameHeader = new PacketHeader("Frame", $"Frame {packetNumber}: {rawBytes.Length} bytes on wire", 0, rawBytes.Length);
        frameHeader.AddField("Frame Number", $"Frame Number: {packetNumber}", 0, 0, packetNumber);
        frameHeader.AddField("Frame Length", $"Frame Length: {rawBytes.Length} bytes", 0, 0, rawBytes.Length);
        frameHeader.AddField("Arrival Time", $"Arrival Time: {timestamp:yyyy-MM-dd HH:mm:ss.ffffff}", 0, 0, timestamp);
        packet.Headers.Add(frameHeader);

        if (span.IsEmpty)
            return packet;

        // 2. Link Layer (Ethernet II)
        if (EthernetParser.TryParse(span, 0, packet, out int ipOffset, out int ipLength, out ushort etherType))
        {
            DecodeNetworkLayer(span, ipOffset, ipLength, etherType, packet);
        }
        else
        {
            // Try direct IPv4 or IPv6 (raw IP captures)
            byte ver = (byte)(span[0] >> 4);
            if (ver == 4)
            {
                DecodeNetworkLayer(span, 0, span.Length, EtherTypes.IPv4, packet);
            }
            else if (ver == 6)
            {
                DecodeNetworkLayer(span, 0, span.Length, EtherTypes.IPv6, packet);
            }
        }

        return packet;
    }

    private static void DecodeNetworkLayer(ReadOnlySpan<byte> span, int offset, int length, ushort etherType, PacketModel packet)
    {
        switch (etherType)
        {
            case EtherTypes.IPv4:
                if (Ipv4Parser.TryParse(span, offset, packet, out int tOffset, out int tLength, out byte ipProto))
                {
                    DecodeTransportLayer(span, tOffset, tLength, ipProto, packet);
                }
                break;

            case EtherTypes.IPv6:
                if (Ipv6Parser.TryParse(span, offset, packet, out int v6Offset, out int v6Length, out byte v6Proto))
                {
                    DecodeTransportLayer(span, v6Offset, v6Length, v6Proto, packet);
                }
                break;

            case EtherTypes.ARP:
                ArpParser.TryParse(span, offset, packet);
                break;

            default:
                packet.Protocol = $"0x{etherType:X4}";
                break;
        }
    }

    private static void DecodeTransportLayer(ReadOnlySpan<byte> span, int offset, int length, byte ipProto, PacketModel packet)
    {
        switch (ipProto)
        {
            case IpProtocols.TCP:
                if (TcpParser.TryParse(span, offset, length, packet, out int tcpPayOffset, out int tcpPayLen, out ushort srcPort, out ushort dstPort))
                {
                    if (tcpPayLen > 0)
                    {
                        DecodeApplicationLayer(span, tcpPayOffset, tcpPayLen, srcPort, dstPort, packet, isTcp: true);
                    }
                }
                break;

            case IpProtocols.UDP:
                if (UdpParser.TryParse(span, offset, length, packet, out int udpPayOffset, out int udpPayLen, out ushort uSrcPort, out ushort uDstPort))
                {
                    if (udpPayLen > 0)
                    {
                        DecodeApplicationLayer(span, udpPayOffset, udpPayLen, uSrcPort, uDstPort, packet, isTcp: false);
                    }
                }
                break;

            case IpProtocols.ICMP:
                IcmpParser.TryParse(span, offset, length, packet);
                break;
        }
    }

    private static void DecodeApplicationLayer(ReadOnlySpan<byte> span, int offset, int length, ushort srcPort, ushort dstPort, PacketModel packet, bool isTcp)
    {
        // DNS (usually UDP or TCP port 53)
        if (srcPort == 53 || dstPort == 53)
        {
            if (isTcp && length > 2)
            {
                // In TCP DNS, first 2 bytes are length prefix
                DnsParser.TryParse(span, offset + 2, length - 2, packet);
                return;
            }
            if (DnsParser.TryParse(span, offset, length, packet))
                return;
        }

        // TLS (usually 443, 8443 or matching record header)
        if (isTcp && TlsParser.TryParse(span, offset, length, packet))
        {
            return;
        }

        // HTTP/1.x (usually 80, 8080, 3000, 8000, etc.)
        if (isTcp && HttpParser.TryParse(span, offset, length, packet))
        {
            return;
        }
    }
}
