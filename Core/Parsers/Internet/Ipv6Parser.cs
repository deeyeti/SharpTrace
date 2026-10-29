using System.Buffers.Binary;
using System.Net;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Internet;

public static class Ipv6Parser
{
    public static bool TryParse(
        ReadOnlySpan<byte> data,
        int offset,
        PacketModel packet,
        out int payloadOffset,
        out int payloadLength,
        out byte nextProtocol)
    {
        payloadOffset = offset;
        payloadLength = 0;
        nextProtocol = 0;

        if (data.Length < offset + 40)
            return false;

        uint vtcFlow = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset, 4));
        byte version = (byte)(vtcFlow >> 28);
        if (version != 6)
            return false;

        byte trafficClass = (byte)((vtcFlow >> 20) & 0xFF);
        uint flowLabel = vtcFlow & 0xFFFFF;

        ushort payloadLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 4, 2));
        byte nextHeader = data[offset + 6];
        byte hopLimit = data[offset + 7];

        var srcIp = new IPAddress(data.Slice(offset + 8, 16)).ToString();
        var dstIp = new IPAddress(data.Slice(offset + 24, 16)).ToString();

        packet.Source = srcIp;
        packet.Destination = dstIp;
        packet.Protocols.Add("ipv6");
        packet.Protocols.Add("ip");

        packet.SetFilterField("ipv6.version", 6);
        packet.SetFilterField("ipv6.tclass", trafficClass);
        packet.SetFilterField("ipv6.flow", flowLabel);
        packet.SetFilterField("ipv6.plen", payloadLen);
        packet.SetFilterField("ipv6.nxt", nextHeader);
        packet.SetFilterField("ipv6.hlim", hopLimit);
        packet.SetFilterField("ipv6.src", srcIp);
        packet.SetFilterField("ipv6.dst", dstIp);
        packet.SetFilterField("ipv6.addr", srcIp);

        var header = new PacketHeader("Internet Protocol Version 6", $"Src: {srcIp}, Dst: {dstIp}", offset, 40);
        header.AddField("Version", "Version: 6", offset, 1, 6);
        header.AddField("Traffic Class", $"Traffic Class: 0x{trafficClass:x2}", offset, 2, trafficClass);
        header.AddField("Flow Label", $"Flow Label: 0x{flowLabel:x5}", offset + 1, 3, flowLabel);
        header.AddField("Payload Length", $"Payload Length: {payloadLen}", offset + 4, 2, payloadLen);
        header.AddField("Next Header", $"Next Header: {IpProtocols.GetName(nextHeader)} ({nextHeader})", offset + 6, 1, nextHeader);
        header.AddField("Hop Limit", $"Hop Limit: {hopLimit}", offset + 7, 1, hopLimit);
        header.AddField("Source Address", $"Source Address: {srcIp}", offset + 8, 16, srcIp);
        header.AddField("Destination Address", $"Destination Address: {dstIp}", offset + 24, 16, dstIp);

        packet.Headers.Add(header);

        payloadOffset = offset + 40;
        int remainingInPacket = data.Length - payloadOffset;
        payloadLength = (payloadLen > 0 && payloadLen <= remainingInPacket) ? payloadLen : remainingInPacket;
        nextProtocol = nextHeader;

        return true;
    }
}
