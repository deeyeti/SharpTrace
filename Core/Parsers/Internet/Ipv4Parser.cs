using System.Buffers.Binary;
using System.Net;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Internet;

public static class Ipv4Parser
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

        if (data.Length < offset + 20)
            return false;

        byte verIhl = data[offset];
        byte version = (byte)(verIhl >> 4);
        byte ihl = (byte)(verIhl & 0x0F);
        int headerLength = ihl * 4;

        if (version != 4 || headerLength < 20 || data.Length < offset + headerLength)
            return false;

        byte tos = data[offset + 1];
        byte dscp = (byte)(tos >> 2);
        byte ecn = (byte)(tos & 0x03);

        ushort totalLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));
        ushort identification = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 4, 2));
        ushort flagsAndFrag = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 6, 2));

        bool df = (flagsAndFrag & 0x4000) != 0;
        bool mf = (flagsAndFrag & 0x2000) != 0;
        ushort fragOffset = (ushort)((flagsAndFrag & 0x1FFF) * 8);

        byte ttl = data[offset + 8];
        byte protocol = data[offset + 9];
        ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 10, 2));

        var srcIp = new IPAddress(data.Slice(offset + 12, 4)).ToString();
        var dstIp = new IPAddress(data.Slice(offset + 16, 4)).ToString();

        packet.Source = srcIp;
        packet.Destination = dstIp;
        packet.Protocols.Add("ip");
        packet.Protocols.Add("ipv4");

        packet.SetFilterField("ip.version", 4);
        packet.SetFilterField("ip.hdr_len", headerLength);
        packet.SetFilterField("ip.dsfield.dscp", dscp);
        packet.SetFilterField("ip.dsfield.ecn", ecn);
        packet.SetFilterField("ip.len", totalLength);
        packet.SetFilterField("ip.id", identification);
        packet.SetFilterField("ip.flags.df", df ? 1 : 0);
        packet.SetFilterField("ip.flags.mf", mf ? 1 : 0);
        packet.SetFilterField("ip.frag_offset", fragOffset);
        packet.SetFilterField("ip.ttl", ttl);
        packet.SetFilterField("ip.proto", protocol);
        packet.SetFilterField("ip.src", srcIp);
        packet.SetFilterField("ip.dst", dstIp);
        packet.SetFilterField("ip.addr", srcIp);

        var header = new PacketHeader("Internet Protocol Version 4", $"Src: {srcIp}, Dst: {dstIp}", offset, headerLength);
        
        var verField = new PacketField("Version", $"Version: 4", offset, 1, 4);
        verField.AddChild(new PacketField("Header Length", $"Header Length: {headerLength} bytes ({ihl})", offset, 1, headerLength));
        header.AddField(verField);

        var tosField = new PacketField("Differentiated Services Field", $"Differentiated Services Field: 0x{tos:x2} (DSCP: {dscp}, ECN: {ecn})", offset + 1, 1, tos);
        tosField.AddChild(new PacketField("DSCP", $"DSCP: {dscp}", offset + 1, 1, dscp));
        tosField.AddChild(new PacketField("ECN", $"ECN: {ecn}", offset + 1, 1, ecn));
        header.AddField(tosField);

        header.AddField("Total Length", $"Total Length: {totalLength}", offset + 2, 2, totalLength);
        header.AddField("Identification", $"Identification: 0x{identification:x4} ({identification})", offset + 4, 2, identification);

        var flagsField = new PacketField("Flags", $"Flags: 0x{(flagsAndFrag >> 13):x2} (DF: {(df ? "Set" : "Not set")}, MF: {(mf ? "Set" : "Not set")})", offset + 6, 2, flagsAndFrag >> 13);
        flagsField.AddChild(new PacketField("Don't Fragment", $"Don't Fragment (DF): {(df ? "1" : "0")}", offset + 6, 2, df));
        flagsField.AddChild(new PacketField("More Fragments", $"More Fragments (MF): {(mf ? "1" : "0")}", offset + 6, 2, mf));
        flagsField.AddChild(new PacketField("Fragment Offset", $"Fragment Offset: {fragOffset}", offset + 6, 2, fragOffset));
        header.AddField(flagsField);

        header.AddField("Time to Live", $"Time to Live: {ttl}", offset + 8, 1, ttl);
        header.AddField("Protocol", $"Protocol: {IpProtocols.GetName(protocol)} ({protocol})", offset + 9, 1, protocol);
        header.AddField("Header Checksum", $"Header Checksum: 0x{checksum:x4}", offset + 10, 2, checksum);
        header.AddField("Source Address", $"Source Address: {srcIp}", offset + 12, 4, srcIp);
        header.AddField("Destination Address", $"Destination Address: {dstIp}", offset + 16, 4, dstIp);

        if (headerLength > 20)
        {
            int optLen = headerLength - 20;
            header.AddField("IP Options", $"IP Options ({optLen} bytes)", offset + 20, optLen);
        }

        packet.Headers.Add(header);

        payloadOffset = offset + headerLength;
        int remainingInPacket = data.Length - payloadOffset;
        int remainingInIp = totalLength - headerLength;
        payloadLength = (remainingInIp > 0 && remainingInIp <= remainingInPacket) ? remainingInIp : remainingInPacket;
        nextProtocol = protocol;

        return true;
    }
}
