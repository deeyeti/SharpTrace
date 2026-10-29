using System.Buffers.Binary;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Transport;

public static class UdpParser
{
    public static bool TryParse(
        ReadOnlySpan<byte> data,
        int offset,
        int length,
        PacketModel packet,
        out int payloadOffset,
        out int payloadLength,
        out ushort srcPort,
        out ushort dstPort)
    {
        payloadOffset = offset;
        payloadLength = 0;
        srcPort = 0;
        dstPort = 0;

        if (data.Length < offset + 8 || length < 8)
            return false;

        srcPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
        dstPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));
        ushort udpLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 4, 2));
        ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 6, 2));

        packet.Protocol = "UDP";
        packet.Protocols.Add("udp");
        packet.ColorClass = "proto-udp";

        packet.SetFilterField("udp.srcport", srcPort);
        packet.SetFilterField("udp.dstport", dstPort);
        packet.SetFilterField("udp.port", srcPort);
        packet.SetFilterField("udp.length", udpLen);
        packet.SetFilterField("udp.checksum", checksum);

        int actualPayloadLen = Math.Max(0, udpLen - 8);
        int availableData = data.Length - (offset + 8);
        if (actualPayloadLen > availableData)
            actualPayloadLen = availableData;

        packet.Info = $"{srcPort} \u2192 {dstPort} Len={actualPayloadLen}";

        var header = new PacketHeader("User Datagram Protocol", $"Src Port: {srcPort}, Dst Port: {dstPort}, Len: {actualPayloadLen}", offset, 8);
        header.AddField("Source Port", $"Source Port: {srcPort}", offset, 2, srcPort);
        header.AddField("Destination Port", $"Destination Port: {dstPort}", offset + 2, 2, dstPort);
        header.AddField("Length", $"Length: {udpLen}", offset + 4, 2, udpLen);
        header.AddField("Checksum", $"Checksum: 0x{checksum:x4}", offset + 6, 2, checksum);

        packet.Headers.Add(header);

        payloadOffset = offset + 8;
        payloadLength = actualPayloadLen;

        return true;
    }
}
