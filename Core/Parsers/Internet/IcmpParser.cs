using System.Buffers.Binary;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Internet;

public static class IcmpParser
{
    public static bool TryParse(ReadOnlySpan<byte> data, int offset, int length, PacketModel packet)
    {
        if (data.Length < offset + 4 || length < 4)
            return false;

        byte type = data[offset];
        byte code = data[offset + 1];
        ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));

        packet.Protocol = "ICMP";
        packet.Protocols.Add("icmp");
        packet.ColorClass = "proto-icmp";

        packet.SetFilterField("icmp.type", type);
        packet.SetFilterField("icmp.code", code);
        packet.SetFilterField("icmp.checksum", checksum);

        string typeName = type switch
        {
            0 => "Echo (ping) reply",
            3 => "Destination unreachable",
            4 => "Source quench",
            5 => "Redirect",
            8 => "Echo (ping) request",
            11 => "Time-to-live exceeded",
            12 => "Parameter problem",
            13 => "Timestamp request",
            14 => "Timestamp reply",
            _ => $"Type {type}"
        };

        var header = new PacketHeader("Internet Control Message Protocol", $"{typeName} (type={type}, code={code})", offset, length);
        header.AddField("Type", $"Type: {type} ({typeName})", offset, 1, type);
        header.AddField("Code", $"Code: {code}", offset + 1, 1, code);
        header.AddField("Checksum", $"Checksum: 0x{checksum:x4}", offset + 2, 2, checksum);

        if ((type == 0 || type == 8) && length >= 8 && data.Length >= offset + 8)
        {
            ushort identifier = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 4, 2));
            ushort seq = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 6, 2));

            packet.SetFilterField("icmp.ident", identifier);
            packet.SetFilterField("icmp.seq", seq);

            header.AddField("Identifier (BE)", $"Identifier (BE): {identifier} (0x{identifier:x4})", offset + 4, 2, identifier);
            header.AddField("Sequence number (BE)", $"Sequence number (BE): {seq} (0x{seq:x4})", offset + 6, 2, seq);

            packet.Info = $"{typeName} id=0x{identifier:x4}, seq={seq}";

            int dataLen = length - 8;
            if (dataLen > 0)
            {
                header.AddField("Data", $"Data ({dataLen} bytes)", offset + 8, dataLen);
            }
        }
        else
        {
            packet.Info = $"{typeName} (code {code})";
            if (length > 4)
            {
                header.AddField("Payload", $"Payload ({length - 4} bytes)", offset + 4, length - 4);
            }
        }

        packet.Headers.Add(header);
        return true;
    }
}
