using System.Buffers.Binary;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Link;

public static class EthernetParser
{
    public static bool TryParse(
        ReadOnlySpan<byte> data,
        int offset,
        PacketModel packet,
        out int payloadOffset,
        out int payloadLength,
        out ushort nextEtherType)
    {
        payloadOffset = offset;
        payloadLength = 0;
        nextEtherType = 0;

        if (data.Length < offset + 14)
            return false;

        var dstMacSpan = data.Slice(offset, 6);
        var srcMacSpan = data.Slice(offset + 6, 6);
        var dstMac = FormatMac(dstMacSpan);
        var srcMac = FormatMac(srcMacSpan);

        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 12, 2));
        int headerLength = 14;

        packet.Protocols.Add("eth");
        packet.SetFilterField("eth.dst", dstMac);
        packet.SetFilterField("eth.src", srcMac);
        packet.SetFilterField("eth.addr", dstMac);

        // Check for 802.1Q VLAN
        ushort vlanId = 0;
        bool hasVlan = false;
        if (etherType == EtherTypes.Dot1Q_Vlan && data.Length >= offset + 18)
        {
            hasVlan = true;
            ushort tci = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 14, 2));
            vlanId = (ushort)(tci & 0x0FFF);
            etherType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 16, 2));
            headerLength = 18;
            packet.Protocols.Add("vlan");
            packet.SetFilterField("vlan.id", vlanId);
        }

        packet.SetFilterField("eth.type", $"0x{etherType:x4}");
        packet.SetFilterField("eth.type.val", (int)etherType);

        var header = new PacketHeader("Ethernet II", $"Src: {srcMac}, Dst: {dstMac}", offset, headerLength);
        header.AddField("Destination", $"Destination: {dstMac}", offset, 6, dstMac);
        header.AddField("Source", $"Source: {srcMac}", offset + 6, 6, srcMac);

        if (hasVlan)
        {
            var vlanField = new PacketField("802.1Q Virtual LAN", $"802.1Q Virtual LAN, VID: {vlanId}", offset + 12, 4);
            vlanField.AddChild(new PacketField("Type", "Type: 802.1Q VLAN (0x8100)", offset + 12, 2, 0x8100));
            vlanField.AddChild(new PacketField("VLAN Identifier", $"VLAN Identifier: {vlanId}", offset + 14, 2, vlanId));
            header.AddField(vlanField);
            header.AddField("Type", $"Type: {EtherTypes.GetName(etherType)}", offset + 16, 2, etherType);
        }
        else
        {
            header.AddField("Type", $"Type: {EtherTypes.GetName(etherType)}", offset + 12, 2, etherType);
        }

        packet.Headers.Add(header);

        payloadOffset = offset + headerLength;
        payloadLength = data.Length - payloadOffset;
        nextEtherType = etherType;

        return true;
    }

    private static string FormatMac(ReadOnlySpan<byte> span) =>
        $"{span[0]:x2}:{span[1]:x2}:{span[2]:x2}:{span[3]:x2}:{span[4]:x2}:{span[5]:x2}";
}
