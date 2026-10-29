using System.Buffers.Binary;
using System.Net;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Internet;

public static class ArpParser
{
    public static bool TryParse(ReadOnlySpan<byte> data, int offset, PacketModel packet)
    {
        if (data.Length < offset + 28)
            return false;

        ushort hwType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
        ushort protoType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));
        byte hwSize = data[offset + 4];
        byte protoSize = data[offset + 5];
        ushort opcode = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 6, 2));

        if (hwSize != 6 || protoSize != 4)
            return false;

        var senderMac = FormatMac(data.Slice(offset + 8, 6));
        var senderIp = new IPAddress(data.Slice(offset + 14, 4)).ToString();
        var targetMac = FormatMac(data.Slice(offset + 18, 6));
        var targetIp = new IPAddress(data.Slice(offset + 24, 4)).ToString();

        string opcodeName = opcode switch
        {
            1 => "Request",
            2 => "Reply",
            3 => "RARP-Request",
            4 => "RARP-Reply",
            _ => $"Opcode-{opcode}"
        };

        string info = opcode switch
        {
            1 => $"Who has {targetIp}? Tell {senderIp}",
            2 => $"{senderIp} is at {senderMac}",
            _ => $"ARP {opcodeName}"
        };

        packet.Source = senderMac;
        packet.Destination = opcode == 1 ? "Broadcast" : targetMac;
        packet.Protocol = "ARP";
        packet.Info = info;
        packet.ColorClass = "proto-arp";
        packet.Protocols.Add("arp");

        packet.SetFilterField("arp.hw.type", hwType);
        packet.SetFilterField("arp.proto.type", protoType);
        packet.SetFilterField("arp.opcode", opcode);
        packet.SetFilterField("arp.src.hw_mac", senderMac);
        packet.SetFilterField("arp.src.proto_ipv4", senderIp);
        packet.SetFilterField("arp.dst.hw_mac", targetMac);
        packet.SetFilterField("arp.dst.proto_ipv4", targetIp);
        packet.SetFilterField("arp.addr", senderIp);

        var header = new PacketHeader("Address Resolution Protocol", $"{opcodeName} ({info})", offset, 28);
        header.AddField("Hardware type", $"Hardware type: Ethernet (1)", offset, 2, hwType);
        header.AddField("Protocol type", $"Protocol type: IPv4 (0x0800)", offset + 2, 2, protoType);
        header.AddField("Hardware size", $"Hardware size: 6", offset + 4, 1, hwSize);
        header.AddField("Protocol size", $"Protocol size: 4", offset + 5, 1, protoSize);
        header.AddField("Opcode", $"Opcode: {opcodeName} ({opcode})", offset + 6, 2, opcode);
        header.AddField("Sender MAC address", $"Sender MAC address: {senderMac}", offset + 8, 6, senderMac);
        header.AddField("Sender IP address", $"Sender IP address: {senderIp}", offset + 14, 4, senderIp);
        header.AddField("Target MAC address", $"Target MAC address: {targetMac}", offset + 18, 6, targetMac);
        header.AddField("Target IP address", $"Target IP address: {targetIp}", offset + 24, 4, targetIp);

        packet.Headers.Add(header);
        return true;
    }

    private static string FormatMac(ReadOnlySpan<byte> span) =>
        $"{span[0]:x2}:{span[1]:x2}:{span[2]:x2}:{span[3]:x2}:{span[4]:x2}:{span[5]:x2}";
}
