using System.Buffers.Binary;
using System.Text;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Transport;

public static class TcpParser
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

        if (data.Length < offset + 20 || length < 20)
            return false;

        srcPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
        dstPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));
        uint seqNumber = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset + 4, 4));
        uint ackNumber = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset + 8, 4));

        byte dataOffsetByte = data[offset + 12];
        int dataOffset = (dataOffsetByte >> 4) * 4;
        if (dataOffset < 20 || data.Length < offset + dataOffset)
            return false;

        byte flagsLow = data[offset + 13];
        bool ns  = (dataOffsetByte & 0x01) != 0;
        bool cwr = (flagsLow & 0x80) != 0;
        bool ece = (flagsLow & 0x40) != 0;
        bool urg = (flagsLow & 0x20) != 0;
        bool ack = (flagsLow & 0x10) != 0;
        bool psh = (flagsLow & 0x08) != 0;
        bool rst = (flagsLow & 0x04) != 0;
        bool syn = (flagsLow & 0x02) != 0;
        bool fin = (flagsLow & 0x01) != 0;

        ushort windowSize = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 14, 2));
        ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 16, 2));
        ushort urgentPointer = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 18, 2));

        packet.Protocol = "TCP";
        packet.Protocols.Add("tcp");
        packet.ColorClass = rst ? "proto-rst" : "proto-tcp";

        packet.SetFilterField("tcp.srcport", srcPort);
        packet.SetFilterField("tcp.dstport", dstPort);
        packet.SetFilterField("tcp.port", srcPort);
        packet.SetFilterField("tcp.seq", seqNumber);
        packet.SetFilterField("tcp.ack", ackNumber);
        packet.SetFilterField("tcp.len", Math.Max(0, length - dataOffset));
        packet.SetFilterField("tcp.hdr_len", dataOffset);
        packet.SetFilterField("tcp.flags.syn", syn ? 1 : 0);
        packet.SetFilterField("tcp.flags.ack", ack ? 1 : 0);
        packet.SetFilterField("tcp.flags.fin", fin ? 1 : 0);
        packet.SetFilterField("tcp.flags.reset", rst ? 1 : 0);
        packet.SetFilterField("tcp.flags.push", psh ? 1 : 0);
        packet.SetFilterField("tcp.flags.urg", urg ? 1 : 0);
        packet.SetFilterField("tcp.window_size", windowSize);
        packet.SetFilterField("tcp.checksum", checksum);

        var flagList = new List<string>();
        if (syn) flagList.Add("SYN");
        if (ack) flagList.Add("ACK");
        if (fin) flagList.Add("FIN");
        if (rst) flagList.Add("RST");
        if (psh) flagList.Add("PSH");
        if (urg) flagList.Add("URG");
        if (cwr) flagList.Add("CWR");
        if (ece) flagList.Add("ECE");

        string flagsStr = flagList.Count > 0 ? $"[{string.Join(", ", flagList)}]" : "[None]";
        int tcpPayloadLen = Math.Max(0, length - dataOffset);
        packet.Info = $"{srcPort} \u2192 {dstPort} {flagsStr} Seq={seqNumber} Ack={ackNumber} Win={windowSize} Len={tcpPayloadLen}";

        var header = new PacketHeader("Transmission Control Protocol", $"Src Port: {srcPort}, Dst Port: {dstPort}, Seq: {seqNumber}, Ack: {ackNumber}, Len: {tcpPayloadLen}", offset, dataOffset);
        header.AddField("Source Port", $"Source Port: {srcPort}", offset, 2, srcPort);
        header.AddField("Destination Port", $"Destination Port: {dstPort}", offset + 2, 2, dstPort);
        header.AddField("Sequence Number", $"Sequence Number: {seqNumber} (raw)", offset + 4, 4, seqNumber);
        header.AddField("Acknowledgment Number", $"Acknowledgment Number: {ackNumber} (raw)", offset + 8, 4, ackNumber);

        var dataOffField = new PacketField("Header Length", $"Header Length: {dataOffset} bytes ({dataOffset / 4})", offset + 12, 1, dataOffset);
        header.AddField(dataOffField);

        var flagsField = new PacketField("Flags", $"Flags: 0x{((dataOffsetByte & 0x0F) << 8 | flagsLow):x3} {flagsStr}", offset + 12, 2, flagsLow);
        flagsField.AddChild(new PacketField("Accurate ECN / NS", $"Nonce (NS): {(ns ? "1" : "0")}", offset + 12, 1, ns));
        flagsField.AddChild(new PacketField("Congestion Window Reduced", $"Congestion Window Reduced (CWR): {(cwr ? "1" : "0")}", offset + 13, 1, cwr));
        flagsField.AddChild(new PacketField("ECN-Echo", $"ECN-Echo (ECE): {(ece ? "1" : "0")}", offset + 13, 1, ece));
        flagsField.AddChild(new PacketField("Urgent", $"Urgent (URG): {(urg ? "1" : "0")}", offset + 13, 1, urg));
        flagsField.AddChild(new PacketField("Acknowledgment", $"Acknowledgment (ACK): {(ack ? "1" : "0")}", offset + 13, 1, ack));
        flagsField.AddChild(new PacketField("Push", $"Push (PSH): {(psh ? "1" : "0")}", offset + 13, 1, psh));
        flagsField.AddChild(new PacketField("Reset", $"Reset (RST): {(rst ? "1" : "0")}", offset + 13, 1, rst, rst ? "error" : null));
        flagsField.AddChild(new PacketField("Syn", $"Syn (SYN): {(syn ? "1" : "0")}", offset + 13, 1, syn));
        flagsField.AddChild(new PacketField("Fin", $"Fin (FIN): {(fin ? "1" : "0")}", offset + 13, 1, fin));
        header.AddField(flagsField);

        header.AddField("Window", $"Window: {windowSize}", offset + 14, 2, windowSize);
        header.AddField("Checksum", $"Checksum: 0x{checksum:x4}", offset + 16, 2, checksum);
        header.AddField("Urgent Pointer", $"Urgent Pointer: {urgentPointer}", offset + 18, 2, urgentPointer);

        // Parse TCP Options if any
        if (dataOffset > 20)
        {
            ParseTcpOptions(data, offset + 20, dataOffset - 20, header);
        }

        packet.Headers.Add(header);

        payloadOffset = offset + dataOffset;
        payloadLength = tcpPayloadLen;

        return true;
    }

    private static void ParseTcpOptions(ReadOnlySpan<byte> data, int optStart, int optLength, PacketHeader header)
    {
        var optionsRoot = new PacketField("Options", $"Options: ({optLength} bytes)", optStart, optLength);
        int cur = optStart;
        int end = optStart + optLength;

        while (cur < end && cur < data.Length)
        {
            byte kind = data[cur];
            if (kind == 0) // End of Option List
            {
                optionsRoot.AddChild(new PacketField("EOL", "TCP Option - End of Option List (EOL)", cur, 1));
                break;
            }
            if (kind == 1) // No-Operation (NOP)
            {
                optionsRoot.AddChild(new PacketField("NOP", "TCP Option - No-Operation (NOP)", cur, 1));
                cur++;
                continue;
            }

            if (cur + 1 >= end || cur + 1 >= data.Length)
                break;

            byte len = data[cur + 1];
            if (len < 2 || cur + len > end || cur + len > data.Length)
                break;

            switch (kind)
            {
                case 2 when len == 4: // MSS
                    ushort mss = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur + 2, 2));
                    optionsRoot.AddChild(new PacketField("MSS", $"TCP Option - Maximum Segment Size: {mss} bytes", cur, len, mss));
                    break;
                case 3 when len == 3: // Window Scale
                    byte shift = data[cur + 2];
                    optionsRoot.AddChild(new PacketField("Window Scale", $"TCP Option - Window Scale: {shift} (multiply by {1 << shift})", cur, len, shift));
                    break;
                case 4 when len == 2: // SACK Permitted
                    optionsRoot.AddChild(new PacketField("SACK Permitted", "TCP Option - SACK Permitted", cur, len));
                    break;
                case 8 when len == 10: // Timestamps
                    uint tsVal = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(cur + 2, 4));
                    uint tsEcr = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(cur + 6, 4));
                    optionsRoot.AddChild(new PacketField("Timestamps", $"TCP Option - Timestamps: TSval {tsVal}, TSecr {tsEcr}", cur, len));
                    break;
                default:
                    optionsRoot.AddChild(new PacketField($"Option-{kind}", $"TCP Option - Kind {kind} ({len} bytes)", cur, len));
                    break;
            }

            cur += len;
        }

        header.AddField(optionsRoot);
    }
}
