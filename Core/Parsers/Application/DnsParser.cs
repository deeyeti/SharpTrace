using System.Buffers.Binary;
using System.Net;
using System.Text;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Application;

public static class DnsParser
{
    public static bool TryParse(ReadOnlySpan<byte> data, int offset, int length, PacketModel packet)
    {
        if (length < 12 || data.Length < offset + 12)
            return false;

        ushort txId = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));
        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 4, 2));
        ushort anCount = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 6, 2));
        ushort nsCount = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 8, 2));
        ushort arCount = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 10, 2));

        bool qr = (flags & 0x8000) != 0;
        byte opcode = (byte)((flags >> 11) & 0x0F);
        bool aa = (flags & 0x0400) != 0;
        bool tc = (flags & 0x0200) != 0;
        bool rd = (flags & 0x0100) != 0;
        bool ra = (flags & 0x0080) != 0;
        byte rcode = (byte)(flags & 0x0F);

        // Sanity check: reasonable count
        if (qdCount > 20 || anCount > 50)
            return false;

        packet.Protocol = "DNS";
        packet.Protocols.Add("dns");
        packet.ColorClass = "proto-dns";

        packet.SetFilterField("dns.id", txId);
        packet.SetFilterField("dns.flags.response", qr ? 1 : 0);
        packet.SetFilterField("dns.flags.opcode", opcode);
        packet.SetFilterField("dns.flags.rcode", rcode);
        packet.SetFilterField("dns.count.queries", qdCount);
        packet.SetFilterField("dns.count.answers", anCount);

        string qrStr = qr ? "response" : "query";
        var header = new PacketHeader("Domain Name System", $"({qrStr}) [txId: 0x{txId:x4}]", offset, length);
        header.AddField("Transaction ID", $"Transaction ID: 0x{txId:x4}", offset, 2, txId);

        var flagsField = new PacketField("Flags", $"Flags: 0x{flags:x4} ({(qr ? "Response" : "Standard query")})", offset + 2, 2, flags);
        flagsField.AddChild(new PacketField("Response", $"Response: Message is a {(qr ? "response (1)" : "query (0)")}", offset + 2, 2, qr));
        flagsField.AddChild(new PacketField("Opcode", $"Opcode: {opcode}", offset + 2, 2, opcode));
        flagsField.AddChild(new PacketField("Authoritative", $"Authoritative: {(aa ? "Server is an authority for domain" : "Server is not an authority")}", offset + 2, 2, aa));
        flagsField.AddChild(new PacketField("Truncated", $"Truncated: {(tc ? "Message is truncated" : "Message is not truncated")}", offset + 2, 2, tc));
        flagsField.AddChild(new PacketField("Recursion desired", $"Recursion desired: {(rd ? "Do query recursively" : "No recursion")}", offset + 2, 2, rd));
        flagsField.AddChild(new PacketField("Recursion available", $"Recursion available: {(ra ? "Server can do recursive queries" : "Not available")}", offset + 2, 2, ra));
        flagsField.AddChild(new PacketField("Reply code", $"Reply code: {GetRCodeName(rcode)} ({rcode})", offset + 2, 2, rcode));
        header.AddField(flagsField);

        header.AddField("Questions", $"Questions: {qdCount}", offset + 4, 2, qdCount);
        header.AddField("Answer RRs", $"Answer RRs: {anCount}", offset + 6, 2, anCount);
        header.AddField("Authority RRs", $"Authority RRs: {nsCount}", offset + 8, 2, nsCount);
        header.AddField("Additional RRs", $"Additional RRs: {arCount}", offset + 10, 2, arCount);

        int cur = offset + 12;
        string firstQueryName = string.Empty;
        string firstQueryType = string.Empty;

        // Parse Questions
        if (qdCount > 0)
        {
            var qTree = new PacketField("Queries", $"Queries ({qdCount})", cur, 0);
            for (int i = 0; i < qdCount && cur < offset + length; i++)
            {
                int qStart = cur;
                string qName = ReadDnsName(data, offset, length, ref cur);
                if (cur + 4 <= offset + length)
                {
                    ushort qType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur, 2));
                    ushort qClass = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur + 2, 2));
                    cur += 4;

                    string typeStr = GetDnsTypeName(qType);
                    if (string.IsNullOrEmpty(firstQueryName))
                    {
                        firstQueryName = qName;
                        firstQueryType = typeStr;
                    }

                    packet.SetFilterField("dns.qry.name", qName);
                    packet.SetFilterField("dns.qry.type", qType);

                    var item = new PacketField(qName, $"{qName}: type {typeStr}, class IN", qStart, cur - qStart);
                    item.AddChild(new PacketField("Name", $"Name: {qName}", qStart, cur - qStart - 4, qName));
                    item.AddChild(new PacketField("Type", $"Type: {typeStr} ({qType})", cur - 4, 2, qType));
                    item.AddChild(new PacketField("Class", $"Class: IN (0x{qClass:x4})", cur - 2, 2, qClass));
                    qTree.AddChild(item);
                }
            }
            header.AddField(qTree);
        }

        // Parse Answers
        string firstAnswer = string.Empty;
        if (anCount > 0 && cur < offset + length)
        {
            var anTree = new PacketField("Answers", $"Answers ({anCount})", cur, 0);
            for (int i = 0; i < anCount && cur < offset + length; i++)
            {
                int ansStart = cur;
                string ansName = ReadDnsName(data, offset, length, ref cur);
                if (cur + 10 <= offset + length)
                {
                    ushort ansType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur, 2));
                    ushort ansClass = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur + 2, 2));
                    uint ttl = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(cur + 4, 4));
                    ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur + 8, 2));
                    cur += 10;

                    string dataStr = "";
                    if (cur + rdLength <= offset + length)
                    {
                        if (ansType == 1 && rdLength == 4) // IPv4
                        {
                            dataStr = new IPAddress(data.Slice(cur, 4)).ToString();
                            packet.SetFilterField("dns.a", dataStr);
                        }
                        else if (ansType == 28 && rdLength == 16) // IPv6
                        {
                            dataStr = new IPAddress(data.Slice(cur, 16)).ToString();
                            packet.SetFilterField("dns.aaaa", dataStr);
                        }
                        else if (ansType == 5) // CNAME
                        {
                            int cnameCur = cur;
                            dataStr = ReadDnsName(data, offset, length, ref cnameCur);
                            packet.SetFilterField("dns.cname", dataStr);
                        }
                        else
                        {
                            dataStr = $"<{rdLength} bytes>";
                        }
                        cur += rdLength;
                    }

                    if (string.IsNullOrEmpty(firstAnswer) && !string.IsNullOrEmpty(dataStr))
                    {
                        firstAnswer = $"{GetDnsTypeName(ansType)} {dataStr}";
                    }

                    var item = new PacketField(ansName, $"{ansName}: type {GetDnsTypeName(ansType)}, class IN, {dataStr}", ansStart, cur - ansStart);
                    item.AddChild(new PacketField("Name", $"Name: {ansName}", ansStart, ansName.Length, ansName));
                    item.AddChild(new PacketField("Type", $"Type: {GetDnsTypeName(ansType)} ({ansType})", ansStart + 2, 2, ansType));
                    item.AddChild(new PacketField("Time to live", $"Time to live: {ttl}s", cur - rdLength - 6, 4, ttl));
                    item.AddChild(new PacketField("Data length", $"Data length: {rdLength}", cur - rdLength - 2, 2, rdLength));
                    item.AddChild(new PacketField("Address", $"Address/Data: {dataStr}", cur - rdLength, rdLength, dataStr));
                    anTree.AddChild(item);
                }
            }
            header.AddField(anTree);
        }

        packet.Headers.Add(header);

        if (!qr)
        {
            packet.Info = $"Standard query 0x{txId:x4} {firstQueryType} {firstQueryName}";
        }
        else
        {
            string ansSummary = !string.IsNullOrEmpty(firstAnswer) ? $" {firstAnswer}" : "";
            packet.Info = $"Standard query response 0x{txId:x4} {firstQueryType} {firstQueryName}{ansSummary}";
        }

        return true;
    }

    private static string ReadDnsName(ReadOnlySpan<byte> fullData, int dnsOffset, int dnsLength, ref int cur)
    {
        var sb = new StringBuilder();
        int jumps = 0;
        int maxJumps = 5;
        int originalCur = -1;
        int readPtr = cur;

        while (readPtr < dnsOffset + dnsLength && jumps < maxJumps)
        {
            byte len = fullData[readPtr];
            if (len == 0)
            {
                readPtr++;
                break;
            }

            // Pointer (0xC0)
            if ((len & 0xC0) == 0xC0)
            {
                if (readPtr + 1 >= dnsOffset + dnsLength) break;
                ushort ptrOffset = (ushort)(((len & 0x3F) << 8) | fullData[readPtr + 1]);
                if (originalCur == -1)
                    originalCur = readPtr + 2;

                readPtr = dnsOffset + ptrOffset;
                jumps++;
                continue;
            }

            readPtr++;
            if (readPtr + len > dnsOffset + dnsLength) break;

            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(fullData.Slice(readPtr, len)));
            readPtr += len;
        }

        cur = originalCur != -1 ? originalCur : readPtr;
        return sb.ToString();
    }

    private static string GetDnsTypeName(ushort type) => type switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        255 => "ANY",
        _ => $"TYPE{type}"
    };

    private static string GetRCodeName(byte rcode) => rcode switch
    {
        0 => "No error (0)",
        1 => "Format error (1)",
        2 => "Server failure (2)",
        3 => "Non-existent domain (NXDOMAIN) (3)",
        4 => "Not implemented (4)",
        5 => "Query refused (5)",
        _ => $"RCODE-{rcode}"
    };
}
