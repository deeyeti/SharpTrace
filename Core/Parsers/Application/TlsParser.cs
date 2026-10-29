using System.Buffers.Binary;
using System.Text;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Application;

public static class TlsParser
{
    public static bool TryParse(ReadOnlySpan<byte> data, int offset, int length, PacketModel packet)
    {
        if (length < 5 || data.Length < offset + 5)
            return false;

        byte contentType = data[offset];
        // Valid content types: ChangeCipherSpec(20), Alert(21), Handshake(22), ApplicationData(23), Heartbeat(24)
        if (contentType < 20 || contentType > 24)
            return false;

        ushort version = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 1, 2));
        // Valid versions: SSL 3.0 (0x0300) to TLS 1.3 (0x0304)
        if (version < 0x0300 || version > 0x0304)
            return false;

        ushort recordLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 3, 2));
        if (recordLen > length - 5 && recordLen > 16384)
            return false;

        packet.Protocol = "TLS";
        packet.Protocols.Add("tls");
        packet.Protocols.Add("ssl");
        packet.ColorClass = "proto-tls";

        string verStr = GetVersionString(version);
        string typeStr = GetContentTypeString(contentType);

        packet.SetFilterField("tls.record.content_type", contentType);
        packet.SetFilterField("tls.record.version", version);
        packet.SetFilterField("tls.record.length", recordLen);

        var header = new PacketHeader($"Transport Layer Security", $"{verStr} Record Layer: {typeStr} Protocol", offset, 5 + Math.Min(recordLen, length - 5));
        header.AddField("Content Type", $"Content Type: {typeStr} ({contentType})", offset, 1, contentType);
        header.AddField("Version", $"Version: {verStr} (0x{version:x4})", offset + 1, 2, version);
        header.AddField("Length", $"Length: {recordLen}", offset + 3, 2, recordLen);

        string infoSummary = $"{verStr} Record: {typeStr}";

        if (contentType == 22 && length >= 9) // Handshake
        {
            byte hsType = data[offset + 5];
            int hsLength = (data[offset + 6] << 16) | (data[offset + 7] << 8) | data[offset + 8];
            string hsName = GetHandshakeTypeName(hsType);

            packet.SetFilterField("tls.handshake.type", hsType);
            var hsField = new PacketField("Handshake Protocol", $"Handshake Protocol: {hsName}", offset + 5, 4 + Math.Min(hsLength, length - 9));
            hsField.AddChild(new PacketField("Handshake Type", $"Handshake Type: {hsName} ({hsType})", offset + 5, 1, hsType));
            hsField.AddChild(new PacketField("Length", $"Length: {hsLength}", offset + 6, 3, hsLength));

            infoSummary = $"{verStr} {hsName}";

            // If Client Hello, try to parse SNI
            if (hsType == 1 && length >= 43)
            {
                string? sni = TryParseClientHelloSni(data, offset + 9, length - 9);
                if (!string.IsNullOrEmpty(sni))
                {
                    packet.SetFilterField("tls.handshake.extensions_server_name", sni);
                    hsField.AddChild(new PacketField("Server Name", $"Server Name (SNI): {sni}", offset + 9, 0, sni));
                    infoSummary += $" (SNI={sni})";
                }
            }

            header.AddField(hsField);
        }
        else if (contentType == 23) // Application Data
        {
            infoSummary = $"{verStr} Application Data";
        }

        packet.Info = infoSummary;
        packet.Headers.Add(header);
        return true;
    }

    private static string? TryParseClientHelloSni(ReadOnlySpan<byte> data, int offset, int length)
    {
        try
        {
            if (length < 34) return null;
            // client_version (2) + random (32)
            int cur = offset + 34;

            // session_id_length (1)
            if (cur >= offset + length) return null;
            byte sessIdLen = data[cur++];
            cur += sessIdLen;

            // cipher_suites_length (2)
            if (cur + 2 > offset + length) return null;
            ushort cipherSuitesLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur, 2));
            cur += 2 + cipherSuitesLen;

            // compression_methods_length (1)
            if (cur >= offset + length) return null;
            byte compLen = data[cur++];
            cur += compLen;

            // extensions_length (2)
            if (cur + 2 > offset + length) return null;
            ushort extTotalLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur, 2));
            cur += 2;
            int extEnd = cur + extTotalLen;

            while (cur + 4 <= extEnd && cur + 4 <= offset + length)
            {
                ushort extType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur, 2));
                ushort extLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur + 2, 2));
                cur += 4;

                if (extType == 0x0000) // Server Name Indication
                {
                    if (cur + 5 <= offset + length)
                    {
                        ushort sniListLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur, 2));
                        byte nameType = data[cur + 2];
                        ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(cur + 3, 2));
                        if (nameType == 0 && cur + 5 + nameLen <= offset + length)
                        {
                            return Encoding.ASCII.GetString(data.Slice(cur + 5, nameLen));
                        }
                    }
                }
                cur += extLen;
            }
        }
        catch
        {
            // Ignore malformed extensions
        }
        return null;
    }

    private static string GetVersionString(ushort version) => version switch
    {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => $"TLS (0x{version:x4})"
    };

    private static string GetContentTypeString(byte type) => type switch
    {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        24 => "Heartbeat",
        _ => $"Type-{type}"
    };

    private static string GetHandshakeTypeName(byte type) => type switch
    {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => $"Handshake-{type}"
    };
}
