using System.Buffers.Binary;
using System.Text;

namespace SharpTrace.Core.Samples;

public static class SampleCaptureGenerator
{
    public static byte[] GenerateDnsSample()
    {
        using var ms = new MemoryStream();
        WritePcapGlobalHeader(ms);

        long baseTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Packet 1: DNS Query A example.com
        var dnsQ1 = BuildDnsQuery(0x1024, "example.com", 1); // 1 = A
        var pkt1 = BuildIpv4UdpPacket("00:1a:2b:3c:4d:5e", "52:54:00:12:34:56", "192.168.1.100", "8.8.8.8", 53421, 53, dnsQ1);
        WritePcapPacket(ms, pkt1, baseTime, 100000);

        // Packet 2: DNS Response A example.com -> 93.184.216.34
        var dnsR1 = BuildDnsResponseA(0x1024, "example.com", "93.184.216.34");
        var pkt2 = BuildIpv4UdpPacket("52:54:00:12:34:56", "00:1a:2b:3c:4d:5e", "8.8.8.8", "192.168.1.100", 53, 53421, dnsR1);
        WritePcapPacket(ms, pkt2, baseTime, 145000);

        // Packet 3: DNS Query AAAA example.com
        var dnsQ2 = BuildDnsQuery(0x1025, "example.com", 28); // 28 = AAAA
        var pkt3 = BuildIpv4UdpPacket("00:1a:2b:3c:4d:5e", "52:54:00:12:34:56", "192.168.1.100", "8.8.8.8", 53422, 53, dnsQ2);
        WritePcapPacket(ms, pkt3, baseTime + 1, 20000);

        // Packet 4: DNS Response AAAA
        var dnsR2 = BuildDnsResponseAaaa(0x1025, "example.com", new byte[] { 0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46 });
        var pkt4 = BuildIpv4UdpPacket("52:54:00:12:34:56", "00:1a:2b:3c:4d:5e", "8.8.8.8", "192.168.1.100", 53, 53422, dnsR2);
        WritePcapPacket(ms, pkt4, baseTime + 1, 62000);

        return ms.ToArray();
    }

    public static byte[] GenerateTcpHandshakeSample()
    {
        using var ms = new MemoryStream();
        WritePcapGlobalHeader(ms);

        long baseTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string clientMac = "00:1a:2b:44:55:66";
        string serverMac = "52:54:00:99:88:77";
        string clientIp = "192.168.1.105";
        string serverIp = "93.184.216.34";
        ushort clientPort = 51940;
        ushort serverPort = 443;

        // 1. SYN
        var pkt1 = BuildIpv4TcpPacket(clientMac, serverMac, clientIp, serverIp, clientPort, serverPort, 1000, 0, 0x02, 64240, Array.Empty<byte>()); // SYN
        WritePcapPacket(ms, pkt1, baseTime, 10000);

        // 2. SYN-ACK
        var pkt2 = BuildIpv4TcpPacket(serverMac, clientMac, serverIp, clientIp, serverPort, clientPort, 5000, 1001, 0x12, 65535, Array.Empty<byte>()); // SYN, ACK
        WritePcapPacket(ms, pkt2, baseTime, 42000);

        // 3. ACK
        var pkt3 = BuildIpv4TcpPacket(clientMac, serverMac, clientIp, serverIp, clientPort, serverPort, 1001, 5001, 0x10, 64240, Array.Empty<byte>()); // ACK
        WritePcapPacket(ms, pkt3, baseTime, 43000);

        // 4. TLS Client Hello (PSH, ACK)
        var tlsHello = BuildTlsClientHello("example.com");
        var pkt4 = BuildIpv4TcpPacket(clientMac, serverMac, clientIp, serverIp, clientPort, serverPort, 1001, 5001, 0x18, 64240, tlsHello); // PSH, ACK
        WritePcapPacket(ms, pkt4, baseTime, 55000);

        // 5. TCP ACK from server
        uint nextAck = 1001 + (uint)tlsHello.Length;
        var pkt5 = BuildIpv4TcpPacket(serverMac, clientMac, serverIp, clientIp, serverPort, clientPort, 5001, nextAck, 0x10, 65535, Array.Empty<byte>());
        WritePcapPacket(ms, pkt5, baseTime, 92000);

        // 6. FIN, ACK from client
        var pkt6 = BuildIpv4TcpPacket(clientMac, serverMac, clientIp, serverIp, clientPort, serverPort, nextAck, 5001, 0x11, 64240, Array.Empty<byte>());
        WritePcapPacket(ms, pkt6, baseTime + 1, 100000);

        // 7. FIN, ACK from server
        var pkt7 = BuildIpv4TcpPacket(serverMac, clientMac, serverIp, clientIp, serverPort, clientPort, 5001, nextAck + 1, 0x11, 65535, Array.Empty<byte>());
        WritePcapPacket(ms, pkt7, baseTime + 1, 135000);

        // 8. Final ACK from client
        var pkt8 = BuildIpv4TcpPacket(clientMac, serverMac, clientIp, serverIp, clientPort, serverPort, nextAck + 1, 5002, 0x10, 64240, Array.Empty<byte>());
        WritePcapPacket(ms, pkt8, baseTime + 1, 136000);

        return ms.ToArray();
    }

    public static byte[] GenerateHttpSample()
    {
        using var ms = new MemoryStream();
        WritePcapGlobalHeader(ms);

        long baseTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string clientMac = "00:50:56:c0:00:01";
        string serverMac = "00:50:56:c0:00:08";
        string clientIp = "10.0.0.15";
        string serverIp = "93.184.216.34";
        ushort clientPort = 49821;
        ushort serverPort = 80;

        // 1. SYN
        var p1 = BuildIpv4TcpPacket(clientMac, serverMac, clientIp, serverIp, clientPort, serverPort, 2000, 0, 0x02, 64240, Array.Empty<byte>());
        WritePcapPacket(ms, p1, baseTime, 10000);

        // 2. SYN, ACK
        var p2 = BuildIpv4TcpPacket(serverMac, clientMac, serverIp, clientIp, serverPort, clientPort, 7000, 2001, 0x12, 65535, Array.Empty<byte>());
        WritePcapPacket(ms, p2, baseTime, 35000);

        // 3. ACK
        var p3 = BuildIpv4TcpPacket(clientMac, serverMac, clientIp, serverIp, clientPort, serverPort, 2001, 7001, 0x10, 64240, Array.Empty<byte>());
        WritePcapPacket(ms, p3, baseTime, 36000);

        // 4. HTTP GET
        string getPayload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 SharpTrace\r\nAccept: text/html,*/*\r\n\r\n";
        byte[] getBytes = Encoding.ASCII.GetBytes(getPayload);
        var p4 = BuildIpv4TcpPacket(clientMac, serverMac, clientIp, serverIp, clientPort, serverPort, 2001, 7001, 0x18, 64240, getBytes);
        WritePcapPacket(ms, p4, baseTime, 45000);

        // 5. TCP ACK
        uint clientSeqAfterGet = 2001 + (uint)getBytes.Length;
        var p5 = BuildIpv4TcpPacket(serverMac, clientMac, serverIp, clientIp, serverPort, clientPort, 7001, clientSeqAfterGet, 0x10, 65535, Array.Empty<byte>());
        WritePcapPacket(ms, p5, baseTime, 72000);

        // 6. HTTP 200 OK
        string httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 53\r\nConnection: close\r\n\r\n<!DOCTYPE html><html><body>SharpTrace Analyzer</body></html>";
        byte[] respBytes = Encoding.ASCII.GetBytes(httpResponse);
        var p6 = BuildIpv4TcpPacket(serverMac, clientMac, serverIp, clientIp, serverPort, clientPort, 7001, clientSeqAfterGet, 0x18, 65535, respBytes);
        WritePcapPacket(ms, p6, baseTime, 85000);

        // 7. ICMP Ping Request (10.0.0.15 -> 8.8.8.8)
        var icmpReq = BuildIcmpEcho(8, 0x0042, 1, "Ping payload from SharpTrace");
        var p7 = BuildIpv4Packet(clientMac, serverMac, clientIp, "8.8.8.8", 1, icmpReq);
        WritePcapPacket(ms, p7, baseTime + 1, 100000);

        // 8. ICMP Ping Reply (8.8.8.8 -> 10.0.0.15)
        var icmpRep = BuildIcmpEcho(0, 0x0042, 1, "Ping payload from SharpTrace");
        var p8 = BuildIpv4Packet(serverMac, clientMac, "8.8.8.8", clientIp, 1, icmpRep);
        WritePcapPacket(ms, p8, baseTime + 1, 128000);

        return ms.ToArray();
    }

    // --- Helpers ---

    private static void WritePcapGlobalHeader(Stream stream)
    {
        var h = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(0, 4), 0xa1b2c3d4); // magic
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(4, 2), 2); // major
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(6, 2), 4); // minor
        BinaryPrimitives.WriteInt32LittleEndian(h.AsSpan(8, 4), 0);  // thiszone
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(12, 4), 0); // sigfigs
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(16, 4), 65535); // snaplen
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(20, 4), 1); // linktype ETHERNET
        stream.Write(h, 0, 24);
    }

    private static void WritePcapPacket(Stream stream, byte[] packetData, long sec, long usec)
    {
        var h = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(0, 4), (uint)sec);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(4, 4), (uint)usec);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(8, 4), (uint)packetData.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(12, 4), (uint)packetData.Length);
        stream.Write(h, 0, 16);
        stream.Write(packetData, 0, packetData.Length);
    }

    private static byte[] ParseMac(string mac)
    {
        var parts = mac.Split(':');
        var res = new byte[6];
        for (int i = 0; i < 6; i++)
            res[i] = Convert.ToByte(parts[i], 16);
        return res;
    }

    private static byte[] ParseIp(string ip) =>
        System.Net.IPAddress.Parse(ip).GetAddressBytes();

    private static byte[] BuildIpv4UdpPacket(string srcMac, string dstMac, string srcIp, string dstIp, ushort srcPort, ushort dstPort, byte[] payload)
    {
        byte[] udp = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(0, 2), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(2, 2), dstPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(4, 2), (ushort)udp.Length);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(6, 2), 0); // checksum optional in IPv4 UDP
        Buffer.BlockCopy(payload, 0, udp, 8, payload.Length);

        return BuildIpv4Packet(srcMac, dstMac, srcIp, dstIp, 17, udp);
    }

    private static byte[] BuildIpv4TcpPacket(string srcMac, string dstMac, string srcIp, string dstIp, ushort srcPort, ushort dstPort, uint seq, uint ack, byte flags, ushort window, byte[] payload)
    {
        byte[] tcp = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0, 2), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2, 2), dstPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(4, 4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(8, 4), ack);
        tcp[12] = 0x50; // Data offset 5 (20 bytes)
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(14, 2), window);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(16, 2), 0xbeef); // checksum placeholder
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(18, 2), 0);
        if (payload.Length > 0)
            Buffer.BlockCopy(payload, 0, tcp, 20, payload.Length);

        return BuildIpv4Packet(srcMac, dstMac, srcIp, dstIp, 6, tcp);
    }

    private static byte[] BuildIpv4Packet(string srcMac, string dstMac, string srcIp, string dstIp, byte proto, byte[] payload)
    {
        int ipLen = 20 + payload.Length;
        byte[] ip = new byte[ipLen];
        ip[0] = 0x45; // Version 4, IHL 5
        ip[1] = 0x00; // TOS
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2, 2), (ushort)ipLen);
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(4, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(6, 2), 0x4000); // DF
        ip[8] = 64; // TTL
        ip[9] = proto;
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(10, 2), 0); // Checksum calculated later
        Buffer.BlockCopy(ParseIp(srcIp), 0, ip, 12, 4);
        Buffer.BlockCopy(ParseIp(dstIp), 0, ip, 16, 4);

        // Calculate IPv4 checksum
        ushort ipCksum = CalculateChecksum(ip.AsSpan(0, 20));
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(10, 2), ipCksum);

        Buffer.BlockCopy(payload, 0, ip, 20, payload.Length);

        // Ethernet frame
        byte[] eth = new byte[14 + ip.Length];
        Buffer.BlockCopy(ParseMac(dstMac), 0, eth, 0, 6);
        Buffer.BlockCopy(ParseMac(srcMac), 0, eth, 6, 6);
        BinaryPrimitives.WriteUInt16BigEndian(eth.AsSpan(12, 2), 0x0800); // IPv4
        Buffer.BlockCopy(ip, 0, eth, 14, ip.Length);

        return eth;
    }

    private static ushort CalculateChecksum(ReadOnlySpan<byte> buffer)
    {
        uint sum = 0;
        for (int i = 0; i < buffer.Length - 1; i += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(i, 2));
        }
        if (buffer.Length % 2 != 0)
        {
            sum += (uint)(buffer[buffer.Length - 1] << 8);
        }
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        return (ushort)~sum;
    }

    private static byte[] BuildIcmpEcho(byte type, ushort id, ushort seq, string payloadStr)
    {
        byte[] pBytes = Encoding.ASCII.GetBytes(payloadStr);
        byte[] icmp = new byte[8 + pBytes.Length];
        icmp[0] = type;
        icmp[1] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(4, 2), id);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(6, 2), seq);
        Buffer.BlockCopy(pBytes, 0, icmp, 8, pBytes.Length);

        ushort ck = CalculateChecksum(icmp);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2, 2), ck);
        return icmp;
    }

    private static byte[] BuildDnsQuery(ushort txId, string domain, ushort qType)
    {
        using var ms = new MemoryStream();
        var h = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(0, 2), txId);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2, 2), 0x0100); // Standard query, RD=1
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4, 2), 1);      // 1 question
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(10, 2), 0);
        ms.Write(h, 0, 12);

        WriteDnsLabels(ms, domain);
        var qTail = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(qTail.AsSpan(0, 2), qType);
        BinaryPrimitives.WriteUInt16BigEndian(qTail.AsSpan(2, 2), 1); // Class IN
        ms.Write(qTail, 0, 4);

        return ms.ToArray();
    }

    private static byte[] BuildDnsResponseA(ushort txId, string domain, string ip)
    {
        using var ms = new MemoryStream();
        var h = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(0, 2), txId);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2, 2), 0x8180); // Response, RD, RA
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4, 2), 1);      // 1 Question
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(6, 2), 1);      // 1 Answer
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(10, 2), 0);
        ms.Write(h, 0, 12);

        // Question
        WriteDnsLabels(ms, domain);
        var qTail = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(qTail.AsSpan(0, 2), 1); // Type A
        BinaryPrimitives.WriteUInt16BigEndian(qTail.AsSpan(2, 2), 1); // Class IN
        ms.Write(qTail, 0, 4);

        // Answer (compression pointer to question: 0xC00C)
        var ansHead = new byte[10];
        ansHead[0] = 0xc0;
        ansHead[1] = 0x0c;
        BinaryPrimitives.WriteUInt16BigEndian(ansHead.AsSpan(2, 2), 1); // Type A
        BinaryPrimitives.WriteUInt16BigEndian(ansHead.AsSpan(4, 2), 1); // Class IN
        BinaryPrimitives.WriteUInt32BigEndian(ansHead.AsSpan(6, 4), 300); // TTL 300
        ms.Write(ansHead, 0, 10);

        var rlen = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(rlen, 4);
        ms.Write(rlen, 0, 2);
        ms.Write(ParseIp(ip), 0, 4);

        return ms.ToArray();
    }

    private static byte[] BuildDnsResponseAaaa(ushort txId, string domain, byte[] ipv6Bytes)
    {
        using var ms = new MemoryStream();
        var h = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(0, 2), txId);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2, 2), 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(6, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(10, 2), 0);
        ms.Write(h, 0, 12);

        // Question
        WriteDnsLabels(ms, domain);
        var qTail = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(qTail.AsSpan(0, 2), 28); // Type AAAA
        BinaryPrimitives.WriteUInt16BigEndian(qTail.AsSpan(2, 2), 1);
        ms.Write(qTail, 0, 4);

        // Answer pointer
        var ansHead = new byte[10];
        ansHead[0] = 0xc0;
        ansHead[1] = 0x0c;
        BinaryPrimitives.WriteUInt16BigEndian(ansHead.AsSpan(2, 2), 28); // Type AAAA
        BinaryPrimitives.WriteUInt16BigEndian(ansHead.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt32BigEndian(ansHead.AsSpan(6, 4), 300);
        ms.Write(ansHead, 0, 10);

        var rlen = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(rlen, 16);
        ms.Write(rlen, 0, 2);
        ms.Write(ipv6Bytes, 0, 16);

        return ms.ToArray();
    }

    private static void WriteDnsLabels(Stream stream, string domain)
    {
        var parts = domain.Split('.');
        foreach (var p in parts)
        {
            byte[] pb = Encoding.ASCII.GetBytes(p);
            stream.WriteByte((byte)pb.Length);
            stream.Write(pb, 0, pb.Length);
        }
        stream.WriteByte(0);
    }

    private static byte[] BuildTlsClientHello(string serverName)
    {
        using var ms = new MemoryStream();

        byte[] sniBytes = Encoding.ASCII.GetBytes(serverName);
        int sniExtLen = 2 + 1 + 2 + sniBytes.Length; // list len (2), name type (1), name len (2), name bytes
        int totalExtLen = 4 + sniExtLen; // ext type (2), ext len (2) + body

        // Handshake payload
        using var hs = new MemoryStream();
        hs.WriteByte(0x03); hs.WriteByte(0x03); // client_version TLS 1.2
        hs.Write(new byte[32]); // 32 bytes random
        hs.WriteByte(0x00); // session id length 0

        // Cipher suites (TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        byte[] cs = new byte[6] { 0x00, 0x04, 0x13, 0x01, 0xc0, 0x2f };
        hs.Write(cs, 0, cs.Length);

        // Compression
        byte[] comp = new byte[2] { 0x01, 0x00 };
        hs.Write(comp, 0, comp.Length);

        // Extensions
        var extH = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(extH, (ushort)totalExtLen);
        hs.Write(extH, 0, 2);

        // Extension: SNI (0x0000)
        var sniH = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(sniH.AsSpan(0, 2), 0x0000);
        BinaryPrimitives.WriteUInt16BigEndian(sniH.AsSpan(2, 2), (ushort)sniExtLen);
        hs.Write(sniH, 0, 4);

        var sniListH = new byte[5];
        BinaryPrimitives.WriteUInt16BigEndian(sniListH.AsSpan(0, 2), (ushort)(3 + sniBytes.Length));
        sniListH[2] = 0; // host_name
        BinaryPrimitives.WriteUInt16BigEndian(sniListH.AsSpan(3, 2), (ushort)sniBytes.Length);
        hs.Write(sniListH, 0, 5);
        hs.Write(sniBytes, 0, sniBytes.Length);

        byte[] hsData = hs.ToArray();

        // TLS Record Header: Type 22 (Handshake), Version TLS 1.0 (0x0301), Length
        ms.WriteByte(0x16); // Handshake
        ms.WriteByte(0x03); ms.WriteByte(0x01); // TLS 1.0 record layer
        int fullHsLen = 4 + hsData.Length;
        var recLen = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(recLen, (ushort)fullHsLen);
        ms.Write(recLen, 0, 2);

        // Handshake Header: Type 1 (Client Hello), Length (3 bytes)
        ms.WriteByte(0x01);
        ms.WriteByte((byte)((hsData.Length >> 16) & 0xFF));
        ms.WriteByte((byte)((hsData.Length >> 8) & 0xFF));
        ms.WriteByte((byte)(hsData.Length & 0xFF));

        ms.Write(hsData, 0, hsData.Length);

        return ms.ToArray();
    }
}
