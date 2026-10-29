using System.Buffers.Binary;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers;

public static class PcapNgParser
{
    private const uint SectionHeaderBlock = 0x0A0D0D0A;
    private const uint InterfaceDescBlock = 0x00000001;
    private const uint EnhancedPacketBlock = 0x00000006;
    private const uint SimplePacketBlock = 0x00000003;

    private const uint BomLittleEndian = 0x1A2B3C4D;
    private const uint BomBigEndian = 0x4D3C2B1A;

    public static async Task<List<PacketModel>> ParseAsync(byte[] fileBytes, CancellationToken ct = default)
    {
        return await Task.Run(() => Parse(fileBytes, ct), ct);
    }

    public static List<PacketModel> Parse(byte[] fileBytes, CancellationToken ct = default)
    {
        var packets = new List<PacketModel>();
        if (fileBytes.Length < 12)
            return packets;

        var span = fileBytes.AsSpan();
        int offset = 0;
        bool isLittleEndian = true;
        int packetNumber = 1;
        DateTime? firstPacketTime = null;

        while (offset + 8 <= fileBytes.Length)
        {
            ct.ThrowIfCancellationRequested();

            uint blockType = ReadUInt32(span.Slice(offset, 4), isLittleEndian);
            uint blockLength = ReadUInt32(span.Slice(offset + 4, 4), isLittleEndian);

            if (blockType == SectionHeaderBlock)
            {
                // Inspect BOM inside SHB (offset + 8)
                if (offset + 12 <= fileBytes.Length)
                {
                    uint bom = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset + 8, 4));
                    if (bom == BomLittleEndian)
                        isLittleEndian = true;
                    else if (bom == BomBigEndian)
                        isLittleEndian = false;

                    // Re-read block length with correct endianness
                    blockLength = ReadUInt32(span.Slice(offset + 4, 4), isLittleEndian);
                }
            }

            if (blockLength < 12 || offset + blockLength > fileBytes.Length)
            {
                break; // Corrupted or truncated block
            }

            if (blockType == EnhancedPacketBlock && blockLength >= 32)
            {
                uint ifId = ReadUInt32(span.Slice(offset + 8, 4), isLittleEndian);
                uint tsHigh = ReadUInt32(span.Slice(offset + 12, 4), isLittleEndian);
                uint tsLow = ReadUInt32(span.Slice(offset + 16, 4), isLittleEndian);
                uint capLen = ReadUInt32(span.Slice(offset + 20, 4), isLittleEndian);
                uint origLen = ReadUInt32(span.Slice(offset + 24, 4), isLittleEndian);

                ulong tsMicro = ((ulong)tsHigh << 32) | tsLow;
                // Standard default resolution for PCAPNG is 1 microsecond (10^-6 s)
                long ticks = (long)(tsMicro * 10);
                var timestamp = DateTime.UnixEpoch.AddTicks(ticks).ToLocalTime();

                if (firstPacketTime == null)
                    firstPacketTime = timestamp;

                double relativeSec = (timestamp - firstPacketTime.Value).TotalSeconds;

                if (offset + 28 + capLen <= fileBytes.Length)
                {
                    byte[] packetBytes = new byte[capLen];
                    span.Slice(offset + 28, (int)capLen).CopyTo(packetBytes);

                    var packet = PacketDecoder.Decode(packetBytes, packetNumber++, timestamp, relativeSec);
                    packets.Add(packet);
                }
            }
            else if (blockType == SimplePacketBlock && blockLength >= 16)
            {
                uint origLen = ReadUInt32(span.Slice(offset + 8, 4), isLittleEndian);
                uint capLen = blockLength - 16;
                if (capLen > origLen) capLen = origLen;

                var timestamp = DateTime.Now;
                if (firstPacketTime == null) firstPacketTime = timestamp;
                double relativeSec = (timestamp - firstPacketTime.Value).TotalSeconds;

                if (offset + 12 + capLen <= fileBytes.Length)
                {
                    byte[] packetBytes = new byte[capLen];
                    span.Slice(offset + 12, (int)capLen).CopyTo(packetBytes);

                    var packet = PacketDecoder.Decode(packetBytes, packetNumber++, timestamp, relativeSec);
                    packets.Add(packet);
                }
            }

            offset += (int)blockLength;
        }

        return packets;
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> span, bool isLittleEndian) =>
        isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(span) : BinaryPrimitives.ReadUInt32BigEndian(span);
}
