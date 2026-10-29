using System.Buffers.Binary;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers;

public static class PcapParser
{
    private const uint MagicMicroLE = 0xa1b2c3d4;
    private const uint MagicMicroBE = 0xd4c3b2a1;
    private const uint MagicNanoLE  = 0xa1b23c4d;
    private const uint MagicNanoBE  = 0x4d3cb2a1;

    public static async Task<List<PacketModel>> ParseAsync(byte[] fileBytes, CancellationToken ct = default)
    {
        return await Task.Run(() => Parse(fileBytes, ct), ct);
    }

    public static List<PacketModel> Parse(byte[] fileBytes, CancellationToken ct = default)
    {
        var packets = new List<PacketModel>();
        if (fileBytes.Length < 24)
            return packets;

        var span = fileBytes.AsSpan();
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(0, 4));

        bool isLittleEndian;
        bool isNanosecond = false;

        if (magic == MagicMicroLE)
        {
            isLittleEndian = true;
        }
        else if (magic == MagicMicroBE)
        {
            isLittleEndian = false;
        }
        else if (magic == MagicNanoLE)
        {
            isLittleEndian = true;
            isNanosecond = true;
        }
        else if (magic == MagicNanoBE)
        {
            isLittleEndian = false;
            isNanosecond = true;
        }
        else
        {
            throw new InvalidDataException($"Invalid PCAP magic number: 0x{magic:X8}");
        }

        uint snapLen = ReadUInt32(span.Slice(16, 4), isLittleEndian);
        uint network = ReadUInt32(span.Slice(20, 4), isLittleEndian);

        int offset = 24;
        int packetNumber = 1;
        DateTime? firstPacketTime = null;

        while (offset + 16 <= fileBytes.Length)
        {
            ct.ThrowIfCancellationRequested();

            uint tsSec = ReadUInt32(span.Slice(offset, 4), isLittleEndian);
            uint tsSub = ReadUInt32(span.Slice(offset + 4, 4), isLittleEndian);
            uint inclLen = ReadUInt32(span.Slice(offset + 8, 4), isLittleEndian);
            uint origLen = ReadUInt32(span.Slice(offset + 12, 4), isLittleEndian);

            offset += 16;
            if (offset + inclLen > fileBytes.Length)
                break;

            long subMicroseconds = isNanosecond ? (tsSub / 1000) : tsSub;
            long ticks = (tsSec * TimeSpan.TicksPerSecond) + (subMicroseconds * (TimeSpan.TicksPerMillisecond / 1000));
            var timestamp = DateTime.UnixEpoch.AddTicks(ticks).ToLocalTime();

            if (firstPacketTime == null)
            {
                firstPacketTime = timestamp;
            }

            double relativeSeconds = (timestamp - firstPacketTime.Value).TotalSeconds;

            byte[] packetBytes = new byte[inclLen];
            span.Slice(offset, (int)inclLen).CopyTo(packetBytes);

            var packet = PacketDecoder.Decode(packetBytes, packetNumber++, timestamp, relativeSeconds);
            packets.Add(packet);

            offset += (int)inclLen;
        }

        return packets;
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> span, bool isLittleEndian) =>
        isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(span) : BinaryPrimitives.ReadUInt32BigEndian(span);

    private static ushort ReadUInt16(ReadOnlySpan<byte> span, bool isLittleEndian) =>
        isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(span) : BinaryPrimitives.ReadUInt16BigEndian(span);
}
