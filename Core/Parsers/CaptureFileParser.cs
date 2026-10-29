using System.Buffers.Binary;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers;

public static class CaptureFileParser
{
    private const uint MagicPcapMicroLE = 0xa1b2c3d4;
    private const uint MagicPcapMicroBE = 0xd4c3b2a1;
    private const uint MagicPcapNanoLE  = 0xa1b23c4d;
    private const uint MagicPcapNanoBE  = 0x4d3cb2a1;
    private const uint MagicPcapNg      = 0x0A0D0D0A;

    public static async Task<List<PacketModel>> ParseAsync(byte[] fileBytes, CancellationToken ct = default)
    {
        if (fileBytes == null || fileBytes.Length < 4)
            return new List<PacketModel>();

        uint magicLE = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(0, 4));

        if (magicLE == MagicPcapNg)
        {
            return await PcapNgParser.ParseAsync(fileBytes, ct);
        }

        if (magicLE == MagicPcapMicroLE || magicLE == MagicPcapMicroBE ||
            magicLE == MagicPcapNanoLE  || magicLE == MagicPcapNanoBE)
        {
            return await PcapParser.ParseAsync(fileBytes, ct);
        }

        // Default attempt PCAP
        return await PcapParser.ParseAsync(fileBytes, ct);
    }
}
