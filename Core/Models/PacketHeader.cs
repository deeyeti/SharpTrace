namespace SharpTrace.Core.Models;

public class PacketHeader
{
    public string ProtocolName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int ByteOffset { get; set; }
    public int ByteLength { get; set; }
    public List<PacketField> Fields { get; set; } = new();

    public PacketHeader() { }

    public PacketHeader(string protocolName, string description, int byteOffset, int byteLength)
    {
        ProtocolName = protocolName;
        Description = description;
        ByteOffset = byteOffset;
        ByteLength = byteLength;
    }

    public void AddField(PacketField field) => Fields.Add(field);

    public void AddField(string name, string displayText, int byteOffset, int byteLength, object? value = null, string? severity = null)
    {
        Fields.Add(new PacketField(name, displayText, byteOffset, byteLength, value, severity));
    }
}
