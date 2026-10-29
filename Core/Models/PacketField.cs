namespace SharpTrace.Core.Models;

public class PacketField
{
    public string Name { get; set; } = string.Empty;
    public string DisplayText { get; set; } = string.Empty;
    public int ByteOffset { get; set; }
    public int ByteLength { get; set; }
    public object? Value { get; set; }
    public string? Severity { get; set; }
    public List<PacketField> Children { get; set; } = new();

    public PacketField() { }

    public PacketField(string name, string displayText, int byteOffset, int byteLength, object? value = null, string? severity = null)
    {
        Name = name;
        DisplayText = displayText;
        ByteOffset = byteOffset;
        ByteLength = byteLength;
        Value = value;
        Severity = severity;
    }

    public void AddChild(PacketField child)
    {
        Children.Add(child);
    }
}
