namespace SharpTrace.Core.Models;

public class PacketModel
{
    public int Number { get; set; }
    public DateTime Timestamp { get; set; }
    public double RelativeTimeSeconds { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public int Length { get; set; }
    public string Info { get; set; } = string.Empty;
    public byte[] RawBytes { get; set; } = Array.Empty<byte>();
    public List<PacketHeader> Headers { get; set; } = new();
    public string ColorClass { get; set; } = "proto-other";

    public HashSet<string> Protocols { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, object> FilterFields { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public void SetFilterField(string key, object value)
    {
        FilterFields[key] = value;
    }

    public object? GetFilterField(string key)
    {
        if (FilterFields.TryGetValue(key, out var val))
            return val;
        return null;
    }

    public bool HasProtocol(string proto)
    {
        return Protocols.Contains(proto);
    }
}
