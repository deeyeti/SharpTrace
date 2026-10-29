namespace SharpTrace.Core.Models;

public record ByteHighlightRange(
    int StartOffset,
    int Length,
    string? Label = null,
    string? ColorClass = "highlight-selected"
)
{
    public int EndOffset => StartOffset + Math.Max(0, Length - 1);

    public bool Contains(int offset) =>
        Length > 0 && offset >= StartOffset && offset <= EndOffset;
}
