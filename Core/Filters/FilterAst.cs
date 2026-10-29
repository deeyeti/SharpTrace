namespace SharpTrace.Core.Filters;

public abstract class FilterNode
{
}

public class BinaryOpNode : FilterNode
{
    public FilterNode Left { get; }
    public TokenType Operator { get; }
    public FilterNode Right { get; }

    public BinaryOpNode(FilterNode left, TokenType op, FilterNode right)
    {
        Left = left;
        Operator = op;
        Right = right;
    }
}

public class UnaryNotNode : FilterNode
{
    public FilterNode Operand { get; }

    public UnaryNotNode(FilterNode operand)
    {
        Operand = operand;
    }
}

public class ComparisonNode : FilterNode
{
    public string Field { get; }
    public TokenType Operator { get; }
    public string Value { get; }

    public ComparisonNode(string field, TokenType op, string value)
    {
        Field = field;
        Operator = op;
        Value = value;
    }
}

public class ProtocolPresenceNode : FilterNode
{
    public string Protocol { get; }

    public ProtocolPresenceNode(string protocol)
    {
        Protocol = protocol;
    }
}
