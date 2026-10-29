using SharpTrace.Core.Models;

namespace SharpTrace.Core.Filters;

public static class FilterEvaluator
{
    public static bool Evaluate(FilterNode node, PacketModel packet)
    {
        return node switch
        {
            ProtocolPresenceNode p => EvaluateProtocolPresence(p, packet),
            UnaryNotNode u => !Evaluate(u.Operand, packet),
            BinaryOpNode b => b.Operator switch
            {
                TokenType.And => Evaluate(b.Left, packet) && Evaluate(b.Right, packet),
                TokenType.Or => Evaluate(b.Left, packet) || Evaluate(b.Right, packet),
                _ => false
            },
            ComparisonNode c => EvaluateComparison(c, packet),
            _ => true
        };
    }

    private static bool EvaluateProtocolPresence(ProtocolPresenceNode node, PacketModel packet)
    {
        if (node.Protocol == "*")
            return true;

        if (packet.HasProtocol(node.Protocol))
            return true;

        if (packet.Protocol.Equals(node.Protocol, StringComparison.OrdinalIgnoreCase))
            return true;

        return packet.Headers.Any(h => h.ProtocolName.Contains(node.Protocol, StringComparison.OrdinalIgnoreCase));
    }

    private static bool EvaluateComparison(ComparisonNode node, PacketModel packet)
    {
        string fieldKey = node.Field.ToLowerInvariant();

        // Handle composite aliases
        if (fieldKey == "ip.addr")
        {
            return CheckSingleComparison("ip.src", node.Operator, node.Value, packet) ||
                   CheckSingleComparison("ip.dst", node.Operator, node.Value, packet);
        }

        if (fieldKey == "tcp.port")
        {
            return CheckSingleComparison("tcp.srcport", node.Operator, node.Value, packet) ||
                   CheckSingleComparison("tcp.dstport", node.Operator, node.Value, packet);
        }

        if (fieldKey == "udp.port")
        {
            return CheckSingleComparison("udp.srcport", node.Operator, node.Value, packet) ||
                   CheckSingleComparison("udp.dstport", node.Operator, node.Value, packet);
        }

        if (fieldKey == "eth.addr")
        {
            return CheckSingleComparison("eth.src", node.Operator, node.Value, packet) ||
                   CheckSingleComparison("eth.dst", node.Operator, node.Value, packet);
        }

        return CheckSingleComparison(fieldKey, node.Operator, node.Value, packet);
    }

    private static bool CheckSingleComparison(string fieldKey, TokenType op, string targetValue, PacketModel packet)
    {
        object? rawVal = packet.GetFilterField(fieldKey);

        // Special handling: "ip.proto == tcp" or "ip.proto == udp"
        if (fieldKey == "ip.proto" && (rawVal is byte bProto || rawVal is int iProto))
        {
            int protoNum = rawVal is byte b ? b : (int)rawVal;
            string targetLower = targetValue.ToLowerInvariant();
            if (targetLower == "tcp" && protoNum == 6) return op == TokenType.Equal;
            if (targetLower == "udp" && protoNum == 17) return op == TokenType.Equal;
            if (targetLower == "icmp" && protoNum == 1) return op == TokenType.Equal;
        }

        if (rawVal == null)
            return op == TokenType.NotEqual;

        string strVal = rawVal.ToString() ?? "";

        // Check if numeric comparison is applicable
        if (TryParseNumber(strVal, out double numVal) && TryParseNumber(targetValue, out double numTarget))
        {
            return op switch
            {
                TokenType.Equal => Math.Abs(numVal - numTarget) < 0.000001,
                TokenType.NotEqual => Math.Abs(numVal - numTarget) >= 0.000001,
                TokenType.GreaterThan => numVal > numTarget,
                TokenType.GreaterThanOrEqual => numVal >= numTarget,
                TokenType.LessThan => numVal < numTarget,
                TokenType.LessThanOrEqual => numVal <= numTarget,
                TokenType.Contains => strVal.Contains(targetValue, StringComparison.OrdinalIgnoreCase),
                _ => false
            };
        }

        // String comparison
        return op switch
        {
            TokenType.Equal => string.Equals(strVal, targetValue, StringComparison.OrdinalIgnoreCase),
            TokenType.NotEqual => !string.Equals(strVal, targetValue, StringComparison.OrdinalIgnoreCase),
            TokenType.Contains => strVal.Contains(targetValue, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool TryParseNumber(string text, out double number)
    {
        number = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        text = text.Trim();

        // Hex support: e.g. 0x80 or 0x0800
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (long.TryParse(text.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out long hexVal))
            {
                number = hexVal;
                return true;
            }
        }

        return double.TryParse(text, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out number);
    }
}
