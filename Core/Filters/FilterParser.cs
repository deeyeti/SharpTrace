namespace SharpTrace.Core.Filters;

public class FilterParser
{
    private readonly List<FilterToken> _tokens;
    private int _current;

    public FilterParser(List<FilterToken> tokens)
    {
        _tokens = tokens;
        _current = 0;
    }

    public static FilterNode Parse(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return new ProtocolPresenceNode("*");

        var lexer = new FilterLexer(input);
        var tokens = lexer.Tokenize();
        var parser = new FilterParser(tokens);
        var ast = parser.ParseExpression();

        if (parser.CurrentToken.Type != TokenType.EndOfInput)
        {
            throw new FormatException($"Unexpected token '{parser.CurrentToken.Value}' at position {parser.CurrentToken.Position}");
        }

        return ast;
    }

    private FilterToken CurrentToken => _tokens[_current];

    private FilterToken Advance()
    {
        var tok = CurrentToken;
        if (_current < _tokens.Count - 1)
            _current++;
        return tok;
    }

    private bool Check(TokenType type) => CurrentToken.Type == type;

    private bool Match(TokenType type)
    {
        if (Check(type))
        {
            Advance();
            return true;
        }
        return false;
    }

    public FilterNode ParseExpression()
    {
        return ParseOr();
    }

    private FilterNode ParseOr()
    {
        var left = ParseAnd();
        while (Match(TokenType.Or))
        {
            var right = ParseAnd();
            left = new BinaryOpNode(left, TokenType.Or, right);
        }
        return left;
    }

    private FilterNode ParseAnd()
    {
        var left = ParseUnary();
        while (Match(TokenType.And))
        {
            var right = ParseUnary();
            left = new BinaryOpNode(left, TokenType.And, right);
        }
        return left;
    }

    private FilterNode ParseUnary()
    {
        if (Match(TokenType.Not))
        {
            var operand = ParseUnary();
            return new UnaryNotNode(operand);
        }
        return ParsePrimary();
    }

    private FilterNode ParsePrimary()
    {
        if (Match(TokenType.OpenParen))
        {
            var expr = ParseExpression();
            if (!Match(TokenType.CloseParen))
            {
                throw new FormatException($"Expected closing parenthesis ')' at position {CurrentToken.Position}");
            }
            return expr;
        }

        if (Check(TokenType.Identifier) || Check(TokenType.IpAddress))
        {
            var identToken = Advance();

            // Look ahead for comparison operator
            if (IsComparisonOperator(CurrentToken.Type))
            {
                var opToken = Advance();
                if (IsValueToken(CurrentToken.Type))
                {
                    var valToken = Advance();
                    return new ComparisonNode(identToken.Value, opToken.Type, valToken.Value);
                }
                throw new FormatException($"Expected value after operator '{opToken.Value}' at position {CurrentToken.Position}");
            }

            // Standalone protocol check (e.g. "tcp", "http", "dns")
            return new ProtocolPresenceNode(identToken.Value);
        }

        throw new FormatException($"Unexpected token '{CurrentToken.Value}' at position {CurrentToken.Position}");
    }

    private static bool IsComparisonOperator(TokenType type) => type switch
    {
        TokenType.Equal or
        TokenType.NotEqual or
        TokenType.GreaterThan or
        TokenType.LessThan or
        TokenType.GreaterThanOrEqual or
        TokenType.LessThanOrEqual or
        TokenType.Contains => true,
        _ => false
    };

    private static bool IsValueToken(TokenType type) => type switch
    {
        TokenType.Identifier or
        TokenType.Number or
        TokenType.StringLiteral or
        TokenType.IpAddress => true,
        _ => false
    };
}
