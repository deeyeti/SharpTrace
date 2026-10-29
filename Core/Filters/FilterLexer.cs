using System.Net;
using System.Text;

namespace SharpTrace.Core.Filters;

public class FilterLexer
{
    private readonly string _input;
    private int _pos;

    public FilterLexer(string input)
    {
        _input = input ?? string.Empty;
        _pos = 0;
    }

    public List<FilterToken> Tokenize()
    {
        var tokens = new List<FilterToken>();

        while (_pos < _input.Length)
        {
            char c = _input[_pos];

            if (char.IsWhiteSpace(c))
            {
                _pos++;
                continue;
            }

            int startPos = _pos;

            // Two-character symbols
            if (Match("==")) { tokens.Add(new FilterToken(TokenType.Equal, "==", startPos)); continue; }
            if (Match("!=")) { tokens.Add(new FilterToken(TokenType.NotEqual, "!=", startPos)); continue; }
            if (Match(">=")) { tokens.Add(new FilterToken(TokenType.GreaterThanOrEqual, ">=", startPos)); continue; }
            if (Match("<=")) { tokens.Add(new FilterToken(TokenType.LessThanOrEqual, "<=", startPos)); continue; }
            if (Match("&&")) { tokens.Add(new FilterToken(TokenType.And, "&&", startPos)); continue; }
            if (Match("||")) { tokens.Add(new FilterToken(TokenType.Or, "||", startPos)); continue; }

            // Single-character symbols
            if (c == '>') { _pos++; tokens.Add(new FilterToken(TokenType.GreaterThan, ">", startPos)); continue; }
            if (c == '<') { _pos++; tokens.Add(new FilterToken(TokenType.LessThan, "<", startPos)); continue; }
            if (c == '!') { _pos++; tokens.Add(new FilterToken(TokenType.Not, "!", startPos)); continue; }
            if (c == '(') { _pos++; tokens.Add(new FilterToken(TokenType.OpenParen, "(", startPos)); continue; }
            if (c == ')') { _pos++; tokens.Add(new FilterToken(TokenType.CloseParen, ")", startPos)); continue; }

            // String literals: "..." or '...'
            if (c == '"' || c == '\'')
            {
                tokens.Add(ReadStringLiteral(c, startPos));
                continue;
            }

            // Word, number, or identifier
            tokens.Add(ReadWordOrNumber(startPos));
        }

        tokens.Add(new FilterToken(TokenType.EndOfInput, "", _pos));
        return tokens;
    }

    private bool Match(string prefix)
    {
        if (_input.Length - _pos >= prefix.Length && _input.Substring(_pos, prefix.Length) == prefix)
        {
            _pos += prefix.Length;
            return true;
        }
        return false;
    }

    private FilterToken ReadStringLiteral(char quoteChar, int startPos)
    {
        _pos++; // skip opening quote
        var sb = new StringBuilder();
        while (_pos < _input.Length && _input[_pos] != quoteChar)
        {
            if (_input[_pos] == '\\' && _pos + 1 < _input.Length)
            {
                _pos++;
                sb.Append(_input[_pos]);
            }
            else
            {
                sb.Append(_input[_pos]);
            }
            _pos++;
        }

        if (_pos < _input.Length && _input[_pos] == quoteChar)
        {
            _pos++; // skip closing quote
        }

        return new FilterToken(TokenType.StringLiteral, sb.ToString(), startPos);
    }

    private FilterToken ReadWordOrNumber(int startPos)
    {
        var sb = new StringBuilder();
        while (_pos < _input.Length)
        {
            char c = _input[_pos];
            if (char.IsWhiteSpace(c) || c == '(' || c == ')' || c == '!' || c == '=' || c == '>' || c == '<' || c == '&' || c == '|')
                break;
            sb.Append(c);
            _pos++;
        }

        string val = sb.ToString();

        // Check keyword operators
        switch (val.ToLowerInvariant())
        {
            case "and": return new FilterToken(TokenType.And, val, startPos);
            case "or": return new FilterToken(TokenType.Or, val, startPos);
            case "not": return new FilterToken(TokenType.Not, val, startPos);
            case "eq": return new FilterToken(TokenType.Equal, val, startPos);
            case "ne": return new FilterToken(TokenType.NotEqual, val, startPos);
            case "gt": return new FilterToken(TokenType.GreaterThan, val, startPos);
            case "lt": return new FilterToken(TokenType.LessThan, val, startPos);
            case "ge": return new FilterToken(TokenType.GreaterThanOrEqual, val, startPos);
            case "le": return new FilterToken(TokenType.LessThanOrEqual, val, startPos);
            case "contains": return new FilterToken(TokenType.Contains, val, startPos);
        }

        // Check if IPv4 address (e.g. 192.168.1.1)
        if (IPAddress.TryParse(val, out _))
        {
            return new FilterToken(TokenType.IpAddress, val, startPos);
        }

        // Check if numeric (decimal or hex)
        if (val.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return new FilterToken(TokenType.Number, val, startPos);
        }

        if (long.TryParse(val, out _))
        {
            return new FilterToken(TokenType.Number, val, startPos);
        }

        return new FilterToken(TokenType.Identifier, val, startPos);
    }
}
