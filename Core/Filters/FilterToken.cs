namespace SharpTrace.Core.Filters;

public enum TokenType
{
    Identifier,
    Number,
    StringLiteral,
    IpAddress,

    // Comparison Operators
    Equal,              // == or eq
    NotEqual,           // != or ne
    GreaterThan,        // > or gt
    LessThan,           // < or lt
    GreaterThanOrEqual, // >= or ge
    LessThanOrEqual,    // <= or le
    Contains,           // contains

    // Logical Operators
    And,                // && or and
    Or,                 // || or or
    Not,                // ! or not

    // Grouping
    OpenParen,          // (
    CloseParen,         // )

    EndOfInput
}

public record FilterToken(TokenType Type, string Value, int Position);
