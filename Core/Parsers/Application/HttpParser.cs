using System.Text;
using SharpTrace.Core.Models;

namespace SharpTrace.Core.Parsers.Application;

public static class HttpParser
{
    private static readonly string[] Methods = { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT" };

    public static bool TryParse(ReadOnlySpan<byte> data, int offset, int length, PacketModel packet)
    {
        if (length < 10 || data.Length < offset + length)
            return false;

        string asciiPrefix = Encoding.ASCII.GetString(data.Slice(offset, Math.Min(length, 16)));
        bool isRequest = Methods.Any(m => asciiPrefix.StartsWith(m + " "));
        bool isResponse = asciiPrefix.StartsWith("HTTP/1.");

        if (!isRequest && !isResponse)
            return false;

        string fullText = Encoding.ASCII.GetString(data.Slice(offset, length));
        int headerEndIndex = fullText.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        int headerLength = headerEndIndex != -1 ? headerEndIndex + 4 : length;

        string headerSection = headerEndIndex != -1 ? fullText.Substring(0, headerEndIndex) : fullText;
        var lines = headerSection.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

        if (lines.Length == 0)
            return false;

        packet.Protocol = "HTTP";
        packet.Protocols.Add("http");
        packet.ColorClass = "proto-http";

        var header = new PacketHeader("Hypertext Transfer Protocol", lines[0], offset, headerLength);

        string firstLine = lines[0];
        header.AddField("Request/Status Line", firstLine, offset, lines[0].Length, firstLine);

        if (isRequest)
        {
            var parts = firstLine.Split(' ');
            if (parts.Length >= 2)
            {
                string method = parts[0];
                string uri = parts[1];
                packet.SetFilterField("http.request.method", method);
                packet.SetFilterField("http.request.uri", uri);
                packet.Info = $"{method} {uri} {(parts.Length > 2 ? parts[2] : "")}";
            }
        }
        else if (isResponse)
        {
            var parts = firstLine.Split(' ', 3);
            if (parts.Length >= 2 && int.TryParse(parts[1], out int statusCode))
            {
                string reason = parts.Length > 2 ? parts[2] : "";
                packet.SetFilterField("http.response.code", statusCode);
                packet.Info = $"HTTP/1.1 {statusCode} {reason}";
            }
        }

        int currentLineOffset = offset + lines[0].Length + 2;
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            int colonIdx = line.IndexOf(':');
            if (colonIdx > 0)
            {
                string key = line.Substring(0, colonIdx).Trim();
                string val = line.Substring(colonIdx + 1).Trim();

                if (key.Equals("Host", StringComparison.OrdinalIgnoreCase))
                    packet.SetFilterField("http.host", val);
                else if (key.Equals("User-Agent", StringComparison.OrdinalIgnoreCase))
                    packet.SetFilterField("http.user_agent", val);
                else if (key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                    packet.SetFilterField("http.content_type", val);

                header.AddField(key, $"{key}: {val}", currentLineOffset, line.Length, val);
            }
            else
            {
                header.AddField("Header", line, currentLineOffset, line.Length, line);
            }
            currentLineOffset += line.Length + 2;
        }

        int bodyLen = length - headerLength;
        if (bodyLen > 0)
        {
            header.AddField("File Data", $"HTTP Payload ({bodyLen} bytes)", offset + headerLength, bodyLen);
        }

        packet.Headers.Add(header);
        return true;
    }
}
