# SharpTrace 📡

> **Client-Side Network Packet Analyzer & Hex Inspector (Web-Based Mini-Wireshark)**  
> Built with **Blazor WebAssembly** on **.NET 8** | Zero Server Backend | Deployed directly to GitHub Pages

![SharpTrace Status](https://img.shields.io/badge/.NET-8.0-512bd4?style=flat-square&logo=dotnet)
![Blazor WebAssembly](https://img.shields.io/badge/Blazor-WASM-512bd4?style=flat-square&logo=blazor)
![Deployment](https://img.shields.io/badge/Deployment-GitHub%20Pages-22c55e?style=flat-square&logo=github)

---

## ⚡ Overview

**SharpTrace** is a browser-native network traffic analysis platform that decodes raw packet captures (`.pcap` and `.pcapng`) 100% client-side in WebAssembly. It delivers the speed and precision of desktop tools like Wireshark directly inside the browser with zero cloud ingestion, zero telemetry, and maximum data privacy.

### Key Capabilities
- **File Ingestion:** Drag-and-drop or select `.pcap` and `.pcapng` files (supports Little-Endian `0xa1b2c3d4`, Big-Endian `0xd4c3b2a1`, nanosecond timestamps, and PCAPNG Section/Interface/Enhanced Packet blocks).
- **Protocol Stack Decoders:**
  - **Link Layer:** Ethernet II (MAC source/destination, EtherType, 802.1Q VLAN).
  - **Internet Layer:** IPv4 (Header length, TTL, Protocol, Checksums, Flags, Fragmentation), IPv6 (Traffic Class, Flow Label, Hop Limit), ARP (Request/Reply, IP/MAC mappings), ICMP (Echo Request/Reply, code/type).
  - **Transport Layer:** TCP (Sequence/Ack, Flags [SYN/ACK/FIN/RST/PSH/URG], Window Size, MSS, Timestamps), UDP (Ports, Length, Checksum).
  - **Application Layer:** DNS (Full recursive query/answer parser with domain compression pointer support), HTTP/1.x (Request method, URI, Status code, Headers, Content-Type), TLS (Record types, handshake inspection, Server Name Indication [SNI] extraction).
- **Interactive Hex & ASCII Inspector:**
  - Synchronized hex addresses (`0000`, `0010`, etc.), 16 hex octets split into 8-byte groups, and ASCII translation.
  - **Linked Dynamic Highlighting:** Clicking on any protocol field or header in the decoded packet tree dynamically highlights the exact corresponding byte slice `[StartOffset..EndOffset]` in the Hex View.
  - Hover over any byte in the Hex view for instant offset, hex, decimal, binary, and ASCII inspection.
- **Wireshark-Style Query Filter Engine:**
  - Tokenizer, recursive-descent parser, and AST evaluator executing client-side with instant feedback.
  - Supports queries like `tcp.port == 443`, `ip.src == 192.168.1.1`, `ip.proto == tcp`, `frame.len > 100`, `dns`, `http`, `tls`, `arp`, `icmp`, `&&`, `||`, `!`.
- **Pre-Loaded Sample Datasets:**
  - 3 built-in simulated captures: "DNS Lookup", "TCP 3-Way Handshake & TLS", "HTTP GET Request & Response" with ICMP ping.
- **Metrics & Analytics Dashboard:**
  - Protocol distribution breakdown with visual bars (% TCP vs UDP vs DNS vs HTTP vs TLS).
  - Total packets, total bytes, duration, estimated throughput (kbps), top talkers IP frequency table, and conversation pairs.
- **High-Performance Architecture:**
  - Zero/low-allocation parsing with `ReadOnlySpan<byte>` and `BinaryPrimitives`.
  - Non-blocking asynchronous processing with `Task.Run` and Blazor `<Virtualize>` component.

---

## 🏗️ Architecture

```
SharpTrace/
├── Core/
│   ├── Filters/          # Lexer, AST nodes, parser, and query evaluator
│   │   ├── FilterAst.cs
│   │   ├── FilterEvaluator.cs
│   │   ├── FilterLexer.cs
│   │   ├── FilterParser.cs
│   │   └── FilterToken.cs
│   ├── Models/           # Packet abstractions, header fields, highlight ranges
│   │   ├── ByteHighlightRange.cs
│   │   ├── PacketField.cs
│   │   ├── PacketHeader.cs
│   │   ├── PacketModel.cs
│   │   └── ProtocolTypes.cs
│   ├── Parsers/          # Endian-safe binary decoders using ReadOnlySpan<byte>
│   │   ├── Application/  # DNS, HTTP/1.x, TLS Record & Client Hello SNI
│   │   ├── Internet/     # IPv4, IPv6, ARP, ICMP
│   │   ├── Link/         # Ethernet II & 802.1Q VLAN
│   │   ├── Transport/    # TCP & UDP
│   │   ├── CaptureFileParser.cs
│   │   ├── PacketDecoder.cs
│   │   ├── PcapNgParser.cs
│   │   └── PcapParser.cs
│   └── Samples/          # Authentic byte generators for instant sample captures
├── Components/
│   ├── FilterBar.razor           # Display filter input with real-time validation
│   ├── HexView.razor             # Offset / Hex / ASCII dump with linked highlighting
│   ├── PacketDetailsTree.razor   # Hierarchical collapsible protocol stack tree
│   ├── PacketList.razor          # Virtualized packet table with Wireshark colors
│   └── StatisticsModal.razor     # Protocol distribution & top talkers dialog
├── Pages/
│   └── Index.razor               # 3-pane responsive dashboard layout
└── .github/workflows/
    └── deploy.yml                # Automated CI/CD pipeline for GitHub Pages
```

---

## 🔍 Display Filter Syntax Reference

| Filter Query | Description |
| :--- | :--- |
| `tcp` | Shows all TCP packets |
| `udp` | Shows all UDP packets |
| `dns` | Shows all DNS queries and responses |
| `http` | Shows all HTTP requests and responses |
| `tls` | Shows all TLS records (Handshake, Client Hello, etc.) |
| `icmp` | Shows ICMP Echo requests and replies |
| `arp` | Shows ARP requests and replies |
| `tcp.port == 443` | Packets where either source or destination port is 443 |
| `ip.src == 192.168.1.1` | Packets originating from 192.168.1.1 |
| `ip.dst == 8.8.8.8` | Packets directed to 8.8.8.8 |
| `ip.addr == 10.0.0.1` | Packets where either source or destination is 10.0.0.1 |
| `frame.len > 100` | Packets larger than 100 bytes |
| `ip.proto == tcp && frame.len >= 64` | Combined logical boolean filtering |
| `!dns && !icmp` | Negation operator |

---

## 🚀 Local Development

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Run Locally
```bash
# Clone the repository
git clone https://github.com/deeyeti/SharpTrace.git
cd SharpTrace

# Run the development server
dotnet run
```
Navigate to `http://localhost:5000` (or the URL printed in the console).

### Build for Production
```bash
dotnet publish SharpTrace.csproj -c Release -o output
```

---

## 🌐 GitHub Pages Deployment

The repository includes an automated GitHub Actions workflow (`.github/workflows/deploy.yml`):
1. Runs `dotnet publish` targeting `net8.0`.
2. Automatically rewrites `<base href="/" />` to `<base href="/SharpTrace/" />`.
3. Creates `404.html` and `.nojekyll` for client-side routing.
4. Publishes to GitHub Pages via `actions/deploy-pages`.

To enable GitHub Pages in your repo:
1. Go to **Settings** > **Pages**.
2. Under **Build and deployment** > **Source**, choose **GitHub Actions**.
3. Push to `main` branch to trigger immediate automated deployment!
