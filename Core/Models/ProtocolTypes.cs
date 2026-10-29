namespace SharpTrace.Core.Models;

public static class EtherTypes
{
    public const ushort IPv4 = 0x0800;
    public const ushort ARP = 0x0806;
    public const ushort WakeOnLan = 0x0842;
    public const ushort Rarp = 0x8035;
    public const ushort Dot1Q_Vlan = 0x8100;
    public const ushort IPv6 = 0x86DD;
    public const ushort QinQ = 0x88A8;
    public const ushort LLDP = 0x88CC;

    public static string GetName(ushort etherType) => etherType switch
    {
        IPv4 => "IPv4 (0x0800)",
        ARP => "ARP (0x0806)",
        WakeOnLan => "Wake-on-LAN (0x0842)",
        Rarp => "RARP (0x8035)",
        Dot1Q_Vlan => "802.1Q VLAN (0x8100)",
        IPv6 => "IPv6 (0x86DD)",
        QinQ => "802.1ad QinQ (0x88A8)",
        LLDP => "LLDP (0x88CC)",
        _ => $"Unknown (0x{etherType:X4})"
    };
}

public static class IpProtocols
{
    public const byte HopByHop = 0;
    public const byte ICMP = 1;
    public const byte IGMP = 2;
    public const byte IPv4 = 4;
    public const byte TCP = 6;
    public const byte UDP = 17;
    public const byte IPv6 = 41;
    public const byte IPv6Route = 43;
    public const byte IPv6Frag = 44;
    public const byte GRE = 47;
    public const byte ESP = 50;
    public const byte AH = 51;
    public const byte ICMPv6 = 58;
    public const byte IPv6NoNext = 59;
    public const byte IPv6Opts = 60;
    public const byte OSPF = 89;
    public const byte SCTP = 132;

    public static string GetName(byte protocol) => protocol switch
    {
        ICMP => "ICMP",
        IGMP => "IGMP",
        IPv4 => "IPv4",
        TCP => "TCP",
        UDP => "UDP",
        IPv6 => "IPv6",
        GRE => "GRE",
        ESP => "ESP",
        AH => "AH",
        ICMPv6 => "ICMPv6",
        OSPF => "OSPF",
        SCTP => "SCTP",
        _ => $"Proto-{protocol}"
    };
}

[Flags]
public enum TcpFlags : ushort
{
    None = 0,
    FIN = 1 << 0,
    SYN = 1 << 1,
    RST = 1 << 2,
    PSH = 1 << 3,
    ACK = 1 << 4,
    URG = 1 << 5,
    ECE = 1 << 6,
    CWR = 1 << 7,
    NS  = 1 << 8
}
