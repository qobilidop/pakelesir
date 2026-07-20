"""Ethernet -> {IPv4 (with options) | IPv6} -> {TCP | UDP}, authored in the eDSL.

The canonical hello-world example. It *branches*: EtherType demuxes to
IPv4 or IPv6, and each IP header demuxes to a shared TCP or UDP successor
(a join in the parse DAG) — so it teaches demultiplexing, not just
field-mapping. A field-for-field port of the Rust builder description
(src/examples.rs); the conformance test asserts proto equality with the
committed gallery `ir.json`.

IPv6 addresses are 128-bit, above the fixed-`bits` ceiling, so they are
`var_bytes` opaque runs (rendered as hex; not tshark-diffed).
"""

from pakeles import Header, Parser, bits, extract, parser, reject, var_bytes
from pakeles.fmt import DEC, ETHER, HEX, IPV4


class Ethernet(Header):
    dst = bits(48, "Destination", ETHER, tshark="eth.dst")
    src = bits(48, "Source", ETHER, tshark="eth.src")
    ethertype = bits(
        16,
        "Type",
        HEX,
        tshark="eth.type",
        labels={
            0x0800: "IPv4",
            0x0806: "ARP",
            0x8100: "802.1Q VLAN",
            0x86DD: "IPv6",
        },
    )


class IPv4(Header):
    version = bits(4, "Version", DEC, tshark="ip.version")
    ihl = bits(4, "Header Length", DEC, doc="in 32-bit words")
    dscp = bits(6, "DSCP", DEC)
    ecn = bits(2, "ECN", DEC)
    total_len = bits(16, "Total Length", DEC, tshark="ip.len")
    id = bits(16, "Identification", HEX)
    flags = bits(3, "Flags", HEX)
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl = bits(8, "Time to Live", DEC, tshark="ip.ttl")
    protocol = bits(
        8,
        "Protocol",
        DEC,
        tshark="ip.proto",
        labels={1: "ICMP", 6: "TCP", 17: "UDP"},
    )
    checksum = bits(16, "Header Checksum", HEX, tshark="ip.checksum")
    src = bits(32, "Source Address", IPV4, tshark="ip.src")
    dst = bits(32, "Destination Address", IPV4, tshark="ip.dst")
    options = var_bytes(ihl * 4 - 20)


class IPv6(Header):
    version = bits(4, "Version", DEC, tshark="ipv6.version")
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_length = bits(16, "Payload Length", DEC, tshark="ipv6.plen")
    next_header = bits(
        8,
        "Next Header",
        DEC,
        tshark="ipv6.nxt",
        labels={1: "ICMP", 6: "TCP", 17: "UDP"},
    )
    hop_limit = bits(8, "Hop Limit", DEC, tshark="ipv6.hlim")
    # 128-bit addresses exceed the fixed-`bits` ceiling: opaque 16-byte runs.
    src = var_bytes(16)
    dst = var_bytes(16)


class TCP(Header):
    sport = bits(16, "Source Port", DEC, tshark="tcp.srcport")
    dport = bits(16, "Destination Port", DEC, tshark="tcp.dstport")
    seq = bits(32, "Sequence Number", DEC)
    ack = bits(32, "Acknowledgment Number", DEC)
    data_offset = bits(4, "Data Offset", DEC, doc="in 32-bit words")
    reserved = bits(4, "Reserved", HEX)
    flags = bits(8, "Flags", HEX)
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent = bits(16, "Urgent Pointer", DEC)


class UDP(Header):
    sport = bits(16, "Source Port", DEC, tshark="udp.srcport")
    dport = bits(16, "Destination Port", DEC, tshark="udp.dstport")
    length = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


def eth_ipvx_l4() -> Parser:
    return parser(
        "eth_ipvx_l4",
        max_depth=4,
        start="parse_ethernet",
        states={
            "parse_ethernet": extract(Ethernet).select(
                Ethernet.ethertype,
                {0x0800: "parse_ipv4", 0x86DD: "parse_ipv6"},
                default=reject("unsupported ethertype", info=True),
            ),
            "parse_ipv4": extract(IPv4).select(
                IPv4.protocol,
                {6: "parse_tcp", 17: "parse_udp"},
                default=reject("unsupported ip protocol", info=True),
            ),
            "parse_ipv6": extract(IPv6).select(
                IPv6.next_header,
                {6: "parse_tcp", 17: "parse_udp"},
                default=reject("unsupported ip protocol", info=True),
            ),
            "parse_tcp": extract(TCP).accept(),
            "parse_udp": extract(UDP).accept(),
        },
    )


if __name__ == "__main__":
    print(eth_ipvx_l4().to_json())
