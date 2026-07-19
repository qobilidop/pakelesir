"""Ethernet -> IPv4 (with options) -> TCP, authored in the Python eDSL.

Field-for-field port of the Rust builder description (src/examples.rs);
the conformance test asserts proto equality with the committed gallery
`ir.json`.
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


def eth_ipv4_tcp() -> Parser:
    return parser(
        "eth_ipv4_tcp",
        max_depth=4,
        start="parse_ethernet",
        states={
            "parse_ethernet": extract(Ethernet).select(
                Ethernet.ethertype,
                {0x0800: "parse_ipv4"},
                default=reject("unsupported ethertype", info=True),
            ),
            "parse_ipv4": extract(IPv4).select(
                IPv4.protocol,
                {6: "parse_tcp"},
                default=reject("unsupported ip protocol", info=True),
            ),
            "parse_tcp": extract(TCP).accept(),
        },
    )
