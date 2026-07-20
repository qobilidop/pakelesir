//! Flow-dissector differential oracle: our parse (projected to bpf_flow_keys)
//! vs golden flow_keys captured from a flow dissector run in the kernel via
//! BPF_PROG_TEST_RUN. Rung 0: eth/IPv4/IPv6/TCP/UDP subset.
use crate::ir::pb;
use serde::{Deserialize, Serialize};

/// The rung-0 subset of `struct bpf_flow_keys`. Addresses are lowercase
/// hex (ipv4 = 8 chars, ipv6 = 32 chars, empty if absent); ports and
/// protocols are host-order integers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowKeys {
    pub nhoff: u16,
    pub thoff: u16,
    pub n_proto: u16,
    pub addr_proto: u16,
    pub ip_proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub ipv4_src: String,
    pub ipv4_dst: String,
    pub ipv6_src: String,
    pub ipv6_dst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub packet_hex: String,
    pub keys: FlowKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub kernel_version: String,
    pub keys_subset: Vec<String>,
    pub entries: Vec<GoldenEntry>,
}

/// Run the interpreter and project an Accept result to the rung-0
/// `FlowKeys`. `None` if the parse rejects (no flow key).
pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<Option<FlowKeys>> {
    let res = crate::interp::run(ir, packet)?;
    if !matches!(res.outcome, crate::interp::Outcome::Accept) {
        return Ok(None);
    }
    let hdr = |inst: &str| res.headers.iter().find(|h| h.instance == inst);
    let u = |inst: &str, f: &str| -> Option<u64> {
        hdr(inst)?
            .fields
            .iter()
            .find(|x| x.name == f)
            .and_then(|x| match &x.value {
                crate::interp::FieldValue::Uint(v) => Some(*v),
                _ => None,
            })
    };
    let bytes = |inst: &str, f: &str| -> Option<Vec<u8>> {
        hdr(inst)?
            .fields
            .iter()
            .find(|x| x.name == f)
            .and_then(|x| match &x.value {
                crate::interp::FieldValue::Bytes(b) => Some(b.clone()),
                _ => None,
            })
    };
    let mut k = FlowKeys::default();
    k.n_proto = u("ethernet", "ethertype").unwrap_or(0) as u16;
    k.addr_proto = k.n_proto;
    // Fallback to ipv6 if ipv4 absent: sound because rung-0 IR reachability
    // guarantees Accept implies exactly one of {ipv4, ipv6} was extracted.
    let ip_inst = if hdr("ipv4").is_some() {
        "ipv4"
    } else {
        "ipv6"
    };
    k.nhoff = (hdr(ip_inst).map(|h| h.start_bit).unwrap_or(0) / 8) as u16;
    if ip_inst == "ipv4" {
        k.ip_proto = u("ipv4", "protocol").unwrap_or(0) as u8;
        k.ipv4_src = format!("{:08x}", u("ipv4", "src").unwrap_or(0));
        k.ipv4_dst = format!("{:08x}", u("ipv4", "dst").unwrap_or(0));
    } else {
        k.ip_proto = u("ipv6", "next_header").unwrap_or(0) as u8;
        k.ipv6_src = bytes("ipv6", "src").map(hex).unwrap_or_default();
        k.ipv6_dst = bytes("ipv6", "dst").map(hex).unwrap_or_default();
    }
    // Fallback to udp if tcp absent: sound because rung-0 IR reachability
    // guarantees Accept implies exactly one of {tcp, udp} was extracted.
    let t_inst = if hdr("tcp").is_some() { "tcp" } else { "udp" };
    k.thoff = (hdr(t_inst).map(|h| h.start_bit).unwrap_or(0) / 8) as u16;
    k.sport = u(t_inst, "sport").unwrap_or(0) as u16;
    k.dport = u(t_inst, "dport").unwrap_or(0) as u16;
    Ok(Some(k))
}

fn hex(b: Vec<u8>) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_file_roundtrips() {
        let g = GoldenFile {
            kernel_version: "6.8.0".into(),
            keys_subset: vec!["nhoff".into()],
            entries: vec![GoldenEntry {
                packet_hex: "aabb".into(),
                keys: FlowKeys {
                    nhoff: 14,
                    ..Default::default()
                },
            }],
        };
        let s = serde_json::to_string(&g).unwrap();
        let back: GoldenFile = serde_json::from_str(&s).unwrap();
        assert_eq!(back.entries[0].keys.nhoff, 14);
        assert_eq!(back.kernel_version, "6.8.0");
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;
    #[test]
    fn projects_v4_tcp_fixture() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = crate::fixtures::tcp_packet(); // eth/ipv4/tcp, sport 12345 dport 443
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 34);
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv4_src, "0a000001");
        assert_eq!(k.ipv4_dst, "0a000002");
    }

    #[test]
    fn projects_v6_tcp_fixture() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = crate::fixtures::ipv6_tcp_packet(); // eth/ipv6/tcp
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 54);
        assert_eq!(k.n_proto, 0x86dd);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv6_src, "20010db8000000000000000000000001");
        assert_eq!(k.ipv6_dst, "20010db8000000000000000000000002");
        assert_eq!(k.ipv4_src, "");
        assert_eq!(k.ipv4_dst, "");
    }

    #[test]
    fn projects_v4_udp_fixture() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = crate::fixtures::udp_packet(); // eth/ipv4/udp, sport 12345 dport 443
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 34);
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.ip_proto, 17);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv4_src, "0a000001");
        assert_eq!(k.ipv4_dst, "0a000002");
    }
}
