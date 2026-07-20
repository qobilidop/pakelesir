//! Flow-dissector differential oracle: our parse (projected to bpf_flow_keys)
//! vs golden flow_keys captured from a flow dissector run in the kernel via
//! BPF_PROG_TEST_RUN. Rung 0: eth/IPv4/IPv6/TCP/UDP subset.
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
