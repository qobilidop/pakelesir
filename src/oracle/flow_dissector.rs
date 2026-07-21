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
    #[serde(default)]
    pub flow_label: u32,
    #[serde(default)]
    pub is_frag: bool,
    #[serde(default)]
    pub is_first_frag: bool,
}

/// Kernel verdict for a corpus packet: did the flow dissector produce a
/// flow key (`BPF_OK`) or drop (`BPF_DROP`)? v1 goldens predate the field
/// and were all accepts — hence the serde default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    #[default]
    Ok,
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub packet_hex: String,
    #[serde(default)]
    pub disposition: Disposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<FlowKeys>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub kernel_version: String,
    pub keys_subset: Vec<String>,
    pub entries: Vec<GoldenEntry>,
}

/// Run the interpreter and project an Accept result to the rung-0
/// `FlowKeys`. `None` if the parse rejects (no flow key).
#[allow(clippy::field_reassign_with_default)]
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
    // Kernel PROG(VLAN) rewrites n_proto to the inner encapsulated proto;
    // vlan_q is the final tag on every VLAN path (the AD path's C-tag or
    // the single Q tag), so its encapsulated_proto is authoritative.
    k.n_proto = u("vlan_q", "encapsulated_proto")
        .or_else(|| u("ethernet", "ethertype"))
        .unwrap_or(0) as u16;
    if let Some(h) = hdr("ipv4") {
        k.addr_proto = 0x0800;
        k.nhoff = (h.start_bit / 8) as u16;
        k.ip_proto = u("ipv4", "protocol").unwrap_or(0) as u8;
        k.ipv4_src = format!("{:08x}", u("ipv4", "src").unwrap_or(0));
        k.ipv4_dst = format!("{:08x}", u("ipv4", "dst").unwrap_or(0));
    } else if let Some(h) = hdr("ipv6") {
        k.addr_proto = 0x86DD;
        k.nhoff = (h.start_bit / 8) as u16;
        k.ip_proto = u("ipv6", "next_header").unwrap_or(0) as u8;
        k.ipv6_src = bytes("ipv6", "src").map(hex).unwrap_or_default();
        k.ipv6_dst = bytes("ipv6", "dst").map(hex).unwrap_or_default();
    } else if let Some(h) = hdr("mpls") {
        // Kernel PROG(MPLS): single-entry read, no key updates — nhoff and
        // thoff stay at the MPLS header start; addr_proto/ports stay 0.
        k.nhoff = (h.start_bit / 8) as u16;
        k.thoff = k.nhoff;
        return Ok(Some(k));
    }
    // Reachability: Accept through an IP path implies exactly one of
    // {tcp, udp} was extracted (unchanged from rung 0).
    let t_inst = if hdr("tcp").is_some() { "tcp" } else { "udp" };
    k.thoff = (hdr(t_inst).map(|h| h.start_bit).unwrap_or(0) / 8) as u16;
    k.sport = u(t_inst, "sport").unwrap_or(0) as u16;
    k.dport = u(t_inst, "dport").unwrap_or(0) as u16;
    Ok(Some(k))
}

fn hex(b: Vec<u8>) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Report from diffing our projected `flow_keys` against a `GoldenFile`.
pub struct FlowDiffReport {
    pub compared: usize,
    pub mismatches: Vec<String>,
}

/// Stringify one `keys_subset` field from both `ours` and `golden` for
/// comparison. Unknown field names surface as a guaranteed mismatch rather
/// than silently passing.
fn field_pair(name: &str, ours: &FlowKeys, golden: &FlowKeys) -> (String, String) {
    match name {
        "nhoff" => (ours.nhoff.to_string(), golden.nhoff.to_string()),
        "thoff" => (ours.thoff.to_string(), golden.thoff.to_string()),
        "n_proto" => (ours.n_proto.to_string(), golden.n_proto.to_string()),
        "addr_proto" => (ours.addr_proto.to_string(), golden.addr_proto.to_string()),
        "ip_proto" => (ours.ip_proto.to_string(), golden.ip_proto.to_string()),
        "sport" => (ours.sport.to_string(), golden.sport.to_string()),
        "dport" => (ours.dport.to_string(), golden.dport.to_string()),
        "ipv4_src" => (ours.ipv4_src.clone(), golden.ipv4_src.clone()),
        "ipv4_dst" => (ours.ipv4_dst.clone(), golden.ipv4_dst.clone()),
        "ipv6_src" => (ours.ipv6_src.clone(), golden.ipv6_src.clone()),
        "ipv6_dst" => (ours.ipv6_dst.clone(), golden.ipv6_dst.clone()),
        "flow_label" => (ours.flow_label.to_string(), golden.flow_label.to_string()),
        "is_frag" => (ours.is_frag.to_string(), golden.is_frag.to_string()),
        "is_first_frag" => (
            ours.is_first_frag.to_string(),
            golden.is_first_frag.to_string(),
        ),
        _ => ("<unknown-field>".into(), name.into()),
    }
}

/// The conformance directory holding the committed goldens, shared by the
/// CLI's default `--goldens` resolution and the `committed_goldens_agree`
/// gate test.
pub const CONFORMANCE_DIR: &str = "examples/linux_flow_dissector/conformance";

/// Find the committed kernel-captured golden file under `dir` (filename
/// starts with `flow_keys.linux-`). Shared by the CLI's default `--goldens`
/// resolution and the `committed_goldens_agree` gate test.
// TODO(rung-2): when multiple kernel-version goldens exist, diff all or
// pick/pin deterministically (find() order is unspecified).
pub fn discover_committed_golden(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("flow_keys.linux-"))
        })
}

/// Diff our `project`ed `flow_keys` against a golden file's entries, over
/// the golden's declared `keys_subset` fields.
pub fn diff_goldens(ir: &pb::Ir, golden: &GoldenFile) -> anyhow::Result<FlowDiffReport> {
    let mut report = FlowDiffReport {
        compared: 0,
        mismatches: Vec::new(),
    };
    for (i, e) in golden.entries.iter().enumerate() {
        let pkt = crate::testvec::hex_decode(&e.packet_hex)?;
        let ours = project(ir, &pkt)?;
        report.compared += 1;
        match (e.disposition, ours) {
            (Disposition::Drop, None) => {} // agree: kernel drops, we reject
            (Disposition::Drop, Some(_)) => report
                .mismatches
                .push(format!("vector {i}: disposition: ours=accept golden=drop")),
            (Disposition::Ok, None) => report
                .mismatches
                .push(format!("vector {i}: disposition: ours=reject golden=ok")),
            (Disposition::Ok, Some(ours)) => {
                let golden_keys = e.keys.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("vector {i}: ok entry without keys — malformed golden")
                })?;
                for field in &golden.keys_subset {
                    let (o, t) = field_pair(field, &ours, golden_keys);
                    if o != t {
                        report
                            .mismatches
                            .push(format!("vector {i}: {field}: ours={o} golden={t}"));
                    }
                }
            }
        }
    }
    Ok(report)
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
                disposition: Disposition::Ok,
                keys: Some(FlowKeys {
                    nhoff: 14,
                    ..Default::default()
                }),
            }],
        };
        let s = serde_json::to_string(&g).unwrap();
        let back: GoldenFile = serde_json::from_str(&s).unwrap();
        assert_eq!(back.entries[0].keys.as_ref().unwrap().nhoff, 14);
        assert_eq!(back.kernel_version, "6.8.0");
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;

    fn hexpkt(s: &str) -> Vec<u8> {
        crate::testvec::hex_decode(s).unwrap()
    }

    #[test]
    fn projects_single_vlan_v4_tcp() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff112233445566810000640800\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 18); // 14 + one 4-byte tag
        assert_eq!(k.thoff, 38);
        assert_eq!(k.n_proto, 0x0800); // kernel: inner encapsulated proto
        assert_eq!(k.addr_proto, 0x0800);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_qinq_v4_tcp() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff11223344556688a80064810000650800\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 22); // 14 + two tags
        assert_eq!(k.thoff, 42);
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.addr_proto, 0x0800);
    }

    #[test]
    fn projects_mpls_stop() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff112233445566884700064140\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 14); // kernel PROG(MPLS) leaves thoff untouched
        assert_eq!(k.n_proto, 0x8847);
        assert_eq!(k.addr_proto, 0); // set only by the IP progs upstream
        assert_eq!(k.ip_proto, 0);
        assert_eq!(k.sport, 0);
        assert_eq!(k.dport, 0);
        assert_eq!(k.ipv4_src, "");
        assert_eq!(k.ipv6_src, "");
    }

    #[test]
    fn projects_vlan_then_mpls() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff11223344556681000064884700064140\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 18);
        assert_eq!(k.thoff, 18);
        assert_eq!(k.n_proto, 0x8847);
        assert_eq!(k.addr_proto, 0);
    }

    #[test]
    fn triple_tag_rejects() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff11223344556688a800648100006581000066\
             080045000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        assert!(project(&ir, &pkt).unwrap().is_none());
    }

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

#[cfg(test)]
mod diff_tests {
    use super::*;
    fn golden_from_fixture() -> GoldenFile {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = crate::fixtures::tcp_packet();
        let keys = super::project(&ir, &pkt).unwrap().unwrap();
        GoldenFile {
            kernel_version: "test".into(),
            keys_subset: vec![
                "nhoff".into(),
                "thoff".into(),
                "sport".into(),
                "dport".into(),
            ],
            entries: vec![GoldenEntry {
                packet_hex: pkt.iter().map(|b| format!("{b:02x}")).collect(),
                disposition: Disposition::Ok,
                keys: Some(keys),
            }],
        }
    }
    #[test]
    fn diff_green_on_self() {
        let ir = crate::examples::linux_flow_dissector();
        let report = diff_goldens(&ir, &golden_from_fixture()).unwrap();
        assert_eq!(report.compared, 1);
        assert!(report.mismatches.is_empty(), "{:#?}", report.mismatches);
    }
    #[test]
    fn diff_catches_mismatch() {
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].keys.as_mut().unwrap().dport = 1; // corrupt
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
    }
    #[test]
    fn drop_entry_agrees_when_we_reject() {
        // ARP ethertype: kernel drops, our parse rejects — agreement.
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].packet_hex = "aabbccddeeff1122334455660806000108000604000111223344\
             55660a000001aabbccddeeff0a000002"
            .into();
        g.entries[0].disposition = Disposition::Drop;
        g.entries[0].keys = None;
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.compared, 1);
        assert!(report.mismatches.is_empty(), "{:#?}", report.mismatches);
    }
    #[test]
    fn drop_entry_mismatches_when_we_accept() {
        // Kernel claims drop on a packet we accept -> disagreement.
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].disposition = Disposition::Drop;
        g.entries[0].keys = None;
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
        assert!(report.mismatches[0].contains("disposition"));
    }
    #[test]
    fn ok_entry_mismatches_when_we_reject() {
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].packet_hex = "aabbcc".into(); // truncated -> we reject
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
        assert!(report.mismatches[0].contains("disposition"));
    }
    #[test]
    fn v2_golden_without_v3_fields_still_parses() {
        // A v2 "ok" entry lacking flow_label/is_frag/is_first_frag must
        // deserialize with those fields defaulted (0 / false).
        let s = r#"{"kernel_version":"6.8.0","keys_subset":["nhoff"],
            "entries":[{"packet_hex":"aabb","disposition":"ok","keys":{"nhoff":14,
            "thoff":0,"n_proto":0,"addr_proto":0,"ip_proto":0,"sport":0,"dport":0,
            "ipv4_src":"","ipv4_dst":"","ipv6_src":"","ipv6_dst":""}}]}"#;
        let g: GoldenFile = serde_json::from_str(s).unwrap();
        let k = g.entries[0].keys.as_ref().unwrap();
        assert_eq!(k.flow_label, 0);
        assert!(!k.is_frag);
        assert!(!k.is_first_frag);
    }
    #[test]
    fn v1_golden_without_disposition_still_parses() {
        let s = r#"{"kernel_version":"6.8.0","keys_subset":["nhoff"],
            "entries":[{"packet_hex":"aabb","keys":{"nhoff":14,"thoff":0,
            "n_proto":0,"addr_proto":0,"ip_proto":0,"sport":0,"dport":0,
            "ipv4_src":"","ipv4_dst":"","ipv6_src":"","ipv6_dst":""}}]}"#;
        let g: GoldenFile = serde_json::from_str(s).unwrap();
        assert_eq!(g.entries[0].disposition, Disposition::Ok);
        assert_eq!(g.entries[0].keys.as_ref().unwrap().nhoff, 14);
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    /// Rung 1's definition of done: Pakeles's projected `flow_keys` agree
    /// with the kernel-captured goldens committed in
    /// `examples/linux_flow_dissector/conformance/` — goldens minted from
    /// upstream `bpf_flow.c` itself, covering the full corpus including
    /// VLAN/MPLS and agreement on kernel drops, not just accepts. If this
    /// fails, that's a real disagreement between our parse/projection and
    /// the kernel — investigate; do NOT edit the golden file to force
    /// green.
    #[test]
    fn committed_goldens_agree() {
        let dir = std::path::Path::new(CONFORMANCE_DIR);
        let golden_path = discover_committed_golden(dir).expect("a committed golden file exists");
        let g: GoldenFile =
            serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
        let report = diff_goldens(&crate::examples::linux_flow_dissector(), &g).unwrap();
        let ok = g
            .entries
            .iter()
            .filter(|e| e.disposition == Disposition::Ok)
            .count();
        let drop = g.entries.len() - ok;
        assert!(
            ok >= 9 && drop >= 4,
            "corpus shape shrank: {ok} ok / {drop} drop entries"
        );
        assert_eq!(report.compared, g.entries.len());
        assert!(
            report.mismatches.is_empty(),
            "Pakeles disagrees with the kernel flow dissector:\n{}",
            report.mismatches.join("\n")
        );
    }
}
