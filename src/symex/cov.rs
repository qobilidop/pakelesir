//! Path coverage: which enumerated paths does a pcap corpus exercise?

use super::engine::enumerate;
use super::pathid::path_id;
use super::z3solver::Z3Solver;
use crate::ir::pb;
use std::collections::BTreeMap;
use std::path::Path;

pub struct Coverage {
    pub total: usize,
    /// path id -> packet hit count (exercised paths only).
    pub hits: BTreeMap<String, usize>,
    pub unexercised: Vec<String>,
    pub packets: usize,
}

pub fn coverage(ir: &pb::Ir, pcap: &Path) -> anyhow::Result<Coverage> {
    let mut solver = Z3Solver::new();
    let enumeration = enumerate(ir, &mut solver)?;
    let all_ids: std::collections::BTreeSet<String> =
        enumeration.paths.iter().map(|p| p.id.clone()).collect();

    let packets = crate::pcapio::read_packets(pcap)?;
    let mut hits: BTreeMap<String, usize> = BTreeMap::new();
    for packet in &packets {
        let result = crate::interp::run(ir, packet)?;
        let id = path_id(ir, &result)?;
        if !all_ids.contains(&id) {
            anyhow::bail!("packet mapped to unknown path `{id}` — pathid/engine divergence");
        }
        *hits.entry(id).or_default() += 1;
    }
    let unexercised = all_ids
        .iter()
        .filter(|id| !hits.contains_key(*id))
        .cloned()
        .collect();
    Ok(Coverage {
        total: all_ids.len(),
        hits,
        unexercised,
        packets: packets.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::examples::eth_ipvx_l4;

    #[test]
    fn fixture_pcap_coverage() {
        let cov = coverage(&eth_ipvx_l4(), Path::new("testdata/basic.pcap")).unwrap();
        assert_eq!(cov.packets, 4);
        assert_eq!(cov.total, 244);
        let ids: Vec<&str> = cov.hits.keys().map(String::as_str).collect();
        assert_eq!(
            ids,
            vec![
                "parse_ethernet/!trunc@ethernet.src",
                "parse_ethernet/arm0/parse_ipv4/ipv4.options=0B/arm0/parse_tcp",
                "parse_ethernet/arm0/parse_ipv4/ipv4.options=0B/arm1/parse_udp",
                "parse_ethernet/arm0/parse_ipv4/ipv4.options=4B/arm0/parse_tcp",
            ]
        );
        assert_eq!(cov.unexercised.len(), 240);
    }

    /// Every committed vector, replayed concretely, must map back to
    /// exactly the path id it was generated from — a 164-case
    /// cross-validation of pathid against the engine.
    #[test]
    fn pathid_roundtrips_all_committed_vectors() {
        let ir = eth_ipvx_l4();
        let Some(suite) = crate::testvec::committed_suite_or_skip("eth_ipvx_l4") else {
            return;
        };
        for v in &suite.vectors {
            let (bits, _) = crate::testvec::Bits::from_pb(v.packet.as_ref().unwrap());
            let result = crate::interp::run_bits(&ir, &bits).unwrap();
            let id = path_id(&ir, &result).unwrap();
            assert_eq!(id, v.id, "vector {} mapped to wrong path", v.id);
        }
    }
}
