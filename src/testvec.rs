//! Test-vector artifacts: generated pb types plus the Rust-native
//! `Bits` input type and BitString canonicalization.

#[allow(clippy::all)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/pakeles.testvec.v1alpha1.rs"));
    include!(concat!(
        env!("OUT_DIR"),
        "/pakeles.testvec.v1alpha1.serde.rs"
    ));
}

use anyhow::Result;

/// Rust-native bit string used throughout the toolchain internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bits {
    pub bytes: Vec<u8>,
    pub bit_len: usize,
}

impl Bits {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            bit_len: bytes.len() * 8,
        }
    }

    /// Canonicalize per the BitString contract: pad short data with
    /// zeros, truncate long data, zero unused trailing bits. Returns
    /// warnings describing every correction made (empty = canonical).
    pub fn from_pb(bs: &pb::BitString) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let bit_len = bs.bit_len as usize;
        let want_bytes = bit_len.div_ceil(8);
        let mut bytes = match hex_decode(&bs.data_hex) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(format!("bad hex ({e}); treating as empty"));
                Vec::new()
            }
        };
        match bytes.len().cmp(&want_bytes) {
            std::cmp::Ordering::Less => {
                warnings.push(format!(
                    "data shorter than bit_len ({} < {} bytes); zero-padded",
                    bytes.len(),
                    want_bytes
                ));
                bytes.resize(want_bytes, 0);
            }
            std::cmp::Ordering::Greater => {
                warnings.push(format!(
                    "data longer than bit_len ({} > {} bytes); truncated",
                    bytes.len(),
                    want_bytes
                ));
                bytes.truncate(want_bytes);
            }
            std::cmp::Ordering::Equal => {}
        }
        let pad_bits = want_bytes * 8 - bit_len;
        if pad_bits > 0 {
            let mask = !((1u16 << pad_bits) - 1) as u8;
            let last = bytes.len() - 1;
            if bytes[last] & !mask != 0 {
                warnings.push("nonzero pad bits; zeroed".into());
                bytes[last] &= mask;
            }
        }
        (Self { bytes, bit_len }, warnings)
    }

    /// Emit canonical wire form (writers must only ever produce this).
    pub fn to_pb(&self) -> pb::BitString {
        debug_assert_eq!(self.bytes.len(), self.bit_len.div_ceil(8));
        pb::BitString {
            data_hex: hex_encode(&self.bytes),
            bit_len: self.bit_len as u64,
        }
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("odd hex length {}", s.len());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|e| anyhow::anyhow!("hex at {}: {e}", 2 * i))
        })
        .collect()
}

/// Byte-aligned vectors as raw packets (pcap is byte-granular), in
/// suite order, with their vector indices. Callers must report the
/// skipped count — no silent drops.
pub fn suite_to_packets(s: &pb::TestSuite) -> (Vec<Vec<u8>>, Vec<usize>) {
    let mut packets = Vec::new();
    let mut indices = Vec::new();
    for (i, v) in s.vectors.iter().enumerate() {
        if let Some(bs) = &v.packet {
            if bs.bit_len.is_multiple_of(8) {
                let (bits, _) = Bits::from_pb(bs);
                packets.push(bits.bytes);
                indices.push(i);
            }
        }
    }
    (packets, indices)
}

pub fn suite_to_json(s: &pb::TestSuite) -> Result<String> {
    Ok(serde_json::to_string_pretty(s)?)
}

pub fn suite_from_json(s: &str) -> Result<pb::TestSuite> {
    Ok(serde_json::from_str(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_roundtrips_without_warnings() {
        let bits = Bits {
            bytes: vec![0xAB, 0xC0],
            bit_len: 12,
        };
        let pb = bits.to_pb();
        assert_eq!(pb.data_hex, "abc0");
        let (back, warnings) = Bits::from_pb(&pb);
        assert_eq!(back, bits);
        assert!(warnings.is_empty());
    }

    #[test]
    fn short_data_zero_padded_with_warning() {
        let (bits, w) = Bits::from_pb(&pb::BitString {
            data_hex: "ab".into(),
            bit_len: 24,
        });
        assert_eq!(bits.bytes, vec![0xAB, 0, 0]);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("zero-padded"));
    }

    #[test]
    fn long_data_truncated_with_warning() {
        let (bits, w) = Bits::from_pb(&pb::BitString {
            data_hex: "aabbcc".into(),
            bit_len: 8,
        });
        assert_eq!(bits.bytes, vec![0xAA]);
        assert!(w[0].contains("truncated"));
    }

    #[test]
    fn nonzero_pad_bits_zeroed_with_warning() {
        let (bits, w) = Bits::from_pb(&pb::BitString {
            data_hex: "ff".into(),
            bit_len: 4,
        });
        assert_eq!(bits.bytes, vec![0xF0]);
        assert!(w[0].contains("pad bits"));
    }

    #[test]
    fn suite_to_packets_selects_byte_aligned() {
        let text = std::fs::read_to_string("examples/eth_ipv4_tcp/vectors.json").unwrap();
        let suite = suite_from_json(&text).unwrap();
        let (packets, indices) = suite_to_packets(&suite);
        assert_eq!(packets.len(), indices.len());
        assert!(!packets.is_empty());
        for (p, i) in packets.iter().zip(&indices) {
            let bs = suite.vectors[*i].packet.as_ref().unwrap();
            assert_eq!(bs.bit_len as usize, p.len() * 8);
        }
        // Every accept vector is byte-aligned and therefore exported.
        let accepts = suite
            .vectors
            .iter()
            .enumerate()
            .filter(|(_, v)| v.category == pb::Category::Accept as i32)
            .count();
        assert!(indices.len() >= accepts);
    }

    #[test]
    fn committed_vectors_pcap_current() {
        let text = std::fs::read_to_string("examples/eth_ipv4_tcp/vectors.json").unwrap();
        let suite = suite_from_json(&text).unwrap();
        let (packets, _) = suite_to_packets(&suite);
        let tmp = std::env::temp_dir().join("pakeles_gallery_check.pcap");
        crate::pcapio::write_pcap(&tmp, &packets).unwrap();
        let fresh = std::fs::read(&tmp).unwrap();
        let committed = std::fs::read("examples/eth_ipv4_tcp/vectors.pcap").unwrap();
        assert_eq!(
            fresh, committed,
            "examples/ drifted; regenerate: ./dev.sh cargo run --bin gen_examples"
        );
    }

    #[test]
    fn suite_json_roundtrip() {
        let suite = pb::TestSuite {
            parser_name: "p".into(),
            ir_version: "0.1.0".into(),
            vectors: vec![pb::TestVector {
                id: "s/arm0".into(),
                category: pb::Category::Accept as i32,
                packet: Some(Bits::from_bytes(&[1, 2]).to_pb()),
                expected: Some(pb::Expected {
                    outcome: Some(pb::expected::Outcome::Reject(pb::Rejected {
                        reason: "r".into(),
                    })),
                }),
            }],
        };
        assert_eq!(
            suite_from_json(&suite_to_json(&suite).unwrap()).unwrap(),
            suite
        );
    }
}
