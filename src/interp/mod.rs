//! Reference interpreter, reject mode. Normative semantics: what this
//! module does *is* what an IR description means.

mod bits;
mod eval;

use crate::ir::pb;
use bits::read_bits;
use eval::{eval_entry, eval_expr, Env};

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Accept,
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Uint(u64),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedField {
    pub name: String,
    pub bit_offset: usize,
    pub bit_len: usize,
    pub value: FieldValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHeader {
    pub instance: String,
    pub header_type: String,
    pub start_bit: usize,
    pub fields: Vec<ParsedField>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseResult {
    pub outcome: Outcome,
    pub headers: Vec<ParsedHeader>,
}

/// Run the parser over one byte-aligned packet. `Err` means the IR
/// itself is malformed; anything about the *packet* is a `Reject`.
pub fn run(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<ParseResult> {
    run_bits(ir, &crate::testvec::Bits::from_bytes(packet))
}

/// Bit-granular entry point (test vectors may end mid-byte).
pub fn run_bits(ir: &pb::Ir, input: &crate::testvec::Bits) -> anyhow::Result<ParseResult> {
    let packet = input.bytes.as_slice();
    let avail_bits = input.bit_len;
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let states: std::collections::HashMap<&str, &pb::State> =
        parser.states.iter().map(|s| (s.name.as_str(), s)).collect();
    let header_types: std::collections::HashMap<&str, &pb::HeaderType> = parser
        .header_types
        .iter()
        .map(|h| (h.name.as_str(), h))
        .collect();

    let mut headers = Vec::new();
    let mut env = Env::new();
    let mut cursor_bits = 0usize;
    let mut depth = 0u32;
    let mut current = parser.start_state.as_str();

    let reject = |reason: &str, headers: Vec<ParsedHeader>| {
        Ok(ParseResult {
            outcome: Outcome::Reject {
                reason: reason.into(),
            },
            headers,
        })
    };

    loop {
        depth += 1;
        if depth > parser.max_depth {
            return reject("max depth exceeded", headers);
        }
        let state = states
            .get(current)
            .ok_or_else(|| anyhow::anyhow!("unknown state `{current}`"))?;

        for ex in &state.extracts {
            let ht = header_types
                .get(ex.header_type.as_str())
                .ok_or_else(|| anyhow::anyhow!("unknown header type `{}`", ex.header_type))?;
            let instance = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            let mut parsed = ParsedHeader {
                instance: instance.clone(),
                header_type: ht.name.clone(),
                start_bit: cursor_bits,
                fields: Vec::new(),
            };
            for field in &ht.fields {
                let width = field
                    .width
                    .as_ref()
                    .and_then(|w| w.width.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("field `{}` has no width", field.name))?;
                match width {
                    pb::field_width::Width::Bits(n) => {
                        let n = *n as usize;
                        let Some(value) = read_bits(packet, avail_bits, cursor_bits, n) else {
                            headers.push(parsed);
                            return reject("out of bounds", headers);
                        };
                        env.insert((instance.clone(), field.name.clone()), value);
                        parsed.fields.push(ParsedField {
                            name: field.name.clone(),
                            bit_offset: cursor_bits,
                            bit_len: n,
                            value: FieldValue::Uint(value),
                        });
                        cursor_bits += n;
                    }
                    pb::field_width::Width::ByteLen(expr) => {
                        let len_bytes = eval_expr(expr, &env)? as usize;
                        if !cursor_bits.is_multiple_of(8) {
                            anyhow::bail!(
                                "var-length field `{}` at non-byte-aligned offset",
                                field.name
                            );
                        }
                        let start = cursor_bits / 8;
                        // len_bytes may be a wrapped u64 (e.g. ihl<5);
                        // checked math makes that an oob, not a panic.
                        let end_bits = len_bytes
                            .checked_mul(8)
                            .and_then(|lb| lb.checked_add(cursor_bits));
                        if end_bits.is_none_or(|e| e > avail_bits) {
                            headers.push(parsed);
                            return reject("out of bounds", headers);
                        }
                        let slice = &packet[start..start + len_bytes];
                        parsed.fields.push(ParsedField {
                            name: field.name.clone(),
                            bit_offset: cursor_bits,
                            bit_len: len_bytes * 8,
                            value: FieldValue::Bytes(slice.to_vec()),
                        });
                        cursor_bits += len_bytes * 8;
                    }
                }
            }
            headers.push(parsed);
        }

        let target = match state.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            None => anyhow::bail!("state `{current}` has no transition"),
            Some(pb::transition::Kind::Direct(t)) => t,
            Some(pb::transition::Kind::Select(sel)) => {
                let mut keys = Vec::with_capacity(sel.keys.len());
                for k in &sel.keys {
                    keys.push(eval_expr(k, &env)?);
                }
                let hit = sel.arms.iter().find(|arm| {
                    arm.entries.len() == keys.len()
                        && arm
                            .entries
                            .iter()
                            .zip(&keys)
                            .all(|(e, k)| eval_entry(e, *k))
                });
                match hit {
                    Some(arm) => arm
                        .next
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("select arm has no target"))?,
                    None => match sel.default_target.as_ref() {
                        Some(t) => t,
                        None => return reject("no matching select arm", headers),
                    },
                }
            }
        };

        match target.kind.as_ref() {
            Some(pb::target::Kind::State(name)) => current = name,
            Some(pb::target::Kind::Accept(_)) => {
                return Ok(ParseResult {
                    outcome: Outcome::Accept,
                    headers,
                })
            }
            Some(pb::target::Kind::Reject(r)) => {
                let reason = r.reason.clone();
                return Ok(ParseResult {
                    outcome: Outcome::Reject { reason },
                    headers,
                });
            }
            None => anyhow::bail!("empty target"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::examples::eth_ipv4_tcp;
    use crate::fixtures::*;

    fn field(res: &ParseResult, instance: &str, name: &str) -> FieldValue {
        res.headers
            .iter()
            .find(|h| h.instance == instance)
            .unwrap_or_else(|| panic!("no header instance `{instance}`"))
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no field `{instance}.{name}`"))
            .value
            .clone()
    }

    #[test]
    fn parses_tcp_packet() {
        let res = run(&eth_ipv4_tcp(), &tcp_packet()).unwrap();
        assert_eq!(res.outcome, Outcome::Accept);
        assert_eq!(
            field(&res, "ethernet", "ethertype"),
            FieldValue::Uint(0x0800)
        );
        assert_eq!(field(&res, "ipv4", "protocol"), FieldValue::Uint(6));
        assert_eq!(field(&res, "ipv4", "options"), FieldValue::Bytes(vec![]));
        assert_eq!(field(&res, "tcp", "dport"), FieldValue::Uint(443));
        let starts: Vec<usize> = res.headers.iter().map(|h| h.start_bit).collect();
        assert_eq!(starts, vec![0, 112, 272]);
    }

    #[test]
    fn parses_ihl6_options() {
        let res = run(&eth_ipv4_tcp(), &tcp_packet_ihl6()).unwrap();
        assert_eq!(res.outcome, Outcome::Accept);
        assert_eq!(
            field(&res, "ipv4", "options"),
            FieldValue::Bytes(vec![0x01, 0x01, 0x01, 0x00])
        );
        assert_eq!(res.headers[2].start_bit, 272 + 32);
        assert_eq!(field(&res, "tcp", "dport"), FieldValue::Uint(443));
    }

    #[test]
    fn rejects_udp() {
        let res = run(&eth_ipv4_tcp(), &udp_packet()).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "unsupported ip protocol".into()
            }
        );
        assert_eq!(res.headers.len(), 2); // ethernet + ipv4 still extracted
    }

    #[test]
    fn rejects_truncated() {
        let res = run(&eth_ipv4_tcp(), &tcp_packet()[..20]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "out of bounds".into()
            }
        );
    }

    #[test]
    fn interp_over_fixture_pcap() {
        let ir = eth_ipv4_tcp();
        let packets =
            crate::pcapio::read_packets(std::path::Path::new("testdata/basic.pcap")).unwrap();
        let accepts: Vec<bool> = packets
            .iter()
            .map(|p| run(&ir, p).unwrap().outcome == Outcome::Accept)
            .collect();
        assert_eq!(accepts, vec![true, true, false, false]);
    }

    #[test]
    fn depth_bound_respected() {
        use crate::builder::{to, ParserBuilder, StateBuilder};
        let ir = ParserBuilder::new("loop", 3)
            .state(StateBuilder::new("s").goto_(to("s")))
            .start("s")
            .build()
            .unwrap();
        let res = run(&ir, &[]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "max depth exceeded".into()
            }
        );
    }
}
