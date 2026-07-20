//! Reference interpreter, reject mode. Normative semantics: what this
//! module does *is* what an IR description means.

mod bits;
mod eval;

use crate::ir::pb;
use bits::read_bits;
use eval::{eval_entry, eval_expr, Env};

/// Expression evaluation for sibling modules (pathid) — same semantics
/// the interpreter itself uses.
#[cfg(feature = "symex")]
pub(crate) fn eval_expr_pub(
    e: &pb::Expr,
    env: &std::collections::HashMap<(String, String), u64>,
) -> anyhow::Result<u64> {
    eval_expr(e, env)
}

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

/// One transition decision, recorded per state entered.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceStep {
    pub state: String,
    pub decision: Decision,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Arm(usize),
    Default,
    Direct,
    /// Parse ended inside this state (oob/depth) before any decision.
    None,
}

/// Diagnose-mode severity of a reject (from `Reject.annotations["severity"]`;
/// built-in rejects are always `Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Info,
}

/// Structured forensics for a reject: where the parse stopped and why.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub state: String,
    pub instance: Option<String>,
    pub field: Option<String>,
    pub bit_offset: usize,
    pub reason: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseResult {
    pub outcome: Outcome,
    pub headers: Vec<ParsedHeader>,
    pub trace: Vec<TraceStep>,
    /// Present iff outcome is Reject.
    pub error: Option<ParseError>,
    /// Bits consumed when parsing stopped; payload/remainder is
    /// `consumed_bits..input.bit_len`.
    pub consumed_bits: usize,
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
    let mut trace: Vec<TraceStep> = Vec::new();
    let mut env = Env::new();
    let mut cursor_bits = 0usize;
    let mut depth = 0u32;
    let mut current = parser.start_state.as_str();

    struct RejectCtx {
        severity: Severity,
        instance: Option<String>,
        field: Option<String>,
    }

    let reject = |reason: &str,
                  ctx: RejectCtx,
                  state: &str,
                  bit_offset: usize,
                  headers: Vec<ParsedHeader>,
                  trace: Vec<TraceStep>| {
        Ok(ParseResult {
            outcome: Outcome::Reject {
                reason: reason.into(),
            },
            headers,
            trace,
            error: Some(ParseError {
                state: state.to_string(),
                instance: ctx.instance,
                field: ctx.field,
                bit_offset,
                reason: reason.into(),
                severity: ctx.severity,
            }),
            consumed_bits: bit_offset,
        })
    };
    let plain = |severity: Severity| RejectCtx {
        severity,
        instance: None,
        field: None,
    };

    loop {
        depth += 1;
        trace.push(TraceStep {
            state: current.to_string(),
            decision: Decision::None,
        });
        if depth > parser.max_depth {
            return reject(
                "max depth exceeded",
                plain(Severity::Error),
                current,
                cursor_bits,
                headers,
                trace,
            );
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
                            let ctx = RejectCtx {
                                severity: Severity::Error,
                                instance: Some(instance.clone()),
                                field: Some(field.name.clone()),
                            };
                            headers.push(parsed);
                            return reject(
                                "out of bounds",
                                ctx,
                                current,
                                cursor_bits,
                                headers,
                                trace,
                            );
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
                            let ctx = RejectCtx {
                                severity: Severity::Error,
                                instance: Some(instance.clone()),
                                field: Some(field.name.clone()),
                            };
                            headers.push(parsed);
                            return reject(
                                "out of bounds",
                                ctx,
                                current,
                                cursor_bits,
                                headers,
                                trace,
                            );
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
            Some(pb::transition::Kind::Direct(t)) => {
                trace.last_mut().expect("state entered").decision = Decision::Direct;
                t
            }
            Some(pb::transition::Kind::Select(sel)) => {
                let mut keys = Vec::with_capacity(sel.keys.len());
                for k in &sel.keys {
                    keys.push(eval_expr(k, &env)?);
                }
                let hit = sel.arms.iter().position(|arm| {
                    arm.entries.len() == keys.len()
                        && arm
                            .entries
                            .iter()
                            .zip(&keys)
                            .all(|(e, k)| eval_entry(e, *k))
                });
                match hit {
                    Some(i) => {
                        trace.last_mut().expect("state entered").decision = Decision::Arm(i);
                        sel.arms[i]
                            .next
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("select arm has no target"))?
                    }
                    None => {
                        trace.last_mut().expect("state entered").decision = Decision::Default;
                        match sel.default_target.as_ref() {
                            Some(t) => t,
                            None => {
                                return reject(
                                    "no matching select arm",
                                    plain(Severity::Error),
                                    current,
                                    cursor_bits,
                                    headers,
                                    trace,
                                )
                            }
                        }
                    }
                }
            }
        };

        match target.kind.as_ref() {
            Some(pb::target::Kind::State(name)) => current = name,
            Some(pb::target::Kind::Accept(_)) => {
                return Ok(ParseResult {
                    outcome: Outcome::Accept,
                    headers,
                    trace,
                    error: None,
                    consumed_bits: cursor_bits,
                })
            }
            Some(pb::target::Kind::Reject(r)) => {
                let severity = match r.annotations.get("severity").map(String::as_str) {
                    Some("info") => Severity::Info,
                    _ => Severity::Error,
                };
                return reject(
                    &r.reason,
                    plain(severity),
                    current,
                    cursor_bits,
                    headers,
                    trace,
                );
            }
            None => anyhow::bail!("empty target"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{
        arm, f, reject_info, to, v, HeaderTypeBuilder, ParserBuilder, StateBuilder,
    };
    use crate::examples::eth_ipvx_l4;
    use crate::fixtures::*;

    /// Minimal two-header IR for exercising engine mechanics without the
    /// gallery example: header `a` (16-bit tag) selects into header `b`
    /// (two 16-bit fields); tag 1 -> parse b -> accept, else reject(info).
    fn mini() -> pb::Ir {
        ParserBuilder::new("mini", 3)
            .header(HeaderTypeBuilder::new("a").bits("tag", 16))
            .header(HeaderTypeBuilder::new("b").bits("x", 16).bits("y", 16))
            .state(StateBuilder::new("s0").extract("a").select(
                vec![f("a", "tag")],
                vec![arm(vec![v(1)], to("s1"))],
                reject_info("unknown tag"),
            ))
            .state(StateBuilder::new("s1").extract("b").accept())
            .start("s0")
            .build()
            .unwrap()
    }

    #[test]
    fn example_smoke_accepts_and_rejects() {
        // One belt-and-suspenders check that the embedded example is
        // wired up; exhaustive behavior lives in the vector suite.
        let ir = eth_ipvx_l4();
        assert_eq!(run(&ir, &tcp_packet()).unwrap().outcome, Outcome::Accept);
        assert_eq!(
            run(&ir, &ipv6_tcp_packet()).unwrap().outcome,
            Outcome::Accept
        );
        assert_eq!(
            run(&ir, &icmp_packet()).unwrap().outcome,
            Outcome::Reject {
                reason: "unsupported ip protocol".into()
            }
        );
    }

    #[test]
    fn rejects_truncated_with_oob_forensics() {
        // 2 bytes: `a` extracts, `b` runs off the end mid-first-field.
        let res = run(&mini(), &[0x00, 0x01]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "out of bounds".into()
            }
        );
        let err = res.error.unwrap();
        assert_eq!(err.state, "s1");
        assert_eq!(err.instance.as_deref(), Some("b"));
        assert_eq!(err.field.as_deref(), Some("x"));
        assert_eq!(err.bit_offset, 16);
        assert_eq!(err.severity, Severity::Error);
        assert_eq!(res.consumed_bits, 16);
    }

    #[test]
    fn payload_boundary_reject_is_info() {
        // tag 2 misses the only arm -> default reject(info).
        let res = run(&mini(), &[0x00, 0x02]).unwrap();
        let err = res.error.unwrap();
        assert_eq!(err.severity, Severity::Info);
        assert_eq!(err.reason, "unknown tag");
        assert_eq!(res.consumed_bits, 16);
    }

    #[test]
    fn accept_has_no_error_and_full_consumption() {
        let res = run(&mini(), &[0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        assert_eq!(res.outcome, Outcome::Accept);
        assert!(res.error.is_none());
        assert_eq!(res.consumed_bits, 48);
    }

    #[test]
    fn interp_over_fixture_pcap() {
        let ir = eth_ipvx_l4();
        let packets =
            crate::pcapio::read_packets(std::path::Path::new("testdata/basic.pcap")).unwrap();
        let accepts: Vec<bool> = packets
            .iter()
            .map(|p| run(&ir, p).unwrap().outcome == Outcome::Accept)
            .collect();
        assert_eq!(accepts, vec![true, true, true, false]);
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
