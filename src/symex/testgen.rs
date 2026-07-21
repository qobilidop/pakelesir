//! Witness construction and suite assembly. Witnesses are raw z3
//! models (completion on, no post-processing — decided 2026-07-19);
//! expected outputs come from the reference interpreter, so the suite
//! is self-checking against normative semantics by construction.

use super::engine::{enumerate, Path, PathKind};
use super::solver::Solver;
use super::z3solver::Z3Solver;
use crate::interp::{run_bits, FieldValue, Outcome};
use crate::ir::pb as irpb;
use crate::testvec::{pb, Bits};
use anyhow::{bail, Context, Result};

pub fn generate(ir: &irpb::Ir) -> Result<pb::TestSuite> {
    let mut solver = Z3Solver::new();
    let enumeration = enumerate(ir, &mut solver)?;
    let parser = ir.parser.as_ref().expect("validated");
    let mut vectors = Vec::with_capacity(enumeration.paths.len());
    for path in &enumeration.paths {
        vectors.push(vector_for(ir, &mut solver, path).with_context(|| path.id.clone())?);
    }
    Ok(pb::TestSuite {
        parser_name: parser.name.clone(),
        ir_version: ir.ir_version.clone(),
        vectors,
    })
}

fn vector_for(ir: &irpb::Ir, solver: &mut dyn Solver, path: &Path) -> Result<pb::TestVector> {
    let Some(bytes) = solver.check(path.bit_len, &path.constraints) else {
        bail!("engine bug: enumerated path is UNSAT");
    };
    let bits = Bits {
        bytes,
        bit_len: path.bit_len,
    };
    let result = run_bits(ir, &bits)?;

    // The interpreter must agree with the path's own expectation —
    // any mismatch is a soundness bug in engine or interpreter.
    let (category, expected) = match (&path.kind, &result.outcome) {
        (PathKind::Accept, Outcome::Accept) => (
            pb::Category::Accept,
            pb::expected::Outcome::Accept(pb::Accepted {
                headers: result
                    .headers
                    .iter()
                    .map(|h| pb::ExpectedHeader {
                        instance: h.instance.clone(),
                        fields: h
                            .fields
                            .iter()
                            .map(|f| pb::ExpectedField {
                                name: f.name.clone(),
                                value: Some(match &f.value {
                                    FieldValue::Uint(u) => pb::expected_field::Value::Uint(*u),
                                    FieldValue::Bytes(b) => pb::expected_field::Value::BytesHex(
                                        crate::testvec::hex_encode(b),
                                    ),
                                }),
                            })
                            .collect(),
                    })
                    .collect(),
            }),
        ),
        (PathKind::Reject { reason }, Outcome::Reject { reason: got }) if reason == got => (
            pb::Category::Reject,
            pb::expected::Outcome::Reject(pb::Rejected {
                reason: got.clone(),
            }),
        ),
        (PathKind::Truncation, Outcome::Reject { reason: got }) if got == "out of bounds" => (
            pb::Category::Truncation,
            pb::expected::Outcome::Reject(pb::Rejected {
                reason: got.clone(),
            }),
        ),
        (kind, outcome) => {
            bail!("soundness bug: path predicts {kind:?}, interpreter says {outcome:?}")
        }
    };

    Ok(pb::TestVector {
        id: path.id.clone(),
        category: category as i32,
        packet: Some(bits.to_pb()),
        expected: Some(pb::Expected {
            outcome: Some(expected),
        }),
    })
}

/// Replay a suite through the reference interpreter; returns mismatch
/// descriptions (empty = green). This — not solver re-runs — is the
/// CI-stable check for committed suites.
pub fn replay(ir: &irpb::Ir, suite: &pb::TestSuite) -> Result<Vec<String>> {
    let mut mismatches = Vec::new();
    for v in &suite.vectors {
        let Some(packet) = &v.packet else {
            mismatches.push(format!("{}: no packet", v.id));
            continue;
        };
        let (bits, warnings) = Bits::from_pb(packet);
        for w in warnings {
            mismatches.push(format!("{}: non-canonical packet: {w}", v.id));
        }
        let result = run_bits(ir, &bits)?;
        let expected = v.expected.as_ref().and_then(|e| e.outcome.as_ref());
        match (expected, &result.outcome) {
            (Some(pb::expected::Outcome::Reject(r)), Outcome::Reject { reason })
                if &r.reason == reason => {}
            (Some(pb::expected::Outcome::Accept(a)), Outcome::Accept) => {
                let got: Vec<pb::ExpectedHeader> = result
                    .headers
                    .iter()
                    .map(|h| pb::ExpectedHeader {
                        instance: h.instance.clone(),
                        fields: h
                            .fields
                            .iter()
                            .map(|f| pb::ExpectedField {
                                name: f.name.clone(),
                                value: Some(match &f.value {
                                    FieldValue::Uint(u) => pb::expected_field::Value::Uint(*u),
                                    FieldValue::Bytes(b) => pb::expected_field::Value::BytesHex(
                                        crate::testvec::hex_encode(b),
                                    ),
                                }),
                            })
                            .collect(),
                    })
                    .collect();
                if got != a.headers {
                    mismatches.push(format!("{}: field mismatch", v.id));
                }
            }
            (e, o) => mismatches.push(format!("{}: expected {e:?}, interpreter {o:?}", v.id)),
        }
    }
    Ok(mismatches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::examples::eth_ipvx_l4;

    #[test]
    fn example_suite_shape_and_replay() {
        let ir = eth_ipvx_l4();
        let suite = generate(&ir).unwrap();
        let by_cat = |c: pb::Category| {
            suite
                .vectors
                .iter()
                .filter(|v| v.category == c as i32)
                .count()
        };
        // Accepts: 11 ipv4 ihl layouts x {tcp,udp} = 22, plus ipv6 x
        // {tcp,udp} = 2 -> 24. Rejects: 5 wrapped ihl (oob) + 11
        // ipv4-default + 1 ipv6-default + 1 eth-default = 18.
        assert_eq!(by_cat(pb::Category::Accept), 24);
        assert_eq!(by_cat(pb::Category::Reject), 18);
        assert_eq!(by_cat(pb::Category::Truncation), 202);
        // IDs unique and sorted.
        let ids: Vec<&str> = suite.vectors.iter().map(|v| v.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted);
        // Self-check: replay green.
        assert!(replay(&ir, &suite).unwrap().is_empty());
    }

    #[test]
    fn committed_vectors_replay_green() {
        let Some(suite) = crate::testvec::committed_suite_or_skip("eth_ipvx_l4") else {
            return;
        };
        let mismatches = replay(&eth_ipvx_l4(), &suite).unwrap();
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }
}
