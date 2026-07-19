//! BMv2 differential oracle: compile the emitted P4 with `p4c-bm2-ss`,
//! run vectors through `simple_switch --use-files` (pcap-file I/O — no
//! veth, no privileges, no runtime CLI), and verdict-compare against the
//! reference interpreter.
//!
//! The generated program deparses a 2-byte verdict per packet:
//! byte 0 = header-validity bitmap (bit i = instance i of
//! `codegen::p4::instance_order`, LSB first), byte 1 = parser error code
//! (see `codegen::p4::ERR_*`). Expected verdicts are derived from
//! `interp::run_bits` per vector — never hardcoded.
//!
//! Semantic notes (from the slice-5 spec):
//! - P4 extracts are atomic: a truncated instance is wholly invalid,
//!   while the interpreter records its partial fields. The expected
//!   bitmap therefore excludes the interpreter's `error.instance` on
//!   truncation.
//! - Interp rejects a negative var-field length by checked arithmetic;
//!   P4 bit arithmetic wraps and fails the varbit extract instead
//!   (`HeaderTooShort`/`PacketTooShort`). Both reject; for such vectors
//!   any of those error codes is accepted.

use crate::ir::pb;
use crate::testvec::pb as tvpb;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Verdict {
    pub delivered: bool,
    pub bitmap: u8,
    pub err: u8,
}

/// Expected observation for one vector: exact bitmap + acceptable errs.
pub struct Expectation {
    pub bitmap: u8,
    pub errs: Vec<u8>,
}

pub fn tools_available() -> bool {
    Command::new("p4c-bm2-ss").arg("--version").output().is_ok()
        && Command::new("simple_switch").arg("--help").output().is_ok()
}

pub fn compile(p4_src: &str, workdir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(workdir)?;
    let src = workdir.join("prog.p4");
    let json = workdir.join("prog.json");
    std::fs::write(&src, p4_src)?;
    let out = Command::new("p4c-bm2-ss")
        .arg(&src)
        .arg("-o")
        .arg(&json)
        .output()
        .context("running p4c-bm2-ss")?;
    if !out.status.success() {
        bail!(
            "p4c-bm2-ss failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(json)
}

/// Run one packet through simple_switch; port 0 in, port 1 out.
pub fn run_one(json: &Path, packet: &[u8], workdir: &Path) -> Result<Verdict> {
    let dir = workdir.join("run");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    crate::pcapio::write_pcap(
        &dir.join("p0_in.pcap"),
        std::slice::from_ref(&packet.to_vec()),
    )?;
    crate::pcapio::write_pcap(&dir.join("p1_in.pcap"), &[])?;
    let mut child = Command::new("simple_switch")
        .args(["--use-files", "0", "-i", "0@p0", "-i", "1@p1"])
        .arg(json.canonicalize()?)
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning simple_switch")?;
    // Generous: the first spawn in a fresh container (cold lib cache,
    // parallel test threads) has been seen to need well over a second,
    // and CI runners are slower still.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let out_pcap = dir.join("p1_out.pcap");
    let verdict = loop {
        if let Ok(pkts) = crate::pcapio::read_packets(&out_pcap) {
            if let Some(p) = pkts.first() {
                if p.len() < 2 {
                    let _ = child.kill();
                    bail!("verdict frame too short: {} bytes", p.len());
                }
                break Verdict {
                    delivered: true,
                    bitmap: p[0],
                    err: p[1],
                };
            }
        }
        if std::time::Instant::now() > deadline {
            break Verdict {
                delivered: false,
                bitmap: 0,
                err: 0,
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    let _ = child.kill();
    let _ = child.wait();
    Ok(verdict)
}

/// Reject reasons declared in the IR (explicit `transition reject`s).
fn declared_reject_reasons(parser: &pb::Parser) -> Vec<String> {
    fn from_target(t: Option<&pb::Target>, out: &mut Vec<String>) {
        if let Some(pb::target::Kind::Reject(r)) = t.and_then(|t| t.kind.as_ref()) {
            out.push(r.reason.clone());
        }
    }
    let mut out = Vec::new();
    for s in &parser.states {
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => from_target(Some(t), &mut out),
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    from_target(arm.next.as_ref(), &mut out);
                }
                from_target(sel.default_target.as_ref(), &mut out);
            }
            None => {}
        }
    }
    out
}

/// Derive the expected BMv2 observation for one vector's bits.
pub fn expected(ir: &pb::Ir, bits: &crate::testvec::Bits) -> Result<Expectation> {
    let parser = ir.parser.as_ref().context("IR has no parser")?;
    let res = crate::interp::run_bits(ir, bits)?;
    let order = crate::codegen::p4::instance_order(parser);
    let bit_of = |inst: &str| -> u8 {
        order
            .iter()
            .position(|(i, _)| i == inst)
            .map(|p| 1u8 << p)
            .unwrap_or(0)
    };
    let mut bitmap: u8 = 0;
    for h in &res.headers {
        bitmap |= bit_of(&h.instance);
    }
    Ok(match &res.outcome {
        crate::interp::Outcome::Accept => Expectation {
            bitmap,
            errs: vec![crate::codegen::p4::ERR_NO_ERROR],
        },
        crate::interp::Outcome::Reject { reason } => {
            if declared_reject_reasons(parser).iter().any(|r| r == reason) {
                // Explicit reject, emitted as select-no-match. The P4-16
                // spec says error.NoMatch (2); BMv2 deviates and stops
                // parsing with NoError (0). Either way the bitmap is
                // partial, which is what separates reject from accept.
                Expectation {
                    bitmap,
                    errs: vec![0, 2],
                }
            } else {
                // Runtime reject (truncation / bad length): the failing
                // instance is invalid in P4 (atomic extract).
                if let Some(inst) = res.error.as_ref().and_then(|e| e.instance.as_ref()) {
                    bitmap &= !bit_of(inst);
                }
                Expectation {
                    bitmap,
                    // PacketTooShort (1) for truncation; HeaderTooShort (4)
                    // or ParserInvalidArgument (6, what BMv2 raises) when a
                    // wrapped negative length exceeds the varbit bound.
                    errs: vec![crate::codegen::p4::ERR_PACKET_TOO_SHORT, 4, 6],
                }
            }
        }
    })
}

pub struct DiffReport {
    pub compared: usize,
    pub skipped_bit_granular: usize,
    pub mismatches: Vec<String>,
}

pub fn diff_suite(ir: &pb::Ir, suite: &tvpb::TestSuite) -> Result<DiffReport> {
    let p4 = crate::codegen::p4::generate_p4(ir)?;
    let workdir = std::env::temp_dir().join(format!("pakeles_bmv2_{}", std::process::id()));
    let json = compile(&p4, &workdir)?;
    let (packets, indices) = crate::testvec::suite_to_packets(suite);
    let mut report = DiffReport {
        compared: 0,
        skipped_bit_granular: suite.vectors.len() - indices.len(),
        mismatches: Vec::new(),
    };
    for (packet, &vi) in packets.iter().zip(indices.iter()) {
        let vector = &suite.vectors[vi];
        let bs = vector.packet.as_ref().context("vector has no packet")?;
        let (bits, _) = crate::testvec::Bits::from_pb(bs);
        let want = expected(ir, &bits)?;
        let got = run_one(&json, packet, &workdir)?;
        report.compared += 1;
        if !got.delivered {
            report.mismatches.push(format!(
                "vector {vi} ({}): no packet delivered (expected bm={:08b})",
                vector.id, want.bitmap
            ));
            continue;
        }
        if got.bitmap != want.bitmap || !want.errs.contains(&got.err) {
            report.mismatches.push(format!(
                "vector {vi} ({}): expected bm={:08b} err in {:?}, got bm={:08b} err={}",
                vector.id, want.bitmap, want.errs, got.bitmap, got.err
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&workdir);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_vector_roundtrips_through_bmv2() {
        if !tools_available() {
            eprintln!("skipping: p4 toolchain not available");
            return;
        }
        let ir = crate::examples::eth_ipv4_tcp();
        let p4 = crate::codegen::p4::generate_p4(&ir).unwrap();
        let dir = std::env::temp_dir().join("pakeles_bmv2_unit");
        let json = compile(&p4, &dir).unwrap();
        let suite = crate::testvec::suite_from_json(
            &std::fs::read_to_string("examples/eth_ipv4_tcp/conformance/vectors.json").unwrap(),
        )
        .unwrap();
        let (packets, indices) = crate::testvec::suite_to_packets(&suite);
        // first byte-aligned ACCEPT vector
        let (pkt, vi) = packets
            .iter()
            .zip(indices.iter())
            .find(|(_, &vi)| suite.vectors[vi].category() == tvpb::Category::Accept)
            .map(|(p, &vi)| (p.clone(), vi))
            .expect("no byte-aligned accept vector");
        let v = run_one(&json, &pkt, &dir).unwrap();
        assert!(v.delivered, "accept vector {vi} produced no output");
        assert_eq!(v.err, crate::codegen::p4::ERR_NO_ERROR);
    }

    #[test]
    fn bmv2_conformance_byte_aligned_suite() {
        if !tools_available() {
            eprintln!("skipping: p4 toolchain not available");
            return;
        }
        let ir = crate::examples::eth_ipv4_tcp();
        let suite = crate::testvec::suite_from_json(
            &std::fs::read_to_string("examples/eth_ipv4_tcp/conformance/vectors.json").unwrap(),
        )
        .unwrap();
        let report = diff_suite(&ir, &suite).unwrap();
        assert!(
            report.compared >= 28,
            "suspiciously few byte-aligned vectors: {}",
            report.compared
        );
        assert!(
            report.mismatches.is_empty(),
            "{} mismatches:\n{}",
            report.mismatches.len(),
            report.mismatches.join("\n")
        );
    }
}
