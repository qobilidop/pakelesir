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

#[derive(Clone, Copy)]
pub struct Verdict {
    pub delivered: bool,
    pub bitmap: u16,
    pub err: u8,
}

/// Expected observation for one vector: exact bitmap + acceptable errs.
pub struct Expectation {
    pub bitmap: u16,
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

/// Serializes `simple_switch` spawns process-wide. Each spawn is heavy
/// (BMv2 loads its target libs cold); under parallel test threads that
/// also run `p4c`/`simple_switch`, concurrent spawns starve one another
/// and a packet can miss even a generous deadline. One switch at a time
/// keeps the differential suite deterministic.
static SWITCH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Decode one output frame into a `Verdict`: `bm_bytes` of big-endian
/// bitmap followed by 1 byte of parser-error code.
fn decode_verdict(frame: &[u8], bm_bytes: usize) -> Result<Verdict> {
    if frame.len() < bm_bytes + 1 {
        bail!("verdict frame too short: {} bytes", frame.len());
    }
    let mut bitmap: u16 = 0;
    for &b in &frame[..bm_bytes] {
        bitmap = (bitmap << 8) | b as u16;
    }
    Ok(Verdict {
        delivered: true,
        bitmap,
        err: frame[bm_bytes],
    })
}

/// Run ALL `packets` through simple_switch and return per-packet verdicts
/// in input order. Processes in modest chunks — one spawn per chunk —
/// amortizing the heavy cold start over CHUNK packets (vs a spawn per
/// packet, which dominated the gate) while keeping each run small enough to
/// finish and flush reliably under the parallel suite's CPU load: a single
/// huge batch stalls when BMv2's internal queue fills faster than the
/// CPU-starved deparser drains it.
pub fn run_batch(
    json: &Path,
    packets: &[Vec<u8>],
    workdir: &Path,
    bm_bytes: usize,
) -> Result<Vec<Verdict>> {
    let _guard = SWITCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    const CHUNK: usize = 32;
    let mut out = Vec::with_capacity(packets.len());
    for chunk in packets.chunks(CHUNK) {
        out.extend(run_chunk(json, chunk, workdir, bm_bytes)?);
    }
    Ok(out)
}

/// One simple_switch spawn over a small chunk (port 0 in, port 1 out);
/// `out[i]` is `packets[i]`'s verdict. Every packet yields exactly one
/// output frame (the deparser always emits the verdict and ingress always
/// sets `egress_spec`), and simple_switch preserves single-port order.
fn run_chunk(
    json: &Path,
    packets: &[Vec<u8>],
    workdir: &Path,
    bm_bytes: usize,
) -> Result<Vec<Verdict>> {
    let n = packets.len();
    let mut out = vec![
        Verdict {
            delivered: false,
            bitmap: 0,
            err: 0,
        };
        n
    ];
    if n == 0 {
        return Ok(out);
    }
    let dir = workdir.join("run");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    // simple_switch buffers its output pcap and only flushes as more packets
    // arrive (it never exits under --use-files). Append a few dummy trailing
    // packets so the chunk's real tail is flushed; their outputs land after
    // the N we read and are ignored. Reuse a real packet as the dummy so it
    // is guaranteed to traverse the pipeline and emit a frame.
    const FLUSH_PAD: usize = 8;
    let dummy = &packets[n - 1];
    let mut input = packets.to_vec();
    for _ in 0..FLUSH_PAD {
        input.push(dummy.clone());
    }
    crate::pcapio::write_pcap(&dir.join("p0_in.pcap"), &input)?;
    crate::pcapio::write_pcap(&dir.join("p1_in.pcap"), &[])?;
    let mut child = Command::new("simple_switch")
        .args(["--use-files", "0", "-i", "0@p0", "-i", "1@p1"])
        .arg(json.canonicalize()?)
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning simple_switch")?;
    let out_pcap = dir.join("p1_out.pcap");
    let decode_into = |pkts: &[Vec<u8>], out: &mut [Verdict]| -> Result<()> {
        for (i, p) in pkts.iter().take(n).enumerate() {
            out[i] = decode_verdict(p, bm_bytes)?;
        }
        Ok(())
    };
    // Wait on PROGRESS (output frame count growing), not a fixed deadline:
    // the single SWITCH_LOCK-serialized switch is CPU-starved by other tests'
    // p4c/tshark/cc. Give up only on a real stall or a hard cap; a small
    // chunk drains well within these even under load.
    let stall = std::time::Duration::from_secs(30);
    let hard_cap = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut seen = 0usize;
    let mut last_progress = std::time::Instant::now();
    loop {
        let pkts = crate::pcapio::read_packets(&out_pcap).unwrap_or_default();
        if pkts.len() > seen {
            seen = pkts.len();
            last_progress = std::time::Instant::now();
        }
        if pkts.len() >= n {
            if let Err(e) = decode_into(&pkts, &mut out) {
                let _ = child.kill();
                return Err(e);
            }
            break;
        }
        let now = std::time::Instant::now();
        if now > hard_cap || now.duration_since(last_progress) > stall {
            // Stalled or capped: decode the partial chunk; any missing tail
            // stays `delivered: false` and surfaces as a mismatch.
            let _ = decode_into(&pkts, &mut out);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(out)
}

/// Run one packet through simple_switch (a single-element `run_batch`).
pub fn run_one(json: &Path, packet: &[u8], workdir: &Path, bm_bytes: usize) -> Result<Verdict> {
    Ok(run_batch(json, &[packet.to_vec()], workdir, bm_bytes)?
        .into_iter()
        .next()
        .expect("run_batch yields one verdict per input packet"))
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
    let bit_of = |inst: &str| -> u16 {
        order
            .iter()
            .position(|(i, _)| i == inst)
            .map(|p| 1u16 << p)
            .unwrap_or(0)
    };
    let mut bitmap: u16 = 0;
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

/// Cap on byte-aligned vectors sent through `simple_switch` per suite.
pub fn diff_suite(ir: &pb::Ir, suite: &tvpb::TestSuite) -> Result<DiffReport> {
    let p4 = crate::codegen::p4::generate_p4(ir)?;
    let parser = ir.parser.as_ref().context("IR has no parser")?;
    let name = &parser.name;
    let bm_bytes =
        crate::codegen::p4::bitmap_bytes(crate::codegen::p4::instance_order(parser).len());
    let workdir = std::env::temp_dir().join(format!("pakeles_bmv2_{name}_{}", std::process::id()));
    let json = compile(&p4, &workdir)?;
    let (packets, indices) = crate::testvec::suite_to_packets(suite);
    let byte_aligned = indices.len();
    let mut report = DiffReport {
        compared: 0,
        skipped_bit_granular: suite.vectors.len() - byte_aligned,
        mismatches: Vec::new(),
    };
    // One batched simple_switch run over every byte-aligned vector — no
    // sampling. `verdicts[i]` corresponds to `packets[i]` / `indices[i]`.
    let verdicts = run_batch(&json, &packets, &workdir, bm_bytes)?;
    for (got, &vi) in verdicts.iter().zip(indices.iter()) {
        let vector = &suite.vectors[vi];
        let bs = vector.packet.as_ref().context("vector has no packet")?;
        let (bits, _) = crate::testvec::Bits::from_pb(bs);
        let want = expected(ir, &bits)?;
        report.compared += 1;
        if !got.delivered {
            report.mismatches.push(format!(
                "vector {vi} ({}): no packet delivered (expected bm={:016b})",
                vector.id, want.bitmap
            ));
            continue;
        }
        if got.bitmap != want.bitmap || !want.errs.contains(&got.err) {
            report.mismatches.push(format!(
                "vector {vi} ({}): expected bm={:016b} err in {:?}, got bm={:016b} err={}",
                vector.id, want.bitmap, want.errs, got.bitmap, got.err
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&workdir);
    eprintln!(
        "bmv2: compared all {} byte-aligned vectors in one simple_switch run",
        report.compared
    );
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
        let ir = crate::examples::eth_ipvx_l4();
        let p4 = crate::codegen::p4::generate_p4(&ir).unwrap();
        let dir = std::env::temp_dir().join("pakeles_bmv2_unit");
        let json = compile(&p4, &dir).unwrap();
        let Some(suite) = crate::testvec::committed_suite_or_skip("eth_ipvx_l4") else {
            return;
        };
        let (packets, indices) = crate::testvec::suite_to_packets(&suite);
        // first byte-aligned ACCEPT vector
        let (pkt, vi) = packets
            .iter()
            .zip(indices.iter())
            .find(|(_, &vi)| suite.vectors[vi].category() == tvpb::Category::Accept)
            .map(|(p, &vi)| (p.clone(), vi))
            .expect("no byte-aligned accept vector");
        let bm_bytes = crate::codegen::p4::bitmap_bytes(
            crate::codegen::p4::instance_order(ir.parser.as_ref().unwrap()).len(),
        );
        let v = run_one(&json, &pkt, &dir, bm_bytes).unwrap();
        assert!(v.delivered, "accept vector {vi} produced no output");
        assert_eq!(v.err, crate::codegen::p4::ERR_NO_ERROR);
    }

    fn bmv2_conformance_byte_aligned(ir: &pb::Ir, min_compared: usize) {
        if !tools_available() {
            eprintln!("skipping: p4 toolchain not available");
            return;
        }
        let name = &ir.parser.as_ref().unwrap().name;
        let Some(suite) = crate::testvec::committed_suite_or_skip(name) else {
            return;
        };
        let report = diff_suite(ir, &suite).unwrap();
        assert!(
            report.compared >= min_compared,
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

    #[test]
    fn bmv2_conformance_byte_aligned_suite() {
        bmv2_conformance_byte_aligned(&crate::examples::eth_ipvx_l4(), 28);
    }

    #[test]
    fn bmv2_conformance_byte_aligned_suite_flow_dissector() {
        // The flow-dissector suite has hundreds of byte-aligned vectors, now
        // all run through ONE batched simple_switch invocation (see
        // `run_batch`) rather than a per-vector spawn — so we exercise the
        // whole byte-aligned set, not a sample.
        bmv2_conformance_byte_aligned(&crate::examples::linux_flow_dissector(), 300);
    }
}
