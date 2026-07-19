//! P4-16 (v1model) backend: emit a BMv2-runnable program from the IR.
//!
//! One P4 header per contiguous run of fixed fields; each var (`byte_len`)
//! field becomes a companion `varbit` header extracted with a computed
//! length (P4 requires a varbit to terminate its header). The program's
//! ingress encodes a 2-byte verdict — header-validity bitmap + parser
//! error code — and the deparser emits only that verdict, so the BMv2
//! differential observes exactly (bitmap, err) per packet.
//!
//! Cyclic state graphs are rejected: P4 loops need header stacks, which
//! arrive with the TLV slice. `max_depth` is vacuous on a DAG.

use crate::ir::pb;
use anyhow::{bail, Context, Result};
use std::fmt::Write;

/// Verdict error codes (mirrors core.p4's error enum; `error` is not
/// bit-castable in P4, so the ingress maps it through an if-chain).
pub const ERR_NO_ERROR: u8 = 0;
pub const ERR_PACKET_TOO_SHORT: u8 = 1;

pub(crate) enum Seg<'a> {
    Fixed(Vec<&'a pb::Field>),
    Var(&'a pb::Field),
}

/// Split a header type at var-field boundaries.
pub(crate) fn segments(ht: &pb::HeaderType) -> Vec<Seg<'_>> {
    let mut out = Vec::new();
    let mut run: Vec<&pb::Field> = Vec::new();
    for f in &ht.fields {
        match f.width.as_ref().and_then(|x| x.width.as_ref()) {
            Some(pb::field_width::Width::Bits(_)) => run.push(f),
            Some(pb::field_width::Width::ByteLen(_)) => {
                if !run.is_empty() {
                    out.push(Seg::Fixed(std::mem::take(&mut run)));
                }
                out.push(Seg::Var(f));
            }
            None => {}
        }
    }
    if !run.is_empty() {
        out.push(Seg::Fixed(run));
    }
    out
}

/// Header instances in first-extract order. Bit *i* of the verdict bitmap
/// (LSB first) is instance *i*; the BMv2 oracle relies on this order.
pub(crate) fn instance_order(parser: &pb::Parser) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for s in &parser.states {
        for ex in &s.extracts {
            let inst = if ex.instance.is_empty() {
                ex.header_type.clone()
            } else {
                ex.instance.clone()
            };
            if !out.iter().any(|(i, _)| *i == inst) {
                out.push((inst, ex.header_type.clone()));
            }
        }
    }
    out
}

fn header_type_of<'a>(parser: &'a pb::Parser, inst: &str) -> Result<&'a pb::HeaderType> {
    let ht_name = instance_order(parser)
        .into_iter()
        .find(|(i, _)| i == inst)
        .map(|(_, t)| t)
        .with_context(|| format!("unknown header instance `{inst}`"))?;
    parser
        .header_types
        .iter()
        .find(|h| h.name == ht_name)
        .with_context(|| format!("unknown header type `{ht_name}`"))
}

fn fixed_bits(parser: &pb::Parser, r: &pb::FieldRef) -> Result<u32> {
    let ht = header_type_of(parser, &r.header)?;
    let f = ht
        .fields
        .iter()
        .find(|f| f.name == r.field)
        .with_context(|| format!("unknown field `{}.{}`", r.header, r.field))?;
    match f.width.as_ref().and_then(|x| x.width.as_ref()) {
        Some(pb::field_width::Width::Bits(n)) => Ok(*n),
        _ => bail!("expr references non-fixed field `{}.{}`", r.header, r.field),
    }
}

/// (min, max) bounds of an expression by interval arithmetic. SUB
/// saturates at 0 (the interpreter rejects negative lengths at runtime,
/// so 0 is a sound floor for a bound).
fn expr_range(e: &pb::Expr, parser: &pb::Parser) -> Result<(u128, u128)> {
    Ok(match e.kind.as_ref().context("empty expression")? {
        pb::expr::Kind::Constant(v) => (*v as u128, *v as u128),
        pb::expr::Kind::Field(r) => (0, (1u128 << fixed_bits(parser, r)?) - 1),
        pb::expr::Kind::Bin(b) => {
            let (lmin, lmax) = expr_range(b.lhs.as_deref().context("binop missing lhs")?, parser)?;
            let (rmin, rmax) = expr_range(b.rhs.as_deref().context("binop missing rhs")?, parser)?;
            match pb::BinOpKind::try_from(b.op) {
                Ok(pb::BinOpKind::Add) => (lmin + rmin, lmax + rmax),
                Ok(pb::BinOpKind::Sub) => (lmin.saturating_sub(rmax), lmax.saturating_sub(rmin)),
                Ok(pb::BinOpKind::Mul) => {
                    (lmin * rmin, lmax.checked_mul(rmax).context("mul overflow")?)
                }
                Ok(pb::BinOpKind::Shl) => (
                    lmin.checked_shl(rmin.min(64) as u32).unwrap_or(0),
                    lmax.checked_shl(rmax.min(64) as u32)
                        .context("shl overflow")?,
                ),
                Ok(pb::BinOpKind::Shr) => (lmin >> rmax.min(127), lmax >> rmin.min(127)),
                Ok(pb::BinOpKind::And) => (0, lmax.min(rmax)),
                Ok(pb::BinOpKind::Or) => (lmin.max(rmin), lmax + rmax),
                _ => bail!("unspecified binop"),
            }
        }
    })
}

/// Upper bound (in the expr's own unit) by interval arithmetic.
pub(crate) fn expr_max(e: &pb::Expr, parser: &pb::Parser) -> Result<u128> {
    Ok(expr_range(e, parser)?.1)
}

fn seg_member(inst: &str, i: usize, seg: &Seg) -> String {
    match seg {
        Seg::Fixed(_) => format!("{inst}_s{i}"),
        Seg::Var(_) => format!("{inst}_v{i}"),
    }
}

/// Struct member holding a given (instance, fixed field).
fn member_of_field(parser: &pb::Parser, r: &pb::FieldRef) -> Result<String> {
    let ht = header_type_of(parser, &r.header)?;
    for (i, seg) in segments(ht).iter().enumerate() {
        if let Seg::Fixed(fs) = seg {
            if fs.iter().any(|f| f.name == r.field) {
                return Ok(seg_member(&r.header, i, seg));
            }
        }
    }
    bail!("field `{}.{}` is not a fixed field", r.header, r.field)
}

/// Expressions evaluate in bit<64> (field widths are <= 64).
fn expr_p4(e: &pb::Expr, parser: &pb::Parser) -> Result<String> {
    Ok(match e.kind.as_ref().context("empty expression")? {
        pb::expr::Kind::Constant(v) => format!("64w{v}"),
        pb::expr::Kind::Field(r) => {
            format!("(bit<64>)hdr.{}.{}", member_of_field(parser, r)?, r.field)
        }
        pb::expr::Kind::Bin(b) => {
            let l = expr_p4(b.lhs.as_deref().context("binop missing lhs")?, parser)?;
            let r = expr_p4(b.rhs.as_deref().context("binop missing rhs")?, parser)?;
            let op = match pb::BinOpKind::try_from(b.op) {
                Ok(pb::BinOpKind::Add) => "+",
                Ok(pb::BinOpKind::Sub) => "-",
                Ok(pb::BinOpKind::Mul) => "*",
                Ok(pb::BinOpKind::Shl) => "<<",
                Ok(pb::BinOpKind::Shr) => ">>",
                Ok(pb::BinOpKind::And) => "&",
                Ok(pb::BinOpKind::Or) => "|",
                _ => bail!("unspecified binop"),
            };
            format!("({l} {op} {r})")
        }
    })
}

fn entry_p4(entry: &pb::KeysetEntry) -> String {
    match entry.kind.as_ref() {
        Some(pb::keyset_entry::Kind::Value(v)) => format!("64w{v}"),
        Some(pb::keyset_entry::Kind::Masked(m)) => format!("64w{} &&& 64w{}", m.value, m.mask),
        Some(pb::keyset_entry::Kind::Range(r)) => format!("64w{} .. 64w{}", r.lo, r.hi),
        None => "default".into(),
    }
}

/// BMv2 does not support `transition reject`; rejects become
/// `error.NoMatch`, either natively (a select with its reject-default
/// omitted) or via a synthetic `verify(false, ...)` state.
fn target_p4(t: &pb::Target) -> Result<String> {
    Ok(match t.kind.as_ref().context("empty target")? {
        pb::target::Kind::State(s) => format!("st_{s}"),
        pb::target::Kind::Accept(_) => "accept".into(),
        pb::target::Kind::Reject(_) => "st__reject".into(),
    })
}

fn is_reject(t: &pb::Target) -> bool {
    matches!(t.kind.as_ref(), Some(pb::target::Kind::Reject(_)))
}

/// Does any target other than a select default point at reject?
/// (Those need the synthetic verify-state.)
fn needs_reject_state(parser: &pb::Parser) -> bool {
    parser.states.iter().any(
        |s| match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => is_reject(t),
            Some(pb::transition::Kind::Select(sel)) => sel
                .arms
                .iter()
                .any(|a| a.next.as_ref().is_some_and(is_reject)),
            None => false,
        },
    )
}

fn state_targets(s: &pb::State) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |t: Option<&pb::Target>| {
        if let Some(pb::target::Kind::State(name)) = t.and_then(|t| t.kind.as_ref()) {
            out.push(name.clone());
        }
    };
    match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
        Some(pb::transition::Kind::Direct(t)) => push(Some(t)),
        Some(pb::transition::Kind::Select(sel)) => {
            for arm in &sel.arms {
                push(arm.next.as_ref());
            }
            push(sel.default_target.as_ref());
        }
        None => {}
    }
    out
}

/// DFS cycle check over the state graph.
fn check_acyclic(parser: &pb::Parser) -> Result<()> {
    fn visit(
        parser: &pb::Parser,
        name: &str,
        color: &mut std::collections::HashMap<String, u8>,
    ) -> Result<()> {
        match color.get(name) {
            Some(1) => bail!(
                "state graph has a cycle through `{name}`: \
                 P4 emission requires a DAG until header stacks land (TLV slice)"
            ),
            Some(2) => return Ok(()),
            _ => {}
        }
        color.insert(name.to_string(), 1);
        if let Some(s) = parser.states.iter().find(|s| s.name == name) {
            for t in state_targets(s) {
                visit(parser, &t, color)?;
            }
        }
        color.insert(name.to_string(), 2);
        Ok(())
    }
    let mut color = std::collections::HashMap::new();
    visit(parser, &parser.start_state, &mut color)
}

pub fn generate_p4(ir: &pb::Ir) -> Result<String> {
    let parser = ir.parser.as_ref().context("IR has no parser")?;
    check_acyclic(parser)?;
    let insts = instance_order(parser);
    if insts.len() > 8 {
        bail!(
            "verdict bitmap supports at most 8 header instances, got {}",
            insts.len()
        );
    }
    if insts.iter().any(|(i, _)| i == "verdict") {
        bail!("header instance name `verdict` is reserved by the P4 backend");
    }

    let mut w = String::new();
    writeln!(
        w,
        "/* Generated by pakeles from `{}`. Do not edit:",
        parser.name
    )?;
    writeln!(w, " * regenerate with `pakeles gen p4`. */")?;
    writeln!(w, "#include <core.p4>")?;
    writeln!(w, "#include <v1model.p4>")?;
    writeln!(w)?;

    // Header declarations, one per segment.
    for (inst, _) in &insts {
        let ht = header_type_of(parser, inst)?;
        for (i, seg) in segments(ht).iter().enumerate() {
            match seg {
                Seg::Fixed(fs) => {
                    writeln!(w, "header {inst}_s{i}_t {{")?;
                    for f in fs {
                        let bits = match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                            Some(pb::field_width::Width::Bits(n)) => *n,
                            _ => unreachable!("fixed segment holds only fixed fields"),
                        };
                        writeln!(w, "    bit<{bits}> {};", f.name)?;
                    }
                    writeln!(w, "}}")?;
                }
                Seg::Var(f) => {
                    let expr = match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                        Some(pb::field_width::Width::ByteLen(e)) => e,
                        _ => unreachable!("var segment holds a byte_len field"),
                    };
                    let max_bits = expr_max(expr, parser)? * 8;
                    if max_bits > 65535 {
                        bail!(
                            "varbit bound for `{}.{}` too large: {max_bits} bits",
                            inst,
                            f.name
                        );
                    }
                    writeln!(w, "header {inst}_v{i}_t {{")?;
                    writeln!(w, "    varbit<{max_bits}> {};", f.name)?;
                    writeln!(w, "}}")?;
                }
            }
            writeln!(w)?;
        }
    }

    writeln!(w, "header verdict_t {{")?;
    writeln!(w, "    bit<8> bitmap;")?;
    writeln!(w, "    bit<8> err;")?;
    writeln!(w, "}}")?;
    writeln!(w)?;

    writeln!(w, "struct headers {{")?;
    writeln!(w, "    verdict_t verdict;")?;
    for (inst, _) in &insts {
        let ht = header_type_of(parser, inst)?;
        for (i, seg) in segments(ht).iter().enumerate() {
            let member = seg_member(inst, i, seg);
            match seg {
                Seg::Fixed(_) => writeln!(w, "    {inst}_s{i}_t {member};")?,
                Seg::Var(_) => writeln!(w, "    {inst}_v{i}_t {member};")?,
            }
        }
    }
    writeln!(w, "}}")?;
    writeln!(w)?;
    writeln!(w, "struct metadata {{")?;
    writeln!(w, "}}")?;
    writeln!(w)?;

    // Parser.
    writeln!(
        w,
        "parser PkParser(packet_in pkt, out headers hdr, inout metadata meta,"
    )?;
    writeln!(w, "                inout standard_metadata_t smeta) {{")?;
    writeln!(w, "    state start {{")?;
    writeln!(w, "        transition st_{};", parser.start_state)?;
    writeln!(w, "    }}")?;
    for s in &parser.states {
        writeln!(w, "    state st_{} {{", s.name)?;
        for ex in &s.extracts {
            let inst = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            let ht = header_type_of(parser, inst)?;
            for (i, seg) in segments(ht).iter().enumerate() {
                let member = seg_member(inst, i, seg);
                match seg {
                    Seg::Fixed(_) => writeln!(w, "        pkt.extract(hdr.{member});")?,
                    Seg::Var(f) => {
                        let expr = match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                            Some(pb::field_width::Width::ByteLen(e)) => e,
                            _ => unreachable!(),
                        };
                        writeln!(
                            w,
                            "        pkt.extract(hdr.{member}, (bit<32>)(64w8 * {}));",
                            expr_p4(expr, parser)?
                        )?;
                    }
                }
            }
        }
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => {
                writeln!(w, "        transition {};", target_p4(t)?)?;
            }
            Some(pb::transition::Kind::Select(sel)) => {
                let keys = sel
                    .keys
                    .iter()
                    .map(|k| expr_p4(k, parser))
                    .collect::<Result<Vec<_>>>()?;
                writeln!(w, "        transition select({}) {{", keys.join(", "))?;
                for arm in &sel.arms {
                    let entries: Vec<String> = arm.entries.iter().map(entry_p4).collect();
                    let pat = if entries.len() == 1 {
                        entries[0].clone()
                    } else {
                        format!("({})", entries.join(", "))
                    };
                    let next = arm.next.as_ref().context("select arm has no target")?;
                    writeln!(w, "            {pat}: {};", target_p4(next)?)?;
                }
                let dt = sel
                    .default_target
                    .as_ref()
                    .context("select has no default")?;
                if !is_reject(dt) {
                    writeln!(w, "            default: {};", target_p4(dt)?)?;
                }
                // A reject default is expressed by omission: no-match
                // raises error.NoMatch, BMv2's native reject.
                writeln!(w, "        }}")?;
            }
            None => bail!("state `{}` has no transition", s.name),
        }
        writeln!(w, "    }}")?;
    }
    if needs_reject_state(parser) {
        writeln!(w, "    state st__reject {{")?;
        writeln!(w, "        verify(false, error.NoMatch);")?;
        writeln!(w, "        transition accept;")?;
        writeln!(w, "    }}")?;
    }
    writeln!(w, "}}")?;
    writeln!(w)?;

    // Checksum stubs + controls.
    writeln!(
        w,
        "control PkVerifyChecksum(inout headers hdr, inout metadata meta) {{"
    )?;
    writeln!(w, "    apply {{ }}")?;
    writeln!(w, "}}")?;
    writeln!(w)?;
    writeln!(
        w,
        "control PkIngress(inout headers hdr, inout metadata meta,"
    )?;
    writeln!(w, "                  inout standard_metadata_t smeta) {{")?;
    writeln!(w, "    apply {{")?;
    writeln!(w, "        hdr.verdict.setValid();")?;
    writeln!(w, "        bit<8> bm = 8w0;")?;
    for (idx, (inst, _)) in insts.iter().enumerate() {
        let ht = header_type_of(parser, inst)?;
        let segs = segments(ht);
        let last = segs.len() - 1;
        let member = seg_member(inst, last, &segs[last]);
        writeln!(
            w,
            "        if (hdr.{member}.isValid()) {{ bm = bm | 8w{}; }}",
            1u32 << idx
        )?;
    }
    writeln!(w, "        hdr.verdict.bitmap = bm;")?;
    writeln!(w, "        bit<8> err = 8w255;")?;
    for (cond, code) in [
        ("error.NoError", 0u8),
        ("error.PacketTooShort", 1),
        ("error.NoMatch", 2),
        ("error.StackOutOfBounds", 3),
        ("error.HeaderTooShort", 4),
        ("error.ParserTimeout", 5),
        ("error.ParserInvalidArgument", 6),
    ] {
        let kw = if code == 0 { "if" } else { "else if" };
        writeln!(
            w,
            "        {kw} (smeta.parser_error == {cond}) {{ err = 8w{code}; }}"
        )?;
    }
    writeln!(w, "        hdr.verdict.err = err;")?;
    writeln!(w, "        smeta.egress_spec = 9w1;")?;
    writeln!(w, "    }}")?;
    writeln!(w, "}}")?;
    writeln!(w)?;
    writeln!(
        w,
        "control PkEgress(inout headers hdr, inout metadata meta,"
    )?;
    writeln!(w, "                 inout standard_metadata_t smeta) {{")?;
    writeln!(w, "    apply {{ }}")?;
    writeln!(w, "}}")?;
    writeln!(w)?;
    writeln!(
        w,
        "control PkComputeChecksum(inout headers hdr, inout metadata meta) {{"
    )?;
    writeln!(w, "    apply {{ }}")?;
    writeln!(w, "}}")?;
    writeln!(w)?;
    writeln!(w, "control PkDeparser(packet_out pkt, in headers hdr) {{")?;
    writeln!(w, "    apply {{")?;
    writeln!(w, "        pkt.emit(hdr.verdict);")?;
    writeln!(w, "    }}")?;
    writeln!(w, "}}")?;
    writeln!(w)?;
    writeln!(
        w,
        "V1Switch(PkParser(), PkVerifyChecksum(), PkIngress(), PkEgress(),"
    )?;
    writeln!(w, "         PkComputeChecksum(), PkDeparser()) main;")?;
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_splits_into_fixed_then_var() {
        let ir = crate::examples::eth_ipv4_tcp();
        let ipv4 = ir
            .parser
            .as_ref()
            .unwrap()
            .header_types
            .iter()
            .find(|h| h.name == "ipv4")
            .unwrap();
        let segs = segments(ipv4);
        assert_eq!(segs.len(), 2);
        assert!(matches!(&segs[0], Seg::Fixed(fs) if fs.len() == 13));
        assert!(matches!(&segs[1], Seg::Var(f) if f.name == "options"));
    }

    #[test]
    fn ipv4_options_max_is_40_bytes() {
        let ir = crate::examples::eth_ipv4_tcp();
        let parser = ir.parser.as_ref().unwrap();
        let ipv4 = parser
            .header_types
            .iter()
            .find(|h| h.name == "ipv4")
            .unwrap();
        let segs = segments(ipv4);
        let Seg::Var(f) = &segs[1] else { panic!() };
        let expr = match f.width.as_ref().unwrap().width.as_ref().unwrap() {
            pb::field_width::Width::ByteLen(e) => e,
            _ => panic!(),
        };
        assert_eq!(expr_max(expr, parser).unwrap(), 40);
    }

    #[test]
    fn instance_order_is_extraction_order() {
        let ir = crate::examples::eth_ipv4_tcp();
        let order = instance_order(ir.parser.as_ref().unwrap());
        let names: Vec<&str> = order.iter().map(|(i, _)| i.as_str()).collect();
        assert_eq!(names, ["ethernet", "ipv4", "tcp"]);
    }

    #[test]
    fn generated_p4_contains_expected_decls() {
        let p4 = generate_p4(&crate::examples::eth_ipv4_tcp()).unwrap();
        for needle in [
            "#include <v1model.p4>",
            "header ethernet_s0_t",
            "bit<48> dst;",
            "varbit<320> options;",
            "state st_parse_ipv4",
            "pkt.extract(hdr.ipv4_s0);",
            "transition select(",
            "64w2048: st_parse_ipv4;",
            "header verdict_t",
            "V1Switch(",
        ] {
            assert!(p4.contains(needle), "missing: {needle}\n---\n{p4}");
        }
        // BMv2 does not support explicit reject transitions; reject
        // defaults are expressed by omission (error.NoMatch).
        assert!(!p4.contains("transition reject"), "---\n{p4}");
        assert!(!p4.contains("default:"), "---\n{p4}");
    }

    #[test]
    fn cyclic_graph_is_rejected() {
        let mut ir = crate::examples::eth_ipv4_tcp();
        let p = ir.parser.as_mut().unwrap();
        let tcp = p.states.iter_mut().find(|s| s.name == "parse_tcp").unwrap();
        tcp.transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Direct(pb::Target {
                kind: Some(pb::target::Kind::State("parse_ethernet".into())),
            })),
        });
        let err = generate_p4(&ir).unwrap_err().to_string();
        assert!(err.contains("cycle"), "unexpected error: {err}");
    }

    #[test]
    fn committed_p4_artifact_current() {
        let p4 = generate_p4(&crate::examples::eth_ipv4_tcp()).unwrap();
        let committed = std::fs::read_to_string("examples/eth_ipv4_tcp/gen/parser.p4").unwrap();
        assert_eq!(
            p4, committed,
            "examples/ drifted; regenerate: ./dev.sh cargo run --bin gen_examples"
        );
    }

    #[test]
    fn generated_p4_compiles_with_p4test() {
        if std::process::Command::new("p4test")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: p4test not available");
            return;
        }
        let p4 = generate_p4(&crate::examples::eth_ipv4_tcp()).unwrap();
        let dir = std::env::temp_dir().join("pakeles_p4test");
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("parser.p4");
        std::fs::write(&src, &p4).unwrap();
        let out = std::process::Command::new("p4test")
            .arg(&src)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "p4test rejected:\n{stderr}\n---\n{p4}"
        );
        assert!(
            !stderr.contains("warning"),
            "p4test warnings:\n{stderr}\n---\n{p4}"
        );
    }
}
