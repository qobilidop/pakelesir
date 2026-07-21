//! P4-16 (v1model) backend: emit a BMv2-runnable program from the IR.
//!
//! One P4 header per contiguous run of fixed fields; each var (`byte_len`)
//! field becomes a companion `varbit` header extracted with a computed
//! length (P4 requires a varbit to terminate its header). The program's
//! ingress encodes the verdict — a header-validity bitmap (`bit<8>`, or
//! `bit<16>` for >8 instances) followed by a 1-byte parser error code —
//! and the deparser emits only that verdict (bitmap big-endian, then err),
//! so the BMv2 differential observes exactly (bitmap, err) per packet.
//!
//! Cyclic state graphs are realized with header stacks: an instance whose
//! extracting state lies on a cycle becomes parallel `[max_depth]` stacks
//! (one per segment), extracted with `.next`, referenced via `.last`, and
//! tested for validity through element `[0]`. On a DAG no instance is
//! stacked, so `max_depth` is vacuous and the emitted P4 is unchanged.

use crate::ir::pb;
use anyhow::{bail, Context, Result};
use std::fmt::Write;

/// Verdict error codes (mirrors core.p4's error enum; `error` is not
/// bit-castable in P4, so the ingress maps it through an if-chain).
pub const ERR_NO_ERROR: u8 = 0;
pub const ERR_PACKET_TOO_SHORT: u8 = 1;

/// Width (in bits) of the verdict validity bitmap for `n` header instances.
/// A `bit<8>` covers the common case (≤8 instances, e.g. `eth_ipvx_l4`);
/// beyond that the bitmap widens to `bit<16>`. The deparser emits the
/// bitmap big-endian, so `bitmap_bytes` bytes precede the 1-byte err.
pub fn bitmap_bits(n: usize) -> u32 {
    if n <= 8 {
        8
    } else {
        16
    }
}

/// Bytes the verdict bitmap occupies on the wire (big-endian), for a
/// parser with the given instance count.
pub fn bitmap_bytes(n: usize) -> usize {
    (bitmap_bits(n) / 8) as usize
}

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
fn expr_p4(
    e: &pb::Expr,
    parser: &pb::Parser,
    stacked: &std::collections::HashSet<String>,
) -> Result<String> {
    Ok(match e.kind.as_ref().context("empty expression")? {
        pb::expr::Kind::Constant(v) => format!("64w{v}"),
        pb::expr::Kind::Field(r) => {
            let member = member_of_field(parser, r)?;
            // member_of_field returns e.g. "ext_opt_s0"; the instance is r.header.
            if stacked.contains(&r.header) {
                format!("(bit<64>)hdr.{member}.last.{}", r.field)
            } else {
                format!("(bit<64>)hdr.{member}.{}", r.field)
            }
        }
        pb::expr::Kind::Bin(b) => {
            let l = expr_p4(
                b.lhs.as_deref().context("binop missing lhs")?,
                parser,
                stacked,
            )?;
            let r = expr_p4(
                b.rhs.as_deref().context("binop missing rhs")?,
                parser,
                stacked,
            )?;
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

/// Instances whose extracting state lies on a cycle (is reachable from
/// itself) — these must be realized as header stacks. Computed by a DFS
/// reachability check per state; small graphs, so O(V·E) is fine.
pub(crate) fn stacked_instances(parser: &pb::Parser) -> std::collections::HashSet<String> {
    fn reaches_self(parser: &pb::Parser, start: &str) -> bool {
        let mut stack = vec![];
        let mut seen = std::collections::HashSet::new();
        if let Some(s) = parser.states.iter().find(|s| s.name == start) {
            stack.extend(state_targets(s));
        }
        while let Some(n) = stack.pop() {
            if n == start {
                return true;
            }
            if !seen.insert(n.clone()) {
                continue;
            }
            if let Some(s) = parser.states.iter().find(|s| s.name == n) {
                stack.extend(state_targets(s));
            }
        }
        false
    }
    let mut out = std::collections::HashSet::new();
    for s in &parser.states {
        if reaches_self(parser, &s.name) {
            for ex in &s.extracts {
                let inst = if ex.instance.is_empty() {
                    ex.header_type.clone()
                } else {
                    ex.instance.clone()
                };
                out.insert(inst);
            }
        }
    }
    out
}

pub fn generate_p4(ir: &pb::Ir) -> Result<String> {
    let parser = ir.parser.as_ref().context("IR has no parser")?;
    let insts = instance_order(parser);
    let stacked = stacked_instances(parser);
    if insts.len() > 16 {
        bail!(
            "verdict bitmap supports at most 16 header instances, got {}",
            insts.len()
        );
    }
    let bm_bits = bitmap_bits(insts.len());
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
    writeln!(w, "    bit<{bm_bits}> bitmap;")?;
    writeln!(w, "    bit<8> err;")?;
    writeln!(w, "}}")?;
    writeln!(w)?;

    writeln!(w, "struct headers {{")?;
    writeln!(w, "    verdict_t verdict;")?;
    for (inst, _) in &insts {
        let ht = header_type_of(parser, inst)?;
        let is_stacked = stacked.contains(inst);
        for (i, seg) in segments(ht).iter().enumerate() {
            let member = seg_member(inst, i, seg);
            let tname = match seg {
                Seg::Fixed(_) => format!("{inst}_s{i}_t"),
                Seg::Var(_) => format!("{inst}_v{i}_t"),
            };
            if is_stacked {
                writeln!(w, "    {tname}[{}] {member};", parser.max_depth)?;
            } else {
                writeln!(w, "    {tname} {member};")?;
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
            let is_stacked = stacked.contains(inst.as_str());
            for (i, seg) in segments(ht).iter().enumerate() {
                let member = seg_member(inst, i, seg);
                let tgt = if is_stacked {
                    format!("hdr.{member}.next")
                } else {
                    format!("hdr.{member}")
                };
                match seg {
                    Seg::Fixed(_) => writeln!(w, "        pkt.extract({tgt});")?,
                    Seg::Var(f) => {
                        let expr = match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                            Some(pb::field_width::Width::ByteLen(e)) => e,
                            _ => unreachable!(),
                        };
                        writeln!(
                            w,
                            "        pkt.extract({tgt}, (bit<32>)(64w8 * {}));",
                            expr_p4(expr, parser, &stacked)?
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
                    .map(|k| expr_p4(k, parser, &stacked))
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
    writeln!(w, "        bit<{bm_bits}> bm = {bm_bits}w0;")?;
    for (idx, (inst, _)) in insts.iter().enumerate() {
        let ht = header_type_of(parser, inst)?;
        let segs = segments(ht);
        let last = segs.len() - 1;
        let member = seg_member(inst, last, &segs[last]);
        let valid = if stacked.contains(inst) {
            format!("hdr.{member}[0].isValid()")
        } else {
            format!("hdr.{member}.isValid()")
        };
        writeln!(
            w,
            "        if ({valid}) {{ bm = bm | {bm_bits}w{}; }}",
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

    /// `eth_ipvx_l4` with `parse_tcp` looped back to `parse_ethernet`, so
    /// `ethernet`/`ipv4`/`ipv6`/`tcp` all lie on a cycle (are stacked).
    fn cyclic_ir() -> pb::Ir {
        let mut ir = crate::examples::eth_ipvx_l4();
        let p = ir.parser.as_mut().unwrap();
        let tcp = p.states.iter_mut().find(|s| s.name == "parse_tcp").unwrap();
        tcp.transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Direct(pb::Target {
                kind: Some(pb::target::Kind::State("parse_ethernet".into())),
            })),
        });
        ir
    }

    #[test]
    fn ipv4_splits_into_fixed_then_var() {
        let ir = crate::examples::eth_ipvx_l4();
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
        let ir = crate::examples::eth_ipvx_l4();
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
        let ir = crate::examples::eth_ipvx_l4();
        let order = instance_order(ir.parser.as_ref().unwrap());
        let names: Vec<&str> = order.iter().map(|(i, _)| i.as_str()).collect();
        assert_eq!(names, ["ethernet", "ipv4", "ipv6", "tcp", "udp"]);
    }

    #[test]
    fn generated_p4_contains_expected_decls() {
        let p4 = generate_p4(&crate::examples::eth_ipvx_l4()).unwrap();
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
    fn cyclic_graph_emits_header_stack() {
        // Make parse_tcp loop back to parse_ethernet: `ethernet` is now
        // extracted on a cycle => stacked.
        let ir = cyclic_ir();
        assert!(!stacked_instances(ir.parser.as_ref().unwrap()).is_empty()); // sanity
        let p4 = generate_p4(&ir).unwrap(); // no longer errors

        // ethernet is stacked -> parallel stack member(s) + .next extract + .last ref.
        assert!(p4.contains("ethernet_s0_t["), "no header stack: {p4}");
        assert!(p4.contains("pkt.extract(hdr.ethernet_s0.next)"), "{p4}");
        assert!(p4.contains("hdr.ethernet_s0.last."), "{p4}");
        // bitmap for a stacked instance tests element 0.
        assert!(p4.contains("hdr.ethernet_s0[0].isValid()"), "{p4}");
        // non-stacked instances keep scalar members/extracts. (udp is off
        // the cycle; ipv4 is *on* it, so ipv4 is stacked — see
        // stacked_instances_detects_self_reachable.)
        assert!(p4.contains("pkt.extract(hdr.udp_s0);"), "{p4}");
    }

    #[test]
    fn stacked_instances_detects_self_reachable() {
        let ir = cyclic_ir();
        let stacked = stacked_instances(ir.parser.as_ref().unwrap());
        assert!(stacked.contains("ethernet"));
        assert!(stacked.contains("ipv4")); // also on the cycle
        assert!(!stacked.contains("udp")); // udp is off the cycle
    }

    #[test]
    fn committed_p4_artifact_current() {
        let p4 = generate_p4(&crate::examples::eth_ipvx_l4()).unwrap();
        let committed = std::fs::read_to_string("examples/eth_ipvx_l4/gen/parser.p4").unwrap();
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
        let p4 = generate_p4(&crate::examples::eth_ipvx_l4()).unwrap();
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

    /// A synthetic linear-chain IR with `n` distinct header instances, all
    /// of the same trivial single-`bit<8>`-field header type. Exists to
    /// exercise the verdict-bitmap width threshold without needing a
    /// real-world example with that many instances.
    fn synth_ir(n: usize) -> pb::Ir {
        let ht = pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "v".into(),
                width: Some(pb::FieldWidth {
                    width: Some(pb::field_width::Width::Bits(8)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let states = (0..n)
            .map(|i| {
                let target = if i + 1 < n {
                    pb::Target {
                        kind: Some(pb::target::Kind::State(format!("s{}", i + 1))),
                    }
                } else {
                    pb::Target {
                        kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                    }
                };
                pb::State {
                    name: format!("s{i}"),
                    extracts: vec![pb::Extract {
                        header_type: "h".into(),
                        instance: format!("h{i}"),
                    }],
                    transition: Some(pb::Transition {
                        kind: Some(pb::transition::Kind::Direct(target)),
                    }),
                    ..Default::default()
                }
            })
            .collect();
        pb::Ir {
            ir_version: "0.1.0".into(),
            parser: Some(pb::Parser {
                name: "synth".into(),
                header_types: vec![ht],
                states,
                start_state: "s0".into(),
                max_depth: n as u32,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn bitmap_bits_thresholds() {
        assert_eq!(bitmap_bits(1), 8);
        assert_eq!(bitmap_bits(8), 8);
        assert_eq!(bitmap_bits(9), 16);
        assert_eq!(bitmap_bits(16), 16);
        assert_eq!(bitmap_bytes(8), 1);
        assert_eq!(bitmap_bytes(9), 2);
    }

    #[test]
    fn verdict_bitmap_widens_past_8_instances() {
        // 9-10 instances is exactly the rung-2 shape this fix unblocks.
        for n in [9, 10] {
            let p4 = generate_p4(&synth_ir(n)).unwrap_or_else(|e| {
                panic!("generate_p4 unexpectedly bailed at {n} instances: {e}")
            });
            assert!(p4.contains("bit<16> bitmap;"), "n={n}\n---\n{p4}");
            assert!(p4.contains("bit<16> bm = 16w0;"), "n={n}\n---\n{p4}");
        }
    }

    #[test]
    fn verdict_bitmap_stays_8_bit_at_or_below_8_instances() {
        let p4 = generate_p4(&synth_ir(8)).unwrap();
        assert!(p4.contains("bit<8> bitmap;"), "{p4}");
        assert!(p4.contains("bit<8> bm = 8w0;"), "{p4}");
        assert!(!p4.contains("bit<16> bitmap"), "{p4}");

        // eth_ipvx_l4 has 5 instances and exercises the same path
        // end-to-end; `committed_p4_artifact_current` pins its exact
        // byte-identical output, guarding the "unchanged for <=8" claim.
        let p4_example = generate_p4(&crate::examples::eth_ipvx_l4()).unwrap();
        assert!(p4_example.contains("bit<8> bitmap;"), "{p4_example}");
    }

    #[test]
    fn more_than_16_instances_still_bails() {
        let err = generate_p4(&synth_ir(17)).unwrap_err();
        assert!(err.to_string().contains("at most 16"), "{err}");
    }

    #[test]
    fn cyclic_p4_compiles_with_p4test() {
        if std::process::Command::new("p4test")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: p4test not available");
            return;
        }
        // The synthetic looped IR must emit header-stack P4 that p4c accepts
        // (`.next`/`.last`/`[0]` on `[max_depth]` stacks).
        let p4 = generate_p4(&cyclic_ir()).unwrap();
        let dir = std::env::temp_dir().join("pakeles_p4test_cyclic");
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
            "p4test rejected cyclic P4:\n{stderr}\n---\n{p4}"
        );
    }
}
