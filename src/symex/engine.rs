//! Path enumeration with layout concretization.
//!
//! Variable-length fields are handled by forking on every feasible
//! value of the length expression (all-SAT, loud cap), which makes all
//! field offsets concrete per path; the only symbolic values are field
//! contents, encoded as extracts of one packet bitvector.

use super::solver::{Constraint, Solver, Term};
use crate::ir::pb;
use std::collections::{HashMap, HashSet};

/// Refuse layouts demanding more than this many bits (1 MiB): a
/// wrapping length expression (e.g. ihl<5) is a semantic reject, not a
/// layout to materialize.
const SANITY_BITS: usize = 8 * 1024 * 1024;

/// All-SAT cap for length-value enumeration. Exceeding it is an error,
/// never a silent truncation.
const LENGTH_VALUES_CAP: usize = 1024;

/// Max times a cyclic state may be entered per path during testgen. A
/// self-loop (e.g. IPv6 option chains) otherwise forks exponentially in
/// loop depth (~arms^depth), so we cap unrolling to a small constant.
/// At 2, this generates 0/1/2 option-header vectors — exercising loop
/// entry, the self-loop taken twice (stack depth 2), and
/// opt→opt→{frag,tcp,udp} — which is sufficient backend coverage, while
/// roughly halving the loop's path contribution vs 3 (which produced
/// ~7346 vectors for the looped example). Deeper chains are a documented
/// divergence covered by the kernel-agreement corpus. This is a coverage
/// bound, NOT parser behavior — over-cap unrollings emit no vector (not a
/// reject). Coexists with the global `max_depth` reject.
const TESTGEN_LOOP_UNROLL: u32 = 2;

#[derive(Debug, Clone, PartialEq)]
pub enum PathKind {
    Accept,
    Reject { reason: String },
    Truncation,
}

#[derive(Debug, Clone)]
pub struct Path {
    pub id: String,
    pub kind: PathKind,
    pub bit_len: usize,
    pub(crate) constraints: Vec<Constraint>,
}

/// Feasibility byproducts consumed by lint.
#[derive(Debug, Default)]
pub struct FeasibilityLog {
    pub reached_states: HashSet<String>,
    /// (state, arm index) attempted at a reached select.
    pub attempted_arms: HashSet<(String, usize)>,
    /// (state, arm index) feasible in at least one context.
    pub feasible_arms: HashSet<(String, usize)>,
}

pub struct Enumeration {
    pub paths: Vec<Path>,
    pub log: FeasibilityLog,
}

struct Ctx<'a> {
    parser: &'a pb::Parser,
    states: HashMap<&'a str, &'a pb::State>,
    header_types: HashMap<&'a str, &'a pb::HeaderType>,
    solver: &'a mut dyn Solver,
    paths: Vec<Path>,
    log: FeasibilityLog,
    /// States reachable from themselves via the transition graph. A
    /// var-length field on such a state forks only min+max witnesses so
    /// loop enumeration stays tractable (see `walk_extracts`).
    cyclic_states: HashSet<String>,
}

#[derive(Clone, Default)]
struct Frame {
    cursor: usize,
    placed: HashMap<(String, String), (usize, usize)>, // (inst,field) -> (bit_off, len)
    constraints: Vec<Constraint>,
    segments: Vec<String>,
    depth: u32,
    /// Per-path entry count for each cyclic state (loop-unroll cap).
    loop_counts: HashMap<String, u32>,
}

pub(crate) fn enumerate(ir: &pb::Ir, solver: &mut dyn Solver) -> anyhow::Result<Enumeration> {
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let mut ctx = Ctx {
        parser,
        states: parser.states.iter().map(|s| (s.name.as_str(), s)).collect(),
        header_types: parser
            .header_types
            .iter()
            .map(|h| (h.name.as_str(), h))
            .collect(),
        solver,
        paths: Vec::new(),
        log: FeasibilityLog::default(),
        cyclic_states: cyclic_states(parser),
    };
    let frame = Frame::default();
    walk_state(&mut ctx, &parser.start_state, frame)?;
    ctx.paths.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Enumeration {
        paths: ctx.paths,
        log: ctx.log,
    })
}

/// State names that lie on a cycle (reachable from themselves) via the
/// transition graph: Direct target, Select arm targets, and Select
/// default. Accept/Reject targets contribute no edge.
fn cyclic_states(parser: &pb::Parser) -> HashSet<String> {
    fn target_state(t: &pb::Target) -> Option<&str> {
        match t.kind.as_ref() {
            Some(pb::target::Kind::State(n)) => Some(n.as_str()),
            _ => None,
        }
    }
    let mut succ: HashMap<&str, Vec<&str>> = HashMap::new();
    for s in &parser.states {
        let mut outs = Vec::new();
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => outs.extend(target_state(t)),
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    if let Some(t) = arm.next.as_ref() {
                        outs.extend(target_state(t));
                    }
                }
                if let Some(t) = sel.default_target.as_ref() {
                    outs.extend(target_state(t));
                }
            }
            None => {}
        }
        succ.insert(s.name.as_str(), outs);
    }
    // A state is cyclic iff it can reach itself. BFS from its successors.
    let mut cyclic = HashSet::new();
    for s in &parser.states {
        let start = s.name.as_str();
        let mut stack: Vec<&str> = succ.get(start).cloned().unwrap_or_default();
        let mut seen: HashSet<&str> = HashSet::new();
        while let Some(cur) = stack.pop() {
            if cur == start {
                cyclic.insert(start.to_string());
                break;
            }
            if seen.insert(cur) {
                stack.extend(succ.get(cur).into_iter().flatten().copied());
            }
        }
    }
    cyclic
}

fn term_of_expr(e: &pb::Expr, frame: &Frame) -> anyhow::Result<Term> {
    match e.kind.as_ref() {
        Some(pb::expr::Kind::Constant(v)) => Ok(Term::Const(*v)),
        Some(pb::expr::Kind::Field(r)) => {
            let (bit_off, len) = frame
                .placed
                .get(&(r.header.clone(), r.field.clone()))
                .ok_or_else(|| {
                    anyhow::anyhow!("unresolved field ref `{}.{}`", r.header, r.field)
                })?;
            Ok(Term::Extract {
                bit_off: *bit_off,
                len: *len,
            })
        }
        Some(pb::expr::Kind::Bin(b)) => {
            let op = pb::BinOpKind::try_from(b.op)
                .map_err(|_| anyhow::anyhow!("unknown binop {}", b.op))?;
            let l = term_of_expr(
                b.lhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing lhs"))?,
                frame,
            )?;
            let r = term_of_expr(
                b.rhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing rhs"))?,
                frame,
            )?;
            Ok(Term::Bin(op, Box::new(l), Box::new(r)))
        }
        None => anyhow::bail!("empty expression"),
    }
}

fn entry_constraint(entry: &pb::KeysetEntry, key: Term) -> Constraint {
    match entry.kind.as_ref() {
        Some(pb::keyset_entry::Kind::Value(v)) => Constraint::Eq(key, *v),
        Some(pb::keyset_entry::Kind::Masked(m)) => Constraint::Masked(key, m.value, m.mask),
        Some(pb::keyset_entry::Kind::Range(r)) => Constraint::InRange(key, r.lo, r.hi),
        // An empty entry matches nothing (mirror interp's eval_entry).
        None => Constraint::Not(Box::new(Constraint::And(vec![]))),
    }
}

fn emit(ctx: &mut Ctx, frame: &Frame, kind: PathKind, bit_len: usize) {
    ctx.paths.push(Path {
        id: frame.segments.join("/"),
        kind,
        bit_len,
        constraints: frame.constraints.clone(),
    });
}

fn walk_state(ctx: &mut Ctx, state_name: &str, mut frame: Frame) -> anyhow::Result<()> {
    frame.depth += 1;
    frame.segments.push(state_name.to_string());
    if frame.depth > ctx.parser.max_depth {
        let bl = frame.cursor;
        emit(
            ctx,
            &frame,
            PathKind::Reject {
                reason: "max depth exceeded".into(),
            },
            bl,
        );
        return Ok(());
    }
    // Testgen loop-unroll cap: a cyclic state may be entered at most
    // TESTGEN_LOOP_UNROLL times per path. Over-cap unrollings are pruned
    // with NO vector emitted (a coverage bound, not parser behavior — the
    // real parser would keep going, so we do not emit a reject). Checked
    // after the `max_depth` reject so that global bound still applies;
    // acyclic states are unaffected.
    if ctx.cyclic_states.contains(state_name) {
        let count = frame.loop_counts.entry(state_name.to_string()).or_insert(0);
        if *count >= TESTGEN_LOOP_UNROLL {
            return Ok(());
        }
        *count += 1;
    }
    ctx.log.reached_states.insert(state_name.to_string());
    let state = *ctx
        .states
        .get(state_name)
        .ok_or_else(|| anyhow::anyhow!("unknown state `{state_name}`"))?;

    // Flatten this state's extracts into (instance, header_type field) work items.
    let mut items: Vec<(String, pb::Field)> = Vec::new();
    for ex in &state.extracts {
        let ht = *ctx
            .header_types
            .get(ex.header_type.as_str())
            .ok_or_else(|| anyhow::anyhow!("unknown header type `{}`", ex.header_type))?;
        let inst = if ex.instance.is_empty() {
            ex.header_type.clone()
        } else {
            ex.instance.clone()
        };
        for f in &ht.fields {
            items.push((inst.clone(), f.clone()));
        }
    }
    walk_extracts(ctx, state, &items, 0, frame)
}

fn walk_extracts(
    ctx: &mut Ctx,
    state: &pb::State,
    items: &[(String, pb::Field)],
    idx: usize,
    mut frame: Frame,
) -> anyhow::Result<()> {
    if idx == items.len() {
        return walk_transition(ctx, state, frame);
    }
    let (inst, field) = &items[idx];
    match field.width.as_ref().and_then(|w| w.width.as_ref()) {
        Some(pb::field_width::Width::Bits(n)) => {
            let n = *n as usize;
            // Truncation fork: fail reading exactly this field.
            {
                let mut t = frame.clone();
                t.segments.push(format!("!trunc@{inst}.{}", field.name));
                let bl = frame.cursor + n - 1;
                emit(ctx, &t, PathKind::Truncation, bl);
            }
            frame
                .placed
                .insert((inst.clone(), field.name.clone()), (frame.cursor, n));
            frame.cursor += n;
            walk_extracts(ctx, state, items, idx + 1, frame)
        }
        Some(pb::field_width::Width::ByteLen(expr)) => {
            let len_term = term_of_expr(expr, &frame)?;
            // On a cyclic state, forking every feasible length compounds
            // multiplicatively per loop iteration and never terminates.
            // Fork only the min and max witnesses (dedup if equal): one
            // representative per control-flow path, preserving the
            // boundary coverage of the length arithmetic. Computed via
            // two z3 optimize solves instead of a solver call per value.
            // Acyclic states keep the exhaustive all-SAT enumeration.
            let values: Vec<u64> = if ctx.cyclic_states.contains(state.name.as_str()) {
                match ctx
                    .solver
                    .min_max(frame.cursor.max(1), &frame.constraints, &len_term)?
                {
                    None => Vec::new(),
                    Some((mn, mx)) if mn == mx => vec![mn],
                    Some((mn, mx)) => vec![mn, mx],
                }
            } else {
                ctx.solver.all_values(
                    frame.cursor.max(1),
                    &frame.constraints,
                    &len_term,
                    LENGTH_VALUES_CAP,
                )?
            };
            for v in values {
                let mut child = frame.clone();
                child.segments.push(format!("{inst}.{}={v}B", field.name));
                child.constraints.push(Constraint::Eq(len_term.clone(), v));
                let len_bits = (v as usize).saturating_mul(8);
                if child.cursor.saturating_add(len_bits) > SANITY_BITS {
                    let bl = child.cursor;
                    emit(
                        ctx,
                        &child,
                        PathKind::Reject {
                            reason: "out of bounds".into(),
                        },
                        bl,
                    );
                    continue;
                }
                if len_bits > 0 {
                    let mut t = child.clone();
                    t.segments.push(format!("!trunc@{inst}.{}", field.name));
                    let bl = child.cursor + len_bits - 1;
                    emit(ctx, &t, PathKind::Truncation, bl);
                }
                // Var-length content is opaque bytes; not placeable for refs.
                child.cursor += len_bits;
                walk_extracts(ctx, state, items, idx + 1, child)?;
            }
            Ok(())
        }
        None => anyhow::bail!("field `{}` has no width", field.name),
    }
}

fn walk_target(ctx: &mut Ctx, target: &pb::Target, frame: Frame) -> anyhow::Result<()> {
    match target.kind.as_ref() {
        Some(pb::target::Kind::State(name)) => walk_state(ctx, name, frame),
        Some(pb::target::Kind::Accept(_)) => {
            let bl = frame.cursor;
            emit(ctx, &frame, PathKind::Accept, bl);
            Ok(())
        }
        Some(pb::target::Kind::Reject(r)) => {
            let bl = frame.cursor;
            emit(
                ctx,
                &frame,
                PathKind::Reject {
                    reason: r.reason.clone(),
                },
                bl,
            );
            Ok(())
        }
        None => anyhow::bail!("empty target"),
    }
}

fn walk_transition(ctx: &mut Ctx, state: &pb::State, frame: Frame) -> anyhow::Result<()> {
    match state.transition.as_ref().and_then(|t| t.kind.as_ref()) {
        None => anyhow::bail!("state `{}` has no transition", state.name),
        Some(pb::transition::Kind::Direct(t)) => walk_target(ctx, t, frame),
        Some(pb::transition::Kind::Select(sel)) => {
            let keys: Vec<Term> = sel
                .keys
                .iter()
                .map(|k| term_of_expr(k, &frame))
                .collect::<anyhow::Result<_>>()?;
            let arm_conds: Vec<Constraint> = sel
                .arms
                .iter()
                .map(|arm| {
                    Constraint::And(
                        arm.entries
                            .iter()
                            .zip(&keys)
                            .map(|(e, k)| entry_constraint(e, k.clone()))
                            .collect(),
                    )
                })
                .collect();
            for (i, arm) in sel.arms.iter().enumerate() {
                ctx.log.attempted_arms.insert((state.name.clone(), i));
                let mut child = frame.clone();
                child.constraints.push(arm_conds[i].clone());
                for cond in arm_conds.iter().take(i) {
                    child
                        .constraints
                        .push(Constraint::Not(Box::new(cond.clone())));
                }
                if ctx
                    .solver
                    .check(child.cursor.max(1), &child.constraints)
                    .is_none()
                {
                    continue; // infeasible in this context; lint sees it via the log
                }
                ctx.log.feasible_arms.insert((state.name.clone(), i));
                child.segments.push(format!("arm{i}"));
                let target = arm
                    .next
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("select arm has no target"))?;
                walk_target(ctx, target, child)?;
            }
            // Default: all arms negated.
            let mut child = frame;
            for cond in &arm_conds {
                child
                    .constraints
                    .push(Constraint::Not(Box::new(cond.clone())));
            }
            if ctx
                .solver
                .check(child.cursor.max(1), &child.constraints)
                .is_some()
            {
                child.segments.push("default".into());
                match sel.default_target.as_ref() {
                    Some(t) => walk_target(ctx, t, child)?,
                    None => {
                        let bl = child.cursor;
                        emit(
                            ctx,
                            &child,
                            PathKind::Reject {
                                reason: "no matching select arm".into(),
                            },
                            bl,
                        );
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::*;
    use crate::symex::z3solver::Z3Solver;

    fn enumerate_ir(ir: &pb::Ir) -> Enumeration {
        let mut solver = Z3Solver::new();
        enumerate(ir, &mut solver).unwrap()
    }

    fn count(paths: &[Path], kind: fn(&PathKind) -> bool) -> usize {
        paths.iter().filter(|p| kind(&p.kind)).count()
    }

    #[test]
    fn linear_accept() {
        let ir = ParserBuilder::new("lin", 1)
            .header(HeaderTypeBuilder::new("h").bits("a", 8))
            .state(StateBuilder::new("s").extract("h").accept())
            .start("s")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(e.paths.len(), 2); // accept + trunc@h.a
        assert_eq!(count(&e.paths, |k| *k == PathKind::Accept), 1);
        assert_eq!(count(&e.paths, |k| *k == PathKind::Truncation), 1);
        let accept = e.paths.iter().find(|p| p.kind == PathKind::Accept).unwrap();
        assert_eq!(accept.id, "s");
        assert_eq!(accept.bit_len, 8);
    }

    #[test]
    fn select_forks() {
        let ir = ParserBuilder::new("sel", 2)
            .header(HeaderTypeBuilder::new("h").bits("f", 8))
            .state(StateBuilder::new("a").extract("h").select(
                vec![f("h", "f")],
                vec![arm(vec![v(1)], to("b"))],
                reject("nope"),
            ))
            .state(StateBuilder::new("b").accept())
            .start("a")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        let ids: Vec<&str> = e.paths.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a/!trunc@h.f", "a/arm0/b", "a/default"]);
    }

    #[test]
    fn shadowed_arm_pruned_and_logged() {
        let ir = ParserBuilder::new("shadow", 2)
            .header(HeaderTypeBuilder::new("h").bits("f", 8))
            .state(StateBuilder::new("a").extract("h").select(
                vec![f("h", "f")],
                vec![arm(vec![range(0, 255)], to("b")), arm(vec![v(3)], to("b"))],
                reject("nope"),
            ))
            .state(StateBuilder::new("b").accept())
            .start("a")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        // arm1 shadowed, default infeasible: only trunc + arm0 remain.
        let ids: Vec<&str> = e.paths.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a/!trunc@h.f", "a/arm0/b"]);
        assert!(e.log.attempted_arms.contains(&("a".into(), 1)));
        assert!(!e.log.feasible_arms.contains(&("a".into(), 1)));
    }

    #[test]
    fn depth_bound_emits_reject() {
        // `s` is a cyclic state, so the loop-unroll cap also gates it; with
        // max_depth == TESTGEN_LOOP_UNROLL the entry that would exceed depth
        // is reached first and the global max_depth reject still fires
        // (checked before the cap), proving the two bounds coexist.
        let md = TESTGEN_LOOP_UNROLL;
        let ir = ParserBuilder::new("loop", md)
            .state(StateBuilder::new("s").goto_(to("s")))
            .start("s")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(e.paths.len(), 1);
        // `s` repeated (md + 1) times: the (md+1)th entry trips max_depth.
        let expected_id = vec!["s"; md as usize + 1].join("/");
        assert_eq!(e.paths[0].id, expected_id);
        assert_eq!(
            e.paths[0].kind,
            PathKind::Reject {
                reason: "max depth exceeded".into()
            }
        );
    }

    #[test]
    fn max_depth_reject_on_acyclic_chain() {
        // A purely ACYCLIC chain longer than max_depth: no state is cyclic,
        // so the loop-unroll cap never applies — the max_depth reject fires
        // on its own. This decouples the global bound from
        // TESTGEN_LOOP_UNROLL (unlike `depth_bound_emits_reject`, which
        // couples cap == max_depth on a self-loop).
        let ir = ParserBuilder::new("chain", 2)
            .state(StateBuilder::new("s0").goto_(to("s1")))
            .state(StateBuilder::new("s1").goto_(to("s2")))
            .state(StateBuilder::new("s2").goto_(to("s3")))
            .state(StateBuilder::new("s3").accept())
            .start("s0")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(e.paths.len(), 1);
        // s0(1) -> s1(2) -> s2(3 > max_depth 2): reject at the 3rd state entered.
        assert_eq!(e.paths[0].id, "s0/s1/s2");
        assert_eq!(
            e.paths[0].kind,
            PathKind::Reject {
                reason: "max depth exceeded".into()
            }
        );
    }

    #[test]
    fn length_forking() {
        // h { n: 2 bits, body: n bytes } -> 4 accepts (n=0..3),
        // 1 trunc@n, 3 trunc@body (n=1..3).
        let ir = ParserBuilder::new("varlen", 1)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("n", 2)
                    .var_bytes("body", f("h", "n")),
            )
            .state(StateBuilder::new("s").extract("h").accept())
            .start("s")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(count(&e.paths, |k| *k == PathKind::Accept), 4);
        assert_eq!(count(&e.paths, |k| *k == PathKind::Truncation), 4);
        let a3 = e
            .paths
            .iter()
            .find(|p| p.kind == PathKind::Accept && p.id.contains("=3B"))
            .unwrap();
        assert_eq!(a3.bit_len, 2 + 24);
    }

    /// Distinct `=NB` length witnesses appearing for `inst.field` across all paths.
    fn byte_len_witnesses(paths: &[Path], inst_field: &str) -> std::collections::BTreeSet<u64> {
        let prefix = format!("{inst_field}=");
        let mut out = std::collections::BTreeSet::new();
        for p in paths {
            for seg in p.id.split('/') {
                if let Some(rest) = seg.strip_prefix(&prefix) {
                    if let Some(n) = rest.strip_suffix('B') {
                        out.insert(n.parse::<u64>().unwrap());
                    }
                }
            }
        }
        out
    }

    #[test]
    fn cyclic_length_forking_bounded_to_min_max() {
        // Self-loop `opt` extracts h{len:4 bits, body:len bytes}; len==0 accepts,
        // any other len loops back to `opt`. The var-length `body` sits on a
        // cyclic state, so per-iteration forking must collapse to the min (0)
        // and max (15) length witnesses instead of every feasible value 0..15.
        let ir = ParserBuilder::new("optloop", 3)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("len", 4)
                    .var_bytes("body", f("h", "len")),
            )
            .state(StateBuilder::new("opt").extract("h").select(
                vec![f("h", "len")],
                vec![arm(vec![v(0)], accept())],
                to("opt"),
            ))
            .start("opt")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        // Only min (0) and max (15) length witnesses fork on the cyclic state —
        // not the 16 values the unbounded all-SAT enumeration would produce.
        assert_eq!(
            byte_len_witnesses(&e.paths, "h.body"),
            [0, 15].into_iter().collect()
        );
        // Termination: bounded path count (2^depth-scale, not 16^depth).
        assert!(
            e.paths.len() < 40,
            "expected a bounded path count, got {}",
            e.paths.len()
        );
        // Boundary witnesses actually produced accepts (min) and looped (max).
        assert!(e
            .paths
            .iter()
            .any(|p| p.kind == PathKind::Accept && p.id.contains("h.body=0B")));
        assert!(e
            .paths
            .iter()
            .any(|p| p.id.contains("h.body=15B/default/opt")));
    }

    #[test]
    fn cyclic_loop_unroll_capped_for_testgen() {
        // Same self-loop as above but with a LARGE max_depth: the loop
        // forks ~exponentially in loop depth (two branches recurse), so
        // without the unroll cap this explodes / hangs. The cap bounds
        // per-path entries of the cyclic `opt` state to
        // TESTGEN_LOOP_UNROLL, keeping enumeration small and fast — the
        // test terminating quickly IS the perf proof.
        let ir = ParserBuilder::new("optloop", 12)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("len", 4)
                    .var_bytes("body", f("h", "len")),
            )
            .state(StateBuilder::new("opt").extract("h").select(
                vec![f("h", "len")],
                vec![arm(vec![v(0)], accept())],
                to("opt"),
            ))
            .start("opt")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        // Bounded, small path count despite max_depth=12.
        assert!(
            e.paths.len() < 64,
            "expected a bounded path count, got {}",
            e.paths.len()
        );
        assert!(!e.paths.is_empty());
        // No single path enters the cyclic state more than the cap.
        let max_entries = e
            .paths
            .iter()
            .map(|p| p.id.split('/').filter(|seg| *seg == "opt").count())
            .max()
            .unwrap();
        assert!(
            max_entries <= TESTGEN_LOOP_UNROLL as usize,
            "cyclic state entered {max_entries} times, cap is {TESTGEN_LOOP_UNROLL}"
        );
        assert_eq!(max_entries, TESTGEN_LOOP_UNROLL as usize);
    }
}
