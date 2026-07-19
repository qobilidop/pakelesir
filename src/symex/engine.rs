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
}

#[derive(Clone, Default)]
struct Frame {
    cursor: usize,
    placed: HashMap<(String, String), (usize, usize)>, // (inst,field) -> (bit_off, len)
    constraints: Vec<Constraint>,
    segments: Vec<String>,
    depth: u32,
}

pub fn enumerate(ir: &pb::Ir, solver: &mut dyn Solver) -> anyhow::Result<Enumeration> {
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
    };
    let frame = Frame::default();
    walk_state(&mut ctx, &parser.start_state, frame)?;
    ctx.paths.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Enumeration { paths: ctx.paths, log: ctx.log })
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
            Ok(Term::Extract { bit_off: *bit_off, len: *len })
        }
        Some(pb::expr::Kind::Bin(b)) => {
            let op = pb::BinOpKind::try_from(b.op)
                .map_err(|_| anyhow::anyhow!("unknown binop {}", b.op))?;
            let l = term_of_expr(
                b.lhs.as_deref().ok_or_else(|| anyhow::anyhow!("binop missing lhs"))?,
                frame,
            )?;
            let r = term_of_expr(
                b.rhs.as_deref().ok_or_else(|| anyhow::anyhow!("binop missing rhs"))?,
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
        emit(ctx, &frame, PathKind::Reject { reason: "max depth exceeded".into() }, bl);
        return Ok(());
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
        let inst = if ex.instance.is_empty() { ex.header_type.clone() } else { ex.instance.clone() };
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
            let values = ctx.solver.all_values(
                frame.cursor.max(1),
                &frame.constraints,
                &len_term,
                LENGTH_VALUES_CAP,
            )?;
            for v in values {
                let mut child = frame.clone();
                child.segments.push(format!("{inst}.{}={v}B", field.name));
                child
                    .constraints
                    .push(Constraint::Eq(len_term.clone(), v));
                let len_bits = (v as usize).saturating_mul(8);
                if child.cursor.saturating_add(len_bits) > SANITY_BITS {
                    let bl = child.cursor;
                    emit(ctx, &child, PathKind::Reject { reason: "out of bounds".into() }, bl);
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
            emit(ctx, &frame, PathKind::Reject { reason: r.reason.clone() }, bl);
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
                            PathKind::Reject { reason: "no matching select arm".into() },
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
        let ir = ParserBuilder::new("loop", 3)
            .state(StateBuilder::new("s").goto_(to("s")))
            .start("s")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(e.paths.len(), 1);
        assert_eq!(e.paths[0].id, "s/s/s/s");
        assert_eq!(
            e.paths[0].kind,
            PathKind::Reject { reason: "max depth exceeded".into() }
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
}
