//! Parse-graph visualization: IR -> Graphviz dot.

use crate::ir::pb;
use std::fmt::Write;

/// Human-readable expression text, shared with docgen.
pub(crate) fn expr_text(e: &pb::Expr) -> String {
    fmt_expr(e)
}

/// Human-readable keyset-entry text, shared with docgen.
pub(crate) fn entry_text(key: &pb::Expr, entry: &pb::KeysetEntry) -> String {
    fmt_entry(key, entry)
}

fn fmt_expr(e: &pb::Expr) -> String {
    match e.kind.as_ref() {
        Some(pb::expr::Kind::Constant(v)) => format!("{v}"),
        Some(pb::expr::Kind::Field(r)) => format!("{}.{}", r.header, r.field),
        Some(pb::expr::Kind::Bin(b)) => {
            let op = match pb::BinOpKind::try_from(b.op) {
                Ok(pb::BinOpKind::Add) => "+",
                Ok(pb::BinOpKind::Sub) => "-",
                Ok(pb::BinOpKind::Mul) => "*",
                Ok(pb::BinOpKind::Shl) => "<<",
                Ok(pb::BinOpKind::Shr) => ">>",
                Ok(pb::BinOpKind::And) => "&",
                Ok(pb::BinOpKind::Or) => "|",
                _ => "?",
            };
            let l = b.lhs.as_deref().map(fmt_expr).unwrap_or_default();
            let r = b.rhs.as_deref().map(fmt_expr).unwrap_or_default();
            format!("({l} {op} {r})")
        }
        None => "?".into(),
    }
}

fn fmt_entry(key: &pb::Expr, entry: &pb::KeysetEntry) -> String {
    let k = fmt_expr(key);
    match entry.kind.as_ref() {
        Some(pb::keyset_entry::Kind::Value(v)) => format!("{k} == {v:#x}"),
        Some(pb::keyset_entry::Kind::Masked(m)) => {
            format!("{k} & {:#x} == {:#x}", m.mask, m.value)
        }
        Some(pb::keyset_entry::Kind::Range(r)) => format!("{k} in {:#x}..={:#x}", r.lo, r.hi),
        None => format!("{k} ?"),
    }
}

/// Render the parse graph as Graphviz dot. States are boxes listing
/// their extracts; `accept` is a doublecircle; each distinct reject
/// reason gets its own diamond.
pub fn to_dot(ir: &pb::Ir) -> String {
    let mut out = String::new();
    let mut rejects: Vec<String> = Vec::new();
    let mut edges: Vec<String> = Vec::new();

    let Some(parser) = &ir.parser else {
        return "digraph empty {}\n".into();
    };

    let mut target_node = |t: &pb::Target| -> String {
        match t.kind.as_ref() {
            Some(pb::target::Kind::State(s)) => s.clone(),
            Some(pb::target::Kind::Accept(_)) => "accept".into(),
            Some(pb::target::Kind::Reject(r)) => {
                let idx = match rejects.iter().position(|x| *x == r.reason) {
                    Some(i) => i,
                    None => {
                        rejects.push(r.reason.clone());
                        rejects.len() - 1
                    }
                };
                format!("reject_{idx}")
            }
            None => "unknown".into(),
        }
    };

    for s in &parser.states {
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => {
                let to = target_node(t);
                edges.push(format!("  \"{}\" -> \"{}\";\n", s.name, to));
            }
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    let label = sel
                        .keys
                        .iter()
                        .zip(&arm.entries)
                        .map(|(k, e)| fmt_entry(k, e))
                        .collect::<Vec<_>>()
                        .join(" && ");
                    if let Some(t) = &arm.next {
                        let to = target_node(t);
                        edges.push(format!(
                            "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
                            s.name, to, label
                        ));
                    }
                }
                if let Some(t) = &sel.default_target {
                    let to = target_node(t);
                    edges.push(format!(
                        "  \"{}\" -> \"{}\" [label=\"default\", style=dashed];\n",
                        s.name, to
                    ));
                }
            }
            None => {}
        }
    }

    writeln!(out, "digraph \"{}\" {{", parser.name).unwrap();
    writeln!(out, "  rankdir=TB;").unwrap();
    writeln!(out, "  node [fontname=\"Helvetica\"];").unwrap();
    for s in &parser.states {
        let extracts = s
            .extracts
            .iter()
            .map(|e| {
                let inst = if e.instance.is_empty() {
                    &e.header_type
                } else {
                    &e.instance
                };
                format!("extract {inst}")
            })
            .collect::<Vec<_>>()
            .join("\\n");
        let label = if extracts.is_empty() {
            s.name.clone()
        } else {
            format!("{}\\n{extracts}", s.name)
        };
        writeln!(out, "  \"{}\" [shape=box, label=\"{label}\"];", s.name).unwrap();
    }
    writeln!(out, "  \"accept\" [shape=doublecircle];").unwrap();
    for (i, reason) in rejects.iter().enumerate() {
        writeln!(
            out,
            "  \"reject_{i}\" [shape=diamond, label=\"reject:\\n{reason}\"];"
        )
        .unwrap();
    }
    for e in &edges {
        out.push_str(e);
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::to_dot;
    use crate::examples::eth_ipv4_tcp;

    #[test]
    fn dot_snapshot() {
        let dot = to_dot(&eth_ipv4_tcp());
        assert!(dot.contains("\"parse_ipv4\" -> \"parse_tcp\""));
        insta::assert_snapshot!(dot);
    }
}
