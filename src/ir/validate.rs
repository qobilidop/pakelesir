//! Well-formedness validation: everything protobuf cannot express.
//! Collects all violations (stable order) rather than failing fast.

use super::pb;

pub fn validate(ir: &pb::Ir) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();

    let Some(parser) = &ir.parser else {
        return Err(vec!["ir has no parser".into()]);
    };

    if parser.max_depth == 0 {
        errs.push("max_depth must be >= 1".into());
    }

    // Header types: unique names, unique field names, sane widths.
    let mut header_types = std::collections::HashMap::new();
    for ht in &parser.header_types {
        if header_types.insert(ht.name.as_str(), ht).is_some() {
            errs.push(format!("duplicate header type `{}`", ht.name));
        }
        let mut fields = std::collections::HashSet::new();
        for f in &ht.fields {
            if !fields.insert(f.name.as_str()) {
                errs.push(format!("duplicate field `{}.{}`", ht.name, f.name));
            }
            match f.width.as_ref().and_then(|w| w.width.as_ref()) {
                Some(pb::field_width::Width::Bits(b)) if !(1..=64).contains(b) => {
                    errs.push(format!(
                        "field `{}.{}` width {b} outside 1..=64",
                        ht.name, f.name
                    ));
                }
                Some(_) => {}
                None => errs.push(format!("field `{}.{}` has no width", ht.name, f.name)),
            }
            if let Some(d) = &f.display {
                let mut label_vals = std::collections::HashSet::new();
                for vl in &d.value_labels {
                    if !label_vals.insert(vl.value) {
                        errs.push(format!(
                            "field `{}.{}` duplicate value label {}",
                            ht.name, f.name, vl.value
                        ));
                    }
                    if let Some(pb::field_width::Width::Bits(w)) =
                        f.width.as_ref().and_then(|x| x.width.as_ref())
                    {
                        let max = if *w == 64 { u64::MAX } else { (1u64 << w) - 1 };
                        if vl.value > max {
                            errs.push(format!(
                                "field `{}.{}` value label {} exceeds {w}-bit width",
                                ht.name, f.name, vl.value
                            ));
                        }
                    }
                }
            }
        }
    }

    // States: unique non-empty names.
    let mut states = std::collections::HashSet::new();
    for s in &parser.states {
        if s.name.is_empty() {
            errs.push("state with empty name".into());
        }
        if !states.insert(s.name.as_str()) {
            errs.push(format!("duplicate state `{}`", s.name));
        }
    }
    if !states.contains(parser.start_state.as_str()) {
        errs.push(format!("unknown start state `{}`", parser.start_state));
    }

    // Header instances: name -> header type (instance defaults to type name).
    let mut instances = std::collections::HashMap::new();
    for s in &parser.states {
        for e in &s.extracts {
            let inst = if e.instance.is_empty() {
                &e.header_type
            } else {
                &e.instance
            };
            if !header_types.contains_key(e.header_type.as_str()) {
                errs.push(format!(
                    "state `{}` extracts unknown header type `{}`",
                    s.name, e.header_type
                ));
            } else {
                instances.insert(inst.as_str(), e.header_type.as_str());
            }
        }
    }

    let check_ref = |r: &pb::FieldRef, ctx: &str, errs: &mut Vec<String>| match instances
        .get(r.header.as_str())
    {
        None => errs.push(format!("{ctx}: unknown header instance `{}`", r.header)),
        Some(ht_name) => {
            let ht = header_types[ht_name];
            if !ht.fields.iter().any(|f| f.name == r.field) {
                errs.push(format!(
                    "{ctx}: header `{}` has no field `{}`",
                    r.header, r.field
                ));
            }
        }
    };

    fn walk_refs<'a>(e: &'a pb::Expr, out: &mut Vec<&'a pb::FieldRef>) {
        match &e.kind {
            Some(pb::expr::Kind::Field(r)) => out.push(r),
            Some(pb::expr::Kind::Bin(b)) => {
                if let Some(l) = &b.lhs {
                    walk_refs(l, out);
                }
                if let Some(r) = &b.rhs {
                    walk_refs(r, out);
                }
            }
            _ => {}
        }
    }

    // Field refs inside variable-length widths.
    for ht in &parser.header_types {
        for f in &ht.fields {
            if let Some(pb::field_width::Width::ByteLen(e)) =
                f.width.as_ref().and_then(|w| w.width.as_ref())
            {
                let mut refs = Vec::new();
                walk_refs(e, &mut refs);
                for r in refs {
                    check_ref(r, &format!("width of `{}.{}`", ht.name, f.name), &mut errs);
                }
            }
        }
    }

    // Transitions: targets resolve, select arity matches, refs resolve,
    // keyset entries fit the key's width when the key is a plain field ref.
    let key_width = |e: &pb::Expr| -> Option<u32> {
        if let Some(pb::expr::Kind::Field(r)) = &e.kind {
            let ht = header_types.get(*instances.get(r.header.as_str())?)?;
            let f = ht.fields.iter().find(|f| f.name == r.field)?;
            if let Some(pb::field_width::Width::Bits(b)) =
                f.width.as_ref().and_then(|w| w.width.as_ref())
            {
                return Some(*b);
            }
        }
        None
    };

    for s in &parser.states {
        let ctx = format!("state `{}`", s.name);
        let check_target = |t: &pb::Target, errs: &mut Vec<String>| match &t.kind {
            Some(pb::target::Kind::State(name)) => {
                if !states.contains(name.as_str()) {
                    errs.push(format!("{ctx}: unknown state `{name}`"));
                }
            }
            Some(pb::target::Kind::Reject(r)) => {
                if let Some(sev) = r.annotations.get("severity") {
                    if sev != "error" && sev != "info" {
                        errs.push(format!(
                            "{ctx}: reject severity `{sev}` (must be `error` or `info`)"
                        ));
                    }
                }
            }
            _ => {}
        };
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            None => errs.push(format!("{ctx}: no transition")),
            Some(pb::transition::Kind::Direct(t)) => check_target(t, &mut errs),
            Some(pb::transition::Kind::Select(sel)) => {
                for k in &sel.keys {
                    let mut refs = Vec::new();
                    walk_refs(k, &mut refs);
                    for r in refs {
                        check_ref(r, &ctx, &mut errs);
                    }
                }
                for arm in &sel.arms {
                    if arm.entries.len() != sel.keys.len() {
                        errs.push(format!(
                            "{ctx}: arm has {} entries for {} keys",
                            arm.entries.len(),
                            sel.keys.len()
                        ));
                    }
                    for (entry, key) in arm.entries.iter().zip(&sel.keys) {
                        if let (Some(w), Some(kind)) = (key_width(key), entry.kind.as_ref()) {
                            let max = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
                            let vals: &[u64] = match kind {
                                pb::keyset_entry::Kind::Value(v) => &[*v],
                                pb::keyset_entry::Kind::Masked(m) => &[m.value, m.mask],
                                pb::keyset_entry::Kind::Range(r) => &[r.lo, r.hi],
                            };
                            if vals.iter().any(|v| *v > max) {
                                errs.push(format!("{ctx}: keyset entry exceeds {w}-bit key width"));
                            }
                        }
                    }
                    if let Some(t) = &arm.next {
                        check_target(t, &mut errs);
                    }
                }
                if let Some(t) = &sel.default_target {
                    check_target(t, &mut errs);
                }
            }
        }
    }

    // Path-sensitive def-use: an expression may only reference header
    // instances *definitely* extracted on every path to its use point.
    // Must-analysis fixpoint: in(s) = ∩ over predecessors p of
    // (in(p) ∪ extracted(p)); in(start) = ∅.
    if errs.is_empty() {
        definite_extraction_errors(parser, &header_types, &mut errs);
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn state_instances(s: &pb::State) -> Vec<String> {
    s.extracts
        .iter()
        .map(|e| {
            if e.instance.is_empty() {
                e.header_type.clone()
            } else {
                e.instance.clone()
            }
        })
        .collect()
}

fn definite_extraction_errors(
    parser: &pb::Parser,
    header_types: &std::collections::HashMap<&str, &pb::HeaderType>,
    errs: &mut Vec<String>,
) {
    use std::collections::{HashMap, HashSet};

    let succs = |s: &pb::State| -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |t: &pb::Target| {
            if let Some(pb::target::Kind::State(n)) = &t.kind {
                out.push(n.clone());
            }
        };
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => push(t),
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    if let Some(t) = &arm.next {
                        push(t);
                    }
                }
                if let Some(t) = &sel.default_target {
                    push(t);
                }
            }
            None => {}
        }
        out
    };

    // Fixpoint over must-extracted sets at state entry.
    let all: HashSet<String> = parser.states.iter().flat_map(state_instances).collect();
    let mut inset: HashMap<&str, HashSet<String>> = parser
        .states
        .iter()
        .map(|s| {
            let init = if s.name == parser.start_state {
                HashSet::new()
            } else {
                all.clone()
            };
            (s.name.as_str(), init)
        })
        .collect();
    loop {
        let mut changed = false;
        for s in &parser.states {
            let out: HashSet<String> = inset[s.name.as_str()]
                .iter()
                .cloned()
                .chain(state_instances(s))
                .collect();
            for succ in succs(s) {
                if let Some(cur) = inset.get_mut(succ.as_str()) {
                    let narrowed: HashSet<String> = cur.intersection(&out).cloned().collect();
                    if narrowed.len() != cur.len() {
                        *cur = narrowed;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Check every expression use point against the available set.
    let mut check_expr = |e: &pb::Expr, avail: &HashSet<String>, ctx: &str| {
        let mut refs = Vec::new();
        collect_refs(e, &mut refs);
        for r in refs {
            if !avail.contains(&r.header) {
                errs.push(format!(
                    "{ctx}: `{}.{}` is not definitely extracted on every path to this point",
                    r.header, r.field
                ));
            }
        }
    };
    for s in &parser.states {
        let mut avail = inset[s.name.as_str()].clone();
        for ex in &s.extracts {
            let inst = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            // Var-length exprs inside this header may use earlier
            // fields of the same instance: add before checking widths.
            avail.insert(inst.clone());
            if let Some(ht) = header_types.get(ex.header_type.as_str()) {
                for f in &ht.fields {
                    if let Some(pb::field_width::Width::ByteLen(e)) =
                        f.width.as_ref().and_then(|w| w.width.as_ref())
                    {
                        check_expr(
                            e,
                            &avail,
                            &format!("state `{}` width of `{inst}.{}`", s.name, f.name),
                        );
                    }
                }
            }
        }
        if let Some(pb::transition::Kind::Select(sel)) =
            s.transition.as_ref().and_then(|t| t.kind.as_ref())
        {
            for k in &sel.keys {
                check_expr(k, &avail, &format!("state `{}` select key", s.name));
            }
        }
    }
}

fn collect_refs<'a>(e: &'a pb::Expr, out: &mut Vec<&'a pb::FieldRef>) {
    match &e.kind {
        Some(pb::expr::Kind::Field(r)) => out.push(r),
        Some(pb::expr::Kind::Bin(b)) => {
            if let Some(l) = &b.lhs {
                collect_refs(l, out);
            }
            if let Some(r) = &b.rhs {
                collect_refs(r, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::super::pb;
    use super::super::test_support::tiny;
    use super::validate;

    fn parser(ir: &mut pb::Ir) -> &mut pb::Parser {
        ir.parser.as_mut().unwrap()
    }

    fn set_direct_target(ir: &mut pb::Ir, state: &str) {
        parser(ir).states[0].transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Direct(pb::Target {
                kind: Some(pb::target::Kind::State(state.into())),
            })),
        });
    }

    fn assert_err_contains(ir: &pb::Ir, needle: &str) {
        let errs = validate(ir).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains(needle)),
            "expected an error containing {needle:?}, got {errs:?}"
        );
    }

    #[test]
    fn accepts_tiny() {
        validate(&tiny()).unwrap();
    }

    #[test]
    fn rejects_missing_parser() {
        let ir = pb::Ir::default();
        assert_err_contains(&ir, "no parser");
    }

    #[test]
    fn rejects_zero_max_depth() {
        let mut ir = tiny();
        parser(&mut ir).max_depth = 0;
        assert_err_contains(&ir, "max_depth");
    }

    #[test]
    fn rejects_dup_state() {
        let mut ir = tiny();
        let dup = parser(&mut ir).states[0].clone();
        parser(&mut ir).states.push(dup);
        assert_err_contains(&ir, "duplicate state `s`");
    }

    #[test]
    fn rejects_unresolved_start() {
        let mut ir = tiny();
        parser(&mut ir).start_state = "nope".into();
        assert_err_contains(&ir, "unknown start state `nope`");
    }

    #[test]
    fn rejects_unresolved_target() {
        let mut ir = tiny();
        set_direct_target(&mut ir, "nope");
        assert_err_contains(&ir, "unknown state `nope`");
    }

    #[test]
    fn rejects_bad_width() {
        let mut ir = tiny();
        parser(&mut ir).header_types.push(pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "f".into(),
                width: Some(pb::FieldWidth {
                    width: Some(pb::field_width::Width::Bits(65)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_err_contains(&ir, "width 65 outside 1..=64");
    }

    fn field_ref(header: &str, field: &str) -> pb::Expr {
        pb::Expr {
            kind: Some(pb::expr::Kind::Field(pb::FieldRef {
                header: header.into(),
                field: field.into(),
            })),
        }
    }

    fn with_select(ir: &mut pb::Ir, keys: Vec<pb::Expr>, arms: Vec<pb::SelectArm>) {
        parser(ir).states[0].transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Select(pb::Select {
                keys,
                arms,
                default_target: Some(pb::Target {
                    kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                }),
            })),
        });
    }

    #[test]
    fn rejects_arity_mismatch() {
        let mut ir = tiny();
        with_select(
            &mut ir,
            vec![field_ref("x", "y")],
            vec![pb::SelectArm {
                entries: vec![],
                next: None,
            }],
        );
        assert_err_contains(&ir, "0 entries for 1 keys");
    }

    #[test]
    fn rejects_unknown_field_ref() {
        let mut ir = tiny();
        with_select(&mut ir, vec![field_ref("ghost", "f")], vec![]);
        assert_err_contains(&ir, "unknown header instance `ghost`");
    }

    #[test]
    fn rejects_bad_severity() {
        let mut ir = tiny();
        parser(&mut ir).states[0].transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Direct(pb::Target {
                kind: Some(pb::target::Kind::Reject(pb::Reject {
                    reason: "r".into(),
                    annotations: [("severity".to_string(), "fatal".to_string())].into(),
                })),
            })),
        });
        assert_err_contains(&ir, "reject severity `fatal`");
    }

    #[test]
    fn rejects_bad_value_labels() {
        let mut ir = tiny();
        parser(&mut ir).header_types.push(pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "f".into(),
                width: Some(pb::FieldWidth {
                    width: Some(pb::field_width::Width::Bits(4)),
                }),
                display: Some(pb::Display {
                    name: "F".into(),
                    value_labels: vec![
                        pb::ValueLabel { value: 3, label: "a".into() },
                        pb::ValueLabel { value: 3, label: "b".into() },
                        pb::ValueLabel { value: 99, label: "c".into() },
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_err_contains(&ir, "duplicate value label 3");
        assert_err_contains(&ir, "value label 99 exceeds 4-bit width");
    }

    #[test]
    fn rejects_branch_dependent_ref() {
        use crate::builder::*;
        let err = ParserBuilder::new("branchy", 3)
            .header(HeaderTypeBuilder::new("h").bits("f", 8))
            .header(HeaderTypeBuilder::new("g").bits("x", 8))
            .state(StateBuilder::new("a").extract("h").select(
                vec![f("h", "f")],
                vec![arm(vec![v(1)], to("b"))],
                to("c"),
            ))
            .state(StateBuilder::new("b").extract("g").goto_(to("c")))
            .state(StateBuilder::new("c").select(
                vec![f("g", "x")],
                vec![arm(vec![v(1)], accept())],
                reject("no"),
            ))
            .start("a")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("not definitely extracted"));
    }

    #[test]
    fn rejects_oversized_keyset_value() {
        let mut ir = tiny();
        parser(&mut ir).header_types.push(pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "f".into(),
                width: Some(pb::FieldWidth {
                    width: Some(pb::field_width::Width::Bits(8)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        });
        parser(&mut ir).states[0].extracts.push(pb::Extract {
            header_type: "h".into(),
            instance: String::new(),
        });
        with_select(
            &mut ir,
            vec![field_ref("h", "f")],
            vec![pb::SelectArm {
                entries: vec![pb::KeysetEntry {
                    kind: Some(pb::keyset_entry::Kind::Value(256)),
                }],
                next: Some(pb::Target {
                    kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                }),
            }],
        );
        assert_err_contains(&ir, "exceeds 8-bit key width");
    }
}
