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
            let inst = if e.instance.is_empty() { &e.header_type } else { &e.instance };
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

    let check_ref = |r: &pb::FieldRef, ctx: &str, errs: &mut Vec<String>| {
        match instances.get(r.header.as_str()) {
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
        let mut check_target = |t: &pb::Target, errs: &mut Vec<String>| {
            if let Some(pb::target::Kind::State(name)) = &t.kind {
                if !states.contains(name.as_str()) {
                    errs.push(format!("{ctx}: unknown state `{name}`"));
                }
            }
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
                                errs.push(format!(
                                    "{ctx}: keyset entry exceeds {w}-bit key width"
                                ));
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

    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::tiny;
    use super::super::pb;
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
            vec![pb::SelectArm { entries: vec![], next: None }],
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
