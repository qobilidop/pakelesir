//! Semantic lint from enumeration byproducts: findings the type-level
//! validator cannot see because they require satisfiability reasoning.

use super::engine::enumerate;
use super::z3solver::Z3Solver;
use crate::ir::pb;

#[derive(Debug, PartialEq)]
pub struct Finding {
    pub location: String,
    pub message: String,
}

pub fn lint(ir: &pb::Ir) -> anyhow::Result<Vec<Finding>> {
    let mut solver = Z3Solver::new();
    let enumeration = enumerate(ir, &mut solver)?;
    let parser = ir.parser.as_ref().expect("validated");
    let mut findings = Vec::new();

    for state in &parser.states {
        if !enumeration.log.reached_states.contains(&state.name) {
            findings.push(Finding {
                location: format!("state `{}`", state.name),
                message: "unreachable: no feasible path enters this state".into(),
            });
        }
        if let Some(pb::transition::Kind::Select(sel)) =
            state.transition.as_ref().and_then(|t| t.kind.as_ref())
        {
            for i in 0..sel.arms.len() {
                let key = (state.name.clone(), i);
                if enumeration.log.attempted_arms.contains(&key)
                    && !enumeration.log.feasible_arms.contains(&key)
                {
                    findings.push(Finding {
                        location: format!("state `{}` arm {i}", state.name),
                        message:
                            "unsatisfiable: shadowed by earlier arms or contradicts guards"
                                .into(),
                    });
                }
            }
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::*;

    #[test]
    fn clean_example_lints_clean() {
        assert!(lint(&crate::examples::eth_ipv4_tcp()).unwrap().is_empty());
    }

    #[test]
    fn reports_shadowed_arm_and_orphan_state() {
        let ir = ParserBuilder::new("bad", 2)
            .header(HeaderTypeBuilder::new("h").bits("f", 8))
            .state(StateBuilder::new("a").extract("h").select(
                vec![f("h", "f")],
                vec![arm(vec![range(0, 255)], to("b")), arm(vec![v(3)], to("b"))],
                reject("nope"),
            ))
            .state(StateBuilder::new("b").accept())
            .state(StateBuilder::new("orphan").accept())
            .start("a")
            .build()
            .unwrap();
        let findings = lint(&ir).unwrap();
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.location.contains("orphan")));
        assert!(findings.iter().any(|f| f.location.contains("arm 1")));
    }
}
