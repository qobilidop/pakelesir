//! The built-in `eth_ipvx_l4` example, loaded from its committed IR.
//!
//! The eDSL (`py/src/pakeles/examples/eth_ipvx_l4.py`) is the single
//! source of truth; `scripts/gen-examples.sh` emits the canonical
//! `ir.json`. Here we embed that committed file at compile time — this
//! doubles as the CLI's default IR, so it must work outside the repo
//! root, which `include_str!` guarantees (a compile-time *embedding*
//! guarantee: the file must exist to build). The parse itself happens
//! at load time — checked by the `embedded_ir_parses_and_validates`
//! test below.

use crate::ir::pb;

/// The gallery example, parsed from the embedded committed IR.
pub fn eth_ipvx_l4() -> pb::Ir {
    crate::ir::from_json(include_str!("../examples/eth_ipvx_l4/eth_ipvx_l4.ir.json"))
        .expect("committed example IR must parse")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_ir_parses_and_validates() {
        crate::ir::validate::validate(&eth_ipvx_l4()).unwrap();
    }

    #[test]
    fn committed_ir_json_is_canonical() {
        // The committed file must already be exactly what the Rust
        // canonical serializer emits — the anti-drift "canonical form"
        // guard (replaces the old builder-vs-committed check).
        let committed =
            std::fs::read_to_string("examples/eth_ipvx_l4/eth_ipvx_l4.ir.json").unwrap();
        let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn committed_py_example_current() {
        let canonical = std::fs::read_to_string("py/src/pakeles/examples/eth_ipvx_l4.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/eth_ipvx_l4/eth_ipvx_l4.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }
}
