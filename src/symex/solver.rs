//! Deliberately minimal solver abstraction — not a pysmt. The engine
//! compiles path conditions to this tiny constraint form; backends
//! decide bitvector encodings. z3 is the only backend in slice 2; the
//! trait exists so solver-agnostic benchmarking stays possible.

use crate::ir::pb;

/// A 64-bit term over the symbolic packet.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Term {
    /// Zero-extended extract of `len` bits (MSB-first) at `bit_off`.
    Extract {
        bit_off: usize,
        len: usize,
    },
    Const(u64),
    Bin(pb::BinOpKind, Box<Term>, Box<Term>),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Constraint {
    Eq(Term, u64),
    /// key & mask == value & mask
    Masked(Term, u64, u64),
    /// lo <= key <= hi (unsigned, inclusive)
    InRange(Term, u64, u64),
    Not(Box<Constraint>),
    And(Vec<Constraint>),
}

pub(crate) trait Solver {
    /// SAT: a completed packet of exactly ceil(packet_bits/8) bytes
    /// (unconstrained bits filled by solver model completion).
    /// None: UNSAT.
    fn check(&mut self, packet_bits: usize, cs: &[Constraint]) -> Option<Vec<u8>>;

    /// All feasible values of `of` under `cs`, ascending. Errors if
    /// more than `cap` values exist (loud, never a silent truncation).
    fn all_values(
        &mut self,
        packet_bits: usize,
        cs: &[Constraint],
        of: &Term,
        cap: usize,
    ) -> anyhow::Result<Vec<u64>>;

    /// The minimum and maximum feasible values of `of` under `cs`, or
    /// `None` if UNSAT. Two optimization solves — O(1) in the size of
    /// the feasible set, unlike `all_values`, which is one solver call
    /// per value. Used to bound var-length forking on cyclic states.
    fn min_max(
        &mut self,
        packet_bits: usize,
        cs: &[Constraint],
        of: &Term,
    ) -> anyhow::Result<Option<(u64, u64)>>;
}
