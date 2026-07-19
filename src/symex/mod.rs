//! Symbolic execution over the IR (slice 2 core).

pub mod engine;
pub mod lint;
pub mod testgen;
pub(crate) mod solver;
pub(crate) mod z3solver;
