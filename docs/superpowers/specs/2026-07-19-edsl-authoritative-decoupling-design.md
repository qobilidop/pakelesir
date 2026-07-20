# Decoupling `src/` from `examples/`: the eDSL becomes authoritative

**Date:** 2026-07-19
**Status:** design approved; implementation pending
**Scope:** one implementation plan (single example, `eth_ipvx_l4`)

## Problem

Today `src/` and `examples/` are coupled three ways:

1. **Dual authoring (the target).** The example is authored *twice* — once
   by the Rust builder `src/examples.rs::eth_ipvx_l4()` (the authoritative
   source that `gen_examples` runs) and once by the Python eDSL
   (`py/src/pakeles/examples/eth_ipvx_l4.py`, kept in lockstep by a
   proto-equality test). Two representations, maintained by hand.
2. **Fixture reuse (incidental).** ~14 Rust test modules call
   `examples::eth_ipvx_l4()` as their universal fixture, so the one
   example's shape leaks into unrelated unit tests and any change ripples
   widely.
3. **Gallery-as-golden-corpus (intentional; keep).** Every backend asserts
   `generate_X(example) == committed examples/…` — the committed gallery is
   the snapshot CI diffs against. This is the anti-rot mechanism and stays.

The eDSL was always meant to be *the* authoring surface. This design makes
it the single source of truth and removes couplings (1) and (2), while
preserving (3).

## Goals

- The eDSL program is the **single source of truth** for the example.
- `ir.json` is **generated** from the eDSL, not hand-written in Rust.
- Rust remains the **canonical serializer and validator** (decision A).
- Unit tests that don't need the real example use **small inline IRs**.
- No artifact drift: committed files are provably `canonical(eDSL)` and
  `generate(committed)`.

## Non-goals

- Changing the IR schema, the eDSL surface API, or any backend.
- Retiring `ParserBuilder` (the low-level Rust IR-construction API). It
  stays — inline test IRs need it. Only the *example builder function*
  `eth_ipvx_l4()` changes from "build" to "load".
- Running regeneration inside CI. CI verifies committedness via guards.

## Key decisions

- **(A) Rust owns canonical serialization.** The eDSL is authoritative for
  *content*; `pakeles fmt-ir` produces the canonical committed `ir.json`.
  Rationale: Python `protobuf.json_format` and Rust `pbjson` differ
  (whitespace, field ordering, int/enum rendering); one canonical
  serializer eliminates cross-language format drift.
- **Full decouple (scope 2):** loader for the example *plus* inline IRs for
  engine-mechanics unit tests.
- **Accepted trade-off:** the Rust builder and the eDSL currently
  cross-check each other as two independent implementations. Single-source
  retires that cross-check. The Rust **validator** remains the authority on
  IR legality; the vector suite remains the authority on behavior.

## Architecture: the regeneration pipeline

Single source of truth: `py/src/pakeles/examples/eth_ipvx_l4.py`.
Everything in `examples/eth_ipvx_l4/` is derived and committed.

```
py/src/pakeles/examples/eth_ipvx_l4.py       ← SINGLE SOURCE (eDSL)
   │  phase 1 (Python): eDSL → proto → rough JSON
   ▼
pakeles fmt-ir                                ← Rust: canonical serializer + validator
   │
   ▼
examples/eth_ipvx_l4/eth_ipvx_l4.ir.json     ← committed normative contract (canonical)
   │  phase 2 (Rust): gen_examples reads the ir.json
   ▼
gen/*   +   conformance/*   +   gallery .py mirror
```

- **Phase 1 (Python → canonical json).** Run the eDSL program, emit its
  proto as rough JSON on stdout, pipe through `pakeles fmt-ir`, which
  validates and writes the canonical `ir.json`. Python never writes the
  committed file directly — the Rust canonical serializer does.
- **Phase 2 (Rust derivations).** Today's `gen_examples`, minus the Rust
  builder: it **reads the committed `ir.json`** (`from_json`) and produces
  `gen/*`, the conformance vectors + pcap, and the browseable `.py` mirror
  (copied from the `py/` package).
- **Orchestration.** A thin script `scripts/gen-examples.sh` chains both
  phases; run as `./dev.sh scripts/gen-examples.sh`. The dev image already
  carries both toolchains.

## The example in Rust: load, don't build

`src/examples.rs`'s hand-coded builder is **deleted**. It is replaced by a
loader that embeds the committed `ir.json` at compile time:

```rust
pub fn eth_ipvx_l4() -> pb::Ir {
    crate::ir::from_json(include_str!(
        "../examples/eth_ipvx_l4/eth_ipvx_l4.ir.json"
    )).expect("committed example IR must parse")
}
```

Why `include_str!` rather than a runtime disk read: `eth_ipvx_l4()` is also
the CLI's built-in default IR (`load_ir`'s `None` arm), which must work
outside the repo root. Embedding bakes the eDSL-authored, Rust-canonicalized
IR into the binary, works anywhere, gives a compile-time parse guarantee,
and leaves every golden/conformance/CLI call site unchanged. The example
`ir.json` must be added to Cargo's publish `include` list.

## Test strategy

Two tiers:

- **Golden / conformance / oracle / CLI tests** use the loaded example
  (`examples::eth_ipvx_l4()` above). They must assert against the real
  committed artifacts, so a stand-in won't do. Call sites are unchanged.
- **Engine-mechanics tests** (interp: truncation → out-of-bounds, depth
  bound, diagnose forensics, select forking; symex engine mechanics) are
  rewritten to build **small inline `ParserBuilder` IRs** in the test body —
  self-contained and readable, decoupled from the example.
- **Example-specific behavior** (does *this* stack parse thus) is already
  exhaustively covered by the 244-vector replay suite; Rust unit tests will
  not duplicate it. One small **smoke test** is kept: load the example,
  parse a known-good packet, assert `Accept` — belt-and-suspenders that the
  embedded IR is wired up.

`src/fixtures.rs` and `testdata/basic.pcap` stay: they feed the tshark
oracle, `cov`, and CLI tests, which operate on the real example.

## Anti-drift guards (a 3-link chain)

1. **Content** — pytest (exists): committed `ir.json` parsed proto-equals
   `eDSL.to_pb()`. Proves *the contract is the eDSL's output*.
2. **Canonical form** — new small Rust test: `to_json(from_json(committed))
   == committed`. Proves *the committed file is Rust-canonical*. This
   replaces the deleted `committed_ir_json_current` (which compared against
   the builder) without needing a builder.
3. **Derivations** — Rust (retargeted to the loader):
   `generate_X(loaded) == committed X` for lua/c/bpf/p4/doc/graph, plus
   vector replay. Proves *gen/\* and vectors are current*.

Composed: `committed == canonical(eDSL)` and every artifact
`== generate(committed)`. No Rust builder in the chain.

The existing `committed_py_example_current` guard (canonical `py/` source ==
gallery `.py` mirror) is kept.

## CI / gate

Unchanged command set. The guards verify committedness **without
regenerating**: pytest compares committed vs eDSL (link 1); `cargo test`
compares committed vs `generate(committed)` (links 2–3). `scripts/
gen-examples.sh` is a developer tool, not a CI step.

## Change surface (file-level)

- `src/examples.rs` — delete the builder body; replace with the
  `include_str!` loader; delete `committed_ir_json_current` and
  `example_validates` builder tests; keep `committed_py_example_current`;
  add the canonical-form guard test (link 2).
- `src/bin/gen_examples.rs` — read committed `ir.json` via `from_json`
  instead of calling the builder; still emit `gen/*`, conformance, `.py`
  mirror.
- `scripts/gen-examples.sh` — new: phase 1 (python emit | `pakeles fmt-ir`)
  then phase 2 (`cargo run --bin gen_examples`).
- `src/interp/mod.rs`, `src/symex/**` tests — convert mechanics tests to
  inline `ParserBuilder` IRs; keep one interp smoke test on the loaded
  example.
- `Cargo.toml` — add `examples/eth_ipvx_l4/eth_ipvx_l4.ir.json` to the
  publish `include` list.
- `py/src/pakeles/examples/eth_ipvx_l4.py` — ensure it is runnable as
  phase-1 emit (a `__main__` that prints `to_json()` to stdout, or an
  equivalent entrypoint the script invokes).
- README / `py/README.md` — document the new regeneration command.

## Risks & trade-offs

- **Loss of the dual-implementation cross-check** (accepted, see decisions).
- **`include_str!` build dependency:** `src/` now depends on the committed
  `examples/…/ir.json` existing at compile time. It is committed, so this
  holds; a fresh checkout builds. Worth a comment at the loader.
- **Bootstrapping:** editing the eDSL requires running
  `scripts/gen-examples.sh` before `cargo build` picks up the new embedded
  IR. Documented in the regeneration instructions.

## Open questions

None blocking. The exact phase-1 entrypoint (a `__main__` in the example
module vs. a small `python -c`) is an implementation detail for the plan.
