# Symex Symbolic-Layout Rework — Design

**Status:** design, foundation validated, engine rework NOT yet implemented (deferred as a focused effort — see §7). 2026-07-21.

**Motivation.** The symbolic-execution engine (`src/symex/engine.rs`) currently uses a **concrete-layout** model: variable-length fields are handled by forking a path on every feasible value of the length expression (all-SAT), which makes every field offset a concrete integer per path. This equates "a path" with "a concrete layout," so a var-length field with N feasible lengths produces N paths. Rung 2's IPv6 option-header loop made this explode (~4^loop-depth); we shipped a pragmatic bound (min+max witnesses + a loop-unroll cap: commits `c6f33a0`/`967d022`/`5eec63f`/`339f586`). This rework does the principled thing instead: **decouple "path" (control flow) from "layout" (offsets) — keep lengths symbolic and solve for ONE witness per control-flow path.**

**Payoff (and non-payoff).** Fewer, cleaner vectors (one witness per control-flow path, not per length value); supersedes the min+max/`min_max` machinery; synergistic with the max-witness-cap follow-up (solve for a *minimal*-length witness → small packets). It adds **no new north-star capability** — the length explosion it targets is already bounded by the shipped R1 approach. This is an architectural refinement.

---

## 1. Validated foundation — symbolic-offset extraction (the crux, PROVEN)

The one genuinely-risky piece is reading a field at a **symbolic** bit offset in z3. It works. Add a `Term` variant:

```rust
// src/symex/solver.rs — Term enum
/// Zero-extended extract of `len` bits (MSB-first) at a SYMBOLIC bit
/// offset `off` from the packet start. `off + len <= packet width` must
/// hold under the path constraints (extraction is only built for fields
/// the path reads; truncation paths constrain the packet shorter).
ExtractAt { off: Box<Term>, len: usize },
```

z3 encoding (MSB-first: the `len` bits at offset `off` sit at LSB positions `[w-off-len, w-off)`, so shift down by `(w-len) - off` and mask):

```rust
// src/symex/z3solver.rs — term()
Term::ExtractAt { off, len } => {
    let w = packet.get_size();
    let len = *len as u32;
    let off64 = self.term(packet, off);                 // 64-bit offset value
    let off_w = match w.cmp(&64) {                       // resize to packet width
        std::cmp::Ordering::Greater => off64.zero_ext(w - 64),
        std::cmp::Ordering::Less => off64.extract(w - 1, 0),
        std::cmp::Ordering::Equal => off64,
    };
    let base = BV::from_u64(&self.ctx, (w - len) as u64, w);
    let shift = base.bvsub(&off_w);
    packet.bvlshr(&shift).extract(len - 1, 0).zero_ext(64 - len)
}
```

Proven by this unit test (passed): use the first byte's value *as* an offset, read 8 bits there, and check the right byte is placed.

```rust
#[test]
fn extract_at_reads_symbolic_offset() {
    let mut s = Z3Solver::new();
    let off = ext(0, 8);
    let read = Term::ExtractAt { off: Box::new(off.clone()), len: 8 };
    let bytes = s.check(24, &[Constraint::Eq(off, 8), Constraint::Eq(read, 0xBC)]).unwrap();
    assert_eq!(bytes[0], 8);      // offset field = 8
    assert_eq!(bytes[1], 0xBC);   // byte at bit-offset 8 = second byte = 0xBC
    // (a second case with offset 16 → third byte also passes)
}
```

**This retires the rework's key technical risk.** ExtractAt must be *used* by the engine (below) — a foundation-only commit fails `clippy -D dead-code` (a variant constructed only in tests is dead in the lib build), so it lands together with the engine change.

---

## 2. Engine rework (`src/symex/engine.rs`)

The change is **big-bang**: offsets and `bit_len` become `Term`s at once (the types ripple, so it neither compiles nor validates incrementally until complete).

- **`Frame.cursor: usize` → `Term`** (symbolic bit offset; starts `Term::Const(0)`).
- **`Frame.placed: HashMap<(inst,field), (usize, usize)>` → `HashMap<(inst,field), (Term, usize)>`** (offset Term + len).
- **`term_of_expr` field ref:** look up `placed` → `(off_term, len)`. If `off_term` is `Const(c)` emit the cheap `Term::Extract { bit_off: c, len }`; else `Term::ExtractAt { off: off_term, len }`. (Keeps concrete extractions — the common case — cheap.)
- **Bits field (`walk_extracts`):** truncation fork's `bit_len` = `cursor + Const(n) - 1` (a Term); `placed.insert((inst,field), (cursor.clone(), n))`; `cursor = cursor + Const(n)`.
- **ByteLen field:** **NO fork.** `len_term = term_of_expr(byte_len_expr)`; truncation at `cursor + 8*len_term - 1`; the out-of-bounds/sanity condition becomes a constraint (or is left to the solve's width bound); `cursor = cursor + Const(8) * len_term`. The var body is opaque (not placeable). This removes the all-SAT / min+max forking entirely.
- **Loop-unroll cap (R1c/R1d): RETAINED** — still needed to bound the number of *control-flow* paths through a cycle (`TESTGEN_LOOP_UNROLL`). Only the *length* forking goes away.
- **`emit` / `Path.bit_len: usize` → `Term`** — the path carries a symbolic total length; `testgen` solves it.

## 3. Solve path (`src/symex/testgen.rs` + `Solver`)

Per path: `W = interval_max(bit_len_term)` (reuse `codegen::p4::expr_range`-style interval arithmetic over the symbolic lengths — each var-length bounded by its expr's max × loop-cap). Solve `check(W, constraints)` → model → concrete `W`-bit packet; evaluate `bit_len_term` in the model → actual length; take that many bits. **Per-path max-width avoids a global big-BV cost** — small paths solve over small BVs, same cost profile as today; only looped paths use a wide BV (as they already do concretely). Optionally `minimize(bit_len_term)` (via `Optimize`) for a **minimal-length** witness → small packets (subsumes the max-witness-cap follow-up).

## 4. Removals

- `Solver::all_values`, `Solver::min_max` (trait + z3 impl + engine call sites).
- The min+max cyclic branch and R1/R1b machinery (superseded). **Keep** R1c/R1d (loop cap) and the acyclic-regression intent.

## 5. Test rewrites (expected — the big surprise)

Several engine/solver tests assert the OLD forking model and must be rewritten for one-witness-per-path:
- `engine::length_forking` (asserts 4 accept + 4 trunc for a var-length field → now **1 accept + 1 trunc**).
- `engine::cyclic_length_forking_bounded_to_min_max`, `min_max_bounds_and_unsat` → obsolete; replace with symbolic-length path-count assertions.
- `z3solver::all_values_enumerates_nibble` → remove with `all_values`.
- Keep/adapt `cyclic_loop_unroll_capped_for_testgen`, `depth_bound_emits_reject`, `max_depth_reject_on_acyclic_chain` (control-flow bounds, unaffected).

## 6. Validation strategy

The rework changes *which packets* are generated but not their validity, and a subtle bug won't fail conformance directly (a "wrong" packet is still internally consistent). The nets that DO catch it:
- **`cov::pathid_roundtrips_all_committed_vectors`** — each generated packet must parse (via the interpreter) to the path id it was generated for. A mis-encoded offset → wrong path → fails.
- **`testgen::committed_vectors_replay_green`** — each packet replays to the recorded outcome/fields.
- **C/eBPF/Lua/BMv2 conformance** — all backends agree with the interpreter on each packet.
- Regenerate (`./dev.sh scripts/gen-examples.sh`) and confirm the above + the full gate; sanity-check the vector count dropped (one-per-path) and packets are small (if minimizing).

Execution order: change all types → make it compile → rewrite the affected tests → `cargo test` green → regen → conformance + pathid/replay green.

## 7. Why deferred

This is a **big-bang rewrite of the symbolic-execution core** (types ripple; ~5 tests rewritten; testgen solve reworked). Its correctness rests on the validation nets above rather than a direct oracle, so a subtle bug can produce valid-but-wrong-coverage vectors. Prudence: do it as a focused, fresh effort, not rushed at the end of a long session. The **key risk is already retired** (§1, symbolic extraction proven), so the remaining work is large but de-risked and mechanical. Recommended as a single subagent-driven-development pass (design→implement→validate) or a careful direct implementation, gated continuously on §6.
