# eDSL-Authoritative Decoupling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Python eDSL the single source of truth for the `eth_ipvx_l4` example — `ir.json` generated from it and Rust-canonicalized — retiring the hand-coded Rust builder.

**Architecture:** Two-phase regeneration (Python emits proto JSON → `pakeles fmt-ir` writes canonical `ir.json` → `gen_examples` reads it and produces `gen/*` + vectors). The Rust builder becomes an `include_str!` loader of the committed `ir.json`. Engine-mechanics tests move to inline `ParserBuilder` IRs; a three-link guard chain proves no artifact drift.

**Tech Stack:** Rust (prost/serde/pbjson), Python eDSL (protobuf), bash, Docker (`./dev.sh`).

## Global Constraints

- All tooling runs in Docker via `./dev.sh` (host has no Rust/Python/protoc/tshark). Prefix every command with `./dev.sh`.
- Rust is the **canonical serializer and validator**; Python is authoritative for **content only**.
- The full gate must stay green: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint && cd py && ruff check . && pyright && pytest`.
- `ParserBuilder` (low-level Rust IR construction) **stays**; only the `eth_ipvx_l4()` *builder function* changes to a loader.
- Committed `ir.json` is camelCase protojson; do not change the schema.
- Commit after every task.

---

### Task 1: Python phase-1 emit entrypoint

**Files:**
- Modify: `py/src/pakeles/examples/eth_ipvx_l4.py` (append a `__main__` block)
- Test: `py/tests/test_conformance.py` (add a subprocess test)

**Interfaces:**
- Consumes: existing `eth_ipvx_l4()` and `Parser.to_json()`.
- Produces: `python3 -m pakeles.examples.eth_ipvx_l4` prints the example's protojson to stdout.

- [ ] **Step 1: Write the failing test**

Add to `py/tests/test_conformance.py`:

```python
import subprocess
import sys


def test_module_main_emits_parseable_json() -> None:
    out = subprocess.run(
        [sys.executable, "-m", "pakeles.examples.eth_ipvx_l4"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert json_format.Parse(out, ir_pb2.Ir()) == eth_ipvx_l4().to_pb()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./dev.sh sh -c 'cd py && pytest tests/test_conformance.py::test_module_main_emits_parseable_json -q'`
Expected: FAIL (module has no `__main__`; `subprocess` exits non-zero).

- [ ] **Step 3: Write minimal implementation**

Append to the end of `py/src/pakeles/examples/eth_ipvx_l4.py`:

```python
if __name__ == "__main__":
    print(eth_ipvx_l4().to_json())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./dev.sh sh -c 'cd py && pytest tests/test_conformance.py::test_module_main_emits_parseable_json -q'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add py/src/pakeles/examples/eth_ipvx_l4.py py/tests/test_conformance.py
git commit -m "feat(py): eth_ipvx_l4 module emits protojson on stdout (phase-1)"
```

---

### Task 2: Regeneration script + `gen_examples` reads the committed IR

**Files:**
- Create: `scripts/gen-examples.sh`
- Modify: `src/bin/gen_examples.rs` (read `ir.json` instead of building; stop writing `ir.json`)

**Interfaces:**
- Consumes: `python3 -m pakeles.examples.eth_ipvx_l4` (Task 1); `pakeles fmt-ir --ir <in> --out <out>`; `crate::ir::from_json`.
- Produces: `scripts/gen-examples.sh` regenerates the whole gallery from the eDSL. `gen_examples` now consumes `examples/eth_ipvx_l4/eth_ipvx_l4.ir.json`.

- [ ] **Step 1: Create the orchestration script**

Create `scripts/gen-examples.sh`:

```bash
#!/usr/bin/env bash
# Regenerate the eth_ipvx_l4 gallery from its single source of truth,
# the Python eDSL. Run inside the dev image: ./dev.sh scripts/gen-examples.sh
set -euo pipefail
cd "$(dirname "$0")/.."

ir="examples/eth_ipvx_l4/eth_ipvx_l4.ir.json"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Phase 1: eDSL -> rough protojson -> Rust-canonical ir.json.
PYTHONPATH=py/src python3 -m pakeles.examples.eth_ipvx_l4 > "$tmp"
cargo run --quiet --bin pakeles -- fmt-ir --ir "$tmp" --out "$ir"

# Phase 2: derive gen/* + conformance/* + .py mirror from the canonical IR.
cargo run --quiet --bin gen_fixtures
cargo run --quiet --bin gen_examples

echo "gallery regenerated from py/src/pakeles/examples/eth_ipvx_l4.py"
```

Make it executable:

```bash
chmod +x scripts/gen-examples.sh
```

- [ ] **Step 2: Point `gen_examples` at the committed IR**

In `src/bin/gen_examples.rs`, replace the builder call and remove the `ir.json` write. Change:

```rust
    let ir = pakeles::examples::eth_ipvx_l4();

    std::fs::write(dir.join("eth_ipvx_l4.ir.json"), pakeles::ir::to_json(&ir)?)?;
```

to:

```rust
    // The eDSL is authoritative; phase 1 (scripts/gen-examples.sh) has
    // already written the canonical ir.json. Read it, don't rebuild it.
    let ir = pakeles::ir::from_json(&std::fs::read_to_string(
        dir.join("eth_ipvx_l4.ir.json"),
    )?)?;
```

Leave the rest of `gen_examples.rs` (the `.py` mirror copy, `gen/*`, conformance writes) unchanged.

- [ ] **Step 3: Regenerate and verify byte-identical output (idempotency)**

Run: `./dev.sh scripts/gen-examples.sh && git status --short examples/`
Expected: script prints "gallery regenerated…" and `git status` shows **no changes** under `examples/` — proving the eDSL→`fmt-ir` path reproduces the committed canonical `ir.json` and that `gen/*` derive identically from it.

- [ ] **Step 4: Run the Rust suite to confirm nothing broke**

Run: `./dev.sh cargo test 2>&1 | grep -E "test result:|FAILED"`
Expected: all `ok`, 0 failed. (`examples::eth_ipvx_l4()` still builds via the not-yet-removed Rust builder here; that is fine — this task only rewired generation.)

- [ ] **Step 5: Commit**

```bash
git add scripts/gen-examples.sh src/bin/gen_examples.rs
git commit -m "build: regenerate gallery from the eDSL; gen_examples reads ir.json"
```

---

### Task 3: Replace the Rust builder with an `include_str!` loader

**Files:**
- Modify: `src/examples.rs` (delete builder body + builder-specific tests; add loader + canonical-form guard)

**Interfaces:**
- Consumes: `crate::ir::{from_json, to_json}`; the committed `examples/eth_ipvx_l4/eth_ipvx_l4.ir.json`.
- Produces: `pub fn eth_ipvx_l4() -> pb::Ir` — now loads the embedded committed IR (same signature; all ~14 call sites unchanged).

- [ ] **Step 1: Replace the module contents**

Replace the entire body of `src/examples.rs` with:

```rust
//! The built-in `eth_ipvx_l4` example, loaded from its committed IR.
//!
//! The eDSL (`py/src/pakeles/examples/eth_ipvx_l4.py`) is the single
//! source of truth; `scripts/gen-examples.sh` emits the canonical
//! `ir.json`. Here we embed that committed file at compile time — this
//! doubles as the CLI's default IR, so it must work outside the repo
//! root, which `include_str!` guarantees (and gives a compile-time
//! parse guarantee for the committed artifact).

use crate::ir::pb;

/// The gallery example, parsed from the embedded committed IR.
pub fn eth_ipvx_l4() -> pb::Ir {
    crate::ir::from_json(include_str!(
        "../examples/eth_ipvx_l4/eth_ipvx_l4.ir.json"
    ))
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
        let canonical =
            std::fs::read_to_string("py/src/pakeles/examples/eth_ipvx_l4.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/eth_ipvx_l4/eth_ipvx_l4.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }
}
```

- [ ] **Step 2: Run the full Rust suite**

Run: `./dev.sh cargo test 2>&1 | grep -E "test result:|FAILED"`
Expected: all `ok`, 0 failed. Every golden/conformance/CLI test calls `eth_ipvx_l4()`, which now returns the loaded IR — proto-identical to what the builder produced, so `generate_X(loaded) == committed` still holds.

- [ ] **Step 3: Confirm clippy is clean (no unused imports left behind)**

Run: `./dev.sh cargo clippy --all-targets -- -D warnings 2>&1 | tail -3`
Expected: `Finished` with no warnings.

- [ ] **Step 4: Commit**

```bash
git add src/examples.rs
git commit -m "refactor: eth_ipvx_l4() loads the committed IR (retire the Rust builder)"
```

---

### Task 4: Inline IRs for interp mechanics; keep one example smoke test

**Files:**
- Modify: `src/interp/mod.rs` (rewrite the `tests` module's example-coupled cases)

**Interfaces:**
- Consumes: `crate::builder::{ParserBuilder, HeaderTypeBuilder, StateBuilder, to, arm, v, f, reject_info}`; `crate::examples::eth_ipvx_l4` (smoke only); fixtures.
- Produces: mechanics tests that no longer depend on the example's field layout.

- [ ] **Step 1: Add a minimal inline IR helper and rewrite mechanics tests**

In `src/interp/mod.rs`, inside `mod tests`, add this helper near the top of the module (after the existing `use` lines):

```rust
    use crate::builder::{arm, f, reject_info, to, HeaderTypeBuilder, ParserBuilder, StateBuilder, v};

    /// Minimal two-header IR for exercising engine mechanics without the
    /// gallery example: header `a` (16-bit tag) selects into header `b`
    /// (two 16-bit fields); tag 1 -> parse b -> accept, else reject(info).
    fn mini() -> Ir {
        ParserBuilder::new("mini", 3)
            .header(HeaderTypeBuilder::new("a").bits("tag", 16))
            .header(HeaderTypeBuilder::new("b").bits("x", 16).bits("y", 16))
            .state(StateBuilder::new("s0").extract("a").select(
                vec![f("a", "tag")],
                vec![arm(vec![v(1)], to("s1"))],
                reject_info("unknown tag"),
            ))
            .state(StateBuilder::new("s1").extract("b").accept())
            .start("s0")
            .build()
            .unwrap()
    }
```

(`Ir` is already in scope via the module's imports; if not, use `crate::ir::pb::Ir`.)

- [ ] **Step 2: Replace the example-coupled mechanics tests**

Delete these tests from `src/interp/mod.rs`'s `tests` module: `parses_tcp_packet`, `parses_ihl6_options`, `parses_udp_packet`, `parses_ipv6_tcp_packet`, `rejects_icmp`, `rejects_truncated`, `diagnose_forensics_on_truncation`, `diagnose_payload_boundary_is_info`, `accept_has_no_error_and_full_consumption`. Replace them with:

```rust
    #[test]
    fn example_smoke_accepts_and_rejects() {
        // One belt-and-suspenders check that the embedded example is
        // wired up; exhaustive behavior lives in the vector suite.
        let ir = eth_ipvx_l4();
        assert_eq!(run(&ir, &tcp_packet()).unwrap().outcome, Outcome::Accept);
        assert_eq!(run(&ir, &ipv6_tcp_packet()).unwrap().outcome, Outcome::Accept);
        assert_eq!(
            run(&ir, &icmp_packet()).unwrap().outcome,
            Outcome::Reject {
                reason: "unsupported ip protocol".into()
            }
        );
    }

    #[test]
    fn rejects_truncated_with_oob_forensics() {
        // 2 bytes: `a` extracts, `b` runs off the end mid-first-field.
        let res = run(&mini(), &[0x00, 0x01]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "out of bounds".into()
            }
        );
        let err = res.error.unwrap();
        assert_eq!(err.state, "s1");
        assert_eq!(err.instance.as_deref(), Some("b"));
        assert_eq!(err.field.as_deref(), Some("x"));
        assert_eq!(err.bit_offset, 16);
        assert_eq!(err.severity, Severity::Error);
        assert_eq!(res.consumed_bits, 16);
    }

    #[test]
    fn payload_boundary_reject_is_info() {
        // tag 2 misses the only arm -> default reject(info).
        let res = run(&mini(), &[0x00, 0x02]).unwrap();
        let err = res.error.unwrap();
        assert_eq!(err.severity, Severity::Info);
        assert_eq!(err.reason, "unknown tag");
        assert_eq!(res.consumed_bits, 16);
    }

    #[test]
    fn accept_has_no_error_and_full_consumption() {
        let res = run(&mini(), &[0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        assert_eq!(res.outcome, Outcome::Accept);
        assert!(res.error.is_none());
        assert_eq!(res.consumed_bits, 48);
    }
```

Keep `interp_over_fixture_pcap` and `depth_bound_respected` as they are (integration on `basic.pcap`, and an already-inline depth test).

- [ ] **Step 3: Run interp tests**

Run: `./dev.sh cargo test --lib interp 2>&1 | grep -E "test result:|FAILED"`
Expected: `ok`, 0 failed.

- [ ] **Step 4: Confirm the `field` helper / fixtures are still used (no dead-code/clippy failure)**

Run: `./dev.sh cargo clippy --all-targets -- -D warnings 2>&1 | tail -3`
Expected: `Finished`, no warnings. (If the `field` helper is now unused, delete it; `tcp_packet`/`ipv6_tcp_packet`/`icmp_packet` remain used by the smoke test, and `tcp_packet_ihl6`/`udp_packet`/`truncated_packet` by `basic_pcap_packets`.)

- [ ] **Step 5: Commit**

```bash
git add src/interp/mod.rs
git commit -m "test: interp mechanics on inline IRs; one example smoke test"
```

---

### Task 5: Cargo publish include + regeneration docs

**Files:**
- Modify: `Cargo.toml` (add the embedded `ir.json` to `include`)
- Modify: `README.md`, `py/README.md` (document the regeneration command)

**Interfaces:**
- Consumes: nothing new.
- Produces: publishable crate (the `include_str!` target is packaged); documented dev workflow.

- [ ] **Step 1: Add the embedded IR to the publish include list**

In `Cargo.toml`, add to the `include = [...]` array (keep existing entries):

```toml
    "examples/eth_ipvx_l4/eth_ipvx_l4.ir.json",
```

- [ ] **Step 2: Verify the package still builds with only included files**

Run: `./dev.sh cargo publish --dry-run 2>&1 | tail -15`
Expected: packaging succeeds; the file list includes `examples/eth_ipvx_l4/eth_ipvx_l4.ir.json`; no "file not found for include_str!" error.

- [ ] **Step 3: Document the regeneration command**

In `README.md`, under the layout/gallery note, add a line:

```markdown
Regenerate the gallery from its single source (the eDSL):
`./dev.sh scripts/gen-examples.sh`.
```

In `py/README.md`, add near the example/regeneration notes:

```markdown
`eth_ipvx_l4.py` is the single source of truth for the gallery example.
Regenerate every derived artifact (canonical `ir.json`, `gen/*`, vectors)
with `./dev.sh scripts/gen-examples.sh` — phase 1 runs this eDSL, phase 2
canonicalizes and derives.
```

- [ ] **Step 4: Run the full gate**

Run: `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint && cd py && ruff check . && pyright && pytest' 2>&1 | grep -E "test result:|passed|error|FAILED|Finished" | tail -20`
Expected: Rust tests `ok`/0 failed, `buf lint` passes, ruff clean, pyright 0 errors, pytest all passed.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml README.md py/README.md
git commit -m "build,docs: package embedded example IR; document eDSL regeneration"
```

---

## Self-Review

**Spec coverage:**
- Single source = eDSL, `ir.json` generated → Tasks 1–2 (phase-1 emit + script + `gen_examples` reads IR). ✓
- Rust canonical serializer (decision A) → Task 2 uses `pakeles fmt-ir` to write `ir.json`. ✓
- Rust builder deleted → `include_str!` loader → Task 3. ✓
- Loader doubles as CLI default, call sites unchanged → Task 3 (same signature). ✓
- Two test tiers + inline IRs + one smoke test → Task 4. ✓
- 3-link guard chain: content (pytest, exists) + canonical-form (Task 3 `committed_ir_json_is_canonical`) + derivations (existing golden tests, retargeted via the loader in Task 3). ✓
- `committed_py_example_current` kept → Task 3. ✓
- Cargo include for the embedded file → Task 5. ✓
- No CI regen step → nothing added to the gate; guards run in `cargo test`/`pytest`. ✓
- `ParserBuilder` retained → used by Task 4's `mini()`. ✓

**Placeholder scan:** No TBD/TODO; every code and command step is concrete. ✓

**Type consistency:** `eth_ipvx_l4() -> pb::Ir` used identically in Tasks 3–4; `from_json`/`to_json` signatures match `src/ir/mod.rs`; builder helpers (`ParserBuilder`, `HeaderTypeBuilder`, `StateBuilder`, `to`, `arm`, `v`, `f`, `reject_info`, `.bits`, `.extract`, `.select`, `.accept`, `.start`, `.build`) match the API in `src/builder.rs`. ✓

**Ordering safety:** After Task 2 the builder still exists (green); Task 3 removes it only once generation no longer depends on it and the committed `ir.json` is confirmed canonical/idempotent. Each task ends green and committed.
