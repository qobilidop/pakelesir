# Flow-Dissector Rung 2 Implementation Plan — IPv6 Extension-Header Chain (bounded loop / header stack)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Pakeles's extracted `flow_keys` agree packet-for-packet with the Linux kernel's `bpf_flow.c@v6.8` over the IPv6 extension-header chain (HopByHop/DestOpts loop, Fragment, `flow_label`), realized as a self-re-entrant state graph with bounded header stacks across all five backends — with no new IR message types.

**Architecture:** The IR schema, interpreter, validator, and symex engine already support cyclic graphs, the `max_depth` bound, and the `byte_len` length arithmetic (verified in review). The genuinely new work is: (1) the P4 backend, which today hard-rejects cycles and has no header-stack codegen; (2) making the C/Lua differential *harnesses* stack-aware (they flatten by instance name); (3) three new `flow_keys` fields (`flow_label`, `is_frag`, `is_first_frag`) with a byte-order-correct capture path; (4) the example gaining the IPv6-chain states and projection reading the *last* link of the loop. C/BPF/interpreter already realize the self-loop with zero new control-flow code.

**Tech Stack:** Rust (interpreter, backends, oracle, factory glue), Python eDSL (`py/`), P4-16/v1model + BMv2, C99 + eBPF, Lua (Wireshark), libbpf + `BPF_PROG_TEST_RUN` (privileged golden factory).

**Spec:** `docs/superpowers/specs/2026-07-20-flow-dissector-rung2-design.md` — read §0 (binding review amendments) first; §0 supersedes any conflicting later section.

## Global Constraints

- **No new IR message types.** `proto/pakeles/ir/v1alpha1/ir.proto` is unchanged. Cyclic control flow uses existing free-form `Transition.Target.state`; loop length is bounded by the existing `Parser.max_depth`; the option-body length uses the existing `FieldWidth.byte_len` Expr.
- **The gate is:** `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint'` plus the Python gate (`ruff`, `pyright` strict = 0 errors, `pytest`). All dev runs through `./dev.sh` (the host has no rust/protoc/tshark/p4c). Each `./dev.sh` invocation is a fresh container; `/tmp` does not persist between runs.
- **Kernel source of truth:** `oracle/flow_dissector/factory/build/bpf_flow.c` (pinned `v6.8`, sha256 `f01d08e66653fbaad811d289adea078c96a8511433ceaa3877b0eea6a208d41a`). It is gitignored/GPL — never commit it.
- **Default-flags fidelity only.** `BPF_PROG_TEST_RUN` zero-inits `keys->flags`, so Fragment is always terminal and `flow_label` never early-stops. The parser stays purely packet-driven.
- **Do NOT edit golden files to force green.** A `committed_goldens_agree` failure is a real disagreement — investigate.
- **Privileged golden re-mint is a user step.** `capture.sh` needs `docker run --privileged` (via `./dev-priv.sh`, allowed by the gitignored `.claude/settings.local.json`). The implementing agent prepares the corpus + `capture.c`; the user runs the privileged mint and commits the new golden, exactly as in rung 1.
- **`max_depth` becomes `10`** (from `5`) — sized for the QinQ + ~5 option-headers + L4 worst case. This is a documented bounded-fidelity boundary (kernel allows ~30 via the tail-call limit); chains of 6–~30 options are a known kernel-accepts / Pakeles-rejects divergence, recorded in the README, NOT added to the agreement corpus.
- **`flow_label` is `__be32`** in `struct bpf_flow_keys` — `capture.c` MUST `ntohl` it. It is NOT host-order like `addr_proto`.

---

## Task ordering rationale (read before starting)

The example gaining the self-loop is a **tree-breaking event**: the instant `linux_flow_dissector()` has a cyclic graph, (a) `gen_examples` aborts because `generate_p4()` calls `check_acyclic()?`, and (b) the C/Lua differential conformance suites hit repeated-instance headers and mis-compare. So the enabling capabilities are built **first, against synthetic cyclic fixtures**, and the example is introduced only once every backend and harness can handle a loop:

1. **Task 1 — Golden schema v3 fields** (isolated; serde-defaulted, back-compat).
2. **Task 2 — Conformance harness stack-awareness** (isolated; unit-tested on a hand-built header list).
3. **Task 3 — P4 header-stack emitter** (isolated; tested on a synthetic cyclic IR; `eth_ipvx_l4` stays DAG-green).
4. **Task 4 — Example + projection** (the integration: add IPv6-chain states + `max_depth=10`, extend the projection to read the last link, regenerate ALL artifacts; dual-example conformance suites now exercise the loop and pass because Tasks 2–3 made them ready).
5. **Task 5 — Factory, corpus, gate-hardening, docs, privileged re-mint** (adds v3 fields to `capture.c` with `ntohl`, grows the drop-aware corpus, tightens the gate to require the 14-name subset, updates the README fidelity boundary; user runs the mint).

Each task ends green under the full gate.

---

## Task 1: Golden schema v3 — `flow_label` / `is_frag` / `is_first_frag`

**Files:**
- Modify: `src/oracle/flow_dissector.rs:10-23` (the `FlowKeys` struct), `:129-144` (`field_pair`)
- Test: `src/oracle/flow_dissector.rs` (`#[cfg(test)] mod tests` / `mod diff_tests`)

**Interfaces:**
- Produces: `FlowKeys` gains `pub flow_label: u32`, `pub is_frag: bool`, `pub is_first_frag: bool` (all `#[serde(default)]` so v2 goldens — which lack them — still deserialize). `field_pair` gains arms for the three names. Consumed by Tasks 4 (projection writes them) and 5 (capture.c emits them, gate asserts the 14-name subset).

- [ ] **Step 1: Write the failing test** — a v2 golden JSON (no new fields) still parses, and the new fields default. Add to `mod diff_tests`:

```rust
#[test]
fn v2_golden_without_v3_fields_still_parses() {
    // A v2 "ok" entry lacking flow_label/is_frag/is_first_frag must
    // deserialize with those fields defaulted (0 / false).
    let s = r#"{"kernel_version":"6.8.0","keys_subset":["nhoff"],
        "entries":[{"packet_hex":"aabb","disposition":"ok","keys":{"nhoff":14,
        "thoff":0,"n_proto":0,"addr_proto":0,"ip_proto":0,"sport":0,"dport":0,
        "ipv4_src":"","ipv4_dst":"","ipv6_src":"","ipv6_dst":""}}]}"#;
    let g: GoldenFile = serde_json::from_str(s).unwrap();
    let k = g.entries[0].keys.as_ref().unwrap();
    assert_eq!(k.flow_label, 0);
    assert!(!k.is_frag);
    assert!(!k.is_first_frag);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./dev.sh cargo test -p pakeles oracle::flow_dissector::diff_tests::v2_golden_without_v3_fields_still_parses`
Expected: FAIL — `no field 'flow_label' on type 'FlowKeys'` (compile error) or missing-field.

- [ ] **Step 3: Add the three fields to `FlowKeys`** (`src/oracle/flow_dissector.rs:10-23`):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowKeys {
    pub nhoff: u16,
    pub thoff: u16,
    pub n_proto: u16,
    pub addr_proto: u16,
    pub ip_proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub ipv4_src: String,
    pub ipv4_dst: String,
    pub ipv6_src: String,
    pub ipv6_dst: String,
    #[serde(default)]
    pub flow_label: u32,
    #[serde(default)]
    pub is_frag: bool,
    #[serde(default)]
    pub is_first_frag: bool,
}
```

- [ ] **Step 4: Add `field_pair` arms** (`src/oracle/flow_dissector.rs:130-142`, before the `_ =>` arm):

```rust
        "flow_label" => (ours.flow_label.to_string(), golden.flow_label.to_string()),
        "is_frag" => (ours.is_frag.to_string(), golden.is_frag.to_string()),
        "is_first_frag" => (
            ours.is_first_frag.to_string(),
            golden.is_first_frag.to_string(),
        ),
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./dev.sh cargo test -p pakeles oracle::flow_dissector`
Expected: PASS — all existing `mod tests`/`project_tests`/`diff_tests`/`gate_tests` still pass (the committed v2 golden's 11-name `keys_subset` is unchanged, so the new fields are not yet compared).

- [ ] **Step 6: Commit**

```bash
git add src/oracle/flow_dissector.rs
git commit -m "feat(oracle): golden schema v3 — flow_label/is_frag/is_first_frag (serde-defaulted)"
```

---

## Task 2: Conformance harness stack-awareness (C + Lua)

**Problem (review SHOULD-FIX-B):** both differential harnesses key expected fields by `{instance}.{field}` into a flat structure. When an instance is extracted more than once (the loop), the interpreter emits N `ParsedHeader`s all with the same `instance`, while the datapath backends store only the **last** extraction (single struct, overwritten) — by design (§4: no addressable stack). The harness must compare the interpreter's **last occurrence per instance name**, matching what the backends store.

**Files:**
- Modify: `src/codegen/c.rs:749-771` (C harness field loop), and add a small dedup helper near it.
- Modify: `src/codegen/lua.rs` (the `headers_to_expected` producer used at `~:766` and the comparison loop `~:768-812`).
- Test: `src/codegen/c.rs` (`#[cfg(test)]`).

**Interfaces:**
- Produces: `fn last_headers_by_instance(headers: &[crate::interp::ParsedHeader]) -> Vec<&crate::interp::ParsedHeader>` — returns one `ParsedHeader` per distinct `instance`, keeping the **last** in extraction order, preserving first-seen order of instances. Both harnesses iterate this instead of raw `headers`. Consumed by the Task 4 conformance runs.

- [ ] **Step 1: Write the failing test** — the helper keeps the last extraction of a repeated instance. Add to `src/codegen/c.rs` tests:

```rust
#[test]
fn last_headers_by_instance_keeps_last_of_repeats() {
    use crate::interp::{FieldValue, ParsedHeader, ParsedField};
    let mk = |inst: &str, nh: u64, start: u64| ParsedHeader {
        instance: inst.into(),
        header_type: "ext_opt".into(),
        start_bit: start,
        fields: vec![ParsedField {
            name: "next_header".into(),
            value: FieldValue::Uint(nh),
        }],
    };
    let hs = vec![
        mk("ipv6", 60, 112),
        mk("ext_opt", 0, 432),   // DestOpts (first link)
        mk("ext_opt", 17, 496),  // HopByHop (last link)
        mk("udp", 0, 560),
    ];
    let last = last_headers_by_instance(&hs);
    let insts: Vec<&str> = last.iter().map(|h| h.instance.as_str()).collect();
    assert_eq!(insts, ["ipv6", "ext_opt", "udp"]); // one ext_opt, first-seen order
    let ext = last.iter().find(|h| h.instance == "ext_opt").unwrap();
    match &ext.fields[0].value {
        FieldValue::Uint(v) => assert_eq!(*v, 17), // the LAST link's next_header
        _ => panic!(),
    }
}
```

Note: confirm the exact field names on `ParsedHeader`/`ParsedField`/`FieldValue` in `src/interp/mod.rs` before writing — adjust the constructor to match (the struct literal above assumes `instance`, `header_type`, `start_bit`, `fields` with `{name, value}`).

- [ ] **Step 2: Run test to verify it fails**

Run: `./dev.sh cargo test -p pakeles codegen::c::tests::last_headers_by_instance_keeps_last_of_repeats`
Expected: FAIL — `cannot find function 'last_headers_by_instance'`.

- [ ] **Step 3: Implement the helper** (add near the top of `src/codegen/c.rs`, module scope):

```rust
/// One header per distinct instance name, keeping the LAST extraction
/// (matching datapath backends, which overwrite a single struct per
/// instance). Preserves first-seen instance order. Rung 2: stacked
/// instances (loop back-edges) appear multiple times in the interpreter's
/// header list; only the terminal link is stored by the backends and is
/// the conformance surface.
pub(crate) fn last_headers_by_instance(
    headers: &[crate::interp::ParsedHeader],
) -> Vec<&crate::interp::ParsedHeader> {
    let mut order: Vec<&str> = Vec::new();
    let mut last: std::collections::HashMap<&str, &crate::interp::ParsedHeader> =
        std::collections::HashMap::new();
    for h in headers {
        if !order.iter().any(|i| *i == h.instance.as_str()) {
            order.push(h.instance.as_str());
        }
        last.insert(h.instance.as_str(), h);
    }
    order.into_iter().map(|i| last[i]).collect()
}
```

- [ ] **Step 4: Route the C harness through it** — replace the `for h in &reference.headers {` loop head at `src/codegen/c.rs:749` with:

```rust
            for h in last_headers_by_instance(&reference.headers) {
```

(The loop body is unchanged.)

- [ ] **Step 5: Route the Lua harness through it** — in `src/codegen/lua.rs`, the `headers_to_expected(&res.headers)` producer (`~:766`) must be fed deduped headers. Change that call site to:

```rust
                    headers_to_expected(&last_headers_by_instance(&res.headers))
```

and add `use crate::codegen::c::last_headers_by_instance;` (or re-export). If `headers_to_expected` takes `&[ParsedHeader]` (owned slice) rather than `&[&ParsedHeader]`, either adjust its signature to accept `&[&ParsedHeader]` or collect owned clones — pick the smaller diff after reading the signature.

- [ ] **Step 6: Run the full conformance suites to verify no regression**

Run: `./dev.sh cargo test -p pakeles codegen::`
Expected: PASS — `c_backend_conformance_full_suite`, `..._flow_dissector`, and the Lua suites still green (no example has a loop yet, so dedup is a no-op on current inputs; the new unit test passes).

- [ ] **Step 7: Commit**

```bash
git add src/codegen/c.rs src/codegen/lua.rs
git commit -m "test(conformance): last-occurrence-per-instance comparison (stack-aware harnesses)"
```

---

## Task 3: P4 header-stack emitter

**Problem (review DECISION):** `generate_p4` calls `check_acyclic(parser)?` (`p4.rs:263`), which `bail!`s on any cycle; and even absent the guard, a var-length header is split into fixed+varbit sub-headers (`segments`), extraction is scalar, and the verdict bitmap tests scalar `.isValid()` — no header-stack support exists. This task builds it, tested against a synthetic cyclic IR. `eth_ipvx_l4` (a DAG) must emit byte-identical P4 to today.

**Design of the emitted P4 for a stacked instance `X` (segments `X_s0` fixed, `X_v1` varbit):**
- Declarations unchanged (`header X_s0_t`, `header X_v1_t`).
- Struct members become **parallel stacks** sized to `max_depth`: `X_s0_t[MAXD] X_s0;` and `X_v1_t[MAXD] X_v1;`.
- Extraction uses `.next`: `pkt.extract(hdr.X_s0.next);` / `pkt.extract(hdr.X_v1.next, <len>);`.
- Field references to a stacked instance (in select keys and in the varbit length expr) use `.last`: `hdr.X_s0.last.<field>`.
- Bitmap validity for a stacked instance tests element 0: `hdr.X_s0[0].isValid()` (valid iff the instance was extracted ≥once). A stack still counts as **one** bitmap bit (`instance_order` dedups by name — unchanged).

**Files:**
- Modify: `src/codegen/p4.rs` — add `stacked_instances`, thread "is this instance stacked" through `member` emission, extract emission, `expr_p4` field refs, and the bitmap; delete `check_acyclic` + its call; replace the `cyclic_graph_is_rejected` test.
- Test: `src/codegen/p4.rs` (`#[cfg(test)]`).

**Interfaces:**
- Consumes: `state_targets` (existing) to compute reachability.
- Produces: `fn stacked_instances(parser: &pb::Parser) -> std::collections::HashSet<String>` — instance names whose extracting state lies on a cycle (reachable from itself). Used internally by `generate_p4`.

- [ ] **Step 1: Write the failing test** — a synthetic cyclic IR emits header stacks + `.next`/`.last` and self-transition, and no longer errors. Replace the existing `cyclic_graph_is_rejected` test (`p4.rs:577-589`) with:

```rust
#[test]
fn cyclic_graph_emits_header_stack() {
    // Make parse_tcp loop back to parse_ethernet: `ethernet` is now
    // extracted on a cycle => stacked.
    let mut ir = crate::examples::eth_ipvx_l4();
    let p = ir.parser.as_mut().unwrap();
    let tcp = p.states.iter_mut().find(|s| s.name == "parse_tcp").unwrap();
    tcp.transition = Some(pb::Transition {
        kind: Some(pb::transition::Kind::Direct(pb::Target {
            kind: Some(pb::target::Kind::State("parse_ethernet".into())),
        })),
    });
    let p4 = generate_p4(&ir).unwrap(); // no longer errors
    assert!(stacked_instances(p.).is_empty() == false); // sanity via helper below
    // ethernet is stacked -> parallel stack member(s) + .next extract + .last ref.
    assert!(p4.contains("ethernet_s0_t["), "no header stack: {p4}");
    assert!(p4.contains("pkt.extract(hdr.ethernet_s0.next)"), "{p4}");
    assert!(p4.contains("hdr.ethernet_s0.last."), "{p4}");
    // bitmap for a stacked instance tests element 0.
    assert!(p4.contains("hdr.ethernet_s0[0].isValid()"), "{p4}");
    // non-stacked instances keep scalar members/extracts.
    assert!(p4.contains("pkt.extract(hdr.ipv4_s0);"), "{p4}");
}

#[test]
fn stacked_instances_detects_self_reachable() {
    let mut ir = crate::examples::eth_ipvx_l4();
    let p = ir.parser.as_mut().unwrap();
    let tcp = p.states.iter_mut().find(|s| s.name == "parse_tcp").unwrap();
    tcp.transition = Some(pb::Transition {
        kind: Some(pb::transition::Kind::Direct(pb::Target {
            kind: Some(pb::target::Kind::State("parse_ethernet".into())),
        })),
    });
    let stacked = stacked_instances(p);
    assert!(stacked.contains("ethernet"));
    assert!(stacked.contains("ipv4")); // also on the cycle
    assert!(!stacked.contains("udp")); // udp is off the cycle
}
```

(Fix the `stacked_instances(p.)` typo when writing — pass `p`.)

- [ ] **Step 2: Run to verify it fails**

Run: `./dev.sh cargo test -p pakeles codegen::p4`
Expected: FAIL — `cannot find function 'stacked_instances'`, and the old cycle-reject path.

- [ ] **Step 3: Add `stacked_instances`** (module scope in `p4.rs`):

```rust
/// Instances whose extracting state lies on a cycle (is reachable from
/// itself) — these must be realized as header stacks. Computed by a DFS
/// reachability check per state; small graphs, so O(V·E) is fine.
pub(crate) fn stacked_instances(
    parser: &pb::Parser,
) -> std::collections::HashSet<String> {
    fn reaches_self(parser: &pb::Parser, start: &str) -> bool {
        let mut stack = vec![];
        let mut seen = std::collections::HashSet::new();
        if let Some(s) = parser.states.iter().find(|s| s.name == start) {
            stack.extend(state_targets(s));
        }
        while let Some(n) = stack.pop() {
            if n == start {
                return true;
            }
            if !seen.insert(n.clone()) {
                continue;
            }
            if let Some(s) = parser.states.iter().find(|s| s.name == n) {
                stack.extend(state_targets(s));
            }
        }
        false
    }
    let mut out = std::collections::HashSet::new();
    for s in &parser.states {
        if reaches_self(parser, &s.name) {
            for ex in &s.extracts {
                let inst = if ex.instance.is_empty() {
                    ex.header_type.clone()
                } else {
                    ex.instance.clone()
                };
                out.insert(inst);
            }
        }
    }
    out
}
```

- [ ] **Step 4: Delete `check_acyclic`** (`p4.rs:233-259`) and its call (`p4.rs:263`). Update the module docstring (`p4.rs:9-11`) to describe header-stack support instead of "cyclic graphs are rejected".

- [ ] **Step 5: Emit stacks in the struct members.** In `generate_p4`, compute `let stacked = stacked_instances(parser);` once (after `let insts = ...`). In the `struct headers` emission (`p4.rs:332-341`), size stacked members to `max_depth`:

```rust
    for (inst, _) in &insts {
        let ht = header_type_of(parser, inst)?;
        let is_stacked = stacked.contains(inst);
        for (i, seg) in segments(ht).iter().enumerate() {
            let member = seg_member(inst, i, seg);
            let tname = match seg {
                Seg::Fixed(_) => format!("{inst}_s{i}_t"),
                Seg::Var(_) => format!("{inst}_v{i}_t"),
            };
            if is_stacked {
                writeln!(w, "    {tname}[{}] {member};", parser.max_depth)?;
            } else {
                writeln!(w, "    {tname} {member};")?;
            }
        }
    }
```

- [ ] **Step 6: Emit `.next` extraction for stacked instances.** In the parser-state extract emission (`p4.rs:359-383`), branch on `stacked.contains(inst)`:

```rust
            let is_stacked = stacked.contains(inst.as_str());
            for (i, seg) in segments(ht).iter().enumerate() {
                let member = seg_member(inst, i, seg);
                let tgt = if is_stacked { format!("hdr.{member}.next") } else { format!("hdr.{member}") };
                match seg {
                    Seg::Fixed(_) => writeln!(w, "        pkt.extract({tgt});")?,
                    Seg::Var(f) => {
                        let expr = match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                            Some(pb::field_width::Width::ByteLen(e)) => e,
                            _ => unreachable!(),
                        };
                        writeln!(
                            w,
                            "        pkt.extract({tgt}, (bit<32>)(64w8 * {}));",
                            expr_p4(expr, parser)?
                        )?;
                    }
                }
            }
```

(Note `inst` here is `&&str`/`&String`; use `inst.as_str()` consistently.)

- [ ] **Step 7: Emit `.last` for field references to stacked instances.** `expr_p4` and `member_of_field` produce `hdr.{member}.{field}`. Make the field-ref case of `expr_p4` (`p4.rs:153-155`) append `.last` when the referenced instance is stacked. Thread `stacked` into `expr_p4` (add a param) or resolve inside via a closure. Minimal change — give `expr_p4` a `stacked: &HashSet<String>` param and update its two call sites (select keys, varbit length) plus the field-ref arm:

```rust
        pb::expr::Kind::Field(r) => {
            let member = member_of_field(parser, r)?;
            // member_of_field returns e.g. "ext_opt_s0"; the instance is r.header.
            if stacked.contains(&r.header) {
                format!("(bit<64>)hdr.{member}.last.{}", r.field)
            } else {
                format!("(bit<64>)hdr.{member}.{}", r.field)
            }
        }
```

- [ ] **Step 8: Emit bitmap validity via element 0 for stacked instances.** In the ingress bitmap loop (`p4.rs:445-455`):

```rust
    for (idx, (inst, _)) in insts.iter().enumerate() {
        let ht = header_type_of(parser, inst)?;
        let segs = segments(ht);
        let last = segs.len() - 1;
        let member = seg_member(inst, last, &segs[last]);
        let valid = if stacked.contains(inst) {
            format!("hdr.{member}[0].isValid()")
        } else {
            format!("hdr.{member}.isValid()")
        };
        writeln!(w, "        if ({valid}) {{ bm = bm | 8w{}; }}", 1u32 << idx)?;
    }
```

- [ ] **Step 9: Run the P4 tests + the DAG-identity guard**

Run: `./dev.sh cargo test -p pakeles codegen::p4`
Expected: PASS — new cyclic tests pass; `committed_p4_artifact_current` still passes (eth_ipvx_l4 is a DAG, `stacked` is empty, output byte-identical); `generated_p4_compiles_with_p4test` still green where `p4test` is available.

- [ ] **Step 10: Commit**

```bash
git add src/codegen/p4.rs
git commit -m "feat(p4): header-stack emitter for cyclic graphs (.next/.last stacks); drop DAG-only guard"
```

---

## Task 4: Example IPv6-chain states + projection (the integration)

**This is the task that introduces the loop into the real example.** By now the P4 emitter (Task 3) and the harnesses (Task 2) can handle it, so regenerating and running the dual-example conformance suites stays green.

**Files:**
- Modify: `py/src/pakeles/examples/linux_flow_dissector.py` (add `IPv6ExtOpt`, `IPv6Frag`, the three IPv6-chain states, `max_depth=10`).
- Modify: `src/examples.rs` (the Rust builder mirror — the gallery `ir.json` is generated from it; the Python example must stay proto-equal per the existing conformance test). **Read `src/examples.rs` first** to mirror the exact builder API used for rung-1 VLAN/MPLS instances.
- Modify: `src/oracle/flow_dissector.rs:88-114` (`project` — IPv6-chain semantics, last-link reads, new fields).
- Regenerate: `examples/linux_flow_dissector/**` via `./dev.sh cargo run --bin gen_examples` and mirror the Python source.
- Test: `src/oracle/flow_dissector.rs` (`mod project_tests`), the Python conformance test (`py/`), the codegen conformance suites.

**Interfaces:**
- Consumes: named instances `Header["name"]` (rung 1), `var_bytes(expr)` + `<<` (already in the eDSL — confirmed, no new code), the stack-aware harness (Task 2), the P4 stack emitter (Task 3).
- Produces: the `linux_flow_dissector()` IR with states `parse_ipv6_opt` (self-loop) and `parse_ipv6_frag`, header types `IPv6ExtOpt`/`IPv6Frag`, `max_depth=10`. `project()` returns `flow_label`/`is_frag`/`is_first_frag` and reads the last `ext_opt` link.

### 4a — eDSL affordance confirmation (no new code; guards the "already done" claim)

- [ ] **Step 1: Write the confirmation test** in `py/` (e.g. `py/tests/test_var_bytes_expr.py`):

```python
from pakeles import Header, bits, var_bytes


def test_var_bytes_length_expression_shifts():
    class ExtOpt(Header):
        next_header = bits(8)
        hdr_ext_len = bits(8)
        body = var_bytes(((1 + hdr_ext_len) << 3) - 2)

    ht = ExtOpt.to_pb()
    body = ht.fields[2]
    # SUB( SHL( ADD(hdr_ext_len, 1), 3 ), 2 )
    assert body.width.HasField("byte_len")
    top = body.width.byte_len
    assert top.bin.op  # BIN_OP_KIND_SUB
    assert top.bin.rhs.constant == 2
    assert top.bin.lhs.bin.rhs.constant == 3  # SHL by 3
```

- [ ] **Step 2: Run — it should PASS immediately** (the eDSL already supports `<<` and `var_bytes(expr)`):

Run: `./dev.sh sh -c 'cd py && python -m pytest tests/test_var_bytes_expr.py -v'`
Expected: PASS. (If it fails, the eDSL regressed — fix `_expr.py`/`_header.py`; not expected.)

- [ ] **Step 3: Commit**

```bash
git add py/tests/test_var_bytes_expr.py
git commit -m "test(edsl): confirm var_bytes length-expression with shift (rung-2 body width)"
```

### 4b — Header types + states in the example

- [ ] **Step 4: Add the header classes** to `linux_flow_dissector.py` (after the `IPv6` class, `~:115`):

```python
class IPv6ExtOpt(Header):  # HopByHop (0) / DestOpts (60) option header
    next_header = bits(8, "Next Header", DEC, tshark="ipv6.opt.nxt")
    hdr_ext_len = bits(8, "Hdr Ext Len", DEC, doc="in 8-octet units, excl. first 8")
    # option body: (1 + hdr_ext_len) * 8 total bytes, minus the 2-byte prefix.
    body = var_bytes(((1 + hdr_ext_len) << 3) - 2)


class IPv6Frag(Header):  # fragment header (nexthdr 44)
    next_header = bits(8, "Next Header", DEC, tshark="ipv6.frag.nxt")
    reserved = bits(8, "Reserved", HEX)
    frag_off = bits(13, "Fragment Offset", DEC, doc="in 8-octet units")
    res2 = bits(2, "Res", HEX)
    m_flag = bits(1, "More Fragments", DEC)
    identification = bits(32, "Identification", HEX)
```

- [ ] **Step 5: Rewire `parse_ipv6` and add the two new states.** Replace the `parse_ipv6` state and add `parse_ipv6_opt`/`parse_ipv6_frag`; bump `max_depth` to `10`:

```python
        max_depth=10,
        ...
            "parse_ipv6": extract(IPv6).select(
                IPv6.next_header,
                {
                    0x00: "parse_ipv6_opt",  # HopByHop
                    0x3C: "parse_ipv6_opt",  # DestOpts (60)
                    0x2C: "parse_ipv6_frag", # Fragment (44)
                    6: "parse_tcp",
                    17: "parse_udp",
                },
                default=reject("unsupported ip protocol", info=True),
            ),
            # Kernel PROG(IPV6OP): walk the option, dispatch on its own
            # next_header — HopByHop/DestOpts loop back (self-edge).
            "parse_ipv6_opt": extract(IPv6ExtOpt["ext_opt"]).select(
                IPv6ExtOpt["ext_opt"].next_header,
                {
                    0x00: "parse_ipv6_opt",
                    0x3C: "parse_ipv6_opt",
                    0x2C: "parse_ipv6_frag",
                    6: "parse_tcp",
                    17: "parse_udp",
                },
                default=reject("unsupported ip protocol", info=True),
            ),
            # Kernel PROG(IPV6FR) under default flags: read the fragment
            # header and stop (BPF_OK), always.
            "parse_ipv6_frag": extract(IPv6Frag["ext_frag"]).accept(),
```

- [ ] **Step 6: Mirror the same in `src/examples.rs`.** Read the rung-1 VLAN instance emission there (named `Header["name"]` → builder `.extract_as("ext_opt", ...)` or equivalent) and add `IPv6ExtOpt`/`IPv6Frag` header types + the three states + `max_depth(10)` identically. The var body uses the builder's `var_bytes(expr)` with `sub(shl(add(field("ext_opt","hdr_ext_len"),1),3),2)` — match the exact builder helper names already in `src/examples.rs` for `ihl*4-20`.

- [ ] **Step 7: Regenerate + check proto-equality**

Run: `./dev.sh cargo run --bin gen_examples`
Then: `./dev.sh sh -c 'cd py && python -m pytest -k linux_flow_dissector -v'`
Expected: the Python example is proto-equal to the regenerated `examples/linux_flow_dissector/linux_flow_dissector.ir.json`. If not, reconcile field order / names between `src/examples.rs` and the `.py`.

### 4c — Projection: IPv6-chain flow_keys (last-link)

- [ ] **Step 8: Write failing projection tests** (`mod project_tests` in `src/oracle/flow_dissector.rs`). Byte-identical packets to the Task-5 corpus lines (keep them in sync):

```rust
#[test]
fn projects_ipv6_hopopt_tcp() {
    // eth/IPv6(nexthdr=0 HopByHop)/HopByHop(hdr_ext_len=0, nexthdr=6)/TCP
    let ir = crate::examples::linux_flow_dissector();
    let pkt = hexpkt(
        "aabbccddeeff11223344556686dd\
         600000000010000040\
         20010db800000000000000000000000120010db8000000000000000000000002\
         06000000000000\
         303901bb00000001000000005018ffff00000000",
    );
    let k = project(&ir, &pkt).unwrap().unwrap();
    assert_eq!(k.n_proto, 0x86dd);
    assert_eq!(k.addr_proto, 0x86dd);
    assert_eq!(k.nhoff, 14);
    assert_eq!(k.ip_proto, 6);          // terminal L4 proto (last link's next_header)
    assert_eq!(k.thoff, 62);            // 14 + 40 (ipv6) + 8 (one option) = start of TCP
    assert!(!k.is_frag);
    assert_eq!(k.sport, 12345);
    assert_eq!(k.dport, 443);
}

#[test]
fn projects_ipv6_frag_first() {
    // eth/IPv6(nexthdr=44 Fragment)/Fragment(frag_off=0, nexthdr=6) — stops
    let ir = crate::examples::linux_flow_dissector();
    let pkt = hexpkt(
        "aabbccddeeff11223344556686dd\
         6000000000082c40\
         20010db800000000000000000000000120010db8000000000000000000000002\
         0600000000000001",
    );
    let k = project(&ir, &pkt).unwrap().unwrap();
    assert!(k.is_frag);
    assert!(k.is_first_frag);
    assert_eq!(k.ip_proto, 6);          // fragment header's next_header
    assert_eq!(k.thoff, 62);            // 14 + 40 + 8 (frag header), ports unparsed
    assert_eq!(k.sport, 0);
    assert_eq!(k.dport, 0);
}
```

Also add: `projects_ipv6_frag_later` (`frag_off != 0` → `is_frag=true, is_first_frag=false`), `projects_ipv6_two_opts_udp` (DestOpts+HopByHop → `ip_proto=17` from the **last** link, proving the last-link fix), and `projects_ipv6_flow_label` (non-zero flow_label recorded). Compute the exact hex + expected offsets by hand; keep each byte-identical to its Task-5 corpus twin.

- [ ] **Step 9: Run to verify failure**

Run: `./dev.sh cargo test -p pakeles oracle::flow_dissector::project_tests`
Expected: FAIL — current `project` has no IPv6-chain handling; `ip_proto`/`thoff`/`is_frag` wrong.

- [ ] **Step 10: Extend `project`** (`src/oracle/flow_dissector.rs`). Add a `last` helper (mirror of `hdr` but taking the last match), record `flow_label` from the IPv6 header, and walk the chain. Replace the IPv6 branch + terminal logic:

```rust
    let last = |inst: &str| res.headers.iter().rev().find(|h| h.instance == inst);
    let last_u = |inst: &str, f: &str| -> Option<u64> {
        last(inst)?.fields.iter().find(|x| x.name == f).and_then(|x| match &x.value {
            crate::interp::FieldValue::Uint(v) => Some(*v),
            _ => None,
        })
    };
    // ... inside the `else if let Some(h) = hdr("ipv6")` branch:
        k.addr_proto = 0x86DD;
        k.nhoff = (h.start_bit / 8) as u16;
        k.flow_label = u("ipv6", "flow_label").unwrap_or(0) as u32;
        k.ipv6_src = bytes("ipv6", "src").map(hex).unwrap_or_default();
        k.ipv6_dst = bytes("ipv6", "dst").map(hex).unwrap_or_default();
        // ip_proto follows the chain: last option link if any, else ipv6.
        k.ip_proto = last_u("ext_frag", "next_header")
            .or_else(|| last_u("ext_opt", "next_header"))
            .or_else(|| u("ipv6", "next_header"))
            .unwrap_or(0) as u8;
        // Fragment stop: is_frag / is_first_frag, thoff past the frag header.
        if let Some(fr) = last("ext_frag") {
            k.is_frag = true;
            k.is_first_frag = last_u("ext_frag", "frag_off") == Some(0);
            k.thoff = (fr.start_bit / 8) as u16 + 8;
            return Ok(Some(k));
        }
```

Then let the existing terminal `tcp`/`udp` logic set `thoff`/`sport`/`dport` — for the L4-terminated chain, `thoff` is the tcp/udp instance start (already exact through the stacked options).

- [ ] **Step 11: Run projection + conformance + full gate**

Run: `./dev.sh cargo test -p pakeles`
Expected: PASS — projection tests green; `c_backend_conformance_full_suite_flow_dissector`, the eBPF and Lua flow-dissector suites green (stacked vectors now compare via last-occurrence); `committed_goldens_agree` still green (committed golden is still v2/11-name, new fields not yet compared).

- [ ] **Step 12: Run the P4/BMv2 differential for the regenerated example** (byte-aligned vectors)

Run: `./dev.sh cargo test -p pakeles diff` (or the bmv2 conformance test name)
Expected: PASS where `simple_switch` is available. If the header-stack P4 mis-parses a looped vector, that is a Task-3 defect surfaced here — fix in `p4.rs`, not by narrowing the example.

- [ ] **Step 13: Commit**

```bash
git add py/src/pakeles/examples/linux_flow_dissector.py src/examples.rs \
        src/oracle/flow_dissector.rs examples/linux_flow_dissector/
git commit -m "feat(example): rung 2 — IPv6 ext-header chain (self-loop) + last-link projection; max_depth=10"
```

---

## Task 5: Factory (capture.c v3 + `ntohl`), corpus, gate-hardening, README; privileged re-mint

**Files:**
- Modify: `oracle/flow_dissector/factory/capture.c:76-77` (14-name subset), `:110-127` (emit the three fields, `ntohl(flow_label)`).
- Modify: `oracle/flow_dissector/factory/corpus.txt` (append rung-2 vectors, drop-aware; keep all rung-0/1 lines first, untouched).
- Modify: `src/oracle/flow_dissector.rs` gate (`committed_goldens_agree`): add the 14-name subset floor assertion; update the ok/drop shape floor.
- Modify: `examples/linux_flow_dissector/README.md` (fidelity boundary: default-flags AND `max_depth` divergence).
- **User step:** privileged re-mint via `./dev-priv.sh oracle/flow_dissector/factory/capture.sh` → commit the new `flow_keys.linux-6.8.0.golden.json`.

- [ ] **Step 1: Widen the `keys_subset` line in `capture.c`** (`:76-77`):

```c
    printf("  \"keys_subset\": [\"nhoff\",\"thoff\",\"n_proto\",\"addr_proto\",\"ip_proto\","
           "\"sport\",\"dport\",\"ipv4_src\",\"ipv4_dst\",\"ipv6_src\",\"ipv6_dst\","
           "\"flow_label\",\"is_frag\",\"is_first_frag\"],\n");
```

- [ ] **Step 2: Emit the three fields with correct byte order** (`capture.c`, extend the ok-entry `printf` at `:119-127`). `flow_label` is `__be32` → `ntohl`; `is_frag`/`is_first_frag` are `__u8` → JSON bool:

```c
        printf("%s    {\"packet_hex\": \"%s\", \"disposition\": \"ok\", \"keys\": {"
               "\"nhoff\": %u, \"thoff\": %u, \"n_proto\": %u, \"addr_proto\": %u, "
               "\"ip_proto\": %u, \"sport\": %u, \"dport\": %u, "
               "\"ipv4_src\": \"%s\", \"ipv4_dst\": \"%s\", "
               "\"ipv6_src\": \"%s\", \"ipv6_dst\": \"%s\", "
               "\"flow_label\": %u, \"is_frag\": %s, \"is_first_frag\": %s}}",
               first ? "" : ",\n", phex,
               k->nhoff, k->thoff, ntohs(k->n_proto), k->addr_proto,
               k->ip_proto, ntohs(k->sport), ntohs(k->dport),
               v4s, v4d, v6s, v6d,
               ntohl(k->flow_label),
               k->is_frag ? "true" : "false",
               k->is_first_frag ? "true" : "false");
```

- [ ] **Step 3: Append the rung-2 corpus vectors** to `corpus.txt` (each a single pure-hex line + a `#` comment; keep rung-0/1 lines first and untouched). Add, with every disposition confirmed against the pinned `bpf_flow.c`:

```
# --- rung 2: IPv6 extension-header chain (default flags) ---
# accept: IPv6 + HopByHop(1 opt, nexthdr=TCP) + TCP — minimal single loop iter
<hex, byte-identical to projects_ipv6_hopopt_tcp>
# accept: IPv6 + DestOpts + HopByHop + UDP — two options (self-loop twice), ip_proto=17 from last link
<hex, byte-identical to projects_ipv6_two_opts_udp>
# accept: IPv6 + Fragment (first frag, offset 0) — stops; is_frag=is_first_frag=true, ports 0
<hex, byte-identical to projects_ipv6_frag_first>
# accept: IPv6 + Fragment (later frag, offset!=0) — stops; is_frag=true, is_first_frag=false
<hex, byte-identical to projects_ipv6_frag_later>
# accept: IPv6 + HopByHop + Fragment — option then frag terminal
<hex>
# accept: IPv6 non-zero flow_label + TCP — flow_label recorded, no early stop
<hex, byte-identical to projects_ipv6_flow_label>
# drop: IPv6 + HopByHop truncated (body runs past packet end) — extract-fail == kernel drop (downstream get_header)
<hex>
# drop: IPv6 + option chain final nexthdr unsupported (89/OSPF) — parse_ip_proto default BPF_DROP
<hex>
```

Keep the accept-vector hex **byte-identical** to the matching `project_tests` packet (the rung-1 contract). The drop vectors have no projection twin.

- [ ] **Step 4: Harden the gate.** In `committed_goldens_agree` (`src/oracle/flow_dissector.rs`), before the mismatch assertion, add the non-maskable subset floor + updated shape floor:

```rust
    for name in [
        "nhoff", "thoff", "n_proto", "addr_proto", "ip_proto", "sport", "dport",
        "ipv4_src", "ipv4_dst", "ipv6_src", "ipv6_dst",
        "flow_label", "is_frag", "is_first_frag",
    ] {
        assert!(
            g.keys_subset.iter().any(|s| s == name),
            "golden keys_subset missing `{name}` — re-mint with rung-2 capture.c \
             (a subset-stale golden would silently skip the new fields)"
        );
    }
    // rung-2 corpus: >=15 ok, >=6 drop (rung-0/1 had 11 ok / 8 drop; rung 2 adds 6 ok / 2 drop).
    assert!(ok >= 15 && drop >= 6, "corpus shape shrank: {ok} ok / {drop} drop entries");
```

**Sequencing note:** this assertion goes RED until the golden is re-minted (Step 6). Land Steps 1–5 in one commit and Step 6 (the re-minted golden) atomically after the mint, so `main`/the branch tip is never RED. During local dev before the mint, run the gate with this test temporarily `#[ignore]`d, or keep Steps 4 uncommitted until the golden arrives.

- [ ] **Step 5: Update the README fidelity boundary** (`examples/linux_flow_dissector/README.md`, the known-divergence section). Add two bullets:

```markdown
- **IPv6 extension headers (default flags):** we model `flags == 0` (what
  `BPF_PROG_TEST_RUN` produces). `flow_label` is recorded but never triggers
  an early stop (`STOP_AT_FLOW_LABEL` off); a Fragment header always stops
  after setting `is_frag`/`is_first_frag` (`PARSE_1ST_FRAG` off). Flag-driven
  behavior is out of scope — the parser takes no side channel.
- **Option-chain depth:** we bound the chain by `max_depth` (~5 option
  headers behind an Ethernet/IPv6 prefix, fewer behind QinQ). The kernel
  bounds it by the tail-call limit (~30). Chains of 6–~30 option headers are
  a known divergence: the kernel accepts, we reject. Not in the agreement
  corpus by construction.
```

- [ ] **Step 6 (USER, privileged): re-mint + commit the golden.** Instruct the user to run:

```bash
./dev-priv.sh oracle/flow_dissector/factory/capture.sh > \
  examples/linux_flow_dissector/conformance/flow_keys.linux-6.8.0.golden.json
```

Then verify agreement and commit:

```bash
./dev.sh cargo test -p pakeles oracle::flow_dissector::gate_tests::committed_goldens_agree
git add oracle/flow_dissector/factory/capture.c oracle/flow_dissector/factory/corpus.txt \
        src/oracle/flow_dissector.rs examples/linux_flow_dissector/
git commit -m "feat(oracle): rung 2 goldens — IPv6 ext-header chain agreement (flow_label/is_frag), ntohl fix"
```

- [ ] **Step 7: Full gate**

Run: `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint'` and the Python gate.
Expected: PASS — `committed_goldens_agree` proves kernel agreement over the full rung-0+1+2 corpus, including IPv6 option loops, Fragment handling, `flow_label`, and drops.

---

## Definition of done

Pakeles agrees with upstream `bpf_flow.c@v6.8`, in-kernel, over the full rung-0+1+2 corpus — IPv6 option-header loops (bounded), Fragment (`is_frag`/`is_first_frag`), `flow_label` recording, and drop agreement (truncation, unsupported terminal proto) — with the loop realized as a self-re-entrant state graph and bounded header stacks across all five backends (interpreter, C, BPF, Lua, P4/bmv2), and **no new IR message types**. The default-flags and `max_depth` fidelity boundaries are documented honestly in the example README. The gate is non-maskable (14-name subset floor).

## Self-review notes (spec coverage)

- §0 BLOCKER-1 (`flow_label` `ntohl`) → Task 5 Step 2. §0 DECISION (P4 first-class) → Task 3. §0 correction (no C/BPF arrays) → Task 4c relies on existing overwrite; no array work. §0 SHOULD-FIX-A (last-link `ip_proto`) → Task 4c Step 10. §0 SHOULD-FIX-B (harness) → Task 2. §0 SHOULD-FIX-C (`max_depth` doc) → Task 4 (`max_depth=10`) + Task 5 Step 5. §0 SHOULD-FIX-D (non-maskable gate + IPv4-frag note) → Task 5 Step 4 + README.
- §6 `var_bytes(expr)` — already implemented (Task 4a confirms). §1 prose fixes — reflected in the README bullets + the design §0; no code.
- Open verification during execution: exact `ParsedHeader`/`ParsedField` field names (Task 2 Step 1), the `src/examples.rs` builder helpers for named instances + `var_bytes(expr)` (Task 4 Step 6), the exact bmv2 conformance test name (Task 4 Step 12), and Lua `field_alignment` behavior across the self-loop (the option body is byte-aligned, so it should pass; if `field_alignment` can't prove alignment through a back-edge, that's a Lua finding to fix minimally).
```
