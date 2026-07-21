# Flow-Dissector Rung 2 Design — IPv6 Extension-Header Chain (bounded loop / header stack)

**Status:** design — reviewed + amended 2026-07-20 (4-way adversarial review), approved → plan. See **§0 Review amendments** for the binding corrections; where §0 conflicts with a later section, §0 wins.
**North-star:** [[flow-dissector-northstar]] — Pakeles's extracted `flow_keys` agree packet-for-packet with `bpf_flow.c` run in the Linux kernel. Rungs 0 and 1 complete+merged. This is rung 2, the ladder's designated *loop / header-stack IR milestone* — the first rung whose kernel behavior cannot be unrolled to a fixed instance count.

**Predecessors:** rung-0 spec `2026-07-19-linux-flow-dissector-design.md`; rung-1 spec `2026-07-20-flow-dissector-rung1-design.md`. This doc assumes their machinery (the golden factory running upstream `bpf_flow.c@v6.8` via `BPF_PROG_TEST_RUN`, golden schema v2 with `disposition`, the harness-side `flow_keys` projection, named header instances).

---

## 0. Review amendments (2026-07-20, 4-way adversarial review)

A four-dimension adversarial review (kernel-semantics, IR/schema, backend-feasibility, projection/corpus) validated the core thesis and surfaced corrections. **These are binding and supersede any conflicting text below.**

**Thesis upheld:** "No new IR message types" is verified — the schema (`FieldWidth.byte_len` Expr, free-form transition targets), the validator (must-analysis is a top-initialized fixpoint, sound on cycles, no DAG assumption), the interpreter (`depth_bound_respected` already tests an `s→s` self-loop), and the symex engine all already support the cyclic graph, the depth bound, and the length arithmetic. The kernel-semantics model was verified against the pinned `factory/build/bpf_flow.c@v6.8` (sha256 `f01d08e6…d41a`): `thoff`/`body` arithmetic, the `frag_off:13` bit-split == `IP6_OFFSET` mask, `ip_proto` at frag-stop, and the default-flags reachability argument all check out.

**BLOCKER-1 — `flow_label` byte order (corrects §4).** `struct bpf_flow_keys.flow_label` is **`__be32`** (network order), NOT host-order. The §4 analogy to `addr_proto` is wrong (`addr_proto` is host-order only because the kernel assigns it a host *constant*). `capture.c` MUST emit `ntohl(k->flow_label)`; the golden is then a logical 20-bit value ≤ `0xFFFFF`, matching the eDSL's `flow_label = bits(20)`. Found independently by two reviewers. Fix before minting v3 goldens.

**DECISION — P4 is a first-class rung-2 task (corrects §5).** The review found P4 is ~10× the implied effort: `p4.rs` has an explicit `check_acyclic()` (+ lock-in test `cyclic_graph_is_rejected`) that aborts on the self-loop, AND no header-stack codegen exists even absent the guard (var-headers are split into fixed+varbit, extraction is scalar, the verdict bitmap tests scalar `.isValid()`). User decision (2026-07-20): **build the P4 header-stack emitter now** — remove/gate `check_acyclic`, emit a stack declaration, `.next` stack-advancing extraction, index-synchronized dual stacks for the fixed+varbit split of the option body, and stack-aware bitmap validity. All five backends stay provably-agreeing at rung 2. **Pipeline guard (also BLOCKER):** `gen_examples` calls `generate_p4()` with `?` for *both* examples, so the committed `linux_flow_dissector/gen/parser.p4` becomes ungeneratable the moment the self-loop lands — the P4 task must land the stack emitter (or an explicit xfail gate) atomically so example regeneration never aborts mid-rung.

**CORRECTION — C/BPF/Lua/interpreter are near-free (corrects §5).** These already realize the self-loop with zero new control-flow code: the C backend is already `for (depth…) { switch(state){…} }` with `state=X; continue;` transitions; a self-loop re-enters the same case, and the single-struct *overwrite* (`out->ext_opt`) with cumulative offset advance is exactly what the projection needs. **Do NOT emit `hdr[MAX_DEPTH]` arrays** for C/BPF (§5's array framing is wrong). The "stacked-instance / reachable-from-self" analysis is a **P4-only stack-sizing** concern, not cross-backend.

**SHOULD-FIX-A — projection `ip_proto` must read the LAST `ext_opt` (corrects §3).** Stacked extractions append separate `ParseResult.headers` entries; the existing `hdr()` helper uses `.find()` = *first*. A DestOpts+HopByHop+UDP chain would wrongly project `ip_proto=0` instead of `17`. The projection must read the last `ext_opt` link (and prefer `ext_frag` when present). The two-option corpus vector self-catches this — don't "fix" it by editing the golden.

**SHOULD-FIX-B — conformance harnesses flatten by instance name.** The C harness (`c.rs` key→field map) and Lua harness (flat tshark JSON key) both key by `{instance}.{field}`; a repeated instance mis-compares. This is real **test-infra** work — the comparison logic, not the backends, breaks first on stacked vectors. Budget it as its own task.

**SHOULD-FIX-C — `max_depth` divergence must be documented (extends §7/§8).** `depth` counts *every* state entered, so the VLAN prefix shares the budget: under QinQ, `eth(1)+vlan_ad(2)+vlan_q(3)+ipv6(4)` leaves only ~4 `ext_opt` iterations before L4. The kernel's bound is the tail-call limit (`MAX_TAIL_CALL_CNT=33`, ~30 options), so **6–~30 option headers: kernel accepts, Pakeles rejects** — a real divergence class. Do NOT add a deep-chain vector to the agreement corpus; DO document this boundary in the README + §7 (as rung 1 documented its boundaries). Set `max_depth` with explicit headroom for the QinQ+options+L4 worst case (the plan sizes it; ≥10 is the floor to fit ~5 options behind a QinQ prefix) and state it is a documented bounded-fidelity boundary regardless.

**SHOULD-FIX-D — non-maskable gate (extends §4).** `diff_goldens` only compares names in the golden's `keys_subset`, so a re-mint whose `capture.c` still emits the 11-name subset would silently skip the 3 new fields and pass. Add a floor assertion that `keys_subset` contains all 14 expected names, add `flow_label`/`is_frag`/`is_first_frag` arms to `field_pair()`, and widen `capture.c`'s subset list. Note `is_frag`/`is_first_frag` are also kernel-set for **IPv4** fragments (which Pakeles doesn't model) — the corpus must stay IPv4-unfragmented; add a one-line §4 note.

**Prose precision fixes.** §1's "non-TCP/UDP nexthdr at chain end rejects ⇔ kernel `BPF_DROP`" is overbroad — reword to "for protocols outside the kernel's dissected set {ICMP, IPIP, IPv6, GRE, TCP, UDP}" (ICMP/GRE/IPIP/IPv6 do NOT drop; 89/OSPF in §8 is correctly a drop). §8's truncated-option drop happens **downstream** (the next `get_header` for L4 or the next option), NOT at the option's own `get_header` (`IPV6OP` reads only the 2-byte prefix and never bounds-checks the body); net disposition still agrees both ways — wording fix only.

---

## 1. Goal & the kernel behavior we must match

Upstream `bpf_flow.c@v6.8` handles the IPv6 extension-header chain across four programs plus a shared dispatch helper. The exact source (pinned, fetched at capture time):

```
parse_ipv6_proto(nexthdr):
    HOPOPTS(0) | DSTOPTS(60) -> tail-call IPV6OP
    FRAGMENT(44)             -> tail-call IPV6FR
    default                  -> parse_ip_proto(nexthdr)   // TCP/UDP/ICMP/GRE terminals

PROG(IPV6):   get ipv6hdr(40); addr_proto=ETH_P_IPV6; copy src+dst;
              thoff += 40; ip_proto = nexthdr; flow_label = ip6_flowlabel(h);
              if flow_label && (flags & STOP_AT_FLOW_LABEL): BPF_OK
              else parse_ipv6_proto(nexthdr)

PROG(IPV6OP): get ipv6_opt_hdr(2); thoff += (1 + hdrlen) << 3;
              ip_proto = nexthdr; parse_ipv6_proto(nexthdr)      // <-- LOOP BACK-EDGE

PROG(IPV6FR): get frag_hdr(8); thoff += 8; is_frag = true; ip_proto = nexthdr;
              if !(frag_off & IP6_OFFSET):                        // first fragment
                  is_first_frag = true
                  if !(flags & PARSE_1ST_FRAG): BPF_OK
              else: BPF_OK                                        // later fragment
              parse_ipv6_proto(nexthdr)   // reached only for first-frag + PARSE_1ST_FRAG
```

Three things make this rung distinct from rung 1:

1. **A genuine loop.** `IPV6OP` advances `thoff`, updates `ip_proto`, and re-enters `parse_ipv6_proto`, which can dispatch back to `IPV6OP`. The chain length is bounded only by the kernel tail-call limit (`MAX_TAIL_CALL_CNT = 33`), not a fixed 2 like VLAN. Unrolling to distinct instances (rung 1's trick) does not scale — the chain can exceed P4's 8-instance verdict-bitmap cap.
2. **New `flow_keys` fields.** `flow_label`, `is_frag`, `is_first_frag` — all already present in the kernel's `struct bpf_flow_keys`, all currently unread by our capture tool.
3. **A variable-length header.** The options header is `2 + ((1+hdrlen)<<3 − 2)` bytes — its body length is computed from a field it just read. This exercises the schema's `FieldWidth.byte_len` Expr (the sized-region construct the ladder nominally slated for rung 3, but which the schema already supports and which full-faithful options handling forces here).

**Scope decision (user: "full faithful"):** rung 2 models the complete IPv6 ext-header story — HopByHop, DestOpts, Fragment, and `flow_label` — recording all three new fields.

**Fidelity boundary (default-flags model).** The kernel's two flag-gated divergences — `STOP_AT_FLOW_LABEL` and `PARSE_1ST_FRAG` — are driven by `keys->flags`, a *caller-supplied side input*, not packet bytes. Pakeles parses packets; it takes no side channel. We therefore model the **default flag configuration (`flags == 0`)**, which is what `BPF_PROG_TEST_RUN` produces with a zero-initialized context and what the overwhelming majority of real callers use. Under `flags == 0`:

- `flow_label` is **recorded** but never triggers an early stop (STOP_AT_FLOW_LABEL off).
- A Fragment header **always stops** (`BPF_OK`) after setting `is_frag` and (for offset 0) `is_first_frag` — both derivable from packet bytes. The "first-fragment-then-continue-to-ports" path is unreachable under default flags.

This keeps the parser purely packet-driven (the core decidability thesis). Flag-parameterized parsing is an explicit **non-goal** for rung 2 — see §7. The factory captures goldens under default flags only, and the README states this boundary honestly, as rung 1 did for its own.

**L4 terminal set stays TCP/UDP.** "Full faithful" here means the ext-header *dimension* (Options + Fragment + flow_label). We do not expand the terminal L4 set: `parse_ip_proto`'s other arms — ICMP (accept, no ports), GRE/IPIP (encap recursion) — remain out of scope. ICMP is a trivial future addition; GRE/IPIP is rung 4 (tunnel re-entrancy). A non-TCP/UDP `nexthdr` at chain end rejects, which agrees with the kernel's `parse_ip_proto` default `BPF_DROP` for protocols it does not dissect.

---

## 2. The IR construct: self-transition + bounded header stack

**Chosen approach (user delegated; this was the recommended option): a self-re-entrant state graph bounded by the existing `max_depth`, with looped instances realized as bounded header stacks. No new IR message types.**

The schema already permits everything the *control flow* needs:

- `Transition.Target.state` is a free-form state name → a state may target itself or an earlier state. Cyclic graphs are already representable; rungs 0–1 simply never produced one.
- `Parser.max_depth` ("states entered") is the mandatory global decidability bound. A self-loop is bounded by it automatically — no per-loop counter is added to the schema.

The genuinely new thing is the **bounded header stack**: an instance extracted on a back-edge (i.e. inside a cycle) is emitted more than once. Backends that materialize a struct per instance (C, BPF, P4/bmv2) must realize such an instance as a fixed-size array. We derive "which instances are stacked" and "how deep" by **static analysis of the state graph**, not a new field:

- An instance is **stacked** iff its extracting state lies on a cycle (reachable from itself).
- Its **stack bound** is `max_depth` (a safe over-approximation: no instance can be extracted more times than the global states-entered cap). Over-allocation wastes at most a few array slots; it is never unsafe.

This is the smallest possible IR delta and reuses the one bound the schema already guarantees. An explicit `Extract.stack_bound` field is a documented **future refinement** (§7) if `max_depth` proves too coarse for P4 resource budgeting — deferred per the user's "refactor later."

### 2.1 The state graph

Header types (new): `IPv6ExtOpt` (HopByHop/DestOpts option header) and `IPv6Frag` (fragment header). Instances: `ext_opt` (stacked), `ext_frag`.

```
parse_ipv6:        extract IPv6; select ipv6.next_header {
                      0x00, 0x3C -> parse_ipv6_opt     # HOPOPTS / DSTOPTS
                      0x2C       -> parse_ipv6_frag     # FRAGMENT
                      6          -> parse_tcp
                      17         -> parse_udp
                      default    -> reject(unsupported ip proto, info)
                   }

parse_ipv6_opt:    extract IPv6ExtOpt["ext_opt"]; select ext_opt.next_header {
                      0x00, 0x3C -> parse_ipv6_opt      # <-- SELF-LOOP (the cycle)
                      0x2C       -> parse_ipv6_frag
                      6          -> parse_tcp
                      17         -> parse_udp
                      default    -> reject(unsupported ip proto, info)
                   }

parse_ipv6_frag:   extract IPv6Frag["ext_frag"]; accept   # default-flags: always stop
```

Under default flags, **Fragment is terminal** (`accept`), so the only cycle is the single self-loop `parse_ipv6_opt → parse_ipv6_opt`. Each extracting state carries its own dispatch table (reading *its own* instance's `next_header`), mirroring the kernel's shared `parse_ipv6_proto` without needing a dispatch state that reads "whichever instance was last extracted" (instances are distinct types, so a shared dispatch cannot name the field). The three tables are identical in structure; the duplication is small and legible, and keeps each select key a plain `FieldRef{instance, "next_header"}`.

`max_depth` rises to accommodate the longest bounded chain: `eth? → ipv6 → ext_opt×K → {tcp|udp}`. We set **`max_depth = 8`** (ipv6 + up to ~5 option headers + L4, with headroom), matching the interpreter/decidability story. This also caps the `ext_opt` stack at 8 — comfortably within P4's per-declaration stack sizing (a header *stack* is one declaration, not N instances; see §5).

### 2.2 Header layouts

```
IPv6ExtOpt:  next_header : bits(8)
             hdr_ext_len : bits(8)              # length in 8-octet units, excl. first 8
             body        : byte_len = ((1 + hdr_ext_len) << 3) - 2   # opaque run
IPv6Frag:    next_header : bits(8)
             reserved    : bits(8)
             frag_off    : bits(13)             # fragment offset (8-octet units)
             res2        : bits(2)
             m_flag      : bits(1)              # more-fragments
             identification : bits(32)
```

`body`'s width is the schema's `FieldWidth.byte_len` Expr over `hdr_ext_len`: `SUB(SHL(ADD(hdr_ext_len, 1), 3), 2)`. The eDSL gains a `var_bytes(expr=...)`-style affordance to author it (rung 1 added `var_bytes(16)` for fixed IPv6 addresses; this generalizes the length to an expression — see §6).

---

## 3. Projection (harness-side `flow_keys`)

`project()` in `src/oracle/flow_dissector.rs` gains IPv6-chain semantics. The kernel updates `thoff`/`ip_proto` incrementally as it walks; our projection reads the final parse state:

- `flow_label` ← `ipv6.flow_label` (already an extractable 20-bit field on the IPv6 header).
- `nhoff` ← IPv6 header byte start (unchanged from rung 1's IP handling).
- `thoff` ← byte offset **past the last extension header** = start of the terminal L4 header (`tcp`/`udp` instance start), or, when the chain stops at a Fragment, the byte offset past the fragment header. Because our extraction offsets are exact, `thoff` is the terminal instance's `start_bit / 8`; when stopped at frag, it is `ext_frag.start_bit/8 + 8`.
- `ip_proto` ← the final `next_header` in the chain (the terminal L4 proto, or the Fragment's `next_header` when stopped there) — read off the last-extracted instance.
- `is_frag` ← `true` iff an `ext_frag` instance was extracted.
- `is_first_frag` ← `true` iff `ext_frag` extracted **and** `(ext_frag.frag_off == 0)` (offset in 8-octet units; the `IP6_OFFSET` bits are exactly our `frag_off` field).
- `sport`/`dport`/`ipv6_src`/`ipv6_dst`/`addr_proto` ← as rung 1; ports are zero when the chain stops at a Fragment (no L4 parsed), matching the kernel.

The stacked `ext_opt` instances contribute only cumulative `thoff` advancement and the running `ip_proto`; the projection needs the *terminal* header offset and the *last* `next_header`, not each option header's bytes — so "keep offsets exact, read the last link" suffices without an addressable stack API.

---

## 4. Golden schema v3 + oracle

Add three fields to `FlowKeys` and to `keys_subset`: `flow_label: u32`, `is_frag: bool`, `is_first_frag: bool`. All `#[serde(default)]` so v2 goldens (which lack them) still parse — the gate stays green until re-mint. `diff_goldens` compares the new fields on `ok` entries exactly as it does the others; the two-sided disposition check is unchanged.

`capture.c` emits the three fields from the kernel `struct bpf_flow_keys` (which already carries them): `flow_label` is **`__be32` (network order) → emit `ntohl(k->flow_label)`** (see §0 BLOCKER-1 — it is NOT host-order like `addr_proto`; the golden is then a logical 20-bit value ≤ `0xFFFFF`), `is_frag`/`is_first_frag` are `__u8` booleans printed as JSON `true`/`false`. `keys_subset` grows to 14 names, and the gate asserts all 14 are present (§0 SHOULD-FIX-D). Note: `is_frag`/`is_first_frag` are kernel-set for IPv4 fragments too, which Pakeles does not model — the corpus must stay IPv4-unfragmented.

The gate test `committed_goldens_agree` keeps its shape floor, updated for the rung-2 corpus (§8).

---

## 5. Backend realization

The header stack is the one construct touching every datapath backend. Conformance suites already run both examples (rung 1); rung 2's example is the first with a cyclic graph, so the suites are what shake out each backend's loop handling.

- **Interpreter** (`src/…` parse engine): handle a cyclic state graph, bounding iterations by `max_depth` (already enforced). A stacked instance extracted N times keeps exact per-extraction offsets; the projection reads the last link. Detect stacked instances via reachable-from-self analysis.
- **C / BPF-C**: emit the stacked instance as a fixed-size array `hdr[MAX_DEPTH]` with a bounded `for` loop (BPF: the verifier requires the `max_depth` bound to be a compile-time constant — it is). Name collisions were already ruled out in rung 1 (emission keyed by instance).
- **Lua (Wireshark)**: a bounded loop registering repeated `ProtoField`s or a subtree per option header.
- **P4 / bmv2**: **P4 header stacks are the canonical fit** — `header IPv6ExtOpt_t[8] ext_opt;` with a parser state that transitions to itself consuming `ext_opt.next` until a terminal. This maps 1:1 to the self-loop. A header stack is **one** header declaration, so it counts as one entry against the verdict-bitmap cap (not N) — the cap is unaffected. The `byte_len` option body maps to P4 `varbit` with a computed length (`ParserModel` already reasons about `byte_len`; the loop is the new part).

**Backend-risk note:** the variable-length `body` (`varbit`/opaque run) under a *loop* is the deepest codegen path this rung exercises. If a backend cannot express variable-length-inside-loop, that is the finding rung 2 exists to surface — fix the backend minimally, add no IR surface.

---

## 6. eDSL surface

- `var_bytes(expr)`: generalize rung 1's fixed `var_bytes(16)` to accept a length **expression** over prior fields, authoring `FieldWidth.byte_len`. `((1 + hdr_ext_len) << 3) - 2` is written with the existing operand/BinOp affordances.
- **Self-transition authoring:** already expressible — a `select` arm names the same state. No new surface; the example simply targets `parse_ipv6_opt` from within `parse_ipv6_opt`.
- The example (`linux_flow_dissector.py`) gains `IPv6ExtOpt`, `IPv6Frag`, and the three IPv6-chain states; `max_depth = 8`. Regeneration produces the cyclic state graph (`gen/graph.svg` will show the self-loop).

---

## 7. Non-goals / explicit boundaries (rung 2)

1. **Flag-parameterized parsing.** `STOP_AT_FLOW_LABEL`, `PARSE_1ST_FRAG` are caller side-inputs; modeling them would give the parser a non-packet input, outside the packet-parser thesis. Default-flags fidelity only (§1). Documented in the README.
2. **Expanded L4 terminals** (ICMP, GRE/IPIP) — future rungs; GRE/IPIP is the rung-4 tunnel milestone.
3. **Explicit `Extract.stack_bound`** schema field — deferred; rung 2 sizes stacks to `max_depth` via static analysis. Revisit if P4 resource budgeting needs a tighter per-loop bound.
4. **Addressable header stack API** (reading option header *k*) — the projection needs only cumulative offset + last link; a full stack-indexing surface is unbuilt (YAGNI).

---

## 8. Corpus (factory, drop-aware)

Keep all rung-0/1 lines first and untouched (cross-validation anchors). Append rung-2 vectors, each a single pure-hex line, every accept/drop confirmed against upstream `bpf_flow.c` in-kernel:

- accept: IPv6 + HopByHop(1 opt, nexthdr=TCP) + TCP — the minimal single-loop-iteration case.
- accept: IPv6 + DestOpts + HopByHop + UDP — two option headers (self-loop twice), interleaved types.
- accept: IPv6 + Fragment (first frag, offset 0) — stops at frag; `is_frag=is_first_frag=true`, ports 0.
- accept: IPv6 + Fragment (later frag, offset≠0) — stops; `is_frag=true, is_first_frag=false`.
- accept: IPv6 + HopByHop + Fragment — option then frag terminal.
- accept: IPv6 with non-zero flow_label + TCP — `flow_label` recorded, no early stop.
- drop: IPv6 + HopByHop truncated (option body runs past packet end) — extract-fail ⇔ kernel `get_header` NULL → `BPF_DROP`.
- drop: IPv6 + option chain whose final nexthdr is an unsupported proto (e.g. 89/OSPF) — `parse_ipv6_proto` default → `parse_ip_proto` default `BPF_DROP` ⇔ our reject.
- (retain rung-1 VLAN/MPLS + rung-0 lines.)

`committed_goldens_agree` shape floor updated to the new ok/drop counts. The single-opt, two-opt, frag, and truncated lines double as projection unit-test packets (kept byte-identical between the Rust `project_tests` and `corpus.txt`, per the rung-1 contract).

---

## 9. Definition of done

Pakeles agrees with upstream `bpf_flow.c@v6.8`, in-kernel, on the full rung-0+1+2 corpus — including IPv6 option-header loops (bounded), Fragment handling (`is_frag`/`is_first_frag`), `flow_label` recording, and agreement on drops (truncation, unsupported terminal proto) — with the loop realized as a self-re-entrant state graph and bounded header stacks across all five backends, and no new IR message types. The default-flags fidelity boundary is documented honestly in the example README.

---

## 10. Task decomposition (preview for the plan)

Rewritten post-review to reflect the true effort allocation (§0). In dependency order (the plan details each with TDD steps); effort tags: **[S]** small, **[M]** medium, **[L]** large.

1. **[S] eDSL `var_bytes(expr)`** — length-*expression* affordance + tests. Note the Rust builder already accepts an arbitrary `Expr` (`builder.rs`); only the Python surface is new.
2. **[S] Golden schema v3** — add `flow_label:u32`/`is_frag:bool`/`is_first_frag:bool`, `#[serde(default)]`; add `field_pair()` arms; **assert `keys_subset` ⊇ the 14 names** (§0 SHOULD-FIX-D).
3. **[M] Example + validator** — `IPv6ExtOpt`/`IPv6Frag` + the three IPv6-chain states (self-loop); size `max_depth` for the QinQ+options+L4 worst case (§0 SHOULD-FIX-C, ≥10 floor); regenerate. Interpreter/validator already handle cycles + the depth bound (verified) — this is mostly authoring + confirming, not new engine code.
4. **[M] Projection** — IPv6-chain `flow_keys`: `thoff` through options, **`ip_proto` reads the LAST `ext_opt`** (§0 SHOULD-FIX-A, not the first-match helper), `is_frag`/`is_first_frag`, `flow_label`.
5. **[S] C / BPF / Lua realization** — verify the existing bounded dispatch loop + single-struct overwrite already produce correct results (§0 correction: **no array codegen**); the only new work is the Lua byte-align check on the option body (holds for `IPv6ExtOpt`).
6. **[M] Conformance test-infra** — make the C and Lua harness comparison logic stack-aware (§0 SHOULD-FIX-B); this breaks before the backends do on stacked vectors.
7. **[L] P4/bmv2 header-stack emitter** (first-class, §0 DECISION) — remove/gate `check_acyclic` + its lock-in test; emit stack declaration; `.next` stack-advancing extraction; index-synchronized fixed+varbit dual stacks for the option body; stack-aware bitmap validity; **gate `gen_examples` so a cyclic example never aborts regeneration**. The one surviving §5 claim: a stack counts as 1 against the 8-instance verdict-bitmap cap.
8. **[M] Factory + corpus + docs** — `capture.c` emits v3 fields (**`ntohl` on `flow_label`**, §0 BLOCKER-1) + 14-name subset; corpus grows (drop-aware, §8); privileged re-mint; cross-validate; tighten gate shape floor; **README fidelity update covers BOTH the default-flags boundary AND the `max_depth`-vs-tail-call divergence** (§0 SHOULD-FIX-C).
