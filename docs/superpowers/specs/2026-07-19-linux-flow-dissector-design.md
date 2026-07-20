# `linux_flow_dissector`: a kernel-agreement north-star for Pakeles

**Date:** 2026-07-19
**Status:** design approved; rung-0 implementation pending
**Scope of this doc:** the whole north-star initiative (roadmap-level) + a detailed first increment (rung 0). Each later rung gets its own spec → plan → build cycle.

## Motivation

Pakeles needs a single, maximally-credible target that every future IR slice must serve. The **Linux kernel flow dissector** (`net/core/flow_dissector.c`, and its eBPF twin `bpf_flow.c`) is that target: the most complicated, most widely-run *bounded* packet parser in existence — it runs on essentially every packet on every Linux box to extract a flow key. It is bounded by construction (a hard `FLOW_DIS_ENCAP_LEVEL` encapsulation cap, no unbounded recursion), which is exactly Pakeles's thesis — *parsing is the decidable subset of packet processing*. Its eBPF form is bounded *because the kernel verifier forces it*, i.e. Pakeles's decidability bet already enforced in production.

The **ultimate test**: Pakeles's extracted `flow_keys`, for a corpus of packets, **agree packet-for-packet with the kernel's own `bpf_flow.c`**. No synthetic example carries this credibility.

This example is a **north-star that guides development**: it does not land whole. Each rung is one flow-dissector feature, the IR capability it forces, and the `flow_keys` fields it newly makes correct.

## Scope: the bounded core, not the heuristic tail

**In scope:** the structurally-clean, bounded core of flow dissection — Ethernet, VLAN/MPLS stacks, IPv4/IPv6 (incl. extension headers), IPv4/TCP options, one tunnel (GRE or IPIP), TCP/UDP.

**Explicitly out of scope (non-goals):** the heuristic / rare tail of `flow_dissector` — PPPoE, batman-adv, PPTP-GRE quirks, and the long grab-bag of `FLOW_DISSECTOR_KEY_*`. Parts of that tail are genuinely heuristic and arguably outside the decidable subset Pakeles is about; chasing 100% parity there would drag the project out of its lane for diminishing credibility. The honest claim is **"the bounded core of the Linux flow dissector,"** stated as a deliberate boundary.

## The staging ladder

| Rung | Flow-dissector feature | IR capability it forces | New `flow_keys` correctness |
|---|---|---|---|
| **0** (first increment) | Eth → IPv4/IPv6 → TCP/UDP demux | none — already exists | `nhoff, n_proto, ip_proto, sport, dport, ipv4/ipv6 addrs` |
| **1** | VLAN + MPLS stacks | counted header loops / header stacks | `nhoff` past the stack |
| **2** | IPv6 extension-header chain | loop-until-terminal over next-header | `thoff, ip_proto, is_frag` |
| **3** | IPv4/TCP options | TLV / sized regions (extends today's varbit) | `thoff` correctness |
| **4** | one tunnel (GRE or IPIP) | encap re-entrancy, depth-capped | `is_encap`, inner addrs (`FLOW_DIS_ENCAP_LEVEL`) |

Rungs 1–4 are precisely Pakeles's deferred TLV / header-stack / sized-region IR work — now each has a concrete, kernel-authoritative driver. Rung 4 (tunnel re-entrancy) is the deepest structural change and the real research milestone. **All of rungs 1–4 are deferred roadmap in this doc.**

## Oracle architecture (settled; feasibility demonstrated)

The oracle is a **golden-diff**, not a live BPF run in the hot loop:

1. **Golden factory** (runs rarely, privileged): the real upstream `bpf_flow.c` (rung 0 uses an in-repo dissector; upstream arrives at rung 1), compiled and loaded as `BPF_PROG_TYPE_FLOW_DISSECTOR`, run over a packet corpus via `BPF_PROG_TEST_RUN`, capturing the returned `struct bpf_flow_keys`. Output is **tagged with the kernel version** (e.g. `flow_keys.linux-6.8.golden.json`), making "agrees with Linux 6.8's flow dissector" a precise, reproducible claim.
2. **Golden corpus** (committed): `(packet, flow_keys)` pairs. Refreshing = re-running the factory and reviewing the diff.
3. **`diff flow-dissector` harness** (everyday gate, unprivileged): runs Pakeles's parse, applies the `flow_keys` projection (see below), and compares field-for-field to the committed goldens. **No BPF, no privilege in the normal loop.**

**Why this split — feasibility findings (spiked 2026-07-19 on this machine):**
- Host kernel is **Ubuntu 6.8.0 aarch64 with `/sys/kernel/btf/vmlinux` present** (BTF) — full modern BPF, flow-dissector prog type + `BPF_PROG_TEST_RUN` supported.
- `bpf()` is **blocked (EPERM)** in the standard `./dev.sh` container (default caps, seccomp, `unprivileged_bpf_disabled=2`) and **works under `--privileged`** (full caps).
- `BPF_PROG_TYPE_FLOW_DISSECTOR` (type 22) loads under privilege.
- **Demonstrated end-to-end:** a minimal flow-dissector program loaded and `BPF_PROG_TEST_RUN` over an eth+IPv4 packet returned a correct 56-byte `bpf_flow_keys` (`nhoff=14 thoff=34 n_proto=0x0800 ip_proto=6 ipv4_src=10.0.0.1 ipv4_dst=10.0.0.2`). The capture pipeline (`clang -target bpf` → load as flow-dissector → `test_run` → decode) is proven.

**Where the factory runs** (any of, by preference):
- **CI (recommended):** a GitHub Actions Linux-runner job (real VM, privileged BPF allowed) mints/refreshes goldens; the runner's kernel is the version pin.
- **Local pinned kernel:** `vmtest` (danobi/vmtest) or `virtme-ng` against a downloaded pinned **arm64** kernel, run on the macOS host (QEMU + HVF acceleration — `flow_keys` output is arch-independent, so no slow foreign-arch emulation). Avoid nesting QEMU inside the Colima VM.
- **Zero-tooling fallback:** a privileged container (`docker run --privileged`) on the existing Colima VM; kernel version = whatever the VM ships, recorded in the goldens.

Userspace BPF VMs (rbpf/ubpf/bpftime) are **not** viable for `bpf_flow.c`: it depends on kernel context rewrites, helpers, and a tail-call prog-array that userspace VMs don't reproduce; re-hosting it faithfully would mean reimplementing kernel internals, defeating the fidelity that makes it a good oracle.

## The `flow_keys` projection: harness-side (option A)

The mapping from Pakeles's parse result to `bpf_flow_keys` lives **in the oracle harness (Rust), not in the IR.** Rationale:
- It is trusted test-harness glue — exactly like the tshark oracle's field-normalization already is. The artifact under test is the *parse*, not the projection.
- It avoids committing normative IR surface (the deferred "projection mechanism" open question) before a working oracle tells us what it needs to express. Evidence before schema.
- It sequences risk like `eth_ipvx_l4` did: get the loop real and green, then promote.

**Deferred:** an in-IR projection construct (so *generated* parsers emit `flow_keys` themselves) is a future promotion, not part of this initiative's near-term work.

## Output contract

Agreement = matching the subset of `bpf_flow_keys` fields the covered protocols populate, growing per rung. Rung-0 subset: `{ nhoff, thoff, n_proto, addr_proto, ip_proto, sport, dport, ipv4_src, ipv4_dst, ipv6_src, ipv6_dst }`. Later rungs add `{ is_frag, is_first_frag, is_encap, flow_label }`. Fields outside the current rung's subset are not compared (documented, never silently skipped).

## Decomposition & first increment (rung 0)

The design doc above is the whole north-star. The **first buildable increment is rung 0, which touches no IR** (it reuses the existing eth/IP/TCP/UDP parsing). Deliverables:

1. **`linux_flow_dissector` example** — its own gallery example (own eDSL program → `ir.json` → gen artifacts), created now per the "own example from day one" decision. Its rung-0 parse covers eth/IPv4/IPv6/TCP/UDP and will look similar to `eth_ipvx_l4`; the two diverge at rung 1. It is the permanent home the initiative grows in and the anchor the goldens/oracle attach to.
2. **Golden factory** — a tool/script that runs a minimal in-repo flow dissector (fidelity-equal to upstream `bpf_flow.c` for eth/IPv4/IPv6/TCP/UDP without options or extension headers) in-kernel via `BPF_PROG_TEST_RUN` over the rung-0 packet corpus, emitting version-tagged golden `flow_keys`. Upstream `bpf_flow.c` (with libbpf and tail-call prog-array) replaces it at rung 1, where its richer parsing is required. Runs privileged (CI / `vmtest` / privileged container).
3. **Committed golden corpus** — rung-0 packets + captured `flow_keys`, kernel-version-tagged.
4. **`diff flow-dissector` oracle** — unprivileged harness: Pakeles parse + harness-side `flow_keys` projection (option A) + compare to goldens; wired into the normal gate.

Rung 0's "definition of done": the `diff flow-dissector` gate is green — Pakeles's `flow_keys` match the kernel's for the rung-0 corpus.

## Non-goals / deferred

- All IR-touching rungs (1–4): header stacks, ext-header loops, TLV/options, tunnel re-entrancy.
- In-IR projection (option B) — generated parsers emitting `flow_keys`.
- The heuristic/rare flow-dissector tail (PPPoE, batman-adv, PPTP-GRE, the `FLOW_DISSECTOR_KEY_*` grab-bag).

## Risks & open questions

- **Golden-factory build complexity.** The real `bpf_flow.c` is heavier than the spike's minimal program (tail-call prog-array, BTF/CO-RE, libbpf loader with `jmp_table` population — mirrors `tools/testing/selftests/bpf/prog_tests/flow_dissector.c`). This is the main construction risk for the first increment; the *capture mechanism* is proven, the *build/load of upstream `bpf_flow.c`* is not yet.
- **Kernel-version pinning strategy.** CI-runner kernel vs a `vmtest` pinned image — decide when building the factory; either way the version is recorded in the golden filename.
- **Harness-projection drift.** The Rust projection must track the example's field names; small and localized, but real. Revisited if it bites (→ promotes the case for in-IR projection).
- **Corpus design.** Rung 0 needs a representative packet corpus (v4/v6 × tcp/udp, plus edge cases the flow dissector cares about). Detailed in the rung-0 plan.
