# Slice 5: "the switch" — P4 emission + BMv2 differential

**Date:** 2026-07-19
**Status:** Approved; implementation follows `plans/2026-07-19-slice5-switch.md`.

## Goal

`gen p4` emits a P4-16/v1model program from the IR; `diff bmv2` runs the
conformance vectors through the compiled program on BMv2 `simple_switch` and
compares verdicts against the reference interpreter. This is the
ceiling-principle proof by construction — the IR compiles into a real P4
parser accepted by p4c and executed by the ecosystem's reference switch — and
the **sixth** artifact / **fifth** provably-agreeing implementation (interp,
Lua, C, eBPF, now BMv2).

## Deliverables

- `pakeles gen p4` — P4-16 program for the v1model architecture.
- `pakeles diff bmv2` — differential oracle verb (compile via `p4c-bm2-ss`,
  execute via `simple_switch --use-files`, verdict-level comparison).
- Dev image: pinned source-built p4c (bmv2 + p4test backends) and
  behavioral-model (`--without-nanomsg --without-thrift`). Verified
  2026-07-19: no p4c/bmv2 packages exist for Ubuntu 24.04 (p4lang OBS stops
  at 23.04; Ubuntu archive has none), so source build it is — consistent
  with the explicit-from-scratch dev-env principle.
- Gallery: `examples/eth_ipv4_tcp/parser.p4`, committed + equality-guarded.
- Conformance test: byte-aligned vector subset, verdict-level, green in CI.
- p4test compile-clean test for the emitted program.
- README + docs updated (five agreeing implementations).

## Design decisions

**Architecture: v1model.** BMv2's canonical, best-supported arch. PSA is
less maintained on BMv2; v1model is what p4c's BMv2 backend targets first.

**IR→P4 mapping.**
- Fixed fields → `bit<N>` header fields, same order (both are MSB-first
  big-endian — semantic match, no byte-order surgery).
- A `byte_len` (var) field ends its P4 header: the emitter splits each IR
  header at var-field boundaries into segments — fixed-run segments and a
  companion `varbit<MAX>` header per var field, extracted in sequence
  (`extract(seg)`, then `extract(var_seg, len_bits)`). `MAX` is computed by
  interval arithmetic over the length expression (field widths bound every
  ref; e.g. ipv4 options: `(15*4-20)*8 = 320`).
- States → parser states 1:1. `select` keys → P4 `select` tuples;
  `KeysetEntry` value/masked/range → literal, `&&&`, `..` (all native P4).
  `accept`/explicit `reject` → `transition accept` / `transition reject`.
- Expressions → P4 arithmetic in `bit<32>` with casts. Semantic note:
  interp rejects a negative length (checked arithmetic); P4 bit arithmetic
  wraps, producing a huge varbit length → `PacketTooShort` reject. Both
  reject: verdict-level equivalent, reason class differs — documented, and
  invisible at the verdict granularity this oracle checks.
- Cyclic state graphs: rejected by `gen p4` with a clear error (P4 loops
  need header stacks — the TLV slice's business, not this one). The v0
  gallery is a DAG.
- `max_depth` is not emitted (the DAG restriction makes it vacuous here).

**Verdict observation.** The program's ingress control writes a 2-byte
`verdict_t { bit<8> bitmap; bit<8> err; }`: one bitmap bit per IR header
instance (in declaration order; an instance counts as present iff its final
segment `isValid()`), and `err` = enumerated `standard_metadata.parser_error`
(NoError=0, PacketTooShort=1, NoMatch=2, StackOutOfBounds=3, HeaderTooShort=4,
ParserTimeout=5, ParserInvalidArgument=6, other=255; P4's `error` type is not
bit-castable, hence the if-chain). The deparser emits **only** the verdict
header; ingress sets `egress_spec = 1`. Output frames are 2 bytes (BMv2 may
pad; the harness reads the first 2 bytes).

**Expected verdict derivation.** Per vector, from the reference interpreter
(`run_bits`), never hardcoded: expected bitmap = fully-parsed instances
(minus `error.instance` on truncation — P4 extracts are atomic while interp
records partial fields); expected err = 0 for accepts and explicit rejects
(v1model delivers explicitly-rejected parses to ingress with `NoError`),
`PacketTooShort` for truncations. If BMv2 empirically drops
rejected packets before ingress instead, absence-of-output is the reject
signal and the mapping degrades gracefully (documented fallback in the
harness).

**Vector subset.** Byte-aligned vectors only (`suite_to_packets` — the
slice-3 precedent). BMv2 parses real wire bytes; bit-granular truncations
cannot exist on the wire. Verdict-level comparison (the eBPF-slice
precedent of matching harness granularity to the artifact's observability).

**Harness mechanics.** `simple_switch --use-files` maps port *i* to
`<name>_in.pcap` / `<name>_out.pcap` — no veth pairs, no privileges, no
Thrift runtime (our parsers need no table entries). One packet per
invocation for order-robustness (~45 byte-aligned vectors × ~1s is
acceptable); batching is a recorded optimization, valid only once
1-in-1-out is empirically established.

## Non-goals

- P4Runtime, tables, checksums, PSA.
- P4 *ingestion* (v1 roadmap item; goes through `p4c --toJSON`, not our code).
- Diagnose-mode/display metadata in P4 (P4 has no such vocabulary; the
  dissector is the Lua backend's job).
- Bit-granular vectors through BMv2.

## Conformance bar

All byte-aligned gallery vectors verdict-match under `simple_switch`;
`p4test` accepts the emitted program with zero warnings; the gallery gains
an equality-guarded `parser.p4`; the full existing gate stays green.
