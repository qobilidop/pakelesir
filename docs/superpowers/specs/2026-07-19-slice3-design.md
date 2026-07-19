# Slice 3 design: the dissector

Date: 2026-07-19. Extends the v0 spec and slice-2 design. High-level
decisions owner-approved in discussion; low-level delegated.
Deliverables: diagnose-mode semantics, typed Display annotations,
Wireshark Lua backend (`gen lua`), vectors→pcap export, tshark-with-
our-dissector conformance loop, doc generator (`doc`).

## Owner-approved decisions

1. **Diagnose mode: same trajectory, richer result.** Identical
   automaton path as reject mode; the result additionally carries a
   structured error record (state, header instance, field, bit offset,
   reason, severity), and the payload region (consumed-bits boundary to
   end of input). No heuristic continuation — new automaton semantics
   are explicitly rejected to preserve decidability; consumers may
   layer heuristics later.
2. **Reject severity.** `Reject` gains an `annotations` map;
   `severity` ∈ {`error` (default), `info`}. `info` marks payload
   boundaries (unknown-next-protocol), rendered as payload, not
   malformedness. Built-in rejects (oob, depth, no-match) are `error`.
3. **Typed `Display` message on `Field`** (name, format enum
   DEC/HEX/BIN/IPV4/IPV6/ETHER, value labels, doc), explicitly
   non-semantic — no execution path may branch on it. The open string
   map stays for consumer-specific keys (`tshark.key`). Display
   formats also give the tshark oracle address normalization (dotted
   quad → u32, colon-hex → u48), closing the slice-1 address gap.
4. **Lua backend: direct translation.** States compile to readable Lua
   functions with real ProtoFields (typed where byte-alignment is
   statically provable, uint fallback otherwise), value-label tables,
   expert-info entries mapped from severity. Deliberately rehearses
   the slice-4 C emitter's shape.
5. **Conformance loop:** byte-aligned vectors from the committed suite
   export to a pcap; `tshark -X lua_script:<generated>` dissects it;
   the JSON is diffed against the suite's expected fields.
   Non-byte-aligned truncation vectors stay interpreter-verified
   (pcap is byte-granular — documented limitation, not hidden).

## Low-level design (delegated)

- **ParseResult additions** (computed always; diagnose is a view, not
  an interpreter mode switch): `error: Option<ParseError>`,
  `consumed_bits` (payload = consumed_bits..input bit_len).
- **Generated dissector shape**: one `Proto` named
  `pakeles_<parser>`; field abbrevs `pakeles_<parser>.<inst>.<field>`
  (deterministic — the conformance diff keys on them, no annotations
  needed for our own output); per-state Lua functions with a runtime
  bit cursor; select → if/elseif on locals bound during extraction
  (only for fields the IR actually references); depth counter
  mirroring `max_depth`; remainder rendered as payload; registration
  overrides `wtap_encap` 1 (Ethernet) so the loaded script replaces
  the built-in dissector for the demo.
- **Lua 5.2 compatibility** (container tshark: Lua 5.2.4): no `//`,
  no native bitwise operators; `math.floor`, arithmetic only.
  Length-expression arithmetic in Lua is signed (no u64 wrap): wrapped
  lengths surface as negative → treated as oob, which agrees with the
  interpreter's outcome on every representable input; noted in the
  generated header comment.
- **Static alignment analysis** in the generator: track cursor mod 8
  per state entry (propagated; conflict → unknown); typed ProtoFields
  (ether/ipv4) only where provably byte-aligned, else uint+HEX.
- **Vectors→pcap**: `testgen --pcap-out <file>` writes byte-aligned
  vectors in suite order and prints the skipped count (no silent
  drops).
- **Doc generator**: `doc [--ir] [--out]` emits markdown — per-header
  field tables (name, bits, format, labels, doc) + state/transition
  summary; consumes only IR + Display (dogfoods the annotation layer).
- **Validation additions**: Display label values must fit the field
  width; duplicate label values rejected; severity annotation value
  must be `error` or `info` when present.
- Example description gains full Display coverage (names, formats,
  labels for ethertype/protocol) + `severity: info` on its two
  payload-boundary rejects + `tshark.key` for the four address fields.

## Non-goals

VLAN/header stacks (slice 5 pressure), value-set parameters, testvec
schema changes (expected diagnose details ride later if a consumer
needs them), `gen c`/`gen ebpf` (slice 4).
