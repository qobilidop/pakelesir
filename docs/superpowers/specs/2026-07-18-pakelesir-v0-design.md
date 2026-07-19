# PakelesIR v0 design

Date: 2026-07-18. Product of the second big-picture session (same day as the project's founding note). Supersedes the roadmap and tech-stack portions of `../garden/scratchpad/2026/2026-07-18/pakelesir-design.md`; that note's vision, positioning, scope, and IR-design sections remain in force and are summarized, not restated, here. Research grounding: `../garden/scratchpad/2026/2026-07-18/portable-pp-compiler-stack-research.md`.

## Win conditions and constraints

- **Win conditions**: learning & craft (IR design, compilers, formal methods, and Rust fluency — Rust learning is an explicit goal, not incidental); career surface (public evidence of expertise in the networking/datapath world); genuine real-world usefulness — not a toy.
- **First users**, in roadmap order: dissector authors, protocol designers, datapath teams. All three are served by the same core.
- **Effort budget**: ~one day/week, sustained. Every milestone must be session-sized and resumable; there must always be a working artifact.
- **Going public**: deferred decision. Repo stays local until at least the slice-3 review point. No package-name reservations made yet — revisit before anything becomes public.

## Scope (reaffirmed)

Parsing only: header-region parsing of a single packet or message — bytes in, typed extraction out, stop at payload. Serialization as the format layer's inverse. Two layers: a domain-generic **format layer** (must express virtio/NVMe-class descriptors, not just packets) and a P4-shaped **automaton layer**. The ceiling principle stands: express everything a P4 parser can and deliberately not much more; bounded depth, no general recursion — staying inside the decidable class is the product, not a limitation. Two evaluation modes (reject and diagnose), projections, and a non-semantic annotation layer, all per the founding note. Out of scope: reassembly, cross-packet state, application-layer parsing, match-action.

## What changed in this session

1. **The toolchain portfolio is the product**, not the single Wireshark demo. The IR sits at the center of: reference interpreter, symbolic execution engine, a backend set chosen for stress diversity, and cheap high-leverage satellites.
2. **The symbolic engine is the keystone, built before any backend.** Because the IR is bounded by construction, symbolic execution over it is *complete*: finite path space, full enumeration. One engine yields path-complete golden test vectors (the oracle factory — every backend is born with a conformance suite), lint (unreachable states, shadowed select arms, unsatisfiable guards), hardware-feasibility metrics (max depth, lookahead window, worst-case extraction), and eventually a genuine decision procedure for parser equivalence.
3. **Rust throughout** (replacing "Python now, Rust later"). Decided after full evaluation: codegen backends are a wash (tree-sitter is the existence proof for Rust-emitting-C parsers), symbolic execution in Rust is viable (MIRAI, haybale, symex; `z3`/`bitwuzla`/`rsmt2` crates; our constraints are pure QF_BV), so the tiebreaker was learning goals plus compiler-guided refactoring, which doubles as re-entry help at day/week cadence. Accepted cost: slower iteration during IR churn.
4. **Proto-first from day one** (replacing "serde JSON now, protobuf later"). See serialization strategy.
5. **Thin-slice roadmap** replacing the big-bang v0 (see roadmap).

## Architecture

Single crate `pakeles` (lib + one binary), by deliberate choice over a multi-crate workspace: no publishing, compile-time, or team pressure exists yet, and a later split (e.g., extracting `pakeles-ir` for embedders at going-public time) is mechanical if module boundaries stay clean. Module discipline: interaction only through public interfaces, `pub(crate)` by default, `ir` depends on no other internal module.

```
proto/pakeles/ir/v1alpha1/   # normative IR schema (proto3)
src/
  ir/        # generated types + well-formedness validation + versioning
  builder/   # ergonomic Rust authoring API (the onnx.helper analog)
  interp/    # reference interpreter: reject + diagnose modes (normative semantics)
  symex/     # path enumeration + QF_BV solving   [cargo feature `symex`]
  codegen/   # backends: lua, c99 (+ ebpf variant), p4
  cli/       # pakeles subcommands: run, diff-tshark, vectors, lint, viz, coverage, doc
testdata/    # language-neutral fixtures: pcaps, IR files, expected-parse JSON
```

The serialized IR file is the only contract between tools. Authoring for v0 is the Rust builder API (consequence of the language decision; the only v0 author is the project owner). A human-readable YAML-ish view remains a possible future mechanical 1:1 projection of the IR — never a second language.

The solver dependency hides behind a small trait and the `symex` cargo feature, keeping default builds light and the solver swappable.

## IR serialization strategy

- **proto3 is the normative IR definition from day one**: `proto/pakeles/ir/v1alpha1/*.proto`, package `pakeles.ir.v1alpha1` (Buf's unstable-package convention — signals instability and scopes `buf breaking` strictness until promotion to `v1`).
- **Toolchain**: `buf` (lint, breaking, generate), `prost` for Rust types, `pbjson` for protojson-compliant JSON. One schema, two encodings from the start: binary for tools, canonical protojson for humans and diffs.
- **Expressions are operator trees in the schema** — no syntax smuggled inside strings (the Kaitai compromise stays rejected).
- **Accepted cost**: prost-generated types are anemic (pervasive `Option`, no invariants). v0 mitigation: use generated types directly everywhere and tolerate the noise; introduce a hand-written domain layer only if it earns its keep. Well-formedness validation lives in `ir` code regardless (protobuf cannot express it).
- **Buf Schema Registry**: publish the schema as its own Buf module at the going-public milestone — the normative contract gets independent versioned distribution plus registry-generated SDKs (Python/Go/TS) for third-party tool authors. Until then the Buf module lives only in-repo. `buf breaking` runs locally/CI from day one.

## Backend portfolio (chosen for stress diversity)

Each backend earns its place by forcing an IR property no other backend forces:

1. **Wireshark Lua dissector** — stresses diagnose mode + annotations. The screenshot-able demo.
2. **eBPF (generated C, `clang -target bpf`)** — stresses reject mode under kernel-verifier constraints; the IR's bounded-depth ceiling maps exactly onto verifier demands. The kernel-sanctioned shape per the kParser verdict, and the highest career-relevance target.
3. **Portable C99** — one dependency-free `parse(buf, len, out)`; covers DPDK/VPP/userspace/embedded via wrappers rather than per-framework backends. The eBPF emitter is a constrained variant sharing machinery.
4. **P4 parser emission** — stresses the ceiling from the other side: any IR feature that cannot emit as P4 is a knowing decision, not drift. Unlocks BMv2 differential testing.
5. **EverParse 3D emission** *(later, distinctive)* — stresses format-layer dependent constraints; payoff is formally verified C from the same description.

Considered and deferred: Rust emission (career surface but no new semantic stress; add on consumer demand), Kaitai export, cBPF for the steering projection, hardware profiles (DDP/flex-parser — when a consumer exists).

## Satellite tools

Cheap, high-leverage, attached to the slice where their machinery is naturally present: **parse-graph visualizer** (IR → Graphviz; slice 1, debugging payoff immediately), **pcap coverage reporter** (paths exercised by a corpus vs. all paths — the vector machinery pointed backwards; slice 2), **doc generator** (annotations → RFC-style field tables; slice 3). Later, by pull: packet fuzzer (valid-except-one-constraint near-miss vectors), semantic diff between description versions. No optimizer until a backend demands it.

## Slice roadmap

Every slice ends with a working, demoable artifact.

1. **The spine.** Devcontainer + repo scaffolding; proto schema covering format + automaton essentials; builder; reference interpreter (reject mode); Ethernet→IPv4→TCP; `pakeles diff-tshark` green on a real pcap; Graphviz visualizer.
2. **The oracle factory.** Symbolic engine: path enumeration + QF_BV constraints → `vectors`, `lint`, feasibility metrics. Solver chosen here empirically behind the trait (Bitwuzla vs Z3 vs SMT-LIB pipe). Pcap coverage reporter.
3. **First backend.** Wireshark Lua generator + diagnose mode + annotation layer, conformance-tested by slice-2 vectors. Doc generator. Natural go-public decision point.
4. **Datapath.** C99 emitter + eBPF variant, differentially tested against the interpreter via generated vectors, including execution under **rbpf** as a userspace eBPF harness (no root, no kernel). "Provably agreeing artifacts" becomes mechanically true here.
5. **The ceiling proof.** P4 emission + BMv2 differential. VLAN/MPLS/header-stack protocols land along the way as the automaton features they exercise arrive.

Beyond v0 (by pull, order not committed): protocol library with golden vectors, P4 frontend, equivalence checker as a first-class command, EverParse 3D backend, descriptor case study (virtio or NVMe), Rust emission.

## Tech stack

- **Environment**: **devcontainer as the reproducible dev environment** — Rust toolchain, `buf`, pinned `tshark`, `graphviz` from slice 1; `clang`/BPF tooling and solver libraries join in slices 2/4. Pinning tshark matters beyond convenience: `tshark -T json` output varies across Wireshark versions, so the container pins the *oracle*, not just the build.
- **Language**: stable Rust, pinned via `rust-toolchain.toml`.
- **Schema**: proto3 + `buf` + `prost` + `pbjson` (see serialization strategy).
- **Solver**: trait-abstracted; `bitwuzla` (best-in-class QF_BV), `z3`, or `rsmt2` piping — decided in slice 2.
- **Codegen**: `minijinja` templates where templating fits, direct emission where not; `insta` snapshot tests per backend.
- **Testing**: `cargo test` + `proptest` (interpreter properties) + `insta`; fixtures in `testdata/` are language-neutral data (pcaps, IR files, expected-parse JSON) doubling as the future conformance suite.
- **Pcap & oracle**: `pcap-parser` (pure Rust) for reading; `tshark -T json` as subprocess oracle, diffed via `serde_json`.
- **CLI & plumbing**: `clap`, `thiserror`/`anyhow`, `tracing`.
- **Checks**: `cargo fmt`, `clippy`, `buf lint`, `buf breaking` runnable locally from day one; GitHub Actions at going-public.

## Decision log (this session)

| Decision | Choice | Deciding factor |
|---|---|---|
| Scope | Parsing-only, reaffirmed | Decidability is the product |
| v0 shape | Thin vertical slices | Day/week cadence; always a working artifact |
| Symbolic engine timing | Before any backend | Completeness over bounded IR → oracle factory for all backends |
| Language | Rust throughout | Learning goal + refactor confidence; technical evaluation was near-even |
| Crate layout | Single crate, module discipline | No splitting pressure exists; split is cheap later if boundaries stay clean |
| IR schema | proto3 from day one, `v1alpha1` | Schema-first discipline, buf tooling, protojson canonically, no migration |
| Schema distribution | Buf Schema Registry at going-public | Independent contract versioning + free SDK generation |
| Dev environment | Devcontainer | Reproducibility incl. pinned tshark oracle |
| Going public | Decide at slice-3 review | Nothing to show yet; name-squatting risk accepted |

## Open design questions (carried forward, to be resolved in-slice)

- Automaton encoding: explicit cyclic state graph vs structured bounded loops (slice 1 forces this).
- Concrete operator inventory for expressions and extraction; format-layer type surface (slice 1, grown by later slices).
- Projection mechanism: how result shapes are declared and checked (slice 2+).
- Diagnose-mode semantics: how far to parse past an error; precise error-annotated result shape (slice 3).
- Annotation schema; protocol-library file conventions (slice 3).
- IR versioning mechanics beyond `v1alpha1` package versioning: opset-style op versioning? (Before going public.)
