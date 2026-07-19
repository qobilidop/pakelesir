# PakelesIR

> [!WARNING]
> **Work in progress, iterating fast — don't use this yet.** The IR
> schema (`v1alpha1`), the CLI, and every API change without notice,
> and compatibility is deliberately not promised at this stage. Watch
> the repo if you're curious; don't build on it.

A serializable IR for wire-format parsers, plus the toolchain that makes
one description yield many artifacts that provably agree: reference
interpretation, generated dissectors and datapath parsers, validators,
and golden test vectors. Parsing is the decidable subset of packet
processing — parsers here are bounded by construction, which is what
makes cross-artifact equivalence provable rather than merely tested.

Status: slice 1 ("the spine") — one description (Ethernet→IPv4→TCP),
authored in Rust, serialized as proto3, interpreted, visualized, and
differentially tested against `tshark`.

## Quickstart

The only host requirement is Docker; `./dev.sh` runs everything inside
the pinned dev image (Rust, protoc, buf, tshark 4.0, graphviz):

```sh
./dev.sh cargo test                                        # full suite
./dev.sh cargo run -- diff-tshark --pcap testdata/basic.pcap
./dev.sh cargo run -- run --pcap testdata/basic.pcap       # JSON per packet
./dev.sh cargo run -- viz | dot -Tsvg -o graph.svg         # parse graph
./dev.sh cargo run -- export-ir                            # the IR itself
```

## Layout

- `proto/pakeles/ir/v1alpha1/` — the normative IR schema (proto3)
- `src/` — `ir` (types + validation), `builder`, `interp` (reference
  interpreter), `viz`, `oracle` (tshark diff), `cli`
- `testdata/` — language-neutral fixtures (regenerate: `cargo run --bin gen_fixtures`)
- `docs/superpowers/specs/` — design docs; start with
  `2026-07-18-pakelesir-v0-design.md`
