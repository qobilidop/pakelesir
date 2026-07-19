# Pakeles

[![CI](https://github.com/qobilidop/pakeles/actions/workflows/ci.yml/badge.svg)](https://github.com/qobilidop/pakeles/actions/workflows/ci.yml)

> [!WARNING]
> **Work in progress, iterating fast — don't use this yet.** The IR
> schema (`v1alpha1`), the CLI, and every API change without notice,
> and compatibility is deliberately not promised at this stage. Watch
> the repo if you're curious; don't build on it.

A toolchain built around a serializable IR (the Pakeles IR) for
wire-format parsers — one description yields many artifacts that
provably agree: reference
interpretation, generated dissectors and datapath parsers, validators,
and golden test vectors. Parsing is the decidable subset of packet
processing — parsers here are bounded by construction, which is what
makes cross-artifact equivalence provable rather than merely tested.

Status: slice 6 ("the authoring surface"). One description
(Ethernet→IPv4→TCP)
is authored in Rust — or in the Python eDSL (`py/`), which produces
proto-identical IR — serialized as proto3, interpreted, visualized,
differentially tested against `tshark`, compiled by symbolic execution
into a path-complete conformance suite (every parse path — truncations
and rejects included — gets a solver-derived witness packet), and compiled into four
more implementations that provably agree with it: a working Wireshark
dissector (`gen lua`, verified inside real tshark), a portable C99
parser (`gen c`, verified field-for-field on all 164 vectors), an
eBPF program (`gen ebpf`, clang-compiled BPF bytecode verified under
the rbpf VM), and a P4-16 program (`gen p4`, p4c-compiled and
verdict-verified on BMv2's `simple_switch` — the decidability ceiling
demonstrated by construction). Docs generate from the same description
via `pakeles doc`.

## Quickstart

The only host requirement is Docker; `./dev.sh` runs everything inside
the pinned dev image (Ubuntu 24.04 + Rust, protoc, buf, tshark 4.2,
graphviz, clang/llvm, and source-built p4c + BMv2):

```sh
./dev.sh cargo test                                        # full suite
./dev.sh cargo run -- diff tshark --pcap testdata/basic.pcap
./dev.sh cargo run -- run --pcap testdata/basic.pcap       # JSON per packet
./dev.sh cargo run -- viz | dot -Tsvg -o graph.svg         # parse graph
./dev.sh cargo run -- export-ir                            # the IR itself
./dev.sh cargo run -- testgen --out vectors.json           # conformance suite
./dev.sh cargo run -- lint                                 # unreachable/shadowed
./dev.sh cargo run -- cov --pcap testdata/basic.pcap       # path coverage
./dev.sh cargo run -- gen lua --out dissector.lua          # Wireshark dissector
./dev.sh cargo run -- doc                                  # markdown docs
./dev.sh cargo run -- gen c --out-dir .                    # portable C99 parser
./dev.sh cargo run -- gen ebpf --out parser.bpf.c                # eBPF variant
./dev.sh cargo run -- gen p4 --out parser.p4               # P4-16 (v1model)
./dev.sh cargo run -- diff bmv2                            # vectors vs BMv2
```

Try the dissector in your own Wireshark:
`tshark -X lua_script:dissector.lua -r some.pcap` (it registers as a
postdissector, so its tree appears alongside Wireshark's built-in
dissection — side-by-side comparison for free).

## Authoring in Python

The recommended authoring surface is the Python eDSL — declarative
header classes, real infix expressions, one line per state:

```python
from pakeles import Header, bits, var_bytes, parser, extract, reject
from pakeles.fmt import DEC

class IPv4(Header):
    version = bits(4, "Version", DEC)
    ihl     = bits(4, "Header Length", DEC, doc="in 32-bit words")
    # ...
    options = var_bytes(ihl * 4 - 20)   # operator trees, eagerly built

eth = parser("my_parser", max_depth=4, start="ipv4", states={
    "ipv4": extract(IPv4).accept(),
})
eth.save("ir.json")                     # then: pakeles lint ir.json
```

The serialized IR stays the only contract: Python authors it, the Rust
CLI validates and compiles it. The eDSL's `eth_ipv4_tcp` example is
proto-equality-tested against the Rust builder's gallery `ir.json` —
two authoring surfaces, provably one artifact. See `py/README.md`.

## Layout

- `proto/pakeles/{ir,testvec}/v1alpha1/` — the normative schemas (proto3)
- `src/` — `ir` (types + validation), `builder`, `interp` (reference
  interpreter), `symex` (symbolic engine: testgen/lint/cov, z3 behind a
  solver trait), `codegen` (backends: Wireshark Lua, C99/eBPF, P4-16),
  `docgen`, `viz`, `oracle` (tshark + BMv2 diffs), `cli`
- `py/` — the Python authoring eDSL (`pakeles` on PyPI, eventually)
- `testdata/` — language-neutral fixtures (regenerate: `cargo run --bin gen_fixtures`)
- `examples/eth_ipv4_tcp/` — the gallery: every artifact one
  description yields, equality-guarded by tests
- `docs/superpowers/specs/` — design docs; start with
  `2026-07-18-pakelesir-v0-design.md`
