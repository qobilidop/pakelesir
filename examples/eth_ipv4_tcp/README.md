# Example: `eth_ipv4_tcp`

One description in, every artifact out — and all of them provably agree.
This directory is organized by role: the **input**, the **contract**,
and everything **derived** from it.

```mermaid
flowchart LR
    PY["eth_ipv4_tcp.py\n(authoring, Python eDSL)"] -->|"emit + fmt-ir"| IR["eth_ipv4_tcp.ir.json\n(normative Pakeles IR)"]
    IR -->|"gen lua"| LUA["gen/dissector.lua"]
    IR -->|"gen c"| C["gen/parser.h/.c"]
    IR -->|"gen ebpf"| EBPF["gen/ebpf.c"]
    IR -->|"gen p4"| P4["gen/parser.p4"]
    IR -->|"doc / viz"| DOCS["gen/doc.md, gen/graph.svg"]
    IR -->|"testgen (symbolic execution)"| V["conformance/\n164 path-complete vectors"]
    V -.->|conformance| LUA & C & EBPF & P4
```

Every file is committed **and equality-guarded**: if anything here
drifts from what the toolchain generates, CI fails. Regenerate with
`./dev.sh cargo run --bin gen_examples`.

## The input

| File | What it is | Verified by |
|---|---|---|
| [`eth_ipv4_tcp.py`](eth_ipv4_tcp.py) | The description, authored in the Python eDSL (mirrored from [`py/`](../../py)) | proto-equal to `eth_ipv4_tcp.ir.json`, which the independent Rust builder ([`src/examples.rs`](../../src/examples.rs)) also produces |

## The contract

| File | What it is | Verified by |
|---|---|---|
| [`eth_ipv4_tcp.ir.json`](eth_ipv4_tcp.ir.json) | The normative Pakeles IR (protojson) — the only artifact other tools consume | schema validation + reference interpretation; differentially tested against `tshark` on real captures |

## Derived: implementations that provably agree

| File | What it is | Verified by |
|---|---|---|
| [`gen/dissector.lua`](gen/dissector.lua) | Working Wireshark dissector (Lua 5.2) | 500+ field comparisons inside real `tshark`, zero mismatches |
| [`gen/parser.h`](gen/parser.h) / [`gen/parser.c`](gen/parser.c) | Portable C99 parser (zero-copy, bit-granular) | field-for-field on **all 164 vectors**; compiles `-Wall -Wextra -Werror` clean |
| [`gen/ebpf.c`](gen/ebpf.c) | Self-contained eBPF variant (verifier-shaped core) | verdict-level on all 164 vectors under the rbpf VM |
| [`gen/parser.p4`](gen/parser.p4) | P4-16 program (v1model) | verdict-level on all 28 byte-aligned vectors under BMv2 `simple_switch`; `p4test` + `p4c-bm2-ss` warning-free |

## Derived: presentation

| File | What it is | Verified by |
|---|---|---|
| [`gen/doc.md`](gen/doc.md) | Field tables + parse graph documentation | equality guard |
| [`gen/graph.dot`](gen/graph.dot) / [`gen/graph.svg`](gen/graph.svg) | The parse graph | equality guard |

## The conformance suite that binds them

| File | What it is | Verified by |
|---|---|---|
| [`conformance/vectors.json`](conformance/vectors.json) | Path-complete suite: 164 solver-derived vectors (11 accept / 17 reject / 136 truncation — every parse path gets a witness packet) | replayed by the reference interpreter in CI; cross-validated by path ids |
| [`conformance/vectors.pcap`](conformance/vectors.pcap) | The 28 byte-aligned vectors as a capture file | same vectors, wire form |

## Try it

Any machine with Wireshark ≥ 4.x — no build required:

```sh
tshark -X lua_script:gen/dissector.lua -r conformance/vectors.pcap -V
```

The dissector registers as a postdissector, so its tree appears
alongside Wireshark's built-in dissection — side-by-side comparison for
free.

![parse graph](gen/graph.svg)
