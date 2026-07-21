# Example: `linux_flow_dissector`

This is Pakeles's **kernel-agreement north-star**: the permanent home of an
initiative to make Pakeles's extracted flow keys agree, packet-for-packet,
with the Linux kernel's own flow dissector (`net/core/flow_dissector.c` and
its eBPF twin `bpf_flow.c`) — the most complicated, most widely-run *bounded*
packet parser in existence. It runs on essentially every packet on every
Linux box. No synthetic example carries that credibility.

The initiative lands in **rungs**, each one flow-dissector feature, the IR
capability it forces, and the `flow_keys` fields it newly makes correct. See
the full roadmap and rationale in
[`docs/superpowers/specs/2026-07-19-linux-flow-dissector-design.md`](../../docs/superpowers/specs/2026-07-19-linux-flow-dissector-design.md).

This directory is **rung 0**: Ethernet → {IPv4 | IPv6} → {TCP | UDP} — the
same demultiplexing shape as [`eth_ipvx_l4`](../eth_ipvx_l4), touching no new
IR capability. Rung 0's contribution is the *oracle*, not the parse.

## Scope: the bounded core, not the heuristic tail

**In scope** (across all rungs): the structurally-clean, bounded core of
flow dissection — Ethernet, VLAN/MPLS stacks, IPv4/IPv6 (incl. extension
headers), IPv4/TCP options, one tunnel (GRE or IPIP), TCP/UDP.

**Explicitly out of scope:** the heuristic / rare tail of `flow_dissector`
— PPPoE, batman-adv, PPTP-GRE quirks, and the long grab-bag of
`FLOW_DISSECTOR_KEY_*`. Parts of that tail are genuinely heuristic and
arguably outside the decidable subset Pakeles is about. The honest claim is
**"the bounded core of the Linux flow dissector,"** stated as a deliberate
boundary — not 100% parity with every dissector quirk.

## The golden-diff oracle

The oracle is a **golden-diff**, not a live BPF run in the everyday gate:

1. **Golden factory** (privileged, out-of-gate; [`oracle/flow_dissector/factory/`](../../oracle/flow_dissector/factory/)) —
   upstream `bpf_flow.c` (Linux v6.8 selftests, fetched pinned at capture
   time), compiled and loaded as `BPF_PROG_TYPE_FLOW_DISSECTOR`, run over a
   packet corpus via `BPF_PROG_TEST_RUN` inside the real kernel. Its output is a
   **kernel-version-tagged** golden file, e.g.
   [`conformance/flow_keys.linux-6.8.0.golden.json`](conformance/flow_keys.linux-6.8.0.golden.json),
   making "agrees with Linux 6.8's flow dissector" a precise, reproducible
   claim.
2. **`diff flow-dissector`** ([`src/oracle/flow_dissector.rs`](../../src/oracle/flow_dissector.rs),
   `cargo run -- diff flow-dissector`) — the everyday, unprivileged gate:
   runs Pakeles's parse, projects the result to the rung-0 subset of
   `struct bpf_flow_keys` (harness-side projection, not in the IR), and
   compares field-for-field against the committed goldens. No BPF, no
   privilege, in the normal loop.

**A note on fidelity:** as of rung 1, the goldens are minted from
**upstream `bpf_flow.c`** itself — the Linux v6.8 selftests source, fetched
pinned at capture time, compiled with its tail-call prog-array and BTF/CO-RE
`jmp_table` population, and run in-kernel via `BPF_PROG_TEST_RUN`. This is a
strictly stronger claim than rung 0's in-repo approximation: agreement now
covers VLAN (depth ≤ 2, following the kernel's own tag-sequencing rules) and
MPLS (single-entry stop), *including* agreement on kernel drops (malformed
or over-depth tag stacks), not just accepts. The rung-1 state graph — VLAN
and MPLS states added — is regenerated at
[`gen/graph.svg`](gen/graph.svg).

**Boundary of the agreement claim:** the reject⇔drop agreement above is
proven over the committed corpus, no further. There are known divergence
classes *outside this rung's scope* where upstream `bpf_flow.c` **accepts**
packets this parser rejects (or parses differently) — these are deliberate
rung boundaries, not bugs:

- **Fragmented IPv4** — the kernel's `PROG(IP)` stops before port parsing
  when `MF`/frag-off is set, returning `BPF_OK` with zero ports; this
  parser would instead read TCP/UDP ports off fragment data or reject.
- **IP protocols other than TCP/UDP** (e.g. ICMP) — the kernel accepts
  with `ip_proto` set and no ports; we reject.
- **IPv6 extension headers** (`PROG(IPV6OP)`/`PROG(IPV6FR)`) — not yet
  modeled.
- **GRE/IPIP encapsulation** — not yet modeled.

Adding any of these as a corpus vector would make the gate legitimately
red until a future rung models them.

Refreshing the goldens (privileged; never part of the normal gate):

```sh
./dev-priv.sh oracle/flow_dissector/factory/capture.sh
```

CI can also refresh them via `.github/workflows/flow-dissector-goldens.yml`
(manual dispatch / schedule, `ubuntu-latest`, out of the required gate).

## Output contract

Agreement = matching the subset of `bpf_flow_keys` fields the covered
protocols populate, growing per rung. Rung-0 subset: `{ nhoff, thoff,
n_proto, addr_proto, ip_proto, sport, dport, ipv4_src, ipv4_dst, ipv6_src,
ipv6_dst }`. Fields outside the current rung's subset are not compared
(documented in each golden file's `keys_subset`, never silently skipped).

## Files

| File | What it is |
|---|---|
| [`linux_flow_dissector.py`](linux_flow_dissector.py) | The description, authored in the Python eDSL — a field-for-field port of the Rust builder ([`src/examples.rs`](../../src/examples.rs)); proto-equal to the IR below |
| [`linux_flow_dissector.ir.json`](linux_flow_dissector.ir.json) | The normative Pakeles IR (protojson) |
| [`gen/`](gen/) | Every generated artifact: Wireshark dissector, C99 parser, eBPF program, P4-16 program, docs, parse graph — same equality-guarded derivation as `eth_ipvx_l4` |
| [`conformance/vectors.json`](conformance/vectors.json) / [`vectors.pcap`](conformance/vectors.pcap) | Path-complete symbolic-execution suite (same discipline as `eth_ipvx_l4`) |
| [`conformance/flow_keys.linux-*.golden.json`](conformance/) | Kernel-captured golden `flow_keys`, version-tagged — the north-star artifact this example exists to hold |

## Try it

```sh
./dev.sh cargo run -- diff flow-dissector   # everyday gate: our flow_keys vs committed goldens
tshark -X lua_script:gen/dissector.lua -r conformance/vectors.pcap -V
```
