# Flow-Dissector Rung 3 — TCP Options as a `doff`-Sized Region — Design

**Status:** design, approved 2026-07-21. North-star ladder rung 3 (see
`docs/superpowers/specs/2026-07-19-linux-flow-dissector-design.md`).

## Motivation

Rung 3 on the ladder is "IPv4/TCP options". The authoritative driver
(vendored `oracle/flow_dissector/factory/build/bpf_flow.c`) shows the kernel
flow dissector does **not** parse *into* options — it opaque-skips them:

- **IPv4**: `keys->thoff += iph->ihl << 2`. Pakeles already reproduces this
  via `options = var_bytes(ihl*4 - 20)`, so IPv4 `thoff` is **already correct**.
- **TCP** (`IPPROTO_TCP`): reads the fixed 20-byte header, then
  `if (doff < 5) DROP`, `if (tcp + doff*4 > data_end) DROP`, else reads
  sport/dport → `OK`. No per-option parsing; it only validates that
  `doff*4` bytes are present.

The current example's `TCP` header already declares `data_offset` but
`parse_tcp` is `extract(TCP).accept()` — it never reads it. So today Pakeles
**accepts** TCP packets the kernel **drops** (`doff<5`, or `doff≥5` with
truncated options). Closing that disposition gap is the whole of rung 3.

There is **no TLV-into-options capability** here — the ladder's "TLV /
sized regions" framing over-promises for this rung. Substreams / peek /
lookahead have no kernel driver and are deferred to a future advanced
example (Babel/DNS; see the RFC-formal-parsing research doc).

## The change

`py/src/pakeles/examples/linux_flow_dissector.py` — add one field to the
`TCP` header class, mirroring IPv4 exactly:

```python
options = var_bytes(data_offset * 4 - 20)
```

`parse_tcp` stays `extract(TCP).accept()`. The option region is the last
field of the TCP header, so it is read as part of TCP extraction.

**Scope: `linux_flow_dissector` only.** `eth_ipvx_l4` (the hello-world) keeps
its fixed TCP — its scope is deliberately locked for teaching, and it already
demonstrates `var_bytes` via IPv4 options.

## Kernel-agreement mapping

The rung-3-preceding symex symbolic-layout rework (commit `c58c041`) already
generates all three control-flow forks of a wrapping/oversized `var_bytes`,
so no engine work is required.

| Packet | kernel `bpf_flow.c` | Pakeles |
|---|---|---|
| `doff < 5` | `DROP` | `doff*4-20` wraps (u64) → oob "out of bounds" reject ⇔ drop |
| `doff ≥ 5`, options truncated | `DROP` (`tcp+doff*4 > data_end`) | truncation ⇔ drop |
| `doff ≥ 5`, options present | `OK`, reads sport/dport | accept, sport/dport in keys |
| `doff = 5` (today's corpus) | `OK` | options = 0 bytes → accept, **keys unchanged** |

The golden schema's two-sided reject⇔drop diff already maps a Pakeles reject
to a kernel `BPF_DROP`. Existing `doff=5` corpus packets are unaffected
(their option region is empty).

## What does NOT change

- **Projection** (`src/oracle/flow_dissector.rs`): TCP options touch no
  `flow_key` — `sport`/`dport`/`thoff` are all at or before the fixed TCP
  header. No change.
- **Backends** (C / eBPF / Lua / BMv2 / P4): all already handle `var_bytes`
  (IPv4 options prove it). TCP is terminal (no header stack), so the P4
  header-stack path is untouched. No change.
- **Symex engine**: wrapping-oob + truncation on `var_bytes` already handled.
  No change.

## What does change

1. `linux_flow_dissector.py`: the one-line `options` field.
2. `oracle/flow_dissector/factory/corpus.txt`: add TCP-options packets —
   a `doff=6` (+4 option bytes) `OK` case on **both** the v4 and v6 arms, a
   `doff<5` drop, and a truncated-options drop. Confirm existing corpus TCP
   packets carry `doff=5` (else they would already mismatch, which the green
   gate rules out).
3. **Privileged golden re-mint** — `./dev-priv.sh oracle/flow_dissector/factory/capture.sh`
   (kernel 6.8.0). A USER step. Regenerates the v3 golden with the new
   vectors; the `keys_subset` name set is unchanged.
4. Regenerate the gallery — `./dev.sh scripts/gen-examples.sh` — and the
   committed suites (gitignored `vectors.json`/`pcap` refresh locally).
5. `README` known-divergence boundary: move "TCP options" from future-rungs
   to done.

## Validation (Definition of Done)

- `committed_goldens_agree` passes over the re-minted golden = Pakeles agrees
  packet-for-packet with in-kernel `bpf_flow.c@v6.8` on TCP-options packets
  (OK, `doff<5` drop, truncated drop) on both the v4 and v6 arms.
- Full gate green: symex path enumeration + `pathid_roundtrips`,
  `committed_vectors_replay_green`, C/eBPF/Lua/BMv2 conformance over the new
  vectors, fmt/clippy/buf/ruff/pyright/pytest.
- Anti-drift pins (`committed_ir_json_is_canonical`, the gen-artifact
  currency pins) pass after regen.

## Cost note

Regen grows modestly: TCP options add a few small-packet paths per transport
arm (`expr_max = 15*4-20 = 40` bytes → ~320-bit BV contribution, **not** the
wide-BV loop cost). The privileged re-mint is the main manual step.
