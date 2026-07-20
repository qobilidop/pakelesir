# Flow-Dissector Rung 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pakeles agrees with upstream `bpf_flow.c` (Linux v6.8) on VLAN/MPLS packets — including agreement on drops — with no IR schema change.

**Architecture:** Unroll the kernel's depth-≤2 VLAN structure into explicit states using named header instances (already in the IR schema; the Python eDSL gains the `Header["name"]` affordance). Replace the golden factory's minimal in-repo dissector with upstream `bpf_flow.c`, fetched pinned at capture time and loaded via libbpf (tail-call prog-array). Golden schema v2 records per-entry disposition (`ok`/`drop`) so the oracle checks rejection agreement too.

**Tech Stack:** Rust (oracle/codegen/symex), Python eDSL (authoring), C + libbpf (privileged capture tool), clang BPF target, Docker (`./dev.sh` unprivileged gate, `./dev-priv.sh` privileged factory).

**Spec:** `docs/superpowers/specs/2026-07-20-flow-dissector-rung1-design.md` — read it first.

## Global Constraints

- ALL builds/tests run inside the dev container: `./dev.sh <cmd>`. The host has no rust/protoc/tshark/clang. The full gate is:
  `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint && cd py && ruff check . && pyright && pytest'`
- The factory alone runs privileged: `./dev-priv.sh oracle/flow_dissector/factory/capture.sh`. Never wire it into the normal gate.
- The Python eDSL is the single authoring source: edit `py/src/pakeles/examples/linux_flow_dissector.py`, then regenerate everything with `./dev.sh scripts/gen-examples.sh`. Never hand-edit `examples/linux_flow_dissector/{*.ir.json,*.py,gen/*}`.
- NEVER commit `bpf_flow.c` or any fetched kernel source — it is GPL-2.0, the repo is Apache-2.0. Fetched files live in gitignored `oracle/flow_dissector/factory/build/`.
- Never edit a committed golden by hand to force green. Goldens are minted only by the factory.
- The gate must be green at every commit.
- Commit messages end with:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

---

### Task 1: eDSL instance references (`Header["name"]`)

**Files:**
- Modify: `py/src/pakeles/_expr.py` (add `BoundField`)
- Modify: `py/src/pakeles/_header.py` (add `Instance`, `Header.__class_getitem__`)
- Modify: `py/src/pakeles/_states.py` (`extract` accepts `Instance`; `SelectSpec.keys` widened)
- Test: `py/tests/test_instance.py` (new)

**Interfaces:**
- Produces: `VLAN["vlan_q"]` → `Instance`; `extract(VLAN["vlan_q"])` extracts under instance name `"vlan_q"`; `VLAN["vlan_q"].encapsulated_proto` → `BoundField` usable as a select key or in expressions, serializing `FieldRef{header: "vlan_q", field: "encapsulated_proto"}`. Bare `extract(VLAN)` / `VLAN.field` still mean the default instance (= header-type name). Task 2 (example) consumes exactly this surface.

- [ ] **Step 1: Write the failing tests**

Create `py/tests/test_instance.py`:

```python
"""Named header instances: `VLAN["vlan_q"]` extracts a second copy of a
header type and yields instance-bound field references."""

import pytest
from google.protobuf import json_format

from pakeles import Header, bits, extract, parser, reject
from pakeles._pb import ir_pb2


class Tag(Header):
    vid = bits(12)
    pad = bits(4)
    proto = bits(16)


class Eth(Header):
    ethertype = bits(16)


def two_tag_parser():
    return parser(
        "two_tags",
        max_depth=3,
        start="s0",
        states={
            "s0": extract(Eth).select(
                Eth.ethertype, {0x8100: "s1"}, default=reject("no")
            ),
            "s1": extract(Tag["outer"]).select(
                Tag["outer"].proto, {0x8100: "s2"}, default=reject("no")
            ),
            "s2": extract(Tag["inner"]).accept(),
        },
    )


def test_extract_records_instance_name() -> None:
    ir = two_tag_parser().to_pb()
    states = {s.name: s for s in ir.parser.states}
    assert states["s1"].extracts[0].header_type == "tag"
    assert states["s1"].extracts[0].instance == "outer"
    assert states["s2"].extracts[0].instance == "inner"
    # Default-instance extraction stays empty (canonical form).
    assert states["s0"].extracts[0].instance == ""


def test_bound_field_ref_serializes_instance_name() -> None:
    ir = two_tag_parser().to_pb()
    states = {s.name: s for s in ir.parser.states}
    key = states["s1"].transition.select.keys[0]
    assert key.field.header == "outer"
    assert key.field.field == "proto"


def test_header_type_emitted_once_for_two_instances() -> None:
    ir = two_tag_parser().to_pb()
    assert [h.name for h in ir.parser.header_types].count("tag") == 1


def test_unknown_field_on_instance_raises() -> None:
    with pytest.raises(AttributeError):
        _ = Tag["outer"].nope


def test_bound_field_arm_width_check_still_applies() -> None:
    with pytest.raises(ValueError, match="does not fit"):
        parser(
            "bad",
            max_depth=2,
            start="s0",
            states={
                "s0": extract(Tag["t"]).select(
                    Tag["t"].vid, {1 << 12: "s0"}, default=reject("no")
                ),
            },
        )


def test_roundtrips_through_json() -> None:
    p = two_tag_parser()
    assert json_format.Parse(p.to_json(), ir_pb2.Ir()) == p.to_pb()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./dev.sh sh -c 'cd py && pytest tests/test_instance.py -v'`
Expected: FAIL — `TypeError: 'type' object is not subscriptable` (no `__class_getitem__` yet).

- [ ] **Step 3: Implement `BoundField` in `py/src/pakeles/_expr.py`**

Append after `FieldSpec` (keep `coerce_expr` last):

```python
@dataclass(frozen=True)
class BoundField(Operand):
    """A `FieldSpec` bound to a header *instance* name
    (`VLAN["vlan_q"].vid`). Presents the same (name, header, width_bits)
    surface as `FieldSpec`, with `header` = the instance name, so select
    keys and expressions accept either."""

    spec: FieldSpec
    instance: str

    @property
    def width_bits(self) -> int | None:
        return self.spec.width_bits

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def header(self) -> str:
        return self.instance

    def as_expr(self) -> Expr:
        return Expr(ref=self)
```

Widen `Expr.ref`'s type (the `to_pb` body needs no change — it only touches `.name`/`.header`):

```python
    ref: FieldSpec | BoundField | None = None
```

(`BoundField` is defined after `Expr`; the annotation is fine under `from __future__ import annotations`.)

- [ ] **Step 4: Implement `Instance` + `__class_getitem__` in `py/src/pakeles/_header.py`**

Add to the imports: `from pakeles._expr import BoundField` (extend the existing `from pakeles._expr import ...` line).

Add inside `class Header`, after `__init__`:

```python
    def __class_getitem__(cls, name: str) -> Instance:
        """`VLAN["vlan_q"]`: a named extraction of this header type.
        The IR schema keys field references by header *instance*; the
        default instance shares the header type's name."""
        if not isinstance(name, str) or not name:
            raise TypeError(f"instance name must be a non-empty string, got {name!r}")
        return Instance(cls, name)
```

Add at module bottom:

```python
class Instance:
    """A (header type, instance name) pair; see `Header.__class_getitem__`.
    Attribute access yields `BoundField` references bound to the name."""

    def __init__(self, header: type[Header], name: str) -> None:
        self._header = header
        self._name = name

    @property
    def header_type(self) -> type[Header]:
        return self._header

    @property
    def name(self) -> str:
        return self._name

    def __getattr__(self, attr: str) -> BoundField:
        for f in self._header._fields:
            if f.name == attr:
                return BoundField(spec=f, instance=self._name)
        raise AttributeError(f"{self._header.__name__} has no field {attr!r}")
```

- [ ] **Step 5: Accept `Instance` in `py/src/pakeles/_states.py`**

Import `Instance` (extend `from pakeles._header import Header` to `from pakeles._header import Header, Instance`) and `BoundField` (add to the `_expr` import). Then:

```python
def _resolve(header: type[Header] | Instance, instance: str | None) -> tuple[type[Header], str | None]:
    if isinstance(header, Instance):
        if instance is not None:
            raise ValueError("pass either Header['name'] or instance=, not both")
        return header.header_type, header.name
    return header, instance
```

Change `StateChain.extract` and the module-level `extract` to:

```python
    def extract(
        self, header: type[Header] | Instance, instance: str | None = None
    ) -> StateChain:
        self._need_open()
        self.extracts.append(_resolve(header, instance))
        return self
```

```python
def extract(header: type[Header] | Instance, instance: str | None = None) -> StateChain:
    return StateChain().extract(header, instance)
```

Widen the select-key type: `SelectSpec.keys: tuple[FieldSpec | BoundField, ...]` and the `select()` parameter `key: FieldSpec | BoundField | tuple[FieldSpec | BoundField, ...]`. (`_build.py`'s `_check` reads only `.width_bits`/`.header`/`.name`, which both types provide — no change needed there; confirm pyright agrees.)

- [ ] **Step 6: Run tests to verify they pass, then the full py suite**

Run: `./dev.sh sh -c 'cd py && ruff check . && pyright && pytest'`
Expected: all PASS, pyright 0 errors. If pyright complains about `SelectSpec.keys` widening in `_build.py`, annotate there with the same union.

- [ ] **Step 7: Commit**

```bash
git add py/src/pakeles/_expr.py py/src/pakeles/_header.py py/src/pakeles/_states.py py/tests/test_instance.py
git commit -m "feat(edsl): named header instances — Header['name'] with instance-bound field refs"
```

---

### Task 2: Golden schema v2 — disposition + two-sided diff

**Files:**
- Modify: `src/oracle/flow_dissector.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub enum Disposition { Ok, Drop }` (serde `snake_case`, default `Ok`); `GoldenEntry { packet_hex, disposition: Disposition, keys: Option<FlowKeys> }`; `diff_goldens` asserting Pakeles-reject ⇔ golden-drop and field agreement on `ok` entries. The committed v1 golden (no `disposition`, `keys` always present) must still parse — `#[serde(default)]` covers it — so the gate stays green until Task 7 re-mints. Task 6's capture tool emits this v2 JSON shape; keep names in sync.

- [ ] **Step 1: Write the failing tests**

In `src/oracle/flow_dissector.rs`, replace the body of `mod diff_tests` with (keep `golden_from_fixture`, adjusted below):

```rust
#[cfg(test)]
mod diff_tests {
    use super::*;
    fn golden_from_fixture() -> GoldenFile {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = crate::fixtures::tcp_packet();
        let keys = super::project(&ir, &pkt).unwrap().unwrap();
        GoldenFile {
            kernel_version: "test".into(),
            keys_subset: vec![
                "nhoff".into(),
                "thoff".into(),
                "sport".into(),
                "dport".into(),
            ],
            entries: vec![GoldenEntry {
                packet_hex: pkt.iter().map(|b| format!("{b:02x}")).collect(),
                disposition: Disposition::Ok,
                keys: Some(keys),
            }],
        }
    }
    #[test]
    fn diff_green_on_self() {
        let ir = crate::examples::linux_flow_dissector();
        let report = diff_goldens(&ir, &golden_from_fixture()).unwrap();
        assert_eq!(report.compared, 1);
        assert!(report.mismatches.is_empty(), "{:#?}", report.mismatches);
    }
    #[test]
    fn diff_catches_mismatch() {
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].keys.as_mut().unwrap().dport = 1; // corrupt
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
    }
    #[test]
    fn drop_entry_agrees_when_we_reject() {
        // ARP ethertype: kernel drops, our parse rejects — agreement.
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].packet_hex =
            "aabbccddeeff1122334455660806000108000604000111223344\
             55660a000001aabbccddeeff0a000002"
                .into();
        g.entries[0].disposition = Disposition::Drop;
        g.entries[0].keys = None;
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.compared, 1);
        assert!(report.mismatches.is_empty(), "{:#?}", report.mismatches);
    }
    #[test]
    fn drop_entry_mismatches_when_we_accept() {
        // Kernel claims drop on a packet we accept -> disagreement.
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].disposition = Disposition::Drop;
        g.entries[0].keys = None;
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
        assert!(report.mismatches[0].contains("disposition"));
    }
    #[test]
    fn ok_entry_mismatches_when_we_reject() {
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].packet_hex = "aabbcc".into(); // truncated -> we reject
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
        assert!(report.mismatches[0].contains("disposition"));
    }
    #[test]
    fn v1_golden_without_disposition_still_parses() {
        let s = r#"{"kernel_version":"6.8.0","keys_subset":["nhoff"],
            "entries":[{"packet_hex":"aabb","keys":{"nhoff":14,"thoff":0,
            "n_proto":0,"addr_proto":0,"ip_proto":0,"sport":0,"dport":0,
            "ipv4_src":"","ipv4_dst":"","ipv6_src":"","ipv6_dst":""}}]}"#;
        let g: GoldenFile = serde_json::from_str(s).unwrap();
        assert_eq!(g.entries[0].disposition, Disposition::Ok);
        assert_eq!(g.entries[0].keys.as_ref().unwrap().nhoff, 14);
    }
}
```

Also update `golden_file_roundtrips` in `mod tests` to construct `GoldenEntry` with `disposition: Disposition::Ok, keys: Some(FlowKeys { nhoff: 14, ..Default::default() })`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./dev.sh cargo test oracle::flow_dissector`
Expected: compile FAILURE (`Disposition` undefined, `keys` not an Option).

- [ ] **Step 3: Implement schema v2 + two-sided diff**

In `src/oracle/flow_dissector.rs`, after `FlowKeys`:

```rust
/// Kernel verdict for a corpus packet: did the flow dissector produce a
/// flow key (`BPF_OK`) or drop (`BPF_DROP`)? v1 goldens predate the field
/// and were all accepts — hence the serde default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    #[default]
    Ok,
    Drop,
}
```

Change `GoldenEntry`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub packet_hex: String,
    #[serde(default)]
    pub disposition: Disposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<FlowKeys>,
}
```

Replace the loop body of `diff_goldens`:

```rust
    for (i, e) in golden.entries.iter().enumerate() {
        let pkt = crate::testvec::hex_decode(&e.packet_hex)?;
        let ours = project(ir, &pkt)?;
        report.compared += 1;
        match (e.disposition, ours) {
            (Disposition::Drop, None) => {} // agree: kernel drops, we reject
            (Disposition::Drop, Some(_)) => report.mismatches.push(format!(
                "vector {i}: disposition: ours=accept golden=drop"
            )),
            (Disposition::Ok, None) => report.mismatches.push(format!(
                "vector {i}: disposition: ours=reject golden=ok"
            )),
            (Disposition::Ok, Some(ours)) => {
                let golden_keys = e.keys.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("vector {i}: ok entry without keys — malformed golden")
                })?;
                for field in &golden.keys_subset {
                    let (o, t) = field_pair(field, &ours, golden_keys);
                    if o != t {
                        report
                            .mismatches
                            .push(format!("vector {i}: {field}: ours={o} golden={t}"));
                    }
                }
            }
        }
    }
```

- [ ] **Step 4: Run the full Rust suite**

Run: `./dev.sh sh -c 'cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test'`
Expected: PASS, including `committed_goldens_agree` (the committed v1 golden parses via the defaults).

- [ ] **Step 5: Commit**

```bash
git add src/oracle/flow_dissector.rs
git commit -m "feat(oracle): golden schema v2 — per-entry disposition, reject<=>drop diff"
```

---

### Task 3: Example gains VLAN/MPLS (kernel-faithful unrolled states)

**Files:**
- Modify: `py/src/pakeles/examples/linux_flow_dissector.py`
- Regenerate (never hand-edit): `examples/linux_flow_dissector/{linux_flow_dissector.ir.json,linux_flow_dissector.py,gen/*,conformance/vectors.json,conformance/vectors.pcap}`

**Interfaces:**
- Consumes: Task 1's `Header["name"]` / `Instance` surface.
- Produces: header instances named `ethernet, ipv4, ipv6, tcp, udp, mpls` (defaults) plus `vlan_ad`, `vlan_q` (explicit); states `parse_vlan_ad`, `parse_vlan_q`, `parse_mpls`; `max_depth=5`. Task 4's projection reads instances `vlan_q` (field `encapsulated_proto`) and `mpls` by exactly these names.

- [ ] **Step 1: Extend the eDSL example**

In `py/src/pakeles/examples/linux_flow_dissector.py`:

1. Update the module docstring to describe rung 1 (VLAN depth-≤2 unrolled to mirror upstream `PROG(VLAN)`'s position-dependent rules — 802.1AD must be followed by 802.1Q, no third tag; MPLS single-entry read-and-stop mirroring `PROG(MPLS)`).
2. Add to the `Ethernet.ethertype` labels: `0x88A8: "802.1AD (QinQ)"`, `0x8847: "MPLS unicast"`, `0x8848: "MPLS multicast"`.
3. Add header classes after `Ethernet`:

```python
class VLAN(Header):
    pcp = bits(3, "Priority", DEC, tshark="vlan.priority")
    dei = bits(1, "DEI", DEC, tshark="vlan.dei")
    vid = bits(12, "VLAN ID", DEC, tshark="vlan.id")
    encapsulated_proto = bits(
        16,
        "Type",
        HEX,
        tshark="vlan.etype",
        labels={
            0x0800: "IPv4",
            0x86DD: "IPv6",
            0x8847: "MPLS unicast",
            0x8848: "MPLS multicast",
        },
    )


class MPLS(Header):
    label = bits(20, "Label", DEC, tshark="mpls.label")
    tc = bits(3, "Traffic Class", DEC, tshark="mpls.exp")
    s = bits(1, "Bottom of Stack", DEC, tshark="mpls.bottom")
    ttl = bits(8, "TTL", DEC, tshark="mpls.ttl")
```

4. Replace the `parser(...)` call:

```python
def linux_flow_dissector() -> Parser:
    return parser(
        "linux_flow_dissector",
        max_depth=5,
        start="parse_ethernet",
        states={
            "parse_ethernet": extract(Ethernet).select(
                Ethernet.ethertype,
                {
                    0x0800: "parse_ipv4",
                    0x86DD: "parse_ipv6",
                    0x8100: "parse_vlan_q",
                    0x88A8: "parse_vlan_ad",
                    0x8847: "parse_mpls",
                    0x8848: "parse_mpls",
                },
                default=reject("unsupported ethertype", info=True),
            ),
            # Upstream PROG(VLAN), 802.1AD arm: the outer S-tag must be
            # followed by exactly one 802.1Q C-tag.
            "parse_vlan_ad": extract(VLAN["vlan_ad"]).select(
                VLAN["vlan_ad"].encapsulated_proto,
                {0x8100: "parse_vlan_q"},
                default=reject("802.1AD must be followed by 802.1Q"),
            ),
            # Upstream PROG(VLAN), common tail: the final (or only) tag;
            # a further Q/AD tag is a kernel drop (no triple tagging, no
            # double-Q).
            "parse_vlan_q": extract(VLAN["vlan_q"]).select(
                VLAN["vlan_q"].encapsulated_proto,
                {
                    0x0800: "parse_ipv4",
                    0x86DD: "parse_ipv6",
                    0x8847: "parse_mpls",
                    0x8848: "parse_mpls",
                    0x8100: reject("vlan stacking beyond kernel depth"),
                    0x88A8: reject("vlan stacking beyond kernel depth"),
                },
                default=reject("unsupported ethertype", info=True),
            ),
            "parse_ipv4": extract(IPv4).select(
                IPv4.protocol,
                {6: "parse_tcp", 17: "parse_udp"},
                default=reject("unsupported ip protocol", info=True),
            ),
            "parse_ipv6": extract(IPv6).select(
                IPv6.next_header,
                {6: "parse_tcp", 17: "parse_udp"},
                default=reject("unsupported ip protocol", info=True),
            ),
            # Upstream PROG(MPLS): read one label entry, stop, BPF_OK.
            "parse_mpls": extract(MPLS).accept(),
            "parse_tcp": extract(TCP).accept(),
            "parse_udp": extract(UDP).accept(),
        },
    )
```

- [ ] **Step 2: Regenerate the gallery**

Run: `./dev.sh scripts/gen-examples.sh`
Expected: exits 0, prints `gallery regenerated from py/src/pakeles/examples/*.py`. `git status` shows `examples/linux_flow_dissector/` regenerated (ir.json, mirrored .py, gen/*, conformance/vectors.*) and `examples/eth_ipvx_l4/` untouched. If P4 generation fails on the instance-count assert, note: this example has exactly 8 instances — the bitmap limit — so it must pass; a 9th would be a real error.

- [ ] **Step 3: Run the full gate**

Run: `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint && cd py && ruff check . && pyright && pytest'`
Expected: PASS. Notably `committed_goldens_agree` stays green: the rung-0 golden packets take the unchanged eth→ip→l4 paths. If `validate` or a backend rejects the two-instance parse, fix THAT code (it claims instance support) — do not restructure the example.

- [ ] **Step 4: Commit**

```bash
git add py/src/pakeles/examples/linux_flow_dissector.py examples/linux_flow_dissector
git commit -m "feat(example): rung 1 — VLAN (depth-2, unrolled) + MPLS states, kernel-faithful"
```

---

### Task 4: Projection updates (VLAN-shifted offsets, MPLS stop)

**Files:**
- Modify: `src/oracle/flow_dissector.rs` (`project` + `mod project_tests`)

**Interfaces:**
- Consumes: Task 3's instance names (`vlan_q`, `mpls`).
- Produces: `project()` semantics per spec §2 — `n_proto` from `vlan_q.encapsulated_proto` else `ethernet.ethertype`; `addr_proto` 0x0800/0x86DD/0; MPLS accepts → `thoff == nhoff == mpls start`, zero ports/addrs. Task 7's gate relies on these matching the kernel goldens.

- [ ] **Step 1: Write the failing tests**

Add to `mod project_tests` (packet hexes are corpus lines from Task 6 — keep identical):

```rust
    fn hexpkt(s: &str) -> Vec<u8> {
        crate::testvec::hex_decode(s).unwrap()
    }

    #[test]
    fn projects_single_vlan_v4_tcp() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff112233445566810000640800\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 18); // 14 + one 4-byte tag
        assert_eq!(k.thoff, 38);
        assert_eq!(k.n_proto, 0x0800); // kernel: inner encapsulated proto
        assert_eq!(k.addr_proto, 0x0800);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_qinq_v4_tcp() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff11223344556688a80064810000650800\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 22); // 14 + two tags
        assert_eq!(k.thoff, 42);
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.addr_proto, 0x0800);
    }

    #[test]
    fn projects_mpls_stop() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff112233445566884700064140\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 14); // kernel PROG(MPLS) leaves thoff untouched
        assert_eq!(k.n_proto, 0x8847);
        assert_eq!(k.addr_proto, 0); // set only by the IP progs upstream
        assert_eq!(k.ip_proto, 0);
        assert_eq!(k.sport, 0);
        assert_eq!(k.dport, 0);
        assert_eq!(k.ipv4_src, "");
        assert_eq!(k.ipv6_src, "");
    }

    #[test]
    fn projects_vlan_then_mpls() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff11223344556681000064884700064140\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 18);
        assert_eq!(k.thoff, 18);
        assert_eq!(k.n_proto, 0x8847);
        assert_eq!(k.addr_proto, 0);
    }

    #[test]
    fn triple_tag_rejects() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = hexpkt(
            "aabbccddeeff11223344556688a800648100006581000066\
             080045000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        assert!(project(&ir, &pkt).unwrap().is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./dev.sh cargo test oracle::flow_dissector::project_tests`
Expected: new tests FAIL (`n_proto` = 0x8100/0x88A8 from `ethernet.ethertype`; MPLS accept panics on missing tcp/udp or wrong thoff). `triple_tag_rejects` may already pass — fine.

- [ ] **Step 3: Reimplement the projection body**

Replace everything in `project()` after the `bytes` closure with:

```rust
    let mut k = FlowKeys::default();
    // Kernel PROG(VLAN) rewrites n_proto to the inner encapsulated proto;
    // vlan_q is the final tag on every VLAN path (the AD path's C-tag or
    // the single Q tag), so its encapsulated_proto is authoritative.
    k.n_proto = u("vlan_q", "encapsulated_proto")
        .or_else(|| u("ethernet", "ethertype"))
        .unwrap_or(0) as u16;
    if let Some(h) = hdr("ipv4") {
        k.addr_proto = 0x0800;
        k.nhoff = (h.start_bit / 8) as u16;
        k.ip_proto = u("ipv4", "protocol").unwrap_or(0) as u8;
        k.ipv4_src = format!("{:08x}", u("ipv4", "src").unwrap_or(0));
        k.ipv4_dst = format!("{:08x}", u("ipv4", "dst").unwrap_or(0));
    } else if let Some(h) = hdr("ipv6") {
        k.addr_proto = 0x86DD;
        k.nhoff = (h.start_bit / 8) as u16;
        k.ip_proto = u("ipv6", "next_header").unwrap_or(0) as u8;
        k.ipv6_src = bytes("ipv6", "src").map(hex).unwrap_or_default();
        k.ipv6_dst = bytes("ipv6", "dst").map(hex).unwrap_or_default();
    } else if let Some(h) = hdr("mpls") {
        // Kernel PROG(MPLS): single-entry read, no key updates — nhoff and
        // thoff stay at the MPLS header start; addr_proto/ports stay 0.
        k.nhoff = (h.start_bit / 8) as u16;
        k.thoff = k.nhoff;
        return Ok(Some(k));
    }
    // Reachability: Accept through an IP path implies exactly one of
    // {tcp, udp} was extracted (unchanged from rung 0).
    let t_inst = if hdr("tcp").is_some() { "tcp" } else { "udp" };
    k.thoff = (hdr(t_inst).map(|h| h.start_bit).unwrap_or(0) / 8) as u16;
    k.sport = u(t_inst, "sport").unwrap_or(0) as u16;
    k.dport = u(t_inst, "dport").unwrap_or(0) as u16;
    Ok(Some(k))
```

(Delete the old `ip_inst` fallback block; the comment about `addr_proto = n_proto` goes with it.)

- [ ] **Step 4: Run the full Rust suite**

Run: `./dev.sh sh -c 'cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test'`
Expected: PASS — rung-0 `project_tests` and `committed_goldens_agree` still green (for pure-IP packets the new code computes identical keys).

- [ ] **Step 5: Commit**

```bash
git add src/oracle/flow_dissector.rs
git commit -m "feat(oracle): projection follows kernel VLAN/MPLS semantics"
```

---

### Task 5: Backend conformance breadth — run every suite on both examples

**Files:**
- Modify: `src/codegen/c.rs` (tests `c_backend_conformance_full_suite`, `bpf_backend_conformance_full_suite`, near lines 631–800)
- Modify: `src/codegen/lua.rs` (test `generated_dissector_conformance`, near line 663)
- Modify: `src/oracle/bmv2.rs` (test `bmv2_conformance_byte_aligned_suite`, near line 247)

**Interfaces:**
- Consumes: Task 3's regenerated example (8 instances, two of one type).
- Produces: each backend's conformance test exercises `crate::examples::linux_flow_dissector()` in addition to `eth_ipvx_l4()` — this is what shakes out any codegen path that assumed instance == header-type name.

- [ ] **Step 1: Parameterize each conformance test**

In each listed file, refactor the existing conformance test body into a helper taking `ir: &pb::Ir` (or the example name), and call it from two `#[test]` functions, e.g. in `src/codegen/c.rs`:

```rust
    fn c_backend_conformance(ir: &crate::ir::pb::Ir) {
        // ... existing body, `ir` replacing the local `eth_ipvx_l4()` ...
    }
    #[test]
    fn c_backend_conformance_full_suite() {
        c_backend_conformance(&crate::examples::eth_ipvx_l4());
    }
    #[test]
    fn c_backend_conformance_full_suite_flow_dissector() {
        c_backend_conformance(&crate::examples::linux_flow_dissector());
    }
```

Mirror the same shape for `bpf_backend_conformance_full_suite`, `generated_dissector_conformance` (lua), and `bmv2_conformance_byte_aligned_suite`. Each helper generates vectors via `crate::symex::testgen::generate(ir)` exactly as the existing bodies do (read the existing body first; keep its mechanics — temp dirs, harness commands, comparisons — identical).

- [ ] **Step 2: Run the four suites**

Run: `./dev.sh sh -c 'cargo test c_backend && cargo test bpf_backend && cargo test generated_dissector && cargo test bmv2_conformance'`
Expected: PASS. **If a backend fails on the two-instance example, that is the finding this task exists for** — fix the backend (typical suspects: name collisions keyed by header type instead of instance in C struct emission, Lua ProtoField registration, P4 header declarations), keeping the fix minimal and adding no new IR surface. Rerun until green.

- [ ] **Step 3: Run the full gate**

Run: `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint && cd py && ruff check . && pyright && pytest'`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/codegen/c.rs src/codegen/lua.rs src/oracle/bmv2.rs
git commit -m "test: backend conformance suites also run linux_flow_dissector (multi-instance)"
```

(Include any backend fixes in the same commit with a message naming what broke.)

---

### Task 6: Factory rewrite — fetch-pinned upstream `bpf_flow.c`, libbpf loader, drop-aware corpus

**Files:**
- Modify: `oracle/flow_dissector/factory/capture.sh`
- Modify: `oracle/flow_dissector/factory/capture.c` (full rewrite)
- Modify: `oracle/flow_dissector/factory/corpus.txt`
- Modify: `.devcontainer/Dockerfile` (add `libbpf-dev`)
- Modify: `.github/workflows/flow-dissector-goldens.yml` (add `libbpf-dev`; reword "in-repo dissector" comments to "pinned upstream bpf_flow.c")
- Modify: `.gitignore` (add `oracle/flow_dissector/factory/build/`)

**Interfaces:**
- Consumes: Task 2's v2 JSON shape (`disposition`, optional `keys`) — capture emits it.
- Produces: `capture.sh` end-to-end mints `examples/linux_flow_dissector/conformance/flow_keys.linux-<ver>.golden.json` from upstream `bpf_flow.c`. Task 7 runs it privileged.

- [ ] **Step 1: Establish the pin**

Fetch once on the host to compute the pin (network OK on host; this file is never committed):

```bash
curl -fsSL https://raw.githubusercontent.com/torvalds/linux/v6.8/tools/testing/selftests/bpf/progs/bpf_flow.c \
  -o /tmp/bpf_flow.c && shasum -a 256 /tmp/bpf_flow.c
```

Record the printed sha256 — it goes into `capture.sh` below. Also check for selftest-local includes: `grep '#include "' /tmp/bpf_flow.c`. Expected: none (only `<...>` system/libbpf includes). If any quoted include exists, add it to the fetch list in `capture.sh` with its own pinned sha256, same URL directory.

- [ ] **Step 2: Rewrite `capture.sh`**

```bash
#!/usr/bin/env bash
# Mint version-tagged golden flow_keys by running UPSTREAM bpf_flow.c
# (Linux v6.8 selftests, GPL-2.0 — fetched at capture time, NEVER
# committed; see the rung-1 design doc) in the kernel over corpus.txt.
# PRIVILEGED — run via:
#   ./dev-priv.sh oracle/flow_dissector/factory/capture.sh
set -euo pipefail
cd "$(dirname "$0")"

# --- pinned upstream source -------------------------------------------
KERNEL_TAG="v6.8"
BPF_FLOW_URL="https://raw.githubusercontent.com/torvalds/linux/${KERNEL_TAG}/tools/testing/selftests/bpf/progs/bpf_flow.c"
BPF_FLOW_SHA256="<sha256 from Step 1>"

mkdir -p build
if ! echo "${BPF_FLOW_SHA256}  build/bpf_flow.c" | sha256sum -c --status 2>/dev/null; then
  curl -fsSL "${BPF_FLOW_URL}" -o build/bpf_flow.c
  echo "${BPF_FLOW_SHA256}  build/bpf_flow.c" | sha256sum -c
fi

ver="$(uname -r)"
short="${ver%%-*}"
out="../../../examples/linux_flow_dissector/conformance/flow_keys.linux-${short}.golden.json"
mkdir -p "$(dirname "$out")"

# -I the multiarch dir so <asm/types.h> resolves under -target bpf (works
# on both arm64 devcontainer and x86_64 CI runners).
clang -O2 -g -target bpf -I"/usr/include/$(uname -m)-linux-gnu" \
  -c build/bpf_flow.c -o build/bpf_flow.o
cc -O2 -o build/capture capture.c -lbpf
build/capture build/bpf_flow.o corpus.txt > "$out"

echo "captured goldens from upstream bpf_flow.c@${KERNEL_TAG} on kernel ${ver} -> ${out}"
```

Substitute the real sha256. Add `oracle/flow_dissector/factory/build/` to `.gitignore`.

- [ ] **Step 3: Rewrite `capture.c` as a libbpf loader**

Full replacement:

```c
// Golden factory: load upstream bpf_flow.c (compiled ELF) with libbpf,
// populate its tail-call prog-array, and BPF_PROG_TEST_RUN the entry
// program over each corpus packet, decoding bpf_flow_keys into a
// GoldenFile v2 JSON on stdout (schema matches src/oracle/flow_dissector.rs:
// per-entry disposition "ok"/"drop", keys only when ok).
//
// Usage: capture <bpf_flow.o> <corpus.txt>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <sys/utsname.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

// BPF_OK / BPF_DROP from the flow-dissector program (linux/pkt_cls.h
// values TC_ACT_OK / TC_ACT_SHOT).
#define RET_OK 0
#define RET_DROP 2

// Upstream bpf_flow.c's jmp_table has MAX_PROG entries whose values are
// the programs named flow_dissector_<index> (the PROG() macro expands
// the IP..VLAN index macros into the symbol name).
#define MAX_PROG 6

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// hex string -> bytes; returns length, or -1 on odd-length/invalid input.
static int unhex(const char *s, unsigned char *out, int cap) {
    int n = 0;
    while (s[0] && s[0] != '\n') {
        if (!is_hex(s[0]) || !is_hex(s[1])) return -1;
        if (n >= cap) return -1;
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

static void hexcat(char *dst, const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) sprintf(dst + i * 2, "%02x", b[i]);
    dst[n * 2] = 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <bpf_flow.o> <corpus.txt>\n", argv[0]); return 2; }

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) { fprintf(stderr, "open %s failed\n", argv[1]); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load failed (need privilege?)\n"); return 1; }

    struct bpf_map *jmp = bpf_object__find_map_by_name(obj, "jmp_table");
    if (!jmp) { fprintf(stderr, "no jmp_table map — pin drift?\n"); return 1; }
    for (uint32_t i = 0; i < MAX_PROG; i++) {
        char name[32];
        snprintf(name, sizeof name, "flow_dissector_%u", i);
        struct bpf_program *p = bpf_object__find_program_by_name(obj, name);
        if (!p) { fprintf(stderr, "missing program %s — pin drift?\n", name); return 1; }
        int fd = bpf_program__fd(p);
        if (bpf_map__update_elem(jmp, &i, sizeof i, &fd, sizeof fd, BPF_ANY)) {
            fprintf(stderr, "jmp_table[%u] update failed\n", i); return 1;
        }
    }
    struct bpf_program *entry = bpf_object__find_program_by_name(obj, "_dissect");
    if (!entry) { fprintf(stderr, "missing entry program _dissect — pin drift?\n"); return 1; }
    int prog_fd = bpf_program__fd(entry);

    struct utsname un; uname(&un);
    printf("{\n  \"kernel_version\": \"%s\",\n", un.release);
    printf("  \"keys_subset\": [\"nhoff\",\"thoff\",\"n_proto\",\"addr_proto\",\"ip_proto\","
           "\"sport\",\"dport\",\"ipv4_src\",\"ipv4_dst\",\"ipv6_src\",\"ipv6_dst\"],\n");
    printf("  \"entries\": [\n");

    FILE *cf = fopen(argv[2], "r");
    if (!cf) { perror("fopen corpus"); return 1; }
    char line[8192];
    int first = 1;
    while (fgets(line, sizeof line, cf)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == 0) continue;
        unsigned char pkt[2048];
        int plen = unhex(line, pkt, sizeof pkt);
        if (plen <= 0) { fprintf(stderr, "bad corpus line\n"); return 1; }

        unsigned char out[256]; memset(out, 0, sizeof out);
        LIBBPF_OPTS(bpf_test_run_opts, topts,
            .data_in = pkt, .data_size_in = (uint32_t)plen,
            .data_out = out, .data_size_out = sizeof out,
            .repeat = 1,
        );
        if (bpf_prog_test_run_opts(prog_fd, &topts)) {
            fprintf(stderr, "TEST_RUN failed\n"); return 1;
        }
        char phex[4200]; hexcat(phex, pkt, plen);
        if (topts.retval == RET_DROP) {
            printf("%s    {\"packet_hex\": \"%s\", \"disposition\": \"drop\"}",
                   first ? "" : ",\n", phex);
            first = 0;
            continue;
        }
        if (topts.retval != RET_OK) {
            fprintf(stderr, "unexpected retval %u (not BPF_OK/BPF_DROP)\n", topts.retval);
            return 1;
        }
        struct bpf_flow_keys *k = (struct bpf_flow_keys *)out;
        char v4s[9] = "", v4d[9] = "", v6s[33] = "", v6d[33] = "";
        if (ntohs(k->n_proto) == 0x0800) {
            hexcat(v4s, (unsigned char *)&k->ipv4_src, 4);
            hexcat(v4d, (unsigned char *)&k->ipv4_dst, 4);
        } else if (ntohs(k->n_proto) == 0x86dd) {
            hexcat(v6s, (unsigned char *)k->ipv6_src, 16);
            hexcat(v6d, (unsigned char *)k->ipv6_dst, 16);
        }
        printf("%s    {\"packet_hex\": \"%s\", \"disposition\": \"ok\", \"keys\": {"
               "\"nhoff\": %u, \"thoff\": %u, \"n_proto\": %u, \"addr_proto\": %u, "
               "\"ip_proto\": %u, \"sport\": %u, \"dport\": %u, "
               "\"ipv4_src\": \"%s\", \"ipv4_dst\": \"%s\", "
               "\"ipv6_src\": \"%s\", \"ipv6_dst\": \"%s\"}}",
               first ? "" : ",\n", phex,
               k->nhoff, k->thoff, ntohs(k->n_proto), ntohs(k->addr_proto),
               k->ip_proto, ntohs(k->sport), ntohs(k->dport),
               v4s, v4d, v6s, v6d);
        first = 0;
    }
    fclose(cf);
    printf("\n  ]\n}\n");
    return 0;
}
```

- [ ] **Step 4: Extend `corpus.txt`**

Keep the four rung-0 lines FIRST and untouched (they are the cross-validation anchor), then append:

```
# --- rung 1: VLAN / MPLS (upstream bpf_flow.c semantics) ---
# accept: single 802.1Q (vid 100) + IPv4/TCP
aabbccddeeff11223344556681000064080045000028123440004006dead0a0000010a000002303901bb00000001000000005018ffff00000000
# accept: single 802.1Q (vid 100) + IPv6/UDP
aabbccddeeff1122334455668100006486dd600000000014114020010db800000000000000000000000120010db8000000000000000000000002303901bb00140001000000005018ffff00000000
# accept: 802.1AD (vid 100) + 802.1Q (vid 101) + IPv4/TCP (QinQ)
aabbccddeeff11223344556688a8006481000065080045000028123440004006dead0a0000010a000002303901bb00000001000000005018ffff00000000
# accept: MPLS unicast, one label (label 100, S=1, ttl 64) — kernel stops here
aabbccddeeff11223344556688470006414045000028123440004006dead0a0000010a000002303901bb00000001000000005018ffff00000000
# accept: 802.1Q + MPLS unicast — VLAN advances offsets, MPLS stops
aabbccddeeff1122334455668100006488470006414045000028123440004006dead0a0000010a000002303901bb00000001000000005018ffff00000000
# drop: Q-in-Q with two 0x8100 tags (kernel forbids double-Q)
aabbccddeeff1122334455668100006481000065080045000028123440004006dead0a0000010a000002303901bb00000001000000005018ffff00000000
# drop: 802.1AD tag after a 802.1Q tag
aabbccddeeff1122334455668100006488a80065080045000028123440004006dead0a0000010a000002303901bb00000001000000005018ffff00000000
# drop: 802.1AD not followed by 802.1Q (IPv4 directly)
aabbccddeeff11223344556688a80064080045000028123440004006dead0a0000010a000002303901bb00000001000000005018ffff00000000
# drop: triple tag AD+Q+Q
aabbccddeeff11223344556688a800648100006581000066080045000028123440004006dead0a0000010a000002303901bb00000001000000005018ffff00000000
# drop: unknown ethertype (ARP)
aabbccddeeff112233445566080600010800060400011122334455660a000001aabbccddeeff0a000002
```

Layout reminder: `eth(12B macs) + outer ethertype + per-tag [TCI 2B + next ethertype 2B] + payload`; the MPLS entry `label(20).tc(3).s(1).ttl(8)` = `00064140` for label 100/S=1/ttl 64. Every line must be ONE unbroken pure-hex string — the loader rejects anything else. The single-Q, QinQ, MPLS, VLAN+MPLS, and triple-tag lines are byte-identical to Task 4's projection-test packets (keep them in sync).

- [ ] **Step 5: Dockerfile + CI workflow**

In `.devcontainer/Dockerfile`, add `libbpf-dev` to the FIRST apt line (the one with `clang llvm`, line ~19). In `.github/workflows/flow-dissector-goldens.yml`: add `libbpf-dev` to its apt install; update the header comment and step names replacing "the in-repo BPF flow dissector" with "upstream bpf_flow.c (pinned, fetched at capture time)".

- [ ] **Step 6: Verify what can be verified unprivileged**

Run: `./dev.sh sh -c 'cd oracle/flow_dissector/factory && bash -n capture.sh && cc -O2 -fsyntax-only capture.c && grep -cv "^#\|^$" corpus.txt'`
Expected: exit 0; corpus line count 14. (Compiling/loading BPF needs privilege — that's Task 7.)

- [ ] **Step 7: Commit**

```bash
git add oracle/flow_dissector/factory .devcontainer/Dockerfile .github/workflows/flow-dissector-goldens.yml .gitignore
git commit -m "feat(factory): upstream bpf_flow.c (pinned fetch) via libbpf; drop-aware corpus"
```

---

### Task 7: Mint goldens, cross-validate, retire the minimal dissector, docs

**Files:**
- Regenerate: `examples/linux_flow_dissector/conformance/flow_keys.linux-6.8.0.golden.json`
- Delete: `oracle/flow_dissector/factory/flow_dissector.bpf.c`
- Modify: `src/oracle/flow_dissector.rs` (gate-test corpus-shape floors)
- Modify: `examples/linux_flow_dissector/README.md`, `dev-priv.sh` (comment only if it mentions the in-repo dissector)

**Interfaces:**
- Consumes: everything prior. This is the rung-1 definition-of-done task.

- [ ] **Step 1: Run the privileged factory**

Run (from repo root, on this machine — Colima VM, kernel 6.8.0): `./dev-priv.sh oracle/flow_dissector/factory/capture.sh`
Expected: exits 0, rewrites `examples/linux_flow_dissector/conformance/flow_keys.linux-6.8.0.golden.json`. If the BPF load fails, read the libbpf error — likely a compile-flag or pin issue; fix in the factory, not by reverting to the minimal dissector.

- [ ] **Step 2: Cross-validate rung 0 against upstream**

Run: `git diff -- examples/linux_flow_dissector/conformance/`
Expected: the four rung-0 entries keep IDENTICAL `keys` values (now wrapped with `"disposition": "ok"`); 5 new ok entries and 5 new drop entries follow. **Any changed rung-0 key value is a finding, not noise** — it means the in-repo dissector diverged from upstream; STOP and investigate before proceeding (this comparison is the promised cross-validation).

- [ ] **Step 3: Tighten the gate test**

In `committed_goldens_agree` (src/oracle/flow_dissector.rs), replace the `report.compared >= 4` assert with:

```rust
        let ok = g
            .entries
            .iter()
            .filter(|e| e.disposition == Disposition::Ok)
            .count();
        let drop = g.entries.len() - ok;
        assert!(
            ok >= 9 && drop >= 4,
            "corpus shape shrank: {ok} ok / {drop} drop entries"
        );
        assert_eq!(report.compared, g.entries.len());
```

- [ ] **Step 4: Run the full gate**

Run: `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint && cd py && ruff check . && pyright && pytest'`
Expected: PASS. `committed_goldens_agree` now proves kernel agreement over 14 vectors including 5 drops. A mismatch here is a REAL disagreement with the kernel — investigate the projection/example against spec §2; never edit the golden.

- [ ] **Step 5: Retire the minimal dissector**

```bash
git rm oracle/flow_dissector/factory/flow_dissector.bpf.c
```

Grep for stale references: `grep -rn "flow_dissector.bpf.c" --exclude-dir=.git .` — update each (README, workflow comments, dev-priv.sh comment, spec references stay historical).

- [ ] **Step 6: Update the example README**

In `examples/linux_flow_dissector/README.md`: replace the rung-0 fidelity caveat (goldens from an in-repo approximation) with the rung-1 statement: goldens are minted from **upstream `bpf_flow.c` (Linux v6.8 selftests, fetched pinned at capture time) run in the kernel via `BPF_PROG_TEST_RUN`**; agreement now covers VLAN (depth ≤ 2, kernel sequencing rules) and MPLS (single-entry stop), including agreement on kernel drops. Mention the regenerated state graph (`gen/graph.svg` already updated by Task 3).

- [ ] **Step 7: Final gate + commit**

Run the full gate once more (same command as Step 4). Expected: PASS.

```bash
git add -A
git commit -m "feat(oracle): rung 1 done — kernel goldens from upstream bpf_flow.c incl. drop agreement"
```

---

## Self-Review Notes (already applied)

- Spec §1 → Tasks 6, 7. Spec §2 → Tasks 1, 3, 4 (+5 for backend risk). Spec §3 → Tasks 6 (corpus), 7 (DoD gate, docs). Ladder amendment lives in the spec itself; memory update happens post-merge, outside this plan.
- Corpus hex strings in Task 4 tests and Task 6 corpus MUST stay identical (single-Q, QinQ, MPLS, VLAN+MPLS, triple-tag lines). Task 6 Step 4 carries an explicit fix-before-commit note for the one intentionally-flagged malformed line.
- Type names consistent: `Disposition::{Ok,Drop}`, `GoldenEntry.keys: Option<FlowKeys>` (Tasks 2, 6, 7); instance names `vlan_ad`/`vlan_q`/`mpls` (Tasks 3, 4).
