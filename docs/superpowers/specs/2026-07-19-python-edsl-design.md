# Python eDSL: the authoring surface

**Date:** 2026-07-19
**Status:** Approved design; implementation scheduled after slice 5 (P4/BMv2).
**Amends:** `2026-07-18-pakelesir-v0-design.md` — the "Python builder" line
becomes a committed plan; the "YAML-ish 1:1 projection" option is closed the
way ONNX closed it (never needed); "never a second language" stands, resolved
as *no language at all* — an authoring library instead.

## Decision

There is no "Pakeles Lang." The answer to "should we build an authoring
language?" is: **no — a Python eDSL** built on direct construction, following
the ML world's proven pattern for declarative layers. The serialized IR stays
the one normative artifact; the Python eDSL becomes the recommended authoring
surface; the gallery pattern (committed canonical `ir.json` + generated
`doc.md`) is the exchange and review surface. A standalone DSL is explicitly
**deferred, not rejected**: revisit only on evidence of non-programmer author
demand (ONNX went eight years without needing one).

Requirements this optimizes for (decided in the 2026-07-19 session):

- Audiences, all in scope: the project owner now, outside authors later, LLM
  authors throughout — staged, no rewrite between stages.
- Optimize for authoring ergonomics and implementation simplicity.
- Strong IDE support, existing or built. (Resolved: existing — pyright.)
- Sequencing: after slice 5.

## Evidence summary

Alternatives evaluated and the load-bearing evidence. Full reasoning lives in
the session discussion; this records what decided it.

**Fresh standalone DSL** (P4/Spicy/EverParse-3d lineage). Highest ergonomic
ceiling; canonical `fmt`; data-not-code files. Cost: parser + formatter +
tree-sitter + LSP, and every grammar change churns all four. Rejected because
the ML evidence (below) shows the pattern is unnecessary for programmer
audiences, and the tooling cost was the user's primary concern.

**P4 subset + `@annotations`.** Superficially attractive because v1 already
plans a P4-subset frontend. Two findings killed it: (1) ingestion of
real-world P4 should go through `p4c` (`p4test --toJSON`), not our own
grammar, so the shared-grammar synergy evaporates; (2) display/diagnose
metadata — most of what we author — doesn't exist in P4 and would drown in
annotations. P4 stays as emission target (slice 5) and ingestion source (v1),
not authoring surface.

**Carrier format (KDL/YAML, Kaitai-style).** Free editor tooling except
inside the expression strings — the two-layer syntax problem: ~30% of a
parser description is expressions, which end up as strings with no tooling.
You build half a parser anyway, with worse leverage.

**Python eDSL (chosen).** The ML world's fifteen-year experiment on "how do
humans author things whose normative form is a serializable IR":

- Three generations of authoring surfaces: explicit graph builders
  (Theano/TF1) lost on ergonomics; eager eDSLs staging to an IR
  (PyTorch/JAX/TF2) won the field; compile-the-host-language succeeded only
  at kernel scope (Triton) and failed at general scope (TorchScript,
  deprecated).
- The exact parallel: ONNX = serializable IR, no DSL, `onnx.helper` for hand
  construction. "ir.json isn't ergonomic" is verbatim the `onnx.helper`
  complaint. ONNX's eventual authoring aid was `onnxscript` — a Python eDSL.
  No "ONNX Lang" ever emerged.
- The security lesson: the ML ecosystem splits **authoring (code)** from
  **exchange (data)** — pickle's arbitrary-code-execution disaster begat
  safetensors. Pakeles already implements this split in `examples/`
  (committed canonical `ir.json`, equality-guarded). Community sharing
  happens at the data artifact, so code-as-authoring is safe.

**Mechanism: direct construction, not tracing/AST.** The criterion that
predicts which mechanism wins in ML is **op granularity × control-flow
freedom**, not structure-vs-computation. Fine-grained ops with rich control
flow (kernels) need tracing or scoped AST compilation (Triton). Coarse-grained
ops with restricted control flow (`nn.Sequential`, `tf.data` pipelines, Beam)
are authored by direct construction — as are parsers, per the combinator
lineage (nom, construct). The Pakeles automaton is the anti-kernel on every
axis: nodes are whole-header extracts, Eth→IPv4→TCP is three states, branching
is value-match select only (the decidability ceiling), and the state graph is
user-facing product (viz, symex paths, coverage) rather than implementation
detail. Additionally, our select is deliberately impoverished; a Python
`if`-based surface would syntactically overpromise and the compiler would
become a rejection machine (the almost-Python trap at miniature scale).

## Design

### Package shape

Pure Python, no pyo3, published as `pakeles` on PyPI (reservation pending).
Two layers, Keras-style progressive disclosure:

- **Bottom:** generated proto classes for `pakeles.ir.v1alpha1` and
  `pakeles.testvec.v1alpha1`. The full IR surface is always reachable.
- **Top:** a thin declarative sugar layer (~1–2k lines — the entire eDSL).

Idioms, each with its precedent:

- **Declarative class bodies** for headers (Django/SQLAlchemy/pydantic/
  construct): attribute name = field name (no string duplication);
  declaration order via documented `__set_name__` semantics; earlier fields
  in scope for later expressions.
- **Operator overloading** for expressions (PyTorch): `ihl * 4 - 20` builds
  the operator tree eagerly; type errors at edit time.
- **Coarse combinators** for the automaton (`tf.data`/nom): one line per
  state, `extract(...).select(...)` / `.then(...)` / `.accept()` chains;
  states dict is the state graph; string keys give forward references
  (the P4 convention).
- **Honest Python**: no tracing, no AST reading, no staged control flow.
  The class-body metaclass collects fields via documented Python semantics
  (the pydantic mechanism); every line executes normally. Build-time
  metaprogramming (a `for` loop emitting fields/states) is ordinary and
  encouraged.

### Canonical example

```python
# eth_ipv4_tcp.py
from pakeles import Header, bits, var_bytes, parser, extract, reject
from pakeles.fmt import DEC, HEX, ETHER, IPV4

class Ethernet(Header):
    dst       = bits(48, "Destination", ETHER, tshark="eth.dst")
    src       = bits(48, "Source", ETHER, tshark="eth.src")
    ethertype = bits(16, "Type", HEX, tshark="eth.type",
                     labels={0x0800: "IPv4", 0x0806: "ARP",
                             0x8100: "802.1Q VLAN", 0x86DD: "IPv6"})

class IPv4(Header):
    version     = bits(4, "Version", DEC, tshark="ip.version")
    ihl         = bits(4, "Header Length", DEC, doc="in 32-bit words")
    dscp        = bits(6, "DSCP", DEC)
    ecn         = bits(2, "ECN", DEC)
    total_len   = bits(16, "Total Length", DEC, tshark="ip.len")
    id          = bits(16, "Identification", HEX)
    flags       = bits(3, "Flags", HEX)
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl         = bits(8, "Time to Live", DEC, tshark="ip.ttl")
    protocol    = bits(8, "Protocol", DEC, tshark="ip.proto",
                       labels={1: "ICMP", 6: "TCP", 17: "UDP"})
    checksum    = bits(16, "Header Checksum", HEX, tshark="ip.checksum")
    src         = bits(32, "Source Address", IPV4, tshark="ip.src")
    dst         = bits(32, "Destination Address", IPV4, tshark="ip.dst")
    options     = var_bytes(ihl * 4 - 20)

class TCP(Header):
    sport       = bits(16, "Source Port", DEC, tshark="tcp.srcport")
    dport       = bits(16, "Destination Port", DEC, tshark="tcp.dstport")
    seq         = bits(32, "Sequence Number", DEC)
    ack         = bits(32, "Acknowledgment Number", DEC)
    data_offset = bits(4,  "Data Offset", DEC, doc="in 32-bit words")
    reserved    = bits(4,  "Reserved", HEX)
    flags       = bits(8,  "Flags", HEX)
    window      = bits(16, "Window", DEC)
    checksum    = bits(16, "Checksum", HEX)
    urgent      = bits(16, "Urgent Pointer", DEC)

eth_ipv4_tcp = parser("eth_ipv4_tcp", max_depth=4, start="ethernet", states={
    "ethernet": extract(Ethernet).select(Ethernet.ethertype,
                    {0x0800: "ipv4"},
                    default=reject("unsupported ethertype", info=True)),
    "ipv4":     extract(IPv4).select(IPv4.protocol,
                    {6: "tcp"},
                    default=reject("unsupported ip protocol", info=True)),
    "tcp":      extract(TCP).accept(),
})

if __name__ == "__main__":
    eth_ipv4_tcp.save("ir.json")
```

~50 lines at full metadata fidelity, vs 165 (Rust builder) and 476
(`ir.json`). API details (positional format constants, exact combinator
names, `save` signature) are illustrative — to be refined at implementation,
guided by real examples, per the user's direction.

### Validation loop

Python does cheap fail-fast checks at construction time with tracebacks
pointing at the author's line: name resolution, bit-width sanity, select keys
fitting field width, unknown state references, field referenced before its
header is extractable. The **Rust validator remains solely authoritative**;
Python never duplicates full validation. The loop:

```
python eth_ipv4_tcp.py && pakeles lint ir.json && pakeles run ...
```

This is also the fast author→validate loop the LLM-authoring audience needs.

### JSON canonicalization (the one real technical risk)

Rust serializes via pbjson; Python via protobuf `json_format`. Both implement
proto3 JSON, but key order, whitespace, and default-field omission may
differ. **The canonical form is defined as what the Rust CLI emits.** New CLI
verb `pakeles fmt-ir` (parse + re-emit) canonicalizes any IR file; the gallery
equality guard and all CI comparisons run post-canonicalization. Cross-language
byte-equality of raw emission is a non-goal.

### Repo, CI, testing

- Monorepo: `py/` directory in this repo — schema and library version
  together.
- CI adds a Python job: ruff + pyright (strict mode — typing quality is a
  headline feature; it *is* the IDE support) + pytest.
- Load-bearing conformance test: the eDSL re-authors `eth_ipv4_tcp` and must
  produce IR **proto-equal to the committed gallery `ir.json`** — the
  equality-guard pattern extended to prove the two authoring surfaces agree.
- Python proto codegen runs in the dev container (protoc already present).
  Committed-vs-build-time generated code: decided at implementation.

### Non-goals

- **Tracing or AST compilation** — per the granularity criterion above.
  Escape-hatch ladder if authoring pressure ever grows, in order:
  (1) build-time metaprogramming (plain Python, already available);
  (2) new coarse combinators (the `region()` move, see appendix);
  (3) only if the IR ever grew kernel-like op density — which the ceiling
  principle forbids — a Triton-style scoped micro-language.
- **pyo3 bindings** — the CLI boundary (`ir.json`) suffices.
- **Standalone grammar / LSP** — deferred, not rejected; revisit on
  non-programmer author demand.
- **Replacing the Rust builder** — it stays for internal use and tests.
  Side quest (no-regret, anytime): operator overloading for the Rust
  builder's `Expr` so `f("ipv4", "ihl") * 4 - 20` works there too.

## Appendix: TLV/options — the design-guiding stress example

TCP options in the proposed surface. This example constrains the eDSL's shape
now and specifies what the IR must eventually grow; the IR extension itself is
**its own future slice** with its own spec.

```python
class OptEol(Header):
    kind = bits(8, "Kind", DEC, labels={0: "End of Option List"})

class OptNop(Header):
    kind = bits(8, "Kind", DEC, labels={1: "No-Operation"})

class OptMss(Header):
    kind   = bits(8, "Kind", DEC, labels={2: "Maximum Segment Size"})
    length = bits(8, "Length", DEC)
    value  = bits(16, "MSS Value", DEC, tshark="tcp.options.mss_val")

class OptWscale(Header):
    kind   = bits(8, "Kind", DEC, labels={3: "Window Scale"})
    length = bits(8, "Length", DEC)
    shift  = bits(8, "Shift Count", DEC, tshark="tcp.options.wscale.shift")

class OptGeneric(Header):                      # unknown TLV: skip by length
    kind   = bits(8, "Kind", DEC)
    length = bits(8, "Length", DEC)
    data   = var_bytes(length - 2)

tcp_options = region(size=TCP.data_offset * 4 - 20, start="opt", states={
    "opt": peek(8).select({
        0: extract(OptEol).then(padding()),    # EOL: rest of region is padding
        1: extract(OptNop).then("opt"),        # NOP: one byte, loop
        2: extract(OptMss).then("opt"),
        3: extract(OptWscale).then("opt"),
    }, default=extract(OptGeneric).then("opt")),
})

# wired in: "tcp": extract(TCP).then(tcp_options).accept()
```

Termination is visible in the construct: region ≤ 40 bytes (by `data_offset`
width), every arm consumes ≥ 1 byte, so ≤ 40 iterations — bounded by
construction.

IR extensions this forces (each with precedent, each under or beside the P4
ceiling):

1. **Sized regions (substreams)** — parse within a computed-length window
   until exhausted; overrun rejects. Kaitai substreams. Doubles as the
   dissector's subtree boundary.
2. **Lookahead select (`peek`)** — branch on bits before extracting.
   P4 `packet.lookahead`.
3. **Header instances (stacks)** — repeated extracts of one type need
   instance indexing in field refs, validation must-analysis, interpreter,
   all backends, and the Lua dissector's unique-key scheme. P4 header
   stacks. The deepest change.
4. **Region-derived loop bounds** — loops inside a region bounded by
   region size ÷ minimum bits per iteration; symex must exploit this
   (path counts grow; testgen cost grows; vector suite gets richer).

Notably, TLV did **not** force an imperative escape hatch: step 2 of the
ladder (a `region` combinator) absorbed it entirely.

## Sequencing

1. Slice 5 (P4 emission + BMv2 differential) — unchanged, next.
2. **Slice 6, "the authoring surface"** — this spec. Implementation plan
   written when the slice starts. Includes PyPI packaging (reservation
   pending from the going-public checklist).
3. Later, own slice: TLV IR extensions (appendix). Later, on demand:
   standalone DSL reconsideration.
