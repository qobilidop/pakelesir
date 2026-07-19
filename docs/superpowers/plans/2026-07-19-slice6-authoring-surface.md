# Slice 6 "the authoring surface" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pip-installable pure-Python eDSL (`py/`) that authors Pakeles IR — Django-style header classes, operator-overloaded expressions, combinator states — emitting `ir.json` proto-equal to what the Rust builder produces.

**Architecture:** Vendored `protoc`-generated proto classes (`py/src/pakeles/_pb/`) under a thin sugar layer (~1–2k lines). No pyo3; the Rust CLI stays the validation authority (`pakeles lint`). Conformance = the eDSL re-authors `eth_ipv4_tcp` and the result is proto-equal to the committed gallery `ir.json`.

**Tech Stack:** Python ≥3.10, `protobuf` runtime, pytest, ruff, pyright (strict). Spec: `docs/superpowers/specs/2026-07-19-python-edsl-design.md`.

## Global Constraints

- The IR JSON canonical form is *what the Rust CLI emits*; Python's emitted JSON need not match byte-for-byte (new `pakeles fmt-ir` verb canonicalizes). Conformance compares **parsed protos**, not strings.
- Honest Python: metaclass field-collection via documented `__set_name__` semantics only; no tracing, no AST reading (spec non-goals).
- Python checks fail fast on the obvious (unknown state names, select key exceeding field width, duplicate field names); full validation stays Rust-side.
- Gate additionally runs, inside the dev container: `ruff check py && pyright py && pytest py` (wired into CI in Task 1).
- Branch `slice6-authoring-surface`; merge with a merge commit.

---

### Task 1: Scaffolding — package, vendored protos, CI job

**Files:**
- Create: `py/pyproject.toml`, `py/src/pakeles/__init__.py` (empty for now), `py/src/pakeles/_pb/__init__.py`
- Create: `py/src/pakeles/_pb/` vendored `*_pb2.py` (generated)
- Modify: `.devcontainer/Dockerfile` (add `python3-pip python3-venv`; a `pip install` layer for ruff/pyright/pytest/protobuf pinned)
- Modify: `.github/workflows/ci.yml` (python steps in the gate)
- Create: `py/README.md` (three-line pointer to the spec + root README)

**Steps:**

- [ ] **Step 1: `py/pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "pakeles"
version = "0.1.0"
description = "Python authoring eDSL for the Pakeles IR"
requires-python = ">=3.10"
dependencies = ["protobuf>=5"]

[tool.setuptools.packages.find]
where = ["src"]

[tool.ruff]
line-length = 88

[tool.pyright]
include = ["src", "tests"]
typeCheckingMode = "strict"
```

- [ ] **Step 2: Vendor generated protos** — run inside the container:

```sh
protoc --proto_path=proto --python_out=py/src/pakeles/_pb \
  proto/pakeles/ir/v1alpha1/ir.proto proto/pakeles/testvec/v1alpha1/testvec.proto
```

Generated files land under `py/src/pakeles/_pb/pakeles/...`; add `py/src/pakeles/_pb/__init__.py` re-exporting `ir_pb2` and `testvec_pb2` by their full paths. Commit the generated files (pip installs need no protoc); a test in Task 5 regenerates and diffs to guard drift.

- [ ] **Step 3: Dockerfile + CI** — append to `.devcontainer/Dockerfile` (separate RUN, keeps p4c layers cached):

```dockerfile
# Python authoring-surface tooling (slice 6).
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3-pip python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --break-system-packages --no-cache-dir \
      "protobuf>=5" "pytest>=8" "ruff>=0.5" "pyright>=1.1.380"
```

Extend the CI gate command with `&& ruff check py && pyright py && pytest py`.

- [ ] **Step 4: Verify** — `./dev.sh sh -c 'ruff check py && pytest py; python3 -c "from pakeles._pb import ir_pb2"'` (pytest passes trivially with no tests; the import must succeed with `PYTHONPATH=py/src`, so set `pythonpath = ["src"]` via `[tool.pytest.ini_options]` in pyproject and run pytest from `py/`).

- [ ] **Step 5: Commit** — `git add py .devcontainer/Dockerfile .github/workflows/ci.yml && git commit -m "feat(py): package scaffolding + vendored protos + CI"`

---

### Task 2: Expressions and field specs

**Files:**
- Create: `py/src/pakeles/_expr.py`, `py/src/pakeles/fmt.py`
- Test: `py/tests/test_expr.py`

**Interfaces:**
- Produces: `Expr` (tree node; `.to_pb() -> ir_pb2.Expr`), `FieldSpec` (declared by `bits`/`var_bytes`; overloads `* + - << >> & |` returning `Expr`), `fmt.DEC/HEX/BIN/IPV4/IPV6/ETHER` (enum aliases of `ir_pb2.DisplayFormat` values).
- A `FieldSpec` knows `.name` (set by the metaclass via `__set_name__`), `.header` (set when its Header class is finalized), `.width_bits` or `.byte_len_expr`.

- [ ] **Step 1: Failing tests**

```python
from pakeles._expr import FieldSpec, Expr, const
from pakeles._pb import ir_pb2

def make_field(name: str = "ihl", bits: int = 4) -> FieldSpec:
    f = FieldSpec(width_bits=bits, display_name="X")
    f.name = name
    f.header = "ipv4"
    return f

def test_field_arithmetic_builds_operator_tree() -> None:
    ihl = make_field()
    e = (ihl * 4 - 20).to_pb()
    assert e.bin.op == ir_pb2.BIN_OP_KIND_SUB
    assert e.bin.lhs.bin.op == ir_pb2.BIN_OP_KIND_MUL
    assert e.bin.lhs.bin.lhs.field.header == "ipv4"
    assert e.bin.lhs.bin.lhs.field.field == "ihl"
    assert e.bin.lhs.bin.rhs.constant == 4
    assert e.bin.rhs.constant == 20

def test_reverse_ops_and_ints() -> None:
    ihl = make_field()
    e = (4 * ihl).to_pb()
    assert e.bin.lhs.constant == 4
    assert e.bin.rhs.field.field == "ihl"
```

- [ ] **Step 2: Run** — `./dev.sh sh -c 'cd py && pytest tests/test_expr.py'` — fails (module missing).

- [ ] **Step 3: Implement `_expr.py`**

```python
"""Operator-overloaded expression trees (direct construction, PyTorch-style)."""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field

from pakeles._pb import ir_pb2

_OPS = {
    "add": ir_pb2.BIN_OP_KIND_ADD, "sub": ir_pb2.BIN_OP_KIND_SUB,
    "mul": ir_pb2.BIN_OP_KIND_MUL, "shl": ir_pb2.BIN_OP_KIND_SHL,
    "shr": ir_pb2.BIN_OP_KIND_SHR, "and": ir_pb2.BIN_OP_KIND_AND,
    "or": ir_pb2.BIN_OP_KIND_OR,
}


class _Operand:
    """Mixin: arithmetic on fields/exprs yields Expr trees."""

    def _as_expr(self) -> Expr:
        raise NotImplementedError

    def _bin(self, op: str, other: object, swap: bool = False) -> Expr:
        rhs = _coerce(other)
        lhs = self._as_expr()
        if swap:
            lhs, rhs = rhs, lhs
        return Expr(op=_OPS[op], lhs=lhs, rhs=rhs)

    def __add__(self, o: object) -> Expr: return self._bin("add", o)
    def __radd__(self, o: object) -> Expr: return self._bin("add", o, swap=True)
    def __sub__(self, o: object) -> Expr: return self._bin("sub", o)
    def __rsub__(self, o: object) -> Expr: return self._bin("sub", o, swap=True)
    def __mul__(self, o: object) -> Expr: return self._bin("mul", o)
    def __rmul__(self, o: object) -> Expr: return self._bin("mul", o, swap=True)
    def __lshift__(self, o: object) -> Expr: return self._bin("shl", o)
    def __rshift__(self, o: object) -> Expr: return self._bin("shr", o)
    def __and__(self, o: object) -> Expr: return self._bin("and", o)
    def __or__(self, o: object) -> Expr: return self._bin("or", o)


@dataclass
class Expr(_Operand):
    op: int | None = None
    lhs: Expr | None = None
    rhs: Expr | None = None
    constant: int | None = None
    ref: tuple[str, str] | None = None  # (header instance, field)

    def _as_expr(self) -> Expr:
        return self

    def to_pb(self) -> ir_pb2.Expr:
        e = ir_pb2.Expr()
        if self.constant is not None:
            e.constant = self.constant
        elif self.ref is not None:
            e.field.header, e.field.field = self.ref
        else:
            assert self.op is not None and self.lhs and self.rhs
            e.bin.op = self.op
            e.bin.lhs.CopyFrom(self.lhs.to_pb())
            e.bin.rhs.CopyFrom(self.rhs.to_pb())
        return e


def const(v: int) -> Expr:
    return Expr(constant=v)


def _coerce(v: object) -> Expr:
    if isinstance(v, int):
        return const(v)
    if isinstance(v, _Operand):
        return v._as_expr()
    raise TypeError(f"cannot use {v!r} in a field expression")


@dataclass
class FieldSpec(_Operand):
    width_bits: int | None = None
    byte_len_expr: Expr | None = None
    display_name: str = ""
    format: int = ir_pb2.DISPLAY_FORMAT_UNSPECIFIED
    doc: str = ""
    labels: dict[int, str] = dc_field(default_factory=dict)
    annotations: dict[str, str] = dc_field(default_factory=dict)
    name: str = ""    # set via __set_name__ (metaclass)
    header: str = ""  # set when the Header subclass is finalized

    def _as_expr(self) -> Expr:
        if not self.name or not self.header:
            raise RuntimeError("field used in expression before declaration completed")
        return Expr(ref=(self.header, self.name))
```

`fmt.py` aliases the `DISPLAY_FORMAT_*` values as `DEC`, `HEX`, `BIN`, `IPV4`, `IPV6`, `ETHER`.

- [ ] **Step 4: Run tests** — pass. **Step 5: `ruff check py && pyright py`** — clean. **Step 6: Commit.**

---

### Task 3: Header classes

**Files:**
- Create: `py/src/pakeles/_header.py`
- Test: `py/tests/test_header.py`

**Interfaces:**
- Produces: `Header` (base class; subclass body declares `FieldSpec`s via `bits(...)`/`var_bytes(...)`), `bits(width, display, format=DEC, *, doc="", labels=None, tshark=None) -> FieldSpec`, `var_bytes(expr) -> FieldSpec`. Class-level: `SomeHeader._fields` (ordered), `SomeHeader._name` (snake_case of class name unless `name=` kwarg in class statement), attribute access `SomeHeader.field` returns the `FieldSpec`.
- Within a class body a prior field is directly usable in expressions (its `header` is patched at class finalization; `_as_expr` defers via the spec object identity — set `header` in `__set_name__` from a class-level pending name).

Key mechanism: `__set_name__(owner, name)` fires for every FieldSpec at class creation, setting `spec.name = name` and `spec.header = owner._name`. But expressions in the class body run *before* class creation — so `FieldSpec._as_expr` must not require `header` yet. Resolution: `Expr.ref` holds the `FieldSpec` object itself, resolved to `(header, name)` lazily in `to_pb()`. Adjust `_expr.py`: `ref: FieldSpec | tuple[str, str] | None`, resolved at serialization. (This is the one subtle point of the whole eDSL; the test below pins it.)

- [ ] **Step 1: Failing test**

```python
from pakeles import Header, bits, var_bytes
from pakeles.fmt import DEC

class IPv4(Header):
    version = bits(4, "Version", DEC)
    ihl = bits(4, "Header Length", DEC, doc="in 32-bit words")
    options = var_bytes(ihl * 4 - 20)

def test_fields_collected_in_order() -> None:
    assert [f.name for f in IPv4._fields] == ["version", "ihl", "options"]
    assert IPv4._name == "ipv4"

def test_intra_class_expr_resolves_after_finalization() -> None:
    e = IPv4._fields[2].byte_len_expr.to_pb()
    assert e.bin.lhs.bin.lhs.field.header == "ipv4"
    assert e.bin.lhs.bin.lhs.field.field == "ihl"

def test_class_attribute_access_returns_spec() -> None:
    assert IPv4.ihl.width_bits == 4
```

- [ ] **Step 2: Run — fails.** **Step 3: Implement** (`__init_subclass__` collects `FieldSpec` attrs in `__dict__` order; `_name` = CamelCase→snake_case, overridable `class IPv4(Header, name="ipv4")`; lazy ref resolution per above). **Step 4: tests + ruff + pyright green.** **Step 5: Commit.**

---

### Task 4: States, parser assembly, save

**Files:**
- Create: `py/src/pakeles/_states.py`, `py/src/pakeles/_build.py`
- Modify: `py/src/pakeles/__init__.py` (public API: `Header bits var_bytes parser extract reject accept`)
- Test: `py/tests/test_parser.py`

**Interfaces:**
- Produces: `extract(HeaderClass, instance=None) -> StateChain`; `StateChain.select(key, arms, default) / .then(target) / .accept()`; `reject(reason, info=False)`; `parser(name, *, max_depth, start, states: dict[str, StateChain]) -> Parser`; `Parser.to_pb() -> ir_pb2.Ir`, `Parser.save(path)` (json via `google.protobuf.json_format.MessageToJson`), `Parser.to_json()`.
- Fast-fail checks in `parser(...)`: unknown state name referenced by any arm/then/start; select key value ≥ 2^width; duplicate field names within a header; annotations `tshark=` → `{"tshark.key": ...}`, `info=True` → `{"severity": "info"}`.

- [ ] **Step 1: Failing test** — build the three-state `eth_ipv4_tcp` automaton skeleton (single header class each) and assert: `ir.parser.states[0].transition.select.arms[0].entries[0].value == 0x0800`, unknown-state and oversized-key cases raise `ValueError` with the offending name in the message.

- [ ] **Step 2–4: Implement, tests green, ruff/pyright green.** `select(key, {6: "tcp"}, default=reject(...))`: key is a `FieldSpec` (→ `Select.keys[0]` = its FieldRef expr); arm values int or tuple-of-int for multi-key; targets: `str` (state), `accept()`, `reject(...)`.

- [ ] **Step 5: Commit.**

---

### Task 5: Conformance + `fmt-ir`

**Files:**
- Create: `py/tests/test_conformance.py`, `py/examples/eth_ipv4_tcp.py` (the full 24-field description — the spec's canonical example, adjusted to the implemented API)
- Modify: `src/cli.rs` (add `FmtIr { input: PathBuf, out: PathBuf }` verb: `from_json` → `to_json`), plus a CLI test
- Test (Rust): `fmt_ir_canonicalizes` — feed a whitespace-mangled ir.json, expect byte-identical output to `to_json` of the parsed IR

**Steps:**

- [ ] **Step 1: The conformance test**

```python
from pathlib import Path
from google.protobuf import json_format

from pakeles._pb import ir_pb2

GALLERY = Path(__file__).resolve().parents[2] / "examples/eth_ipv4_tcp/ir.json"

def test_python_authoring_matches_gallery() -> None:
    from pakeles.examples.eth_ipv4_tcp import eth_ipv4_tcp  # the py example
    ours = eth_ipv4_tcp().to_pb()
    committed = json_format.Parse(GALLERY.read_text(), ir_pb2.Ir())
    assert ours == committed  # proto equality, field for field
```

(Ship the example inside the package as `pakeles.examples.eth_ipv4_tcp` so the test needs no path games; it doubles as user documentation.)

- [ ] **Step 2: Write `eth_ipv4_tcp.py`** — port `src/examples.rs` field-for-field (all 24 fields, labels, tshark keys, docs, severity-info rejects). Iterate until proto-equal; every mismatch is a real eDSL bug or a deliberate Rust-builder default the eDSL must reproduce (e.g. empty `instance` vs explicit) — fix the eDSL, never the assertion.
- [ ] **Step 3: `fmt-ir` verb + Rust test.** **Step 4: Full gate incl. python steps.** **Step 5: Commit.**

---

### Task 6: Docs + merge

- [ ] **Step 1:** Root README: authoring section with the Python example snippet + `pip install -e py` note; py/README brief usage.
- [ ] **Step 2:** Full gate. **Step 3:** `git checkout main && git merge --no-ff slice6-authoring-surface -m "Merge slice 6: the authoring surface"` and push; watch CI.
