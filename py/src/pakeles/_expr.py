"""Operator-overloaded expression trees (direct construction, PyTorch-style).

`ihl * 4 - 20` builds an `Expr` operator tree eagerly. Field references
hold the `FieldSpec` *object* and resolve to (header, field) names lazily
at serialization: inside a Header class body the spec's name/header are
not yet assigned (the metaclass sets them at class finalization), but the
object identity is already stable.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field

from pakeles._pb import ir_pb2

_OPS: dict[str, ir_pb2.BinOpKind] = {
    "add": ir_pb2.BIN_OP_KIND_ADD,
    "sub": ir_pb2.BIN_OP_KIND_SUB,
    "mul": ir_pb2.BIN_OP_KIND_MUL,
    "shl": ir_pb2.BIN_OP_KIND_SHL,
    "shr": ir_pb2.BIN_OP_KIND_SHR,
    "and": ir_pb2.BIN_OP_KIND_AND,
    "or": ir_pb2.BIN_OP_KIND_OR,
}


class _Operand:
    """Mixin: arithmetic on fields/exprs yields Expr trees."""

    def _as_expr(self) -> Expr:
        raise NotImplementedError

    @staticmethod
    def _coerce(v: object) -> Expr:
        if isinstance(v, int):
            return const(v)
        if isinstance(v, _Operand):
            return v._as_expr()
        raise TypeError(f"cannot use {v!r} in a field expression")

    def _bin(self, op: str, other: object, swap: bool = False) -> Expr:
        rhs = _Operand._coerce(other)
        lhs = self._as_expr()
        if swap:
            lhs, rhs = rhs, lhs
        return Expr(op=_OPS[op], lhs=lhs, rhs=rhs)

    def __add__(self, o: object) -> Expr:
        return self._bin("add", o)

    def __radd__(self, o: object) -> Expr:
        return self._bin("add", o, swap=True)

    def __sub__(self, o: object) -> Expr:
        return self._bin("sub", o)

    def __rsub__(self, o: object) -> Expr:
        return self._bin("sub", o, swap=True)

    def __mul__(self, o: object) -> Expr:
        return self._bin("mul", o)

    def __rmul__(self, o: object) -> Expr:
        return self._bin("mul", o, swap=True)

    def __lshift__(self, o: object) -> Expr:
        return self._bin("shl", o)

    def __rshift__(self, o: object) -> Expr:
        return self._bin("shr", o)

    def __and__(self, o: object) -> Expr:
        return self._bin("and", o)

    def __or__(self, o: object) -> Expr:
        return self._bin("or", o)


@dataclass
class Expr(_Operand):
    op: ir_pb2.BinOpKind | None = None
    lhs: Expr | None = None
    rhs: Expr | None = None
    constant: int | None = None
    ref: FieldSpec | None = None

    def _as_expr(self) -> Expr:
        return self

    def to_pb(self) -> ir_pb2.Expr:
        e = ir_pb2.Expr()
        if self.constant is not None:
            e.constant = self.constant
        elif self.ref is not None:
            if not self.ref.name or not self.ref.header:
                raise RuntimeError(
                    "field reference used outside a finalized Header class"
                )
            e.field.header = self.ref.header
            e.field.field = self.ref.name
        else:
            assert self.op is not None and self.lhs is not None and self.rhs is not None
            e.bin.op = self.op
            e.bin.lhs.CopyFrom(self.lhs.to_pb())
            e.bin.rhs.CopyFrom(self.rhs.to_pb())
        return e


def const(v: int) -> Expr:
    if v < 0:
        raise ValueError(f"IR constants are unsigned, got {v}")
    return Expr(constant=v)


@dataclass
class FieldSpec(_Operand):
    """One declared field; created by `bits()` / `var_bytes()` in a
    Header class body. `name` and `header` are assigned by the Header
    machinery at class finalization."""

    width_bits: int | None = None
    byte_len_expr: Expr | None = None
    display_name: str = ""
    format: ir_pb2.DisplayFormat = ir_pb2.DISPLAY_FORMAT_UNSPECIFIED
    doc: str = ""
    labels: dict[int, str] = dc_field(default_factory=dict[int, str])
    annotations: dict[str, str] = dc_field(default_factory=dict[str, str])
    name: str = ""
    header: str = ""

    def _as_expr(self) -> Expr:
        return Expr(ref=self)
