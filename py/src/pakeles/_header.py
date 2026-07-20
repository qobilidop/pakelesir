"""Declarative header classes (Django/pydantic-style).

A `Header` subclass body declares fields with `bits()` / `var_bytes()`;
the attribute name becomes the field name (no string duplication), and
declaration order is preserved via documented class-body semantics.
Earlier fields are in scope for later expressions (`ihl * 4 - 20`);
their references resolve lazily once the class is finalized.
"""

from __future__ import annotations

import re

from pakeles._expr import BoundField, Expr, FieldSpec, Operand, coerce_expr
from pakeles._pb import ir_pb2


def _snake(name: str) -> str:
    """CamelCase -> snake_case, splitting only at lower/digit->Upper
    boundaries: IPv4 -> ipv4, OptMss -> opt_mss. Acronym-adjacent names
    (TCPOption) should pass an explicit name= instead."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def bits(
    width: int,
    display: str = "",
    format: ir_pb2.DisplayFormat = ir_pb2.DISPLAY_FORMAT_UNSPECIFIED,
    *,
    doc: str = "",
    labels: dict[int, str] | None = None,
    tshark: str | None = None,
) -> FieldSpec:
    """A fixed-width field (1..64 bits, big-endian MSB-first)."""
    if not 1 <= width <= 64:
        raise ValueError(f"bits width must be 1..64, got {width}")
    spec = FieldSpec(width_bits=width, display_name=display, format=format, doc=doc)
    if labels:
        spec.labels = dict(labels)
    if tshark is not None:
        spec.annotations["tshark.key"] = tshark
    return spec


def var_bytes(length: Expr | Operand | int) -> FieldSpec:
    """An opaque byte run whose length (in bytes) is computed from
    previously extracted fields."""
    expr = coerce_expr(length)
    return FieldSpec(byte_len_expr=expr)


class Header:
    """Base class for header declarations. Subclass and declare fields:

    class IPv4(Header):                  # IR name "ipv4" (or name="...")
        version = bits(4, "Version")
        ...
    """

    _fields: list[FieldSpec] = []
    _name: str = ""

    def __init_subclass__(cls, name: str | None = None, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        cls._name = name if name is not None else _snake(cls.__name__)
        fields: list[FieldSpec] = []
        seen: set[str] = set()
        for attr, value in vars(cls).items():
            if isinstance(value, FieldSpec):
                if attr in seen:  # pragma: no cover - dict keys are unique
                    raise ValueError(f"duplicate field {attr!r}")
                seen.add(attr)
                value.name = attr
                value.header = cls._name
                fields.append(value)
        cls._fields = fields
        if not fields:
            raise ValueError(f"header {cls.__name__!r} declares no fields")

    def __init__(self) -> None:
        raise TypeError("Header classes are declarations; do not instantiate")

    def __class_getitem__(cls, name: str) -> Instance:
        """`VLAN["vlan_q"]`: a named extraction of this header type.
        The IR schema keys field references by header *instance*; the
        default instance shares the header type's name."""
        if not name:
            raise TypeError(f"instance name must be a non-empty string, got {name!r}")
        return Instance(cls, name)

    @classmethod
    def ir_name(cls) -> str:
        return cls._name

    @classmethod
    def to_pb(cls) -> ir_pb2.HeaderType:
        ht = ir_pb2.HeaderType(name=cls._name)
        for f in cls._fields:
            pf = ht.fields.add()
            pf.name = f.name
            if f.width_bits is not None:
                pf.width.bits = f.width_bits
            else:
                assert f.byte_len_expr is not None
                pf.width.byte_len.CopyFrom(f.byte_len_expr.to_pb())
            if f.display_name or f.format or f.doc or f.labels:
                pf.display.name = f.display_name
                pf.display.format = f.format
                pf.display.doc = f.doc
                for value, label in f.labels.items():
                    vl = pf.display.value_labels.add()
                    vl.value = value
                    vl.label = label
            for k, v in sorted(f.annotations.items()):
                pf.annotations[k] = v
        return ht


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
        for f in self._header._fields:  # type: ignore[attr-defined]
            if f.name == attr:
                return BoundField(spec=f, instance=self._name)
        raise AttributeError(f"{self._header.__name__} has no field {attr!r}")
