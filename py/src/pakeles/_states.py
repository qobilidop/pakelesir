"""Coarse state combinators (tf.data/nom-style): one line per state.

`extract(IPv4).select(IPv4.protocol, {6: "tcp"}, default=reject(...))`
builds a state; the states dict passed to `parser()` is the state graph,
with string keys as P4-convention forward references.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field

from pakeles._expr import BoundField, FieldSpec
from pakeles._header import Header, Instance


@dataclass(frozen=True)
class Accept:
    pass


@dataclass(frozen=True)
class Reject:
    reason: str
    info: bool = False


def accept() -> Accept:
    return Accept()


def reject(reason: str, *, info: bool = False) -> Reject:
    """Explicit reject. `info=True` marks a payload boundary (unknown
    next protocol) rather than malformedness."""
    return Reject(reason=reason, info=info)


Target = str | Accept | Reject
ArmKey = int | tuple[int, ...]


def _resolve(header: type[Header] | Instance, instance: str | None) -> tuple[type[Header], str | None]:
    if isinstance(header, Instance):
        if instance is not None:
            raise ValueError("pass either Header['name'] or instance=, not both")
        return header.header_type, header.name
    return header, instance


@dataclass
class SelectSpec:
    keys: tuple[FieldSpec | BoundField, ...]
    arms: dict[ArmKey, Target]
    default: Target


@dataclass
class StateChain:
    """One state under construction: extracts plus one transition."""

    extracts: list[tuple[type[Header], str | None]] = dc_field(
        default_factory=list[tuple[type[Header], str | None]]
    )
    transition: SelectSpec | Target | None = None

    def _need_open(self) -> None:
        if self.transition is not None:
            raise ValueError("state already has a transition")

    def extract(
        self, header: type[Header] | Instance, instance: str | None = None
    ) -> StateChain:
        self._need_open()
        self.extracts.append(_resolve(header, instance))
        return self

    def select(
        self,
        key: FieldSpec | BoundField | tuple[FieldSpec | BoundField, ...],
        arms: dict[ArmKey, Target],
        *,
        default: Target,
    ) -> StateChain:
        self._need_open()
        keys = key if isinstance(key, tuple) else (key,)
        self.transition = SelectSpec(keys=keys, arms=dict(arms), default=default)
        return self

    def then(self, target: Target) -> StateChain:
        self._need_open()
        self.transition = target
        return self

    def accept(self) -> StateChain:
        return self.then(Accept())


def extract(header: type[Header] | Instance, instance: str | None = None) -> StateChain:
    return StateChain().extract(header, instance)
