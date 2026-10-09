"""Minimal generic result structures shared by scanner analyses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Evidence:
    """A single observation made during analysis."""

    description: str
    location: str | None = None
    value: Any | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class Invocation:
    """A statically traced invocation of a callable.

    ``callable`` is a dotted name such as ``builtins.eval``. ``arguments`` holds
    the statically reconstructed argument values, preserved only as evidence, or
    ``None`` when they could not be resolved.
    """

    callable: str
    arguments: tuple[Any, ...] | None
    operation: str
    offset: int


@dataclass
class Limitation:
    """Behavior the analysis could not fully determine.

    A limitation means the result is incomplete at this point; it must not be
    read as evidence that the artifact is safe.
    """

    description: str
    offset: int | None = None


#: One analysis event. ``ScanResult.events`` keeps them in the order produced.
Event = Evidence | Invocation | Limitation


@dataclass
class ScanResult:
    """Outcome of scanning one target."""

    target: str
    events: list[Event] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def evidence(self) -> list[Evidence]:
        return [e for e in self.events if isinstance(e, Evidence)]

    @property
    def invocations(self) -> list[Invocation]:
        return [e for e in self.events if isinstance(e, Invocation)]

    @property
    def limitations(self) -> list[Limitation]:
        return [e for e in self.events if isinstance(e, Limitation)]
