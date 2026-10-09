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
class ScanResult:
    """Outcome of scanning one target."""

    target: str
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    invocations: list[Invocation] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors
