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
class ScanResult:
    """Outcome of scanning one target."""

    target: str
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors
