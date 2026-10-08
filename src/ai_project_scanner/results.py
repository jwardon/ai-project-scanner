"""Minimal generic result structures shared by scanner analyses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Evidence:
    """A single observation made during analysis, with its location."""

    kind: str
    name: str
    offset: int
    detail: Optional[str] = None


@dataclass
class ScanResult:
    """Outcome of scanning one target."""

    target: str
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors
