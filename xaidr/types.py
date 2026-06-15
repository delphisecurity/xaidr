"""Shared types for the xaidr SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Action(str, Enum):
    ALLOWED = "allowed"
    FLAGGED = "flagged"
    BLOCKED = "blocked"
    ESCALATED = "escalated"


class Direction(str, Enum):
    INPUT = "input"
    OUTPUT = "output"


@dataclass
class ScanResult:
    action: str
    score: float
    category: Optional[str] = None
    rules: list[str] = field(default_factory=list)
    latency_ms: int = 0

    @property
    def is_blocked(self) -> bool:
        return self.action == Action.BLOCKED.value

    @property
    def is_allowed(self) -> bool:
        return self.action == Action.ALLOWED.value


class DelphiBlockedError(Exception):
    """Raised when the Sentinel Brain returns action=blocked."""

    def __init__(self, result: ScanResult, message: Optional[str] = None):
        self.result = result
        super().__init__(
            message
            or f"Delphi blocked prompt: category={result.category} rules={result.rules}"
        )
