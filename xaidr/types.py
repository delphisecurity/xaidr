"""Shared types for the xaidr SDK."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


def safe_content_hash(text: str) -> str:
    """Stable 16-char sha256 of ``text`` — NEVER raises on malformed unicode.

    Encodes with ``errors="surrogatepass"`` so lone/paired surrogates (e.g. a
    ``\\udcff`` that arrived from an undecodable byte) hash losslessly instead of
    raising ``UnicodeEncodeError``. This is the B1 fail-open fix: a malformed
    byte in user content must never crash a scan (a self-DoS on a security
    tool). ``surrogatepass`` only changes how surrogate code points encode —
    which under the previous strict UTF-8 path *raised* — so for every
    well-formed input the digest is byte-identical to the old
    ``sha256(text.encode()).hexdigest()[:16]``.

    Every content-hash call site (sensor prompt/output/tool/A2A hashes and the
    schema content_hash builder) MUST route through this helper; do not call
    ``.encode()`` directly on user-controlled content.
    """
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


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
    # Set to "not_scannable" when the scan received malformed/wrong-typed input
    # (the verdict stays fail-open allowed). None on all normal scans, so this is
    # fully additive and backward-compatible.
    input_status: Optional[str] = None

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
