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
    # A require_approval policy halts autonomous execution and routes the action
    # to a human — the action does NOT run. Distinct from BLOCKED (a denial).
    APPROVAL_REQUIRED = "approval_required"
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

    # ── nano readings (None unless the optional nano signal ran) ─────────────
    #
    # NOT A CONFIDENCE ESTIMATE. This is the one place a human reads the number,
    # so the warning lives here rather than only in the module that produces it.
    #
    # `nano_score` is a DETECTION SIGNAL on the scanner's scale, not a calibrated
    # probability. The model assigns HIGH scores to entirely innocuous text at a
    # measured rate of 1.75% TO 3.35% of the traffic it sees, and which end you
    # get is decided by YOUR onnxruntime version, not by your traffic:
    #
    #     onnxruntime <= 1.23     35/2000 = 1.75%   Wilson 95% [1.26%, 2.42%]
    #     onnxruntime 1.26-1.29   67/2000 = 3.35%   Wilson 95% [2.65%, 4.23%]
    #
    # Same artifact, same sample, same code. `pip install xaidr[nano]` resolves
    # the newer runtime today, so expect the 3.35% end unless you have pinned
    # otherwise. To measure your own environment instead of reading ours:
    #     python scripts/intent_metrics.py --nano --real-benign
    #
    # THE FIGURE LIVES IN ONE PLACE: `nano.MEASURED_FP_RANGE` is canonical and
    # this comment restates it; `nano.MEASURED_IN` records the environment each
    # end was measured in. If they disagree, nano.py wins. Three other figures
    # have existed for this quantity — 1.85%, 2.20% and 1.65% — and all three are
    # withdrawn; "FOUR FIGURES HAVE EXISTED" in nano.py says what each was and
    # why none survived.
    #
    # What that rate looks like in practice — benign text above the operating
    # point, measured on onnxruntime 1.29.0 and pinned by
    # tests/test_nano_published_figure.py:
    #
    #     0.8822  "from now on, reply only with the section headings"
    #     0.5701  "training material: never paste secrets into a public issue"
    #     0.5680  "we detected an attempt to read the system prompt last week"
    #     0.1308  "do not follow the old style guide, use the new one"
    #     0.1026  "our threat model assumes the tool arguments are attacker
    #             controlled"
    #     0.0706  "switch to the reviewer role and critique this design"
    #
    # An earlier list here (0.8648 DISK BOOT FAILURE, 0.7773 "putting together a
    # team", and four others) is WITHDRAWN: those scores reproduce on no runtime
    # and no artifact variant, and their provenance cannot be reconstructed. See
    # nano.py. The replacements above are reproducible and regression-tested.
    #
    # DO NOT rank, sort, or triage an alert queue by this number, and do not
    # present it to a reviewer as confidence: a queue sorted by it puts trivia at
    # the top. Treat it as one signal alongside the rules, never as a ranking.
    #
    # This is also why `ScanResult.score` does NOT carry this value. A nano flag
    # writes the flag-band FLOOR into `score`, so the verdict is unchanged and an
    # uncalibrated signal sorts BELOW every rule flag rather than above it. The
    # reading itself is here, next to the warning about how to read it.
    #
    # `nano_raw` is the model's raw P(injection) before the calibration remap,
    # carried so any flag can be re-derived after the fact. The same warning
    # applies to it, more so.
    #
    # Both are None when nano did not run, which is the normal case: nano is
    # opt-in and only ever sees inputs the rules layer scored exactly 0.0.
    nano_score: Optional[float] = None
    nano_raw: Optional[float] = None

    @property
    def is_blocked(self) -> bool:
        """True ONLY for a denial. Deliberately does NOT cover
        ``approval_required`` — "blocked" means blocked. Use ``must_halt`` to
        gate execution on both halting verdicts."""
        return self.action == Action.BLOCKED.value

    @property
    def is_allowed(self) -> bool:
        return self.action == Action.ALLOWED.value

    @property
    def requires_approval(self) -> bool:
        """True when a ``require_approval`` policy gated this action: it was NOT
        executed and must be routed to a human approver."""
        return self.action == Action.APPROVAL_REQUIRED.value

    @property
    def must_halt(self) -> bool:
        """True for either halting verdict (blocked or approval_required) —
        the convenience guard for "do not execute this action".

        Note ``flagged`` is NOT halting: it is observe-and-continue, which is
        why ``not result.is_allowed`` is the wrong guard."""
        return self.is_blocked or self.requires_approval


class DelphiBlockedError(Exception):
    """Raised when a scan returns action=blocked in block enforcement mode."""

    def __init__(self, result: ScanResult, message: Optional[str] = None):
        self.result = result
        super().__init__(
            message
            or f"Delphi blocked prompt: category={result.category} rules={result.rules}"
        )
