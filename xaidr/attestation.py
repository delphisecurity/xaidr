"""The verdict vocabulary the gateway reads, and open's mapping onto it.

Delphi Core's attestation reads four verdicts: ``allowed``, ``flagged``,
``held`` and ``blocked``. The sensor has five actions (``xaidr.types.Action``).
``core_verdict`` is the one mapping between them, so an attestation and the
tests that pin it read the same table:

    allowed            -> allowed
    flagged            -> flagged
    approval_required  -> held       (the action does not run; a human decides)
    blocked            -> blocked
    escalated          -> flagged    (the nearest verdict that lowers nothing)

Any other action maps to ``None``: that scan is not attested, and the caller
counts the case. ``None`` is never spelled as a verdict, because an attestation
Core cannot read is refused (``SENSOR_attestation_unreadable``) while one that
is absent is merely absent.
"""

from __future__ import annotations

from typing import Optional

__all__ = ["CORE_VERDICTS", "core_verdict"]

#: The verdicts Core's ``AttestationV1`` accepts, in order of strictness.
CORE_VERDICTS = ("allowed", "flagged", "held", "blocked")

_ACTION_TO_VERDICT = {
    "allowed": "allowed",
    "flagged": "flagged",
    "approval_required": "held",
    "blocked": "blocked",
    "escalated": "flagged",
}


def core_verdict(action: object) -> Optional[str]:
    """The Core verdict for one sensor action, or ``None`` when there is none."""
    if not isinstance(action, str):
        return None
    return _ACTION_TO_VERDICT.get(action)
