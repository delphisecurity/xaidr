"""The egress attestation: Core's verdict vocabulary, the view, and its bounds.

Delphi Core reads one attestation per call. Open builds the VIEW of a call
(``extensions.EgressView``) and hands it to S14 ``attest_egress``; the overlay
turns the view into the signed header. This module holds what both sides have
to agree on, so the sensor, the overlay and the tests read one table.

Verdicts. Core's ``AttestationV1`` reads four: ``allowed``, ``flagged``,
``held`` and ``blocked``. The sensor has five actions (``xaidr.types.Action``):

    allowed            -> allowed
    flagged            -> flagged
    approval_required  -> held       (the action does not run; a human decides)
    blocked            -> blocked
    escalated          -> flagged    (the nearest verdict that lowers nothing)

Any other action maps to ``None``: that scan is not attested, and the sensor
counts the case (``Sensor._attest_unmapped``). ``None`` is never spelled as a
verdict, because an attestation Core cannot read is refused
(``SENSOR_attestation_unreadable``) while one that is absent is merely absent.

Bounds. A header value is at most 10,923 characters, Core's bound on the
attestation header; a rule list is at most 50 ids, Core's bound on attested
rules. The others are open's: at most 4 headers per extension, names matching
``^[a-z0-9-]{1,64}$``, at most 16 KiB of headers per request, at most 4 scans
on a view.

The digest. ``body_sha256`` is the unpadded base64url SHA-256 of the exact
bytes the request carries, which is the body form of Core's call digest. It is
a hash: no content crosses the seam.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Mapping, Optional

from .extensions import ScanView

__all__ = [
    "CORE_VERDICTS", "core_verdict", "scan_view", "header_items",
    "MAX_HEADER_VALUE", "MAX_HEADERS_PER_EXTENSION", "MAX_HEADER_BYTES_PER_REQUEST",
    "MAX_SCANS", "MAX_RULES",
]

#: The verdicts Core's ``AttestationV1`` accepts, in order of strictness.
CORE_VERDICTS = ("allowed", "flagged", "held", "blocked")

#: Core's bound on the attestation header value (``attestation.ts:25``).
MAX_HEADER_VALUE = 10_923
#: Core's bound on attested rule ids (``attestation.ts:26``).
MAX_RULES = 50
#: Open's bounds on what one request may carry from S14.
MAX_HEADERS_PER_EXTENSION = 4
MAX_HEADER_BYTES_PER_REQUEST = 16 * 1024
MAX_SCANS = 4

#: An S14 header name: lowercase token, at most 64 characters.
HEADER_NAME = re.compile(r"[a-z0-9-]{1,64}")

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


def _body_sha256(data: bytes) -> str:
    """Unpadded base64url SHA-256 of the exact request bytes: Core's body form."""
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def scan_view(record, final, direction: str, *, impact_class=None,
              parent_scan_id=None) -> Optional[ScanView]:
    """The ``ScanView`` for one scan bound to a request.

    ``record`` is the result as the sensor found it, taken BEFORE ``_apply_mode``
    (its ``found_action`` and ``scan_id`` are read); ``final`` is the result the
    host received (its ``action`` is ``enforced``). Returns ``None`` when either
    verdict has no Core mapping; the caller counts that.
    """
    found = core_verdict(getattr(record, "found_action", None))
    enforced = core_verdict(getattr(final, "action", None))
    if found is None or enforced is None:
        return None
    rules = tuple(str(r) for r in (getattr(record, "rules", None) or []))[:MAX_RULES]
    wire = getattr(getattr(getattr(record, "value_origin", None), "wire", None), "value", None)
    return ScanView(
        scan_id=getattr(record, "scan_id", None),
        direction=direction,
        found=found,
        enforced=enforced,
        rules=rules,
        category=getattr(record, "category", None),
        impact_class=impact_class,
        value_origin=wire if isinstance(wire, str) and wire else None,
        parent_scan_id=parent_scan_id,
    )


def header_items(extra, budget: list) -> list:
    """Validate one extension's ``attest_egress`` return and spend the request's
    byte budget. Raises ``TypeError`` or ``ValueError`` naming the shape, never a
    value. Every check a transport would refuse later is made here, so a fault
    is the extension's and never the host's."""
    if not isinstance(extra, Mapping):
        raise TypeError(f"attest_egress() returned {type(extra).__name__}, not a Mapping")
    items = list(extra.items())
    if len(items) > MAX_HEADERS_PER_EXTENSION:
        raise ValueError(
            f"attest_egress() returned {len(items)} headers; at most "
            f"{MAX_HEADERS_PER_EXTENSION} per extension")
    out = []
    total = 0
    for name, value in items:
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError(
                "attest_egress() returned a header whose name or value is not a str "
                f"({type(name).__name__}: {type(value).__name__})")
        if not HEADER_NAME.fullmatch(name):
            raise ValueError("attest_egress() returned a header name outside ^[a-z0-9-]{1,64}$")
        if not (value.isascii() and value.isprintable()) or value != value.strip():
            raise ValueError(
                "attest_egress() returned a header value outside printable ASCII, or "
                "with leading or trailing whitespace")
        if len(value) > MAX_HEADER_VALUE:
            raise ValueError(
                f"attest_egress() returned a header value longer than {MAX_HEADER_VALUE} characters")
        total += len(name) + len(value) + 4
        out.append((name, value))
    if total > budget[0]:
        raise ValueError(
            f"attest_egress() headers exceed the {MAX_HEADER_BYTES_PER_REQUEST}-byte "
            "bound for one request")
    budget[0] -= total
    return out
