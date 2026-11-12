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
import collections
import hashlib
import json
import logging
import re
import threading
import time
from typing import Mapping, Optional

from .extensions import ScanView

__all__ = [
    "CORE_VERDICTS", "core_verdict", "scan_view", "header_items", "order_scans",
    "tools_call", "ToolCallTable",
    "MAX_HEADER_VALUE", "MAX_HEADERS_PER_EXTENSION", "MAX_HEADER_BYTES_PER_REQUEST",
    "MAX_SCANS", "MAX_RULES",
]

logger = logging.getLogger(__name__)

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


#: Strictness of Core's verdicts, for ordering the scans on a view.
_SEVERITY = {"allowed": 0, "flagged": 1, "held": 2, "blocked": 3}


def order_scans(scans) -> tuple:
    """The scans of one request, strictest found first; on a tie the tool-call
    scan first. The attestation names ``scans[0]`` and never merges two."""
    return tuple(sorted(
        scans, key=lambda sc: (-_SEVERITY.get(sc.found, -1), sc.direction != "tool_call")))


def tools_call(body) -> Optional[tuple]:
    """``(name, arguments)`` when ``body`` is a JSON-RPC ``tools/call`` request,
    else None. Reads the shape only; never raises."""
    if not body:
        return None
    try:
        msg = json.loads(body)
    except Exception:
        return None
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        return None
    params = msg.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        return None
    arguments = params.get("arguments")
    return params["name"], (arguments if isinstance(arguments, dict) else {})


class ToolCallTable:
    """Pending tool-call scans, awaiting the MCP ``tools/call`` POST that
    carries them out (binding B2).

    Per sensor, behind a lock, not a ContextVar: the MCP transport sends the POST
    from its writer task, not from the task that called ``call_tool`` (measured
    on mcp 1.30.0), so nothing task-local survives from the scan to the send.

    An entry is keyed by tool name and the hash of the arguments as canonical
    JSON. ``take`` consumes the oldest matching entry once. Bounds: 256 entries
    (the oldest is evicted first, counted) and 300 s (an expired entry never
    binds, counted). When two entries match one body with differing found
    verdicts the strictest binds, and the ambiguity is logged once per tool.
    """

    CAPACITY = 256
    TTL_SECONDS = 300.0

    def __init__(self):
        self._lock = threading.Lock()
        self._entries: collections.deque = collections.deque()
        self._ambiguous_logged: set = set()
        self.evicted = 0
        self.expired = 0

    def _now(self) -> float:
        return time.monotonic()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def record(self, name: str, args_key: str, view: ScanView) -> None:
        with self._lock:
            self._entries.append((self._now(), name, args_key, view))
            while len(self._entries) > self.CAPACITY:
                self._entries.popleft()
                self.evicted += 1

    def take(self, name: str, args_key: str) -> Optional[ScanView]:
        now = self._now()
        with self._lock:
            live = collections.deque()
            matches = []
            for entry in self._entries:
                if now - entry[0] > self.TTL_SECONDS:
                    self.expired += 1
                    continue
                live.append(entry)
                if entry[1] == name and entry[2] == args_key:
                    matches.append(entry)
            self._entries = live
            if not matches:
                return None
            chosen = matches[0]
            if len({m[3].found for m in matches}) > 1:
                chosen = max(matches, key=lambda m: _SEVERITY.get(m[3].found, -1))
                if name not in self._ambiguous_logged:
                    self._ambiguous_logged.add(name)
                    logger.info(
                        "xaidr: %d pending tool-call scans match one tools/call for %r "
                        "with differing found verdicts; the strictest binds (logged once "
                        "per tool)", len(matches), name)
            self._entries.remove(chosen)
            return chosen[3]


    def discard(self, name: str, args_key: str) -> bool:
        """Drop one pending entry for a ``tools/call`` refused before it left.

        The refused request attests nothing, so which entry it drops decides only
        what the requests that DO leave can still bind: it drops the least strict
        matching entry (the oldest of those), so the strictest stays for the next
        request, as ``take`` would bind it (Q14). Expired entries are pruned as
        ``take`` prunes them. Returns whether an entry was dropped."""
        now = self._now()
        with self._lock:
            live = collections.deque()
            matches = []
            for entry in self._entries:
                if now - entry[0] > self.TTL_SECONDS:
                    self.expired += 1
                    continue
                live.append(entry)
                if entry[1] == name and entry[2] == args_key:
                    matches.append(entry)
            self._entries = live
            if not matches:
                return False
            least = min(_SEVERITY.get(m[3].found, -1) for m in matches)
            chosen = next(m for m in matches if _SEVERITY.get(m[3].found, -1) == least)
            self._entries.remove(chosen)
            return True


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
    # Value origin is attached to the result AFTER the pre-mode record is taken,
    # so it is read from the final result first.
    vo = getattr(final, "value_origin", None)
    if vo is None:
        vo = getattr(record, "value_origin", None)
    wire = getattr(getattr(vo, "wire", None), "value", None)
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
