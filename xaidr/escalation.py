"""Escalator — the seam a second-opinion scanner plugs into (S3).

Open is a THREE-STATE local scanner and stays one: allow / flag / block, no
backend, no network. This module adds the place where a distribution that DOES
have a backend can ask for a second opinion, and nothing else. With no escalator
registered every code path here is skipped and the verdict is byte-identical to
the one open returned before this module existed.

WHERE IT RUNS, AND WHY ONLY THERE. Escalation happens after the local verdict is
computed and only when that verdict is a FLAG. The two ends of the range are
already decided: a block-band score has enough local evidence to act on, and an
allow-band score has none worth a round-trip. The flag band is the one place a
second opinion changes an outcome, so it is the only place a link is consulted.

AND NOT EVEN ALL OF THE FLAG BAND. A score that reached the flag band only
because a CAP put it there — the benign-mention and documentary-prose caps in
`scanner/local.py` — is not an uncertain verdict. It is a verdict the local
scanner is confident about and has deliberately parked below the block
threshold. Escalating those would spend a network round-trip per benign
document, which is exactly the cost the caps exist to avoid.

FAILURE IS VISIBLE, NEVER SILENT. A link that raises, or that runs past its own
`timeout_ms`, is SKIPPED and the result says so (`escalation="skipped"`,
`escalation_reason="<name>_unreachable"` / `"_timeout"`). A security control that
degrades to "no answer" and reports nothing is indistinguishable from one that
answered "fine", and that is the failure class this whole seam set exists to
prevent. The local verdict stands in both cases: escalation can only ever be an
addition to a verdict open already computed on its own.

TIMEOUTS USE A DAEMON THREAD, deliberately. `concurrent.futures` joins its
workers at interpreter exit, so a genuinely hung link would hang the HOST's
shutdown — trading a slow scan for an unkillable process. A daemon thread that
is abandoned after `timeout_ms` leaks a thread until the process ends, which is
the lesser failure and the one the operator can see.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger("xaidr.escalation")

__all__ = ["Escalator", "HealthReport", "run_escalators"]

#: Marker written to ``ScanResult.escalation`` when a link could not answer.
ESCALATION_SKIPPED = "skipped"
#: Marker written when a link answered and its verdict was taken.
ESCALATION_APPLIED = "applied"


@dataclass(frozen=True)
class HealthReport:
    """What an escalator says about itself at construction.

    ``healthy=False`` does NOT disable the link — a backend that is down when
    the agent boots may be up by the first scan, and refusing to start would
    make a transient outage into an outage of the host. It is reported so an
    operator can see a control that is not currently answering.
    """

    healthy: bool
    detail: str = ""


class Escalator:
    """A second-opinion scanner. Subclass and override :meth:`scan`.

    ``timeout_ms`` is the link's OWN budget and is enforced by the caller, not
    by the subclass — an escalator that forgets to bound its own network call
    must not be able to stall every scan in the host process.
    """

    #: Appears in logs and in ``escalation_reason``. Subclasses should set it.
    name: str = "escalator"

    #: Wall-clock budget for one :meth:`scan` call. The default is deliberately
    #: small: with ``ext_authz`` on a gateway egress route, escalation inherits
    #: the PEP's 200 ms timeout, so anything slower than this is already too
    #: slow for the path it will most often run on.
    timeout_ms: int = 200

    def scan(self, req: Any, local_result: Any) -> Optional[Any]:
        """Return a ScanResult to replace the local verdict, or None to decline.

        ``None`` means "no opinion" and the local verdict stands — the same
        Optional-means-proceed convention every other seam uses.
        """
        return None

    def health(self) -> HealthReport:
        """Called ONCE, at construction. Never on the scan path."""
        return HealthReport(healthy=True)


def _call_with_timeout(fn, timeout_ms: int):
    """Run ``fn`` in a daemon thread, giving up after ``timeout_ms``.

    Returns ``(status, value)`` where status is one of ``"ok"``, ``"timeout"``,
    ``"error"``. The thread is abandoned on timeout, not killed — Python has no
    safe way to kill a thread, and a daemon thread at least cannot hold the
    interpreter open.
    """
    box: dict = {}

    def _run():
        try:
            box["value"] = fn()
            box["status"] = "ok"
        except BaseException as exc:      # noqa: BLE001 — reported, not swallowed
            box["error"] = exc
            box["status"] = "error"

    thread = threading.Thread(target=_run, daemon=True,
                              name="xaidr-escalation")
    thread.start()
    thread.join(timeout=max(0.0, timeout_ms / 1000.0))
    if thread.is_alive():
        return "timeout", None
    status = box.get("status", "error")
    if status == "ok":
        return "ok", box.get("value")
    return "error", box.get("error")


def run_escalators(escalators, req, local_result):
    """Walk the chain; first non-None answer wins. Returns (result, escalation,
    reason) where ``result`` is ``local_result`` unless a link answered.

    Never raises. Every failure mode returns the LOCAL verdict plus a reason,
    because an escalation layer that can take down a scan is worse than no
    escalation layer.
    """
    skipped_reason = None
    for esc in escalators:
        name = getattr(esc, "name", type(esc).__name__)
        timeout_ms = getattr(esc, "timeout_ms", 200)
        status, value = _call_with_timeout(
            lambda e=esc: e.scan(req, local_result), timeout_ms
        )
        if status == "timeout":
            skipped_reason = skipped_reason or f"{name}_timeout"
            logger.error(
                "xaidr: escalator %r exceeded its %d ms budget — SKIPPED. The "
                "local verdict stands and this scan was NOT given a second "
                "opinion.", name, timeout_ms,
            )
            continue
        if status == "error":
            skipped_reason = skipped_reason or f"{name}_unreachable"
            logger.error(
                "xaidr: escalator %r raised (%s: %s) — SKIPPED. The local "
                "verdict stands and this scan was NOT given a second opinion.",
                name, type(value).__name__, value,
            )
            continue
        if value is not None:
            return value, ESCALATION_APPLIED, None
    if skipped_reason is not None:
        return local_result, ESCALATION_SKIPPED, skipped_reason
    return local_result, None, None
