"""SensorExtension — the one seam an enterprise package plugs into.

WHY ONE OBJECT AND NOT FIFTEEN CALLABLES. Paid behaviour that open lacks has to
attach somewhere. Fifteen separate ``on_x=`` constructor kwargs would be fifteen
independently-validated, independently-documented surfaces, and the ADV-2
failure class says what happens to a security control handed something it does
not understand: it is ignored, quietly, and the deployment believes it is
protected. So there is one object, it is validated by ``isinstance`` at
construction, and a bad one raises.

Precedent: ``Reporter`` is a Protocol; ``CircuitBreaker`` is a concrete object
checked with ``isinstance`` (``sensor.py``). We follow the second, because a
Protocol with optional methods cannot be runtime-checked and the loud-validation
rule requires a check.

THE FOUR RULES THIS MODULE ENCODES:

1. **Unregistered means unchanged.** Every hook here is a no-op returning the
   "declined" value. A sensor with no extensions must produce a byte-identical
   verdict, score and rule set to one built before this module existed. That is
   a test (``tests/test_seam_zero_movement.py``), not a promise.
2. **Validate at construction, loudly.** ``Sensor(extensions=[object()])``
   raises ``ValueError`` naming the received type.
3. **``Optional[X]`` return means proceed.** A hook returning ``None`` has
   declined and the open path continues. A value short-circuits. This is the
   convention already in ``autopatch/core.py`` and the CrewAI hooks.
4. **Fail-safe at call time, but not silently.** A fault inside a hook is
   caught, the scan proceeds on the open verdict, and the fault is logged at
   ERROR once per extension per hook per sensor. Two deliberate exceptions,
   both in ``sensor.py``: ``on_attach`` raises (a construction failure is not a
   runtime degradation), and a ``transform_verdict`` that STRENGTHENS a verdict
   raises (that is a contract violation, not an environment fault).

   THE FAULT LINE NEVER CARRIES THE EXCEPTION MESSAGE. Every hook here has been
   handed content the sensor is scanning — ``gate`` and ``transform_verdict``
   receive ``ScanRequest.text`` outright — and an exception message is routinely
   built by interpolating the value that caused the fault. The extension is
   entitled to that content; the sensor's log is not, and it ships to the host's
   pipeline like any other. What is logged is the extension name, the hook, the
   exception TYPE and the code location inside the extension
   (``xaidr.reporters.safe_fault``).

WHAT THE VIEWS DO NOT CARRY. Nothing here hands an extension the raw prompt
beyond what the hook already receives as the scan input (``ScanRequest.text``,
which the scan already has). Destinations are host-only; tool arguments and
response bodies are hashed. The enterprise reporter's ``capture_content``
default-``False`` is enterprise config, not an open seam.

Only S1 (attach), S5 (gate chain) and S6 (verdict transform) are wired today.
The remaining hooks are declared here rather than added one per PR so the public
contract stops moving: an enterprise package written against this class does not
have to re-subclass every time another seam lands.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

__all__ = [
    "SensorExtension",
    "ScanRequest",
    "ResponseView",
    "DestinationView",
    "ToolView",
]


# ── the public views ─────────────────────────────────────────────────────────
# Frozen: an extension must not be able to mutate what the sensor will act on
# next. A hook that wants to change the outcome returns a value; it does not
# edit the request in place. That is what makes the ordering in the design doc
# checkable — every effect is a return value at a named point.


@dataclass(frozen=True)
class ScanRequest:
    """What is being scanned, at whichever boundary it arrived on.

    ``direction`` is the sensor's own vocabulary and is the field an extension
    should branch on: ``"input"``, ``"output"``, ``"tool_call"``, ``"a2a"``
    (outbound) or ``"a2a_inbound"``.

    ``text`` is the scan input and is ``None`` on boundaries that do not have a
    single text body (a tool call carries ``tool_name`` plus
    ``arguments_hash`` instead). It is the ONE place raw content appears, and it
    is the content the caller already handed to ``scan()``.
    """

    agent_id: str
    direction: str
    text: Optional[str] = None
    destination: Optional[str] = None
    provider: Optional[str] = None
    tool_name: Optional[str] = None
    mcp_server: Optional[str] = None
    arguments_hash: Optional[str] = None
    enforcement_mode: str = "monitor"


@dataclass(frozen=True)
class ResponseView:
    """An egress response, for S8. Body is reached through ``json`` lazily."""

    provider: Optional[str] = None
    host: Optional[str] = None
    status: Optional[int] = None
    content_type: Optional[str] = None
    json: Any = None


@dataclass(frozen=True)
class DestinationView:
    """An egress destination, for S10/S12. HOST ONLY — never the URL or query.

    The host-only ``dest_id`` is the same value the open sensor emits. The three
    enterprise ``print`` statements that leaked full URLs do not come across;
    this is deliberately the only destination shape a seam can see.
    """

    host: Optional[str] = None
    dest_id: Optional[str] = None
    method: Optional[str] = None


@dataclass(frozen=True)
class ToolView:
    """A declared tool, for S13. Description and schema are HASHED, not carried."""

    name: str
    description_hash: Optional[str] = None
    args_schema_hash: Optional[str] = None


# ── the extension object ─────────────────────────────────────────────────────


class SensorExtension:
    """Base class. Every hook is a no-op; subclasses override what they need.

    Attach with ``Sensor(extensions=[MyExtension()])``. Order is significant and
    is the order given: the gate chain and the verdict-transform chain both walk
    it front to back.

    ``name`` appears in logs and in the protection manifest, so an operator can
    see what is installed. Subclasses should set it.
    """

    name: str = "extension"

    # ── S1 ───────────────────────────────────────────────────────────────────
    def on_attach(self, sensor: Any) -> None:
        """Called once, in order, on a fully-built sensor.

        A fault here RAISES out of the constructor. An extension that cannot
        attach has not degraded, it has failed to install, and a deployment that
        believes it installed an enterprise control it did not have is the
        failure this whole module exists to prevent.

        The sensor also logs the failure at ERROR on the way out, so a host that
        catches this exception and falls back still leaves a record. That line
        carries the extension name, the exception TYPE and the code location —
        never the exception MESSAGE, which is the same content rule every other
        hook's fault line follows (see ``Sensor._extension_failed``). The
        message reaches the CALLER, on the raised exception, where they own the
        disclosure decision.
        """

    # ── S5 ───────────────────────────────────────────────────────────────────
    def gate(self, req: "ScanRequest") -> Optional[Any]:
        """Short-circuit before detection runs. Return a ScanResult or None.

        This is the quarantine seam. A gated verdict skips telemetry enqueue,
        the breaker observation and the mode transform, exactly as an open
        circuit does — that is the "quarantine gates before the mode transform"
        invariant, and it holds by construction because a gated verdict never
        reaches ``_apply_mode``.
        """
        return None

    # ── S6 ───────────────────────────────────────────────────────────────────
    def transform_verdict(self, req: "ScanRequest", result: Any) -> Any:
        """Last look at the verdict, AFTER telemetry and the breaker have seen it.

        This is the seam for a fleet-driven mode (the Brain says this deployment
        is ``watch``). It may only move a verdict TOWARD ``allowed``: returning
        something stricter than it received raises, because a strengthening
        transform would bypass the breaker and the telemetry record of the true
        verdict. Strengthening is what ``gate`` is for.
        """
        return result

    # ── declared, not yet wired (S2, S3, S4, S7, S8, S9, S10, S11, S12, S13) ──
    def policy_conditions(self) -> Mapping[str, Any]:
        return {}

    def escalators(self) -> Sequence[Any]:
        return ()

    def before_scan(self, req: "ScanRequest") -> Optional[Any]:
        return None

    def enforcement_policy(self) -> Optional[Any]:
        return None

    def on_response(self, resp: "ResponseView") -> None:
        ...

    def subject_trust(self, agent_id: str) -> Optional[float]:
        return None

    def destination_policy(self, dest: "DestinationView") -> Optional[Any]:
        return None

    def blocked_urls(self) -> Optional[Sequence[str]]:
        return None

    def outbound_headers(self, dest: "DestinationView") -> Mapping[str, str]:
        return {}

    def on_tools_declared(self, tools: Sequence["ToolView"]) -> None:
        ...
