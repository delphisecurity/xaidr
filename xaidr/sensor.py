"""DelphiSensor — main SDK entry point.

Standalone: local L1/L2/DLP + compositional scanning with a 3-state verdict
model (allow / flag / block). No account, no backend, no network escalation.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional
from uuid import uuid4

# NOTE: httpx is an OPTIONAL dependency, imported lazily only when the HTTP-
# intercept feature is used (protect_http / ProtectedHttpClient). It is NOT
# imported at module level so the open package imports in a bare environment.
# All httpx type hints in this module are string-quoted for the same reason.

from . import local_policy as _policy
from . import provenance as _prov
from . import provenance_chain as _chain
from .authz import classify
from .authz.classifier import (
    SHELL_ARG_KEYS as _SHELL_ARG_KEYS,
    classify_command_findings as _command_findings,
    classify_sql_findings as _sql_findings,
    extract_shell_command as _extract_shell_command,
    extract_sql as _extract_sql,
)
from .circuit_breaker import (
    CIRCUIT_OPEN_CATEGORY,
    CIRCUIT_OPEN_RULE,
    CircuitBreaker,
    _CircuitRuntime,
)
from .reporters import Reporter
from .scanner.a2a_structural import A2AStructuralValidator, A2AIdTracker
from .scanner.command_parse import reconstruct as _reconstruct_command
from .scanner.dlp import (
    HIGH_CONFIDENCE_SECRET_CATEGORIES as _HIGH_CONFIDENCE_SECRETS,
    scan_dlp as _scan_dlp,
)
from .scanner.l1 import scan_l1 as _scan_l1
from .scanner.l1 import (
    L1_MAX_SCAN_CHARS as _L1_MAX_SCAN_CHARS,
    OVERSIZED_INPUT_CATEGORY as _OVERSIZED_INPUT_CATEGORY,
    OVERSIZED_INPUT_RULE as _OVERSIZED_INPUT_RULE,
    iter_scan_windows as _iter_scan_windows,
)
from .scanner.directive_context import (
    documentary_mention as _documentary_mention,
    strip_code_spans as _strip_code_spans,
)
from .scanner.local import LocalScanner
from .scanner.normalizer import TypoNormalizer
from .telemetry import SyncTelemetryQueue
from .trace_context import ParentContext
from .privilege_tiers import (
    least_privileged_tier as _least_privileged_tier,
    validate_tier as _validate_tier,
)
from .types import DelphiBlockedError, ScanResult, safe_content_hash


class _StructuralThreat:
    """A detection finding produced by the PARSE rather than by a text regex.

    Shaped like the L1 ``ThreatDetail`` the tool-argument scan already collects
    (``rule`` / ``category`` / ``score``) so it flows through the same scoring,
    blocking and telemetry path with no special-casing. The category is the
    IMPACT CLASS (``escalate``, ``evade``, …) because that is the string a
    customer's SIEM rules key on, and it names the actual fact rather than
    borrowing a neighbouring category's name.
    """

    __slots__ = ("rule", "category", "score")

    def __init__(self, rule: str, category: str, score: float):
        self.rule = rule
        self.category = category
        self.score = score

logger = logging.getLogger("xaidr.sensor")

# Marker emitted when a scan entry point receives a non-scannable input. A
# security sensor must never crash on bad input — it fails OPEN (a non-string is
# not an attack) but RECORDS the event so the caller's bug stays visible.
NOT_SCANNABLE_CATEGORY = "input_not_scannable"
NOT_SCANNABLE_RULE = "INPUT_NOT_SCANNABLE"

# Marker emitted when a scan ENTRY POINT catches an UNEXPECTED internal error
# (a scanner/normalizer/regex bug, a json.dumps failure on a pathological A2A
# envelope, ...). A security sensor embedded in a host must NEVER crash that
# host: on an unexpected fault it fails OPEN (allowed) — there is no verdict to
# preserve once detection itself has raised — but emits a DISTINCT, alertable
# telemetry event AND a WARN log so the degradation is visible, not a silent
# allow. This is the "safe result + signal" discipline (never "stop detecting":
# normal scans are untouched; this triggers only on a would-be host crash).
SCAN_ERROR_CATEGORY = "scan_error"
SCAN_ERROR_RULE = "SCAN_FAILED_OPEN"


def _resolve_provenance(
    agent_id: str,
    per_call: dict | None = None,
    tier: int | None = None,
) -> Optional[dict]:
    """Build the provenance block for one emitted event (Option-1 wiring).

    When set_origin()/origin_scope() (or a per-call principal) established an
    origin context AND no begin_flow chain is active, emit provenance.resolve()'s
    COMPLETE block — on_behalf_of + actor + the SUPPLIED correlation_id +
    principal origin_agent — instead of discarding all but on_behalf_of. When a
    begin_flow chain IS active, fall through to build_provenance so the multi-hop
    chain path is unchanged byte-for-byte. Neither present → build_provenance
    returns None as before (no fabricated provenance).
    """
    base = _prov.resolve(agent_id, per_call=per_call)
    if base is not None and not _chain.is_flow_active():
        return base
    obo = base.get("on_behalf_of") if base else None
    # `tier` records THIS agent's configured privilege tier on its own hop, so
    # the next hop downstream receives it in the x-openA2A-tiers header. It only
    # ever labels the hop this sensor is adding; it can never touch another
    # hop's claim.
    return _chain.build_provenance(agent_id, on_behalf_of=obo, tier=tier)


def _coerce_scannable(value) -> Optional[str]:
    """Return a scannable string, or None if the input is not scannable.

    str passes through; bytes/bytearray are decoded (UTF-8, replacement on bad
    bytes) so byte payloads are scanned, not rejected. Everything else (int,
    float, list, dict, None, tuple, ...) is not scannable -> None.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8", errors="replace")
        except Exception:
            return None
    return None


class DelphiSensor:
    """Standalone agent security sensor.

    Scans locally with a 3-state verdict model (allow / flag / block).
    ``enforcement_mode`` gates whether a block verdict actually blocks:
    "monitor" (default) observes only; "block" enforces. No account, no
    backend, no network required.

    Usage::

        async with Sensor(agent_id="my-agent") as sensor:
            result = sensor.scan("ignore previous instructions")
    """

    def __init__(
        self,
        agent_id: str,
        enforcement_mode: str = "monitor",
        shadow_mode: bool = False,
        dlp_enabled: bool = True,
        block_threshold: float = 0.60,
        flag_threshold: float = 0.20,
        telemetry_batch_size: int = 50,
        telemetry_flush_interval_sec: float = 5.0,
        reporter: "Reporter" = None,
        schema: str | None = None,
        policy_file: str | None = None,
        a2a_structural_enforcement: str = "flag",
        blocked_tools: list | None = None,
        blocked_urls: list | None = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        privilege_tier: int | None = None,
    ):
        if not agent_id:
            raise ValueError("agent_id is required")
        if enforcement_mode not in ("monitor", "block"):
            raise ValueError(
                f"enforcement_mode must be 'monitor' or 'block', got {enforcement_mode!r}"
            )

        # PRIVILEGE TIER (OWASP ASI03) — CONFIG-SOURCED, and only here.
        #
        # There is deliberately no setter and no property setter: a tier that
        # agent code could raise at runtime is not a control, because agent code
        # is precisely what an injected instruction gets to influence. It is read
        # from the constructor and nowhere else — never from an inbound header,
        # which carries CLAIMS about upstream hops and cannot speak for this
        # sensor.
        #
        # Validated LOUDLY per the ADV-2 precedent set by enforcement_mode above:
        # a security control handed a value it does not understand fails at
        # construction rather than defaulting quietly and then enforcing
        # something other than what the deployer wrote.
        self.privilege_tier = _validate_tier(privilege_tier)
        # Whether the deployer actually configured one. The tier itself defaults
        # to 4 so every computation has a value, but "configured as lowest" and
        # "never configured" are different operational facts, and conflating them
        # would be a guess dressed up as a claim. So the DECLARED tier — the one
        # published downstream in x-openA2A-tiers and recorded in telemetry —
        # stays None when nothing was configured, leaving an honest gap. Both
        # resolve to 4 at computation time, so this changes the audit trail and
        # never the verdict.
        self._privilege_tier_configured = privilege_tier is not None
        self._declared_tier = self.privilege_tier if privilege_tier is not None else None

        self.agent_id = agent_id
        self.shadow_mode = shadow_mode
        # shadow_mode forces observe-only — it IS monitor mode.
        self.enforcement_mode = "monitor" if shadow_mode else enforcement_mode

        self._scanner = LocalScanner(
            block_threshold=block_threshold,
            flag_threshold=flag_threshold,
            shadow_mode=shadow_mode,
            dlp_enabled=dlp_enabled,
            enforcement_mode=self.enforcement_mode,
        )
        self._scanner_mode = "local"

        # Telemetry delivery is decoupled from any backend via the Reporter seam.
        # Default to StdoutReporter so the sensor emits events with no account
        # and no backend.
        resolved_reporter = reporter
        if resolved_reporter is None:
            from .reporters import StdoutReporter
            resolved_reporter = StdoutReporter()
        # Propagate schema= to the reporter(s) — auto-created OR user-passed —
        # so Sensor(schema="openA2A", reporter=MyReporter()) actually emits the
        # requested format on the path every deployment uses. A reporter's own
        # explicit schema wins; this only fills reporters that don't have one.
        if schema is not None:
            from .reporters import apply_default_schema
            apply_default_schema(resolved_reporter, schema)
        self._telemetry = SyncTelemetryQueue(
            reporter=resolved_reporter,
            batch_size=telemetry_batch_size,
            flush_interval_sec=telemetry_flush_interval_sec,
        )
        self._closed = False

        self._blocked_tools: set[str] = set(
            str(n) for n in (blocked_tools or ())
        )
        self._blocked_urls: list[str] = [
            str(u) for u in (blocked_urls or ()) if u
        ]

        # Local YAML policy source (no backend). None if absent/malformed —
        # load_policy fails safe and logs what it loads. Auto-loads
        # ./xaidr-policy.yaml when no explicit file is given.
        self._policy = _policy.load_policy(policy_file)

        # A2A structural validation (Tier A, content-blind) + local id tracking
        # (Tier B, LOCAL ONLY — catches references to ids this sensor never
        # issued; cross-agent id correlation across agents is out of scope here).
        # Shared across scan_a2a calls so the id tracker accumulates state.
        if a2a_structural_enforcement not in ("flag", "block"):
            raise ValueError(
                "a2a_structural_enforcement must be 'flag' or 'block', got "
                f"{a2a_structural_enforcement!r}"
            )
        self._a2a_structural_enforcement = a2a_structural_enforcement
        self._a2a_validator = A2AStructuralValidator()
        self._a2a_id_tracker = A2AIdTracker()
        # A2A field extractor (lazy). scan_a2a routes content through the same
        # A2A-aware extractor the HTTP-intercept path uses, so it scans the text
        # buried in params.message.parts[].text / artifacts / metadata — NOT the
        # raw serialized JSON (which buries split attacks behind syntax and
        # false-positives on ids/keys). The extractor is pure (no client state).
        self._a2a_extractor: Optional["ProtectedHttpClient"] = None

        # Opt-in circuit breaker. None (the default) means the feature is
        # ENTIRELY off: no counters, no state, no new telemetry, and every scan
        # path behaves exactly as it did before the feature existed. A config
        # with no trigger configured is likewise inert.
        self._breaker: Optional[_CircuitRuntime] = None
        if circuit_breaker is not None:
            if not isinstance(circuit_breaker, CircuitBreaker):
                raise ValueError(
                    "circuit_breaker must be a CircuitBreaker instance, got "
                    f"{type(circuit_breaker).__name__}"
                )
            if circuit_breaker.enabled:
                self._breaker = _CircuitRuntime(
                    circuit_breaker, self.agent_id, self.enforcement_mode
                )
                self._breaker._emit_hook = self._emit_circuit_event

    # ── circuit breaker ──────────────────────────────────────────────────
    # Every method below is fail-SAFE: a fault anywhere in the breaker degrades
    # to "no breaker" rather than breaking a scan or taking the host down. That
    # is the same discipline as the rest of the sensor, applied to the one
    # feature that deliberately halts the agent.

    @property
    def circuit_state(self) -> str:
        """``"closed"`` or ``"open"``. Always ``"closed"`` with no breaker.

        Reading this is what advances an elapsed cooldown (there is no
        background thread), so it is safe to poll.
        """
        if self._breaker is None:
            return "closed"
        try:
            return self._breaker.state()
        except Exception as exc:
            logger.warning(
                "xaidr: circuit_breaker state read failed (%s: %s) — reporting closed",
                type(exc).__name__, exc,
            )
            return "closed"

    def reset_circuit(self) -> None:
        """Close the circuit immediately and clear both counters. No-op if off."""
        if self._breaker is None:
            return
        try:
            self._breaker.reset()
        except Exception as exc:
            logger.warning(
                "xaidr: circuit_breaker reset failed (%s: %s)",
                type(exc).__name__, exc,
            )

    def _emit_circuit_event(self, event: dict) -> None:
        """Emit a breaker trip/close event.

        ``type`` is ``"circuit_breaker"``, NOT ``"scan"`` — a breaker event is a
        state transition of the sensor, not a verdict on a message, and a
        consumer must be able to tell them apart.
        """
        try:
            data = {
                "eventId": uuid4().hex[:12],
                "agentId": self.agent_id,
                "enforcementMode": self.enforcement_mode,
                **event,
            }
            self._telemetry.enqueue({
                "type": "circuit_breaker",
                "agentId": self.agent_id,
                "data": data,
            })
        except Exception as exc:
            logger.warning(
                "xaidr: circuit_breaker telemetry failed (%s: %s)",
                type(exc).__name__, exc,
            )

    def _circuit_is_blocking(self) -> bool:
        """True when the circuit is open AND this mode enforces it.

        Monitor mode never returns True: the breaker still trips, still emits,
        and still fires ``on_trip``, but monitor's contract that nothing is
        blocked holds — including for the breaker.
        """
        if self._breaker is None:
            return False
        try:
            if self.enforcement_mode != "block":
                return False
            return self._breaker.state() == "open"
        except Exception as exc:
            logger.warning(
                "xaidr: circuit_breaker check failed (%s: %s) — treating as closed",
                type(exc).__name__, exc,
            )
            return False

    def _emit_circuit_open_verdict(self, direction: str, **extra) -> ScanResult:
        """The verdict returned while the circuit is open in block mode.

        Detection does NOT run — that is the point of an open circuit. Carries
        its own category/rule so an operator can tell a breaker halt from a
        content block at a glance.
        """
        result = ScanResult(
            action="blocked",
            score=1.0,
            category=CIRCUIT_OPEN_CATEGORY,
            rules=[CIRCUIT_OPEN_RULE],
            latency_ms=0,
        )
        try:
            data = {
                "scanId": uuid4().hex[:12],
                "agentId": self.agent_id,
                "action": "blocked",
                "score": 1.0,
                "category": CIRCUIT_OPEN_CATEGORY,
                "rules": [CIRCUIT_OPEN_RULE],
                "direction": direction,
                "enforcementMode": self.enforcement_mode,
                "scanTimeMs": 0,
                "promptLength": 0,
                "promptHash": None,
            }
            data.update(extra)
            self._telemetry.enqueue({
                "type": "scan",
                "agentId": self.agent_id,
                "data": data,
            })
        except Exception:
            pass
        return result

    def _breaker_observe(self, result: ScanResult) -> None:
        """Count one verdict's TRUE (pre-downgrade) action toward the breaker.

        MUST be called with the verdict BEFORE ``_apply_mode``. Two shapes count
        as a true block:

        * ``action == "blocked"`` — the tool-call and A2A paths compute a real
          block before the mode gate.
        * ``action == "flagged"`` with ``score >= block_threshold`` — on the
          scan()/scan_output() path the LocalScanner ALREADY collapsed monitor
          mode's block-worthy verdict to ``flagged`` internally, so the block is
          only recoverable from the score. This is what lets the breaker trip in
          monitor mode at all.

        ``approval_required`` is deliberately NOT counted: an approval gate is a
        pending human decision, not a denial (and its 0.6 policy severity would
        otherwise clear the default 0.60 block threshold and be miscounted).
        """
        if self._breaker is None:
            return
        try:
            action = result.action
            if action == "blocked":
                is_violation = True
            elif action == "flagged":
                is_violation = result.score >= self._scanner.block_threshold
            else:
                is_violation = False
            if is_violation:
                self._breaker.record_violation()
        except Exception as exc:
            logger.warning(
                "xaidr: circuit_breaker violation count failed (%s: %s)",
                type(exc).__name__, exc,
            )

    def _breaker_tool_tick(self) -> None:
        """Count one ``scan_tool_call`` invocation toward the rate trigger.

        Tool calls ONLY — a chatty agent making many ``scan()`` calls must not
        trip the breaker.
        """
        if self._breaker is None:
            return
        try:
            self._breaker.record_tool_call()
        except Exception as exc:
            logger.warning(
                "xaidr: circuit_breaker rate count failed (%s: %s)",
                type(exc).__name__, exc,
            )

    def _extract_a2a_content(self, body: Optional[dict], raw: Optional[str]) -> str:
        """Extract scannable text from a parsed A2A body (or raw fallback)."""
        if self._a2a_extractor is None:
            self._a2a_extractor = ProtectedHttpClient(None, self)
        return self._a2a_extractor._extract_message(
            body, None if body is not None else raw
        )

    def set_policy(self, policy: dict | None) -> bool:
        """Set the local authorization policy from a dict. Returns True if a
        valid policy was applied, False if it was malformed/cleared."""
        if policy is None:
            self._policy = None
            return False
        parsed = _policy.set_policy_dict(policy)
        self._policy = parsed
        return parsed is not None

    def _apply_mode(self, result: ScanResult) -> ScanResult:
        """In monitor mode, downgrade a halting verdict to 'flagged'.

        Both halting actions are downgraded: 'blocked' and 'approval_required'
        (the latter from a ``require_approval`` policy). Monitor mode must never
        interrupt the agent — an approval gate halts autonomous execution just as
        a block does, so leaving it un-downgraded would make monitor mode stop
        traffic. Telemetry keeps the true pre-downgrade verdict (it is emitted
        from the composed action BEFORE this gate runs); only the returned action
        is softened. The local scanner already gates on enforcement_mode; this is
        a belt-and-suspenders guard. Quarantine is never downgraded."""
        if self.enforcement_mode == "monitor" and result.action in (
            "blocked", "approval_required",
        ):
            return ScanResult(
                action="flagged",
                score=result.score,
                category=result.category,
                rules=result.rules,
                latency_ms=result.latency_ms,
            )
        return result

    def _emit_not_scannable(self, direction: str, **extra) -> ScanResult:
        """Record a non-scannable input and return a fail-open ScanResult.

        Fail OPEN (allowed, score 0) — a wrong-typed input is a caller bug, not
        an attack — but emit a telemetry event marking it so the bug is visible.
        No raw content is carried (there is none to hash)."""
        result = ScanResult(
            action="allowed",
            score=0.0,
            category=NOT_SCANNABLE_CATEGORY,
            rules=[NOT_SCANNABLE_RULE],
            latency_ms=0,
            input_status="not_scannable",
        )
        data = {
            "scanId": uuid4().hex[:12],
            "agentId": self.agent_id,
            "action": "allowed",
            "score": 0.0,
            "category": NOT_SCANNABLE_CATEGORY,
            "rules": [NOT_SCANNABLE_RULE],
            "direction": direction,
            "enforcementMode": self.enforcement_mode,
            "scanTimeMs": 0,
            "promptLength": 0,
            "promptHash": None,
        }
        data.update(extra)
        self._telemetry.enqueue({
            "type": "scan",
            "agentId": self.agent_id,
            "data": data,
        })
        return result

    def _emit_scan_error(
        self, direction: str, exc: BaseException, prompt=None, **extra
    ) -> ScanResult:
        """Fail OPEN on an unexpected internal scan error, with a visible signal.

        Returns a safe (allowed) ScanResult so an internal fault can never crash
        the host agent, and emits a DISTINCT telemetry event (``degraded: True``,
        rule ``SCAN_FAILED_OPEN``) plus a WARN log an operator can alert on. No
        raw content is carried (hash-only, and only when it can be computed).
        This method NEVER raises — the degradation signal cannot itself become a
        new failure point.

        THE LOG IS HELD TO THE SAME CONTENT RULE AS THE TELEMETRY. An exception
        MESSAGE is not a safe thing to print: it is routinely built by
        interpolating the value that caused the fault, so a scanner fault on a
        prompt containing a key can put that key in the message, and this log
        ships to the host's pipeline like any other. So the message body is never
        logged — only the exception TYPE, the code location the fault came from
        (our own module and line, not input-derived), the direction, and the scan
        id. That last one is the correlation handle: the same id is on the
        telemetry event below, so an operator who sees the WARN can find the
        event, and anyone who genuinely needs the message can catch it at their
        own logging boundary where they own the disclosure decision."""
        scan_id = uuid4().hex[:12]
        try:
            # Code location of the fault, from OUR traceback: diagnostic and
            # never attacker-controlled. Best-effort; absent on a raised-without-
            # traceback exception.
            origin = "unknown"
            tb = getattr(exc, "__traceback__", None)
            while tb is not None:
                frame = tb.tb_frame
                origin = f"{frame.f_globals.get('__name__', '?')}:{tb.tb_lineno}"
                tb = tb.tb_next
            logger.warning(
                "xaidr: scan failed open on %s (%s at %s) scan_id=%s "
                "[message suppressed: may contain scanned content]",
                direction, type(exc).__name__, origin, scan_id,
            )
        except Exception:
            pass
        result = ScanResult(
            action="allowed",
            score=0.0,
            category=SCAN_ERROR_CATEGORY,
            rules=[SCAN_ERROR_RULE],
            latency_ms=0,
            input_status="scan_error",
        )
        try:
            phash = safe_content_hash(prompt) if isinstance(prompt, str) else None
            plen = len(prompt) if isinstance(prompt, str) else 0
            data = {
                # Same id as the WARN above, so the log line and this event are
                # correlatable. They were independently generated before, which
                # left an operator no way to join them.
                "scanId": scan_id,
                "agentId": self.agent_id,
                "action": "allowed",
                "score": 0.0,
                "category": SCAN_ERROR_CATEGORY,
                "rules": [SCAN_ERROR_RULE],
                "direction": direction,
                "enforcementMode": self.enforcement_mode,
                "scanTimeMs": 0,
                "promptLength": plen,
                "promptHash": phash,
                "degraded": True,
                "errorType": type(exc).__name__,
            }
            data.update(extra)
            self._telemetry.enqueue(
                {"type": "scan", "agentId": self.agent_id, "data": data}
            )
        except Exception:
            pass
        return result

    def scan(
        self,
        prompt: str,
        direction: str = "input",
        destination: Optional[str] = None,
        provider: Optional[str] = None,
        origin_context: dict | None = None,
        parent_context: Optional[ParentContext] = None,
    ) -> ScanResult:
        """Synchronous scan — used by LangChain middleware and direct calls.

        Wrapped so an UNEXPECTED internal fault fails OPEN with a signal (see
        ``_emit_scan_error``) instead of raising into the host. ``DelphiBlockedError``
        (intentional control flow) is re-raised. Normal verdicts are unchanged.

        With an OPEN circuit breaker in block mode this returns the
        ``CIRCUIT_BREAKER_OPEN`` verdict without running detection.
        """
        if self._circuit_is_blocking():
            return self._emit_circuit_open_verdict(
                direction,
                destinationType="external_api",
                destinationIdentifier=destination or provider or "llm",
            )
        try:
            return self._scan_impl(
                prompt, direction, destination, provider, origin_context, parent_context
            )
        except DelphiBlockedError:
            raise
        except Exception as exc:
            return self._emit_scan_error(
                direction, exc, prompt,
                destinationType="external_api",
                destinationIdentifier=destination or provider or "llm",
            )

    def _scan_impl(
        self,
        prompt: str,
        direction: str = "input",
        destination: Optional[str] = None,
        provider: Optional[str] = None,
        origin_context: dict | None = None,
        parent_context: Optional[ParentContext] = None,
    ) -> ScanResult:
        """Core scan implementation — see ``scan`` for the fail-open wrapper.

        For agent→LLM (input/output) calls, ``destination``/``provider`` label
        the LLM endpoint (e.g. "anthropic") so a downstream topology view can
        draw an agent→LLM edge. If neither is given, the edge falls back to a
        generic "llm" node.

        ``origin_context`` is a per-call provenance override (OBO principal,
        actor, correlation id); it beats any context set via ``set_origin``.

        ``parent_context`` is an OPTIONAL, read-only W3C Trace Context parent
        (resolved by the host — inbound ``traceparent`` or an active OTel span).
        It is attached to telemetry as additive metadata ONLY; it never changes
        the verdict. Absent, behavior is byte-identical.
        """
        # Crash guard: coerce to a scannable string (bytes are decoded+scanned);
        # non-scannable types (None, int, list, dict, ...) fail open gracefully.
        prompt = _coerce_scannable(prompt)
        if prompt is None:
            return self._emit_not_scannable(
                direction=direction,
                destinationType="external_api",
                destinationIdentifier=destination or provider or "llm",
            )

        # resolve the app-supplied principal (3b semantics: per-call > set context)
        prov = _resolve_provenance(
            self.agent_id, per_call=origin_context, tier=self._declared_tier
        )

        result = self._scanner.scan(
            prompt=prompt,
            agent_id=self.agent_id,
            direction=direction,
        )

        data = {
            "scanId": uuid4().hex[:12],
            "agentId": self.agent_id,
            "action": result.action,
            "score": result.score,
            "category": result.category,
            "rules": result.rules,
            "direction": direction,
            "destinationType": "external_api",
            "destinationIdentifier": destination or provider or "llm",
            "enforcementMode": self.enforcement_mode,
            "scanTimeMs": result.latency_ms,
            "promptLength": len(prompt),
            "promptHash": safe_content_hash(prompt),
        }
        if prov:
            data["provenance"] = prov
        if parent_context is not None:
            data["traceParent"] = parent_context.as_metadata()
        self._telemetry.enqueue({
            "type": "scan",
            "agentId": self.agent_id,
            "data": data,
        })

        # Breaker sees the TRUE verdict — before _apply_mode softens it.
        self._breaker_observe(result)
        return self._apply_mode(result)

    def scan_output(
        self,
        response: str,
        destination: Optional[str] = None,
        provider: Optional[str] = None,
        origin_context: dict | None = None,
    ) -> ScanResult:
        """Scan LLM output for DLP/secrets."""
        return self.scan(
            response,
            direction="output",
            destination=destination,
            provider=provider,
            origin_context=origin_context,
        )

    def scan_a2a(
        self,
        message: str,
        destination: str,
        origin_context: dict | None = None,
        parent_context: Optional[ParentContext] = None,
        received: bool = False,
    ) -> ScanResult:
        """Scan an A2A delegation message (fail-open wrapper).

        An unexpected internal fault — e.g. ``json.dumps`` raising on a circular
        or pathologically deep envelope — fails OPEN with a signal instead of
        raising into the host. See ``_scan_a2a_impl`` for the logic.

        ``received=True`` marks this as a message this agent RECEIVED (inbound
        flow) rather than one it is SENDING (outbound, the default), so telemetry
        records the correct interaction direction. It is a labelling-only flag —
        the detection/verdict is identical either way.
        """
        emit_direction = "a2a_inbound" if received else "a2a"
        if self._circuit_is_blocking():
            return self._emit_circuit_open_verdict(
                emit_direction, destinationAgent=destination,
            )
        try:
            return self._scan_a2a_impl(
                message, destination, origin_context, parent_context, received
            )
        except DelphiBlockedError:
            raise
        except Exception as exc:
            return self._emit_scan_error(
                emit_direction, exc,
                prompt=message if isinstance(message, str) else None,
                destinationAgent=destination,
            )

    def _scan_a2a_impl(
        self,
        message: str,
        destination: str,
        origin_context: dict | None = None,
        parent_context: Optional[ParentContext] = None,
        received: bool = False,
    ) -> ScanResult:
        """Core A2A scan implementation — see ``scan_a2a`` for the wrapper.

        ``message`` may be a JSON string, bytes, or a dict A2A envelope. Content
        is scanned via the A2A-aware field extractor (params.message.parts[].text,
        artifacts, metadata, with id/envelope noise filtered) — NOT the raw
        serialized JSON. The parsed dict is also used for structural validation.
        Other types fail open gracefully.

        ``received`` only labels the emitted telemetry direction (inbound for a
        received message, outbound for a sent one); the scanner is always invoked
        with the internal ``"a2a"`` direction, so detection is unchanged.

        ``parent_context`` is an OPTIONAL, read-only W3C Trace Context parent
        (host-resolved: inbound ``traceparent`` or an active OTel span). It is
        attached to telemetry as additive metadata ONLY — it does NOT alter the
        A2A extraction, the structural/id checks, or the verdict. Absent, the
        result is byte-identical to before.
        """
        # Telemetry-only flow label; the scanner direction stays "a2a".
        emit_direction = "a2a_inbound" if received else "a2a"
        # PRIVILEGE TIERS: a RECEIVED A2A message is, by definition, work that
        # arrived from another agent. Marking the context here is one half of the
        # delegation discriminator (extract_context is the other), and it is what
        # makes header STRIPPING lose: an attacker who removes x-openA2A-chain
        # still cannot make an inbound message look like the agent's own local
        # work, so the unidentified upstream resolves to tier 4 rather than
        # vanishing. Flag-only — it never touches detection or the verdict here.
        if received:
            _chain.mark_inbound()
        # Crash guard. A dict envelope / JSON string is parsed so we can extract
        # the A2A text fields and validate structure. bytes are decoded.
        body_obj = message if isinstance(message, dict) else None
        if body_obj is not None:
            scan_message = json.dumps(message)
        else:
            scan_message = _coerce_scannable(message)
        if scan_message is None:
            return self._emit_not_scannable(
                direction=emit_direction,
                destinationAgent=destination,
            )

        # Parse the body once (reused for both content extraction and the
        # structural validators below).
        if body_obj is not None:
            body = body_obj
        else:
            try:
                parsed = json.loads(scan_message)
                body = parsed if isinstance(parsed, dict) else None
            except Exception:
                # Widened from (ValueError, TypeError) so a runtime whose
                # json.loads raises RecursionError (or other) at depth can't
                # break the "never raises" contract. Non-dict / unparseable ->
                # body=None (scanned as raw text). BaseException still propagates.
                body = None

        # Content to scan = text EXTRACTED from the A2A fields, not the raw JSON.
        # This catches attacks split across parts (the extractor concatenates
        # field text) and avoids false positives on ids/keys/JSON syntax. Falls
        # back to the raw message when there is no JSON body (already-extracted
        # text from the HTTP path, or a plain string).
        content_to_scan = self._extract_a2a_content(body, scan_message)
        if not content_to_scan:
            content_to_scan = scan_message

        # resolve the app-supplied principal (3b semantics: per-call > set context)
        prov = _resolve_provenance(
            self.agent_id, per_call=origin_context, tier=self._declared_tier
        )

        result = self._scanner.scan(
            prompt=content_to_scan,
            agent_id=self.agent_id,
            direction="a2a",
        )

        # ---- A2A structural (Tier A) + local id tracking (Tier B) -----------
        # Content-blind, flag-level signals fused into the content verdict by
        # MAX (they can only RAISE the score). Structural confidences cap at
        # ~0.45 < the block threshold, so they flag but never hard-block on
        # their own — unless a2a_structural_enforcement is explicitly "block",
        # which is decoupled from the main enforcement_mode.
        score = result.score
        action = result.action
        category = result.category
        rules = list(result.rules)

        # `body` was parsed once at the top (reused here for structural checks).
        if isinstance(body, dict):
            sv = self._a2a_validator.validate(body, "a2a")      # Tier A
            idv = self._a2a_id_tracker.check_outbound(body)     # Tier B (local)
            struct_score = max(sv["score"], idv["score"])
            structural_signals = sv["signals"] + idv["signals"]
            if structural_signals:
                rules = rules + structural_signals
                if struct_score > score:
                    score = struct_score
                # Re-derive the action from the fused score. Structural/id hits
                # are flag-level: lift an "allowed" to "flagged" when over the
                # flag threshold; never downgrade a stricter content verdict.
                if action == "allowed" and score >= self._scanner.flag_threshold:
                    action = "flagged"
                # Explicit opt-in: only when structural enforcement is "block"
                # does a structural/id finding escalate to a hard block.
                if self._a2a_structural_enforcement == "block":
                    action = "blocked"

        result = ScanResult(
            action=action,
            score=round(score, 3),
            category=category,
            rules=rules,
            latency_ms=result.latency_ms,
        )

        data = {
            "scanId": uuid4().hex[:12],
            "agentId": self.agent_id,
            "action": result.action,
            "score": result.score,
            "category": result.category,
            "rules": result.rules,
            "direction": emit_direction,
            "destinationAgent": destination,
            "enforcementMode": self.enforcement_mode,
            "scanTimeMs": result.latency_ms,
            "promptLength": len(scan_message),
            "promptHash": safe_content_hash(scan_message),
        }
        if prov:
            data["provenance"] = prov
        if parent_context is not None:
            data["traceParent"] = parent_context.as_metadata()
        self._telemetry.enqueue({
            "type": "scan",
            "agentId": self.agent_id,
            "data": data,
        })
        # Breaker sees the TRUE verdict — before _apply_mode softens it.
        self._breaker_observe(result)
        return self._apply_mode(result)

    def _arg_normalizer(self) -> TypoNormalizer:
        """The unicode/typo normalizer used for tool-argument content scanning.

        Reuses the LocalScanner's normalizer (the SAME Port-1 normalizer the
        scan() path applies) so obfuscated tool args are folded identically to
        prompt content; builds one lazily as a fallback. Cached after first use.
        """
        n = getattr(self, "_tool_arg_norm", None)
        if n is None:
            n = getattr(self._scanner, "_normalizer", None) or TypoNormalizer()
            self._tool_arg_norm = n
        return n

    def scan_tool_call(
        self,
        tool_name: str,
        arguments: dict | None = None,
        mcp_server: Optional[str] = None,
        origin_context: dict | None = None,
        server_name: Optional[str] = None,
    ) -> ScanResult:
        """Scan a tool call (fail-open wrapper).

        An unexpected internal fault (classifier/authz/policy/L1 bug) fails OPEN
        with a signal instead of raising into the host. See ``_scan_tool_call_impl``.

        This is the ONLY entry point that feeds the breaker's rate trigger. The
        tick happens after the open-circuit check, so calls rejected by an open
        circuit do not keep re-counting.
        """
        if self._circuit_is_blocking():
            return self._emit_circuit_open_verdict(
                "tool_call",
                toolName=tool_name if isinstance(tool_name, str) else None,
                destinationType="mcp_server" if (mcp_server or server_name) else "tool_call",
                destinationIdentifier=mcp_server or server_name,
            )
        self._breaker_tool_tick()
        try:
            return self._scan_tool_call_impl(
                tool_name, arguments, mcp_server, origin_context, server_name
            )
        except DelphiBlockedError:
            raise
        except Exception as exc:
            return self._emit_scan_error(
                "tool_call", exc,
                prompt=tool_name if isinstance(tool_name, str) else None,
                toolName=tool_name if isinstance(tool_name, str) else None,
                destinationIdentifier=mcp_server or server_name,
            )

    def _least_privileged_tier(self) -> int:
        """The privilege ceiling for the action about to be taken.

        Numeric MAX across this sensor's own configured tier and every OTHER hop
        in the delegation chain (1 = highest privilege, 4 = lowest), so a
        low-privilege caller cannot borrow a high-privilege callee's authority —
        the ASI03 shape.

        The absence semantics are the load-bearing part and live in
        ``provenance_chain.is_delegated``: when nothing was delegated, only this
        agent's OWN tier applies, so an un-instrumented tier-1 agent doing its
        own work is NOT gated by a phantom unknown upstream. When something WAS
        delegated but arrived without provenance — including the
        header-stripping case — the unidentified upstream counts as tier 4.
        """
        if not _chain.is_delegated(self.agent_id):
            return self.privilege_tier
        upstream = _chain.delegating_hop_tiers(self.agent_id)
        if not upstream and not _chain.has_upstream_hop(self.agent_id):
            # Delegated, and NOT ONE upstream hop is even named. Something sent
            # this work and left no trace of what it was — which is precisely
            # what stripping x-openA2A-chain produces. Falling back to this
            # agent's own tier here would make removing the header a clean
            # BYPASS: the attacker's hop would simply cease to exist and a
            # tier-1 callee would compute 1. So the unidentified upstream is
            # materialised as a single unknown hop, which resolves to tier 4.
            # Stripping therefore costs the attacker the gate instead of opening
            # it.
            #
            # The has_upstream_hop() guard is what keeps this from also firing on
            # a well-provenanced human-originated flow: chain
            # [alice:principal, self:agent] yields an empty TIER list (humans are
            # not tiered) but does name an upstream hop, so it is not a stripped
            # chain and must not be treated as one. Without that distinction
            # every flow that names its principal — the documented way to start
            # one — would gate its own work.
            upstream = [None]
        return _least_privileged_tier(self.privilege_tier, upstream)

    def _prose_mention_arg(self, arguments: dict | None, raw_text: str) -> bool:
        """True when a tool argument is benign DOCUMENTARY PROSE that merely quotes
        a dangerous command, so the tool-arg scan should FLAG it rather than BLOCK.

        Three conditions, all required — the first is specific to this path:

        * NO shell-argument key. ``run_command(command=…)``, ``exec(script=…)``,
          ``sh(args=[…])`` are execution requests, and a command reaching a tool
          arrives there as a bare string, never as markdown-quoted prose. Gating on
          the key puts the whole attack corpus and every prefixed-attack probe
          structurally out of reach of this cap.
        * documentary_mention: the command sits inside a code span and a
          documentary frame cue sits in the prose OUTSIDE it.
        * the prose residue (code spans removed) carries no hard-category signal —
          so a live command outside the quotes still blocks, whatever the framing.

        ``raw_text`` is the PRE-normalization arg text: the typo normalizer folds a
        backtick that directly precedes a keyword, which unbalances the code span.
        The residue is normalized before it is scanned, so obfuscation outside the
        quotes is still caught.
        """
        for key in (arguments or {}):
            if str(key).lower() in _SHELL_ARG_KEYS:
                return False
        if not _documentary_mention(raw_text):
            return False
        residue = self._arg_normalizer().normalize(_strip_code_spans(raw_text))
        return not any(
            t.category in ("code_execution", "excessive_agency", "prompt_injection",
                           "credential_access")
            for t in _scan_l1(residue[:_L1_MAX_SCAN_CHARS]).threats
        )

    def _scan_tool_call_impl(
        self,
        tool_name: str,
        arguments: dict | None = None,
        mcp_server: Optional[str] = None,
        origin_context: dict | None = None,
        server_name: Optional[str] = None,
    ) -> ScanResult:
        """Core tool-call scan implementation — see ``scan_tool_call`` for wrapper.

        Use this for any non-LangChain integration (manual wrappers, custom
        frameworks). Enforces the same blocked_tools + local YAML policy + tool-
        argument content scan that protect_tools() applies, and emits telemetry
        so the dashboard records the verdict. Honors enforcement mode (monitor
        downgrades block->flag).

        Pass ``mcp_server`` (alias ``server_name``) to attribute the call to an
        MCP server (a downstream topology view then draws an agent→MCP edge
        instead of a generic tool edge).
        """
        mcp_server = mcp_server or server_name

        # Crash guard: tool_name must be a string (it is hashed + matched against
        # the blocked-tools list). A wrong-typed name is a caller bug — fail open
        # gracefully rather than crash on tool_name.encode()/membership.
        tool_name = _coerce_scannable(tool_name)
        if tool_name is None:
            return self._emit_not_scannable(
                direction="tool_call",
                destinationType="mcp_server" if mcp_server else "tool_call",
                destinationIdentifier=mcp_server,
                mcpServer=mcp_server,
            )

        action = "allowed"
        score = 0.0
        category: Optional[str] = None
        rules: list[str] = []

        # Impact classification — feeds the local YAML policy overlay below (which
        # is the open authorization mechanism). classify() never raises.
        impact_class, impact_tier = classify(tool_name, arguments, mcp_server)

        # Blocked-tools list (the explicit operator denylist).
        if tool_name in self._blocked_tools:
            action, score, category, rules = "blocked", 1.0, "blocked_tool", ["TOOL_BLOCKED"]

        # Content scan of the tool name + string args for dangerous command /
        # code-execution patterns (ASI02/ASI05). Even with NO policy configured,
        # the sensor must not stay silent on e.g. shell_exec("rm -rf /") or
        # eval("__import__('os').system(...)") — it raises at least a FLAG. Policy
        # (below) remains the BLOCK layer; this only ADDS a signal, never lowers.
        if action == "allowed":
            arg_text = " ".join(
                str(v) for v in (arguments or {}).values() if v is not None
            )
            # Route the tool name + attacker-controlled arg content through the
            # SAME Port-1 unicode normalizer the scan() path uses BEFORE L1, so a
            # zero-width / homoglyph-obfuscated command or injection in an arg
            # value ("ignore all previous instructions", homoglyph "rm -rf") is
            # folded to its canonical form and caught — closing the §11 gap where
            # the arg path ran raw L1 with no normalizer. Additive: the normalizer
            # only folds obfuscation, so benign args are unchanged (its partial
            # folding is keyword-gated and never spells a keyword on benign text).
            normalized_args = self._arg_normalizer().normalize(f"{tool_name} {arg_text}")
            # Over-length tool args have the SAME truncation bypass as scan(): an
            # attacker pads an arg past L1_MAX_SCAN_CHARS to hide a payload after
            # the cap. Scan the full arg text in bounded overlapping windows (same
            # helper, same total budget as scan()), so a payload past the cap is
            # reached; and flag over-length so it is never a silent pass.
            _arg_scan_start = time.perf_counter()
            danger = []
            for _idx, _win in _iter_scan_windows(normalized_args, _arg_scan_start):
                danger.extend(
                    t for t in _scan_l1(_win).threats
                    if t.category in (
                        "code_execution", "excessive_agency", "prompt_injection",
                        "credential_access", "data_exfiltration",
                    )
                )
            # STRUCTURAL RE-SCAN. Everything above regexed the argument STRING, so
            # it matches famous spellings rather than behaviour: `rm -rf /` blocks
            # and `r''m -r''f /` — the same command, quote-split — scores nothing.
            # The parser already collapses that (shlex resolves `e''nv` to `env`),
            # but only CLASSIFICATION used the parse. Scanning the parser's
            # canonical reconstruction through the SAME rules closes the whole
            # quote/`$IFS`/empty-string obfuscation family without adding a single
            # new evasion pattern — the tokenizer generalises where a regex list
            # cannot.
            #
            # MAX-fused: this only ADDS threats to `danger`, and the block decision
            # below is unchanged, so a reconstruction can never LOWER a verdict.
            # Applied ONLY to arguments that really are shell command lines (the
            # SHELL_ARG_KEYS the classifier parses — shared so the two cannot
            # drift), because reconstruction necessarily drops quoting: running it
            # over prose would strip the quotes that mark a command as quoted.
            shell_command = _extract_shell_command(arguments or {})
            if shell_command:
                rebuilt = _reconstruct_command(shell_command)
                if rebuilt and rebuilt != shell_command:
                    rebuilt = self._arg_normalizer().normalize(rebuilt)
                    danger.extend(
                        t for t in _scan_l1(rebuilt[:_L1_MAX_SCAN_CHARS]).threats
                        if t.category in (
                            "code_execution", "excessive_agency", "prompt_injection",
                            "credential_access", "data_exfiltration",
                        )
                        and t.rule not in {x.rule for x in danger}
                    )
                # STRUCTURAL findings from the impact-class ruleset. Everything
                # above — raw string and reconstruction alike — is still a REGEX
                # over text, so it recognises spellings. These findings come from
                # the PARSE (verb + object sensitivity + redirect direction), which
                # is what lets `rm important.db` and `rm -rf /var/lib/postgresql/data`
                # be the same fact as `rm -rf /` instead of three separate patterns
                # to remember. Only rules carrying an explicit `detect` block
                # enforce; the classify-only majority (a deploy agent's `terraform
                # destroy`, `systemctl enable`, `sudo`) stays a policy decision.
                # Additive to `danger`, so this can only raise a verdict.
                for f in _command_findings(shell_command):
                    if f["rule"] in {x.rule for x in danger}:
                        continue
                    danger.append(_StructuralThreat(
                        rule=f["rule"], category=f["impact_class"], score=f["score"]
                    ))

            # STRUCTURAL findings from SQL in an argument value. Deliberately
            # OUTSIDE the `if shell_command:` block above: an agent runs SQL by
            # calling run_sql(query=…), not through a shell, so gating this on the
            # six SHELL_ARG_KEYS would make the whole surface unreachable, which
            # is exactly the gap this closes. extract_sql looks at every key and
            # gates on the VALUE beginning with a SQL statement instead.
            #
            # Same discipline as the command findings: only rules carrying a
            # `detect` block appear, so a migration's `DROP TABLE` classifies for
            # policy and does not block, and additive to `danger`, so this can
            # only raise a verdict and never lower one.
            sql_statement = _extract_sql(arguments or {})
            if sql_statement:
                for f in _sql_findings(sql_statement):
                    if f["rule"] in {x.rule for x in danger}:
                        continue
                    danger.append(_StructuralThreat(
                        rule=f["rule"], category=f["impact_class"], score=f["score"]
                    ))
            # data_exfiltration is surfaced too (BS2) but is FLAG-DEFAULT: agents
            # make legit outbound calls constantly, so an exfil signal in a tool
            # arg flags for review, it does not block by default. pii_detected
            # stays FILTERED — a benign email/PII value in a send_email arg must
            # not FP. The hard categories still block in block mode.
            # credential_access is a HARD category: reading a private key or an
            # instance-metadata credential endpoint out of a tool argument has no
            # benign reading. It reports under its own name rather than borrowing
            # excessive_agency, because the category string is what a customer's
            # SIEM rules key on and "excessive agency" would misdescribe the fact.
            if danger:
                score = max(score, max(t.score for t in danger))
                hard = [t for t in danger if t.category != "data_exfiltration"]
                category = category or (hard[0].category if hard else danger[0].category)
                rules = rules + [t.rule for t in danger if t.rule not in rules]
                # Benign DOCUMENTARY-PROSE cap. This path runs raw L1 over the arg
                # text with none of scan()'s context calibration, so an agent that
                # passes an incident report, runbook, policy doc or detection-rule
                # doc into a tool argument (summarise_document(text=…),
                # send_message(body=…)) BLOCKED on the command the prose QUOTES.
                # Same structural test as scan(): quoted command, documentary frame
                # outside the quotes, and a prose residue with no dangerous signal.
                # Additionally gated OFF whenever the call carries a shell-argument
                # key — run_command(command=…) & friends are an execution request,
                # never documentation, so the whole attack corpus and every
                # prefixed-attack probe are structurally out of reach of this cap.
                if hard and self.enforcement_mode == "block" and self._prose_mention_arg(
                    arguments, f"{tool_name} {arg_text}"
                ):
                    hard = []
                # Only the hard (destructive/injection) categories enforce a block;
                # data_exfiltration alone surfaces as a flag (monitor-default).
                if hard and self.enforcement_mode == "block":
                    action = "blocked"
                else:
                    action = "flagged"
            # --- SECRETS in tool arguments (DLP, secrets ONLY) -----------------
            # This path ran NO DLP at all, so send_message(body="AKIA…") carried a
            # live AWS key straight out of the agent without a signal. The L1 rules
            # above are behavioral (they detect a command that WOULD READ a secret);
            # this is material (the secret is already IN the argument, on its way
            # out), which is a different and strictly worse fact.
            #
            # SECRETS ONLY — PII IS DELIBERATELY EXCLUDED, and the distinction is
            # the whole reason this is safe to enforce on. A secret has a
            # self-identifying SHAPE (an AKIA/ghp_ prefix, PEM armour, a JWT's three
            # segments, a URL with inline credentials): the pattern IS the evidence,
            # so a hit is unambiguous. PII has no such shape — an email address or a
            # phone number in a `send_email` argument is overwhelmingly the tool
            # doing its job, and blocking it would make the sensor unusable for
            # exactly the workloads that carry customer data. So `pii_*` stays
            # FILTERED here, matching the existing rule for the L1 categories above,
            # and only `secret_*` enforces.
            #
            # Within secrets, only the HIGH-confidence categories block;
            # `secret_password` matches ordinary prose ("reset your password:
            # instructions at …") and is signal-only. See dlp.py for the taxonomy —
            # it lives beside the patterns so a new pattern cannot inherit an
            # enforcement decision nobody made.
            if self._scanner.dlp_enabled and arg_text.strip():
                dlp_hits = [
                    t for t in _scan_dlp(arg_text[:_L1_MAX_SCAN_CHARS]).threats
                    if t.category in _HIGH_CONFIDENCE_SECRETS
                ]
                if dlp_hits:
                    score = max(score, max(t.score for t in dlp_hits))
                    category = category or dlp_hits[0].category
                    rules = rules + [t.rule for t in dlp_hits if t.rule not in rules]
                    if self.enforcement_mode == "block":
                        action = "blocked"
                    elif action == "allowed":
                        action = "flagged"

            # Over-length arg content is itself anomalous — flag-default (never a
            # hard block on size alone, never a silent pass) if nothing stronger
            # already fired.
            if len(normalized_args) > _L1_MAX_SCAN_CHARS:
                if action == "allowed":
                    action = "flagged"
                if score < 0.2:
                    score = 0.2
                if not category:
                    category = _OVERSIZED_INPUT_CATEGORY
                if _OVERSIZED_INPUT_RULE not in rules:
                    rules = rules + [_OVERSIZED_INPUT_RULE]

        # Compose the local YAML policy as an overlay (STRICTER WINS), BEFORE the
        # enforcement_mode gate so the same gate (_apply_mode) sees the composed
        # action. Policy can only tighten the detection verdict, never weaken it.
        _local_policy_decision: Optional[str] = None
        _local_policy_id: Optional[str] = None
        # Computed unconditionally (it is cheap and pure) so telemetry can record
        # it on every tool call, not only on the calls a policy happened to gate.
        _least_priv = self._least_privileged_tier()
        if self._policy is not None:
            pol = _policy.evaluate_policy(
                self._policy,
                agent_id=self.agent_id,
                trust=None,                       # standalone sensor has no trust score
                tool_name=tool_name,
                impact_class=impact_class,        # from the existing classifier
                impact_tier=impact_tier,          # from the existing classifier
                destination_type="mcp_server" if mcp_server else "tool_call",
                destination_identifier=mcp_server or tool_name,
                # Feeds the `mcp_server:` match field, which reads from the
                # request context. Without this it is silently inert.
                # `least_privileged_tier` feeds the `min_chain_tier_above:`
                # CONDITION (a numeric comparison, not a glob match field) — same
                # reasoning: unpopulated, the condition can never fire.
                context={
                    "mcp_server": mcp_server,
                    "least_privileged_tier": _least_priv,
                },
            )
            action = _policy.compose(action, pol.decision)
            _local_policy_decision = pol.decision
            _local_policy_id = pol.policy_id

            # When the local policy is the decider, make the event ACTIONABLE.
            # A bare policy block otherwise carries score=0, category=None,
            # rules=[] — "blocked" with no reason. Fill policy metadata without
            # clobbering a real detection category/score (only fill/raise).
            if pol.decision not in (None, "allow", "allowed"):
                if not category:
                    category = "policy"
                rule_label = (
                    f"policy:{_local_policy_id}" if _local_policy_id else "policy"
                )
                if rule_label not in rules:
                    rules = rules + [rule_label]
                # Minimal nonzero severity so score-based dashboards aren't misled
                # by 0.0 on a policy block. Never lowers a higher real score.
                policy_severity = {
                    "blocked": 0.6,
                    "approval_required": 0.6,
                    "flag": 0.3,
                    "monitor": 0.3,
                }.get(pol.decision, 0.0)
                if policy_severity > score:
                    score = policy_severity

        result = ScanResult(
            action=action, score=score, category=category, rules=rules, latency_ms=0,
        )

        # Emit telemetry (mirrors the scan() enqueue shape, direction=tool_call)
        # resolve the app-supplied principal (3b semantics: per-call > set context)
        prov = _resolve_provenance(
            self.agent_id, per_call=origin_context, tier=self._declared_tier
        )
        data = {
            "scanId": uuid4().hex[:12],
            "agentId": self.agent_id,
            "action": action,
            "score": score,
            "category": category,
            "rules": rules,
            "direction": "tool_call",
            "toolName": tool_name,
            "destinationType": "mcp_server" if mcp_server else "tool_call",
            "destinationIdentifier": mcp_server or tool_name,
            "mcpServer": mcp_server,
            "impactClass": impact_class,
            "impactTier": impact_tier,
            # The open authorization mechanism is the local YAML policy; surface
            # its decision for audit (None when no policy is configured).
            "authzDecision": _local_policy_decision,
            "authzPolicyId": _local_policy_id,
            "enforcementMode": self.enforcement_mode,
            # PRIVILEGE-TIER AUDIT (OWASP ASI03). Emitted on EVERY tool call, not
            # only on a halt: a control that stops an action without leaving a
            # record is the recurring failure in this codebase, and an operator
            # asked "why was this approval required?" needs the computed ceiling,
            # this agent's own tier, and the chain it was derived from — all
            # three, in the same event. `authzPolicyId` above carries the rule id.
            # The chain itself rides `provenance.delegation_chain` below.
            "privilegeTier": self.privilege_tier,
            "privilegeTierConfigured": self._privilege_tier_configured,
            "leastPrivilegedTier": _least_priv,
            "delegated": _chain.is_delegated(self.agent_id),
            "chainTiers": _chain.current_tiers(),
            "scanTimeMs": 0,
            "promptLength": 0,
            "promptHash": safe_content_hash(tool_name),
        }
        if prov:
            data["provenance"] = prov
        self._telemetry.enqueue({
            "type": "scan",
            "agentId": self.agent_id,
            "data": data,
        })

        # Breaker sees the TRUE verdict — before _apply_mode softens it.
        self._breaker_observe(result)
        return self._apply_mode(result)

    def block_tools(self, tool_names: list) -> None:
        """Add tool names to the blocked-tools list.

        Any tool whose name is in this list is denied by ``scan_tool_call``
        and by wrappers from ``protect_tools`` — unconditionally, in both
        enforcement modes (an operator's explicit block is not a detection
        verdict, so monitor mode does not downgrade it in the wrapper).
        """
        self._blocked_tools.update(str(n) for n in tool_names)

    def unblock_tools(self, tool_names: list) -> None:
        """Remove tool names from the blocked-tools list (unknown names ignored)."""
        for n in tool_names:
            self._blocked_tools.discard(str(n))

    def block_urls(self, urls: list) -> None:
        """Add URL/destination substrings to the blocked-destinations list.

        Any outgoing HTTP request whose URL contains one of these substrings is
        blocked by ``protect_http`` — for EVERY method (GET/DELETE included),
        regardless of body content. This is the operator destination blocklist;
        the local YAML deny-destination policy is the structured alternative.
        """
        self._blocked_urls.extend(str(u) for u in urls if u)

    def unblock_urls(self, urls: list) -> None:
        """Remove URL substrings from the blocked-destinations list."""
        drop = {str(u) for u in urls}
        self._blocked_urls = [u for u in self._blocked_urls if u not in drop]

    def protect_tools(self, tools: list) -> list:
        """Wrap tools so every invocation is scanned and enforced before it runs.

        Each wrapped call runs ``scan_tool_call(tool_name, arguments)`` on the
        ACTUAL call arguments before invoking the original tool. That applies,
        in one pass: the blocked-tools list (``block_tools``), the L1 content
        scan of the tool name + argument values (destructive shell commands,
        code execution, injection, exfiltration), and the local YAML policy
        (``policy_file`` / ``set_policy``), and emits telemetry for the call.

        Either HALTING verdict short-circuits: the original tool is NOT invoked.
        A "blocked" verdict returns a ``[BLOCKED]`` message string; an
        "approval_required" verdict (from a ``require_approval`` policy) returns
        a distinct ``[APPROVAL REQUIRED]`` string saying the action was not
        executed and needs a human approver — a denial and a pending approval are
        never collapsed into the same message. Detection and policy verdicts
        honor ``enforcement_mode`` ("monitor" observes/flags — including
        downgrading an approval gate to ``flagged``, so the tool DOES run —
        "block" enforces); tools explicitly named via ``block_tools`` are
        denied in both modes. An unexpected internal scan fault fails OPEN
        (the tool runs, with a degraded-telemetry signal) — see
        ``scan_tool_call`` — but a clean halting verdict always stops the tool.

        Usage::

            protected = sensor.protect_tools([query_db, send_email])
            agent = create_agent(model=llm, tools=protected)

        Args:
            tools: LangChain ``@tool`` objects or plain callables.

        Returns:
            List of wrapped tools with scanning + blocking enforcement.
        """
        wrapped = []
        for t in tools:
            tool_name = getattr(t, "name", None) or getattr(t, "__name__", "unknown")
            # LangChain tools carry the callable in .func; a plain callable IS
            # the tool. (Previously plain callables were never invoked at all —
            # the wrapper returned args[0] — silently no-op'ing benign tools.)
            original_func = getattr(t, "func", None)
            if original_func is None and callable(t):
                original_func = t

            def make_wrapper(orig_func, tname):
                def wrapper(*args, **kwargs):
                    arguments = {f"arg{i}": v for i, v in enumerate(args)}
                    arguments.update(kwargs)
                    # scan_tool_call applies blocked-tools + L1 arg scan +
                    # local YAML policy, emits telemetry, and NEVER raises
                    # (internal faults fail open with a degraded signal).
                    result = self.scan_tool_call(tname, arguments)
                    if tname in self._blocked_tools:
                        # Explicit operator block: enforced in both modes,
                        # so monitor mode's downgrade does not soften it.
                        print(f"[xaidr] TOOL BLOCKED: {tname}")
                        return f"[BLOCKED] Tool '{tname}' has been blocked by local policy."
                    # Both halting verdicts short-circuit: the original tool is
                    # NOT invoked. "approval_required" (a require_approval
                    # policy) halts autonomous execution exactly like a block,
                    # but keeps a DISTINCT message — the operator must be able to
                    # tell a denial (final) from a pending approval (routable).
                    if result.action in ("blocked", "approval_required"):
                        if result.action == "approval_required":
                            print(
                                f"[xaidr] TOOL APPROVAL REQUIRED: {tname} "
                                f"({result.category}: {', '.join(result.rules)})"
                            )
                            return (
                                f"[APPROVAL REQUIRED] Tool '{tname}' requires "
                                f"human approval and was NOT executed "
                                f"({result.category}). Route this action to a "
                                "human approver."
                            )
                        print(
                            f"[xaidr] TOOL BLOCKED: {tname} "
                            f"({result.category}: {', '.join(result.rules)})"
                        )
                        return (
                            f"[BLOCKED] Tool '{tname}' blocked by security policy "
                            f"({result.category})."
                        )
                    if orig_func is not None:
                        return orig_func(*args, **kwargs)
                    return None
                return wrapper

            new_func = make_wrapper(original_func, tool_name)

            # Preserve LangChain tool metadata (name, description, args_schema)
            # by copying the original tool with only `func` replaced. model_copy
            # is the supported Pydantic v2 path for LangChain BaseTool.
            if hasattr(t, "model_copy") and original_func is not None:
                new_tool = t.model_copy(update={"func": new_func})
            else:
                # Non-LangChain callable — wrap and return as-is
                new_func.__name__ = tool_name
                new_func.__doc__ = getattr(original_func, "__doc__", None) or f"Protected: {tool_name}"
                new_tool = new_func

            wrapped.append(new_tool)

        return wrapped

    def protect_http(self, client: "httpx.Client") -> "ProtectedHttpClient":
        """Wrap an httpx.Client to enforce on outgoing HTTP calls.

        Two independent, stricter-wins enforcement layers:

        * DESTINATION (every method, incl. GET/DELETE): the request URL is
          checked against the blocked-URL list (``block_urls`` / the
          ``blocked_urls`` ctor arg) and the local deny-destination YAML policy.
          A denied destination is blocked regardless of body content.
        * BODY CONTENT (POST/PUT/PATCH): message text is extracted from the JSON
          body (A2A ``params.message.parts[]``, plus message/prompt/content
          fields) and scanned via ``scan_a2a``; the response body is scanned for
          output DLP. A malicious body is blocked even to an allowed destination.

        Requires the ``http`` extra (``pip install xaidr[http]`` — pulls in
        httpx). Destination agent is inferred from URL (/agents/{id}/) or body
        (targetAgent, agentId).

        Usage::

            import httpx
            from xaidr import Sensor

            sensor = Sensor(agent_id="orchestrator", ...)
            sensor.block_urls(["evil.com"])            # destination blocklist
            protected = sensor.protect_http(httpx.Client())

            # Body-scanned, and blocked if the destination is denied:
            resp = protected.post("http://billing:3002/ask", json={"message": task})

        Args:
            client: An httpx.Client instance to wrap.

        Returns:
            A ProtectedHttpClient that proxies all methods, blocks denied
            destinations on every verb, and body-scans POST/PUT/PATCH.
        """
        return ProtectedHttpClient(client, self)

    def flush(self) -> None:
        """Flush pending telemetry synchronously — the sync-safe flush.

        Sync callers MUST use this (or ``close_sync``) to force emission before
        reading the sink; ``close`` is a coroutine and is a silent no-op if
        called without ``await`` from sync code. ``flush`` keeps the sensor
        usable — the reporter stays open and later scans keep emitting.
        Idempotent.
        """
        self._telemetry.flush_sync()

    def close_sync(self) -> None:
        """Synchronous full shutdown — the sync counterpart of ``await close()``.

        Flushes telemetry, closes the reporter, and closes the scanner. Use this
        (not ``close``) from sync code; use ``flush`` if you want to keep
        emitting afterwards. Idempotent.
        """
        if self._closed:
            return
        self._closed = True
        self._telemetry.close_sync()
        if hasattr(self._scanner, "close"):
            try:
                self._scanner.close()
            except Exception:
                pass

    async def close(self) -> None:
        """Asynchronous shutdown (for ``async with`` / async callers).

        Sync callers must use ``close_sync`` or ``flush`` instead — awaiting is
        required here, so calling ``close()`` without ``await`` from sync code
        does nothing (a coroutine is created and dropped).
        """
        self.close_sync()

    async def __aenter__(self) -> "DelphiSensor":
        self._telemetry.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()


import re as _re


class ProtectedHttpClient:
    """Wraps httpx.Client to auto-scan outgoing A2A HTTP traffic.

    Proxies all methods to the underlying client. POST, PUT, and PATCH
    requests are scanned before sending. Response bodies are scanned
    for output DLP.
    """

    def __init__(self, client: "httpx.Client", sensor: DelphiSensor):
        self._client = client
        self._sensor = sensor

    def _extract_destination(self, url: str, json_body: dict | None) -> str:
        """Infer destination agent from URL pattern or body fields."""
        match = _re.search(r'/agents/([^/]+)', str(url))
        if match:
            return match.group(1)

        if json_body:
            for field in ('targetAgent', 'agentId', 'agent_id', 'destination'):
                val = json_body.get(field)
                if val and isinstance(val, str):
                    return val

        match = _re.search(r'://([^:./]+)', str(url))
        if match:
            host = match.group(1)
            if host not in ('localhost', '127', '0'):
                return host

        return 'unknown'

    # Known LLM API hosts → provider label. Used so agent→LLM edges in
    # downstream telemetry are attributed to a named provider rather than a
    # generic node.
    _PROVIDER_HOSTS = (
        ("anthropic", "anthropic"),
        ("openai", "openai"),
        ("azure", "azure-openai"),
        ("generativelanguage", "google"),
        ("googleapis", "google"),
        ("cohere", "cohere"),
        ("mistral", "mistral"),
        ("bedrock", "bedrock"),
        ("groq", "groq"),
    )

    def _extract_provider(self, url: str) -> Optional[str]:
        """Map a request URL host to a known LLM provider, or None."""
        match = _re.search(r'://([^/:]+)', str(url))
        host = match.group(1).lower() if match else str(url).lower()
        for needle, provider in self._PROVIDER_HOSTS:
            if needle in host:
                return provider
        return None

    # Minimum length for a string to be worth scanning in the catch-all pass.
    _CATCHALL_MIN_LEN = 4

    # Cap on total extracted text fed to the scanner — a safety bound against a
    # pathologically large body. Must be >= the scanner's over-length threshold
    # (L1_MAX_SCAN_CHARS) and window reach, otherwise this extractor would
    # silently truncate A2A content BELOW the point at which the scanner flags +
    # windows it — recreating the truncation bypass on the A2A path. Sized to the
    # scanner's total windowed reach; the scanner itself bounds the scan latency.
    _EXTRACT_CHAR_CAP = _L1_MAX_SCAN_CHARS * 8

    # Keys whose string values are non-content identifiers (IDs, protocol
    # envelope fields). Skipped in the recursive catch-all AND in metadata
    # extraction. High-signal content keys (text/content/description/name/
    # query/prompt/message/hint) are never here, so attack text in metadata
    # (e.g. metadata.hint) is still captured.
    _NOISE_KEYS = frozenset({
        # protocol / envelope
        'id', 'messageid', 'taskid', 'contextid', 'artifactid',
        'jsonrpc', 'method', 'kind', 'role', 'mimetype', 'version', 'uuid',
        # identity / routing identifiers — these carry IDs and addresses
        # (often PII-shaped, e.g. an email in metadata.userId), not prose.
        # Scanning them as content produces DLP false positives on benign
        # A2A traffic without adding attack coverage.
        'userid', 'user_id', 'useremail', 'user_email', 'email',
        'sessionid', 'session_id', 'requestid', 'request_id',
        'traceid', 'trace_id', 'correlationid', 'correlation_id',
        'source', 'timestamp', 'fileid', 'file_id',
    })

    # A canonical UUID (8-4-4-4-12 hex). Such values are IDs, never prose.
    _UUID_RE = _re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        _re.IGNORECASE,
    )
    # A long unbroken hex run (>= 16 chars). Catches hex token/task IDs that
    # aren't UUID-formatted, e.g. "abc123def456...".
    _LONG_HEX_RE = _re.compile(r'^[0-9a-f]{16,}$', _re.IGNORECASE)

    def _extract_message(self, json_body: dict | None, content: str | bytes | None) -> str:
        """Extract all text worth scanning from an outgoing request body.

        A2A-protocol-aware hybrid extractor. Real A2A JSON-RPC traffic buries
        prompt text under nested paths like ``params.message.parts[].text``;
        the old top-level-field scan missed all of it. This runs two passes:

        1. A structured pass over known A2A text-bearing paths (request,
           response, and fallback "A2A-ish" envelope shapes), plus the legacy
           top-level fields so simple bodies still work.
        2. A recursive catch-all that walks the entire JSON tree and collects
           any remaining string value, guarding against spec drift and
           nonstandard nesting. ID/envelope noise is filtered out by key name
           and by UUID/long-hex value shape.

        Returns every distinct extracted string joined with newlines (so
        downstream L1/L2 scans see each text-bearing field), capped at
        ``_EXTRACT_CHAR_CAP`` chars.
        """
        ordered: list[str] = []
        seen: set[str] = set()

        def add(value) -> None:
            if isinstance(value, str):
                text = value.strip()
                if text and text not in seen:
                    seen.add(text)
                    ordered.append(text)

        def add_string_values(node) -> None:
            """Add every string value reachable under ``node`` (any container)."""
            if isinstance(node, str):
                add(node)
            elif isinstance(node, dict):
                for v in node.values():
                    add_string_values(v)
            elif isinstance(node, (list, tuple)):
                for v in node:
                    add_string_values(v)

        # Resolve the JSON we'll scan. `content` may itself carry JSON; if it
        # parses, fold it into the structured + catch-all logic. Otherwise it's
        # a raw string body we still want to scan.
        body = json_body if isinstance(json_body, dict) else None
        content_str: str | None = None
        if isinstance(content, bytes):
            content_str = content.decode('utf-8', errors='ignore')
        elif isinstance(content, str):
            content_str = content

        content_json = None
        if content_str:
            try:
                parsed = json.loads(content_str)
            except Exception:
                # Widened from (ValueError, TypeError): the extractor's "never
                # raises" guarantee must not depend on the runtime's json
                # behavior (some builds raise RecursionError at depth). Any parse
                # failure falls through to the not-JSON / raw-string path.
                # BaseException still propagates (not caught).
                parsed = None
            if isinstance(parsed, (dict, list)):
                content_json = parsed

        # ---- Structured pass -------------------------------------------------
        if body is not None:
            self._extract_structured(body, add, add_string_values)
        if isinstance(content_json, dict):
            self._extract_structured(content_json, add, add_string_values)

        # ---- Recursive catch-all pass ---------------------------------------
        # Walk the entire tree and collect any string >= min length whose key
        # isn't obvious ID/envelope noise and whose value isn't a bare ID.
        if body is not None:
            self._extract_catchall(body, None, add)
        if content_json is not None:
            self._extract_catchall(content_json, None, add)

        # If content wasn't JSON, include it as a raw string.
        if content_json is None and content_str:
            add(content_str)

        # ---- Join + cap ------------------------------------------------------
        result = '\n'.join(ordered)
        if len(result) > self._EXTRACT_CHAR_CAP:
            logger.warning(
                "xaidr: extracted text truncated from %d to %d chars",
                len(result), self._EXTRACT_CHAR_CAP,
            )
            result = result[:self._EXTRACT_CHAR_CAP]
        return result

    def _extract_structured(self, body: dict, add, add_string_values) -> None:
        """Pull text from known A2A text-bearing paths in ``body``."""
        # Legacy top-level fields — keep simple bodies working.
        for field in ('message', 'prompt', 'content', 'input', 'text', 'query'):
            val = body.get(field)
            if isinstance(val, str):
                add(val)

        params = body.get('params')
        if isinstance(params, dict):
            # Single-string envelope variants.
            for field in ('input', 'prompt', 'query'):
                add(params.get(field))

            # params.message — request shape.
            msg = params.get('message')
            if isinstance(msg, dict):
                add(msg.get('content'))  # single-string content variant
                self._extract_parts(msg.get('parts'), add, add_string_values)
                self._extract_metadata(msg.get('metadata'), add_string_values)

            # params.messages[] — OpenAI-chat / ACP fallback shapes.
            messages = params.get('messages')
            if isinstance(messages, list):
                for m in messages:
                    if not isinstance(m, dict):
                        continue
                    # OpenAI-chat: content is a string (or list of blocks).
                    add_string_values(m.get('content'))
                    # ACP: nested parts with text/content.
                    self._extract_parts(m.get('parts'), add, add_string_values)

        result = body.get('result')
        if isinstance(result, dict):
            # Response: result.message.parts[].text
            rmsg = result.get('message')
            if isinstance(rmsg, dict):
                self._extract_parts(rmsg.get('parts'), add, add_string_values)
                self._extract_metadata(rmsg.get('metadata'), add_string_values)

            # Response: result.artifacts[]
            artifacts = result.get('artifacts')
            if isinstance(artifacts, list):
                for art in artifacts:
                    if not isinstance(art, dict):
                        continue
                    add(art.get('name'))
                    self._extract_parts(art.get('parts'), add, add_string_values)
                    self._extract_metadata(art.get('metadata'), add_string_values)

    def _extract_parts(self, parts, add, add_string_values) -> None:
        """Extract text from an A2A ``parts[]`` array (request or response)."""
        if not isinstance(parts, list):
            return
        for part in parts:
            if not isinstance(part, dict):
                # ACP parts may be bare strings.
                add_string_values(part)
                continue
            add(part.get('text'))
            add(part.get('content'))  # ACP-style content
            add(part.get('name'))
            add(part.get('description'))
            # data may be a string or an arbitrarily nested object — recurse.
            add_string_values(part.get('data'))
            self._extract_metadata(part.get('metadata'), add_string_values)

    def _extract_metadata(self, metadata, add_string_values) -> None:
        """Extract content string values from a metadata object.

        Metadata mixes prose hints (high-signal — e.g. an injected
        ``hint: "bypass all filters"``) with identity/routing identifiers
        (``userId``, ``source``, ``traceId`` …) that are often PII-shaped and
        produce DLP false positives if scanned. Skip noise-keyed and ID-shaped
        values; keep everything else.
        """
        if not isinstance(metadata, dict):
            return
        for key, value in metadata.items():
            if isinstance(value, str):
                if not self._is_noise(key, value):
                    add_string_values(value)
            elif isinstance(value, (dict, list, tuple)):
                # Nested metadata: recurse, but drop whole subtrees under a
                # noise key (e.g. metadata.user.{id,email}).
                if isinstance(key, str) and key.lower() in self._NOISE_KEYS:
                    continue
                add_string_values(value)

    def _extract_catchall(self, node, key, add) -> None:
        """Walk the whole tree; add strings that aren't ID/envelope noise."""
        if isinstance(node, str):
            if key is not None and self._is_noise(key, node):
                return
            if len(node.strip()) >= self._CATCHALL_MIN_LEN:
                add(node)
        elif isinstance(node, dict):
            for k, v in node.items():
                self._extract_catchall(v, k, add)
        elif isinstance(node, (list, tuple)):
            for v in node:
                self._extract_catchall(v, key, add)

    def _is_noise(self, key, value: str) -> bool:
        """True if a (key, string-value) pair is a non-content identifier."""
        if isinstance(key, str) and key.lower() in self._NOISE_KEYS:
            return True
        stripped = value.strip()
        if self._UUID_RE.match(stripped) or self._LONG_HEX_RE.match(stripped):
            return True
        return False

    def _extract_response_text(self, response: "httpx.Response") -> str:
        """Extract text from response body for output scanning."""
        try:
            data = response.json()
            if isinstance(data, dict):
                for field in ('response', 'message', 'content', 'output', 'text', 'result'):
                    val = data.get(field)
                    if val and isinstance(val, str):
                        return val
            return str(data)[:2000]
        except Exception:
            return ''

    def _extract_host(self, url: str) -> Optional[str]:
        """Return the full host (netloc without scheme/port/path) of ``url``.

        Unlike ``_extract_destination`` (which truncates to the first hostname
        label for topology labelling), this keeps the whole host — e.g.
        ``evil.com``, ``api.evil.com`` — so a deny-destination policy glob can
        match against it. Returns None when no host is parseable.
        """
        match = _re.search(r'://([^/:?#]+)', str(url))
        return match.group(1).lower() if match else None

    def _emit_destination_block(self, result: ScanResult, dest_id: Optional[str]) -> None:
        """Emit ONE telemetry event for a destination-level block.

        Destination blocks raise before any scan_* method runs, so without this
        they would be the only enforcement path in the SDK that produces no audit
        record — a blocked exfiltration attempt with nothing in the SIEM. Mirrors
        the event shape the scan()/scan_a2a()/scan_tool_call() paths emit.

        PRIVACY: carries the destination HOST only, never the full URL. Request
        query strings routinely carry tokens and API keys, and the hash-only
        content guarantee has to hold on this path too.

        NEVER raises and NEVER swallows the block: it is called immediately
        before ``raise DelphiBlockedError`` and has its own guard, so an emit
        fault cannot be mistaken for a fail-open by the caller's handler.
        """
        try:
            dest = dest_id or "unknown"
            data = {
                "scanId": uuid4().hex[:12],
                "agentId": self._sensor.agent_id,
                "action": result.action,
                "score": result.score,
                "category": result.category,
                "rules": result.rules,
                "direction": "a2a",
                "destinationType": "external_api",
                # HOST ONLY — never the URL, never the query string.
                "destinationIdentifier": dest,
                "enforcementMode": self._sensor.enforcement_mode,
                "scanTimeMs": 0,
                "promptLength": 0,
                "promptHash": safe_content_hash(dest),
            }
            prov = _resolve_provenance(self._sensor.agent_id)
            if prov:
                data["provenance"] = prov
            self._sensor._telemetry.enqueue({
                "type": "scan",
                "agentId": self._sensor.agent_id,
                "data": data,
            })
        except Exception as exc:
            try:
                logger.warning(
                    "xaidr: destination-block telemetry failed (%s: %s)",
                    type(exc).__name__, exc,
                )
            except Exception:
                pass

    def _check_destination(self, url: str, json_body: dict | None = None) -> None:
        """Destination-level block: blocked-URL list + local deny-destination
        policy. Applies to EVERY method (GET/DELETE included) and is independent
        of body content — a denied destination blocks even with a benign body.

        Raises DelphiBlockedError on a block, and emits ONE telemetry event per
        block first (host only — see ``_emit_destination_block``) so a denied
        destination leaves an audit record like every other verdict path.
        Fail-open: an unexpected internal fault here must never crash the host
        request (the caller still runs any body content scan), so it is caught
        and logged, not raised.
        """
        try:
            url_str = str(url).lower()
            # 1. Explicit blocked-URL substrings (operator destination blocklist)
            for blocked_url in self._sensor._blocked_urls:
                if blocked_url and blocked_url.lower() in url_str:
                    result = ScanResult(
                        action="blocked",
                        score=1.0,
                        category="blocked_url",
                        rules=["URL_BLOCKED"],
                        latency_ms=0,
                    )
                    # Destination identifier computed ONCE and used for both the
                    # console line and the audit record, so the two cannot drift
                    # into disagreeing about what this path discloses.
                    dest_id = (
                        self._extract_host(url)
                        or self._extract_destination(url, json_body)
                    )
                    # HOST ONLY, never the full URL: a query string routinely
                    # carries a token or an API key, and this line goes to the
                    # host's stdout like any other. The audit record below has
                    # always been host-only; this used to be broader than the
                    # record sitting beside it. The pattern echoed back is the
                    # operator's OWN block_urls() substring, which is
                    # configuration feedback (which of your rules fired) rather
                    # than anything derived from the request.
                    print(
                        f"[xaidr] URL BLOCKED: {dest_id} "
                        f"matches pattern '{blocked_url}'"
                    )
                    # Audit record BEFORE the raise — host only, no URL.
                    self._emit_destination_block(result, dest_id)
                    raise DelphiBlockedError(result)

            # 2. Local deny-destination YAML policy (host-based, structured).
            #    Consult the SAME local policy the tool-call path uses, keyed on
            #    the request destination. A "blocked"/"approval_required" verdict
            #    denies the destination regardless of body content.
            policy = self._sensor._policy
            if policy is not None:
                host = self._extract_host(url)
                dest = self._extract_destination(url, json_body)
                seen: set[str] = set()
                for dest_id in (host, dest):
                    if not dest_id or dest_id in seen:
                        continue
                    seen.add(dest_id)
                    pol = _policy.evaluate_policy(
                        policy,
                        agent_id=self._sensor.agent_id,
                        trust=None,
                        tool_name="http_request",
                        impact_class="network",
                        impact_tier="external",
                        destination_type="external_api",
                        destination_identifier=dest_id,
                    )
                    if pol.decision not in (None, "allow", "allowed", "monitor"):
                        rule_label = (
                            f"policy:{pol.policy_id}" if pol.policy_id else "POLICY_DENY"
                        )
                        result = ScanResult(
                            action="blocked",
                            score=1.0,
                            category="policy",
                            rules=[rule_label],
                            latency_ms=0,
                        )
                        # Same rule as the blocked-URL branch above: the
                        # destination identifier, never the full URL. `dest_id`
                        # is already the host (or the inferred destination), and
                        # is exactly what the audit record below carries.
                        print(
                            f"[xaidr] DESTINATION BLOCKED by policy: {dest_id} "
                            f"({pol.reason or pol.policy_id or dest_id})"
                        )
                        # Audit record BEFORE the raise — dest_id is the host (or
                        # the inferred destination agent), never the URL.
                        self._emit_destination_block(result, dest_id)
                        raise DelphiBlockedError(
                            result,
                            message=f"Destination '{dest_id}' blocked by policy",
                        )
        except DelphiBlockedError:
            raise
        except Exception as exc:
            # Fail open: the destination check must never crash the host request.
            # The exception MESSAGE is suppressed for the same reason it is on the
            # scan path: a fault raised while handling a URL can interpolate that
            # URL, query string included, into its own message. Type only.
            logger.warning(
                "xaidr: destination check failed open (%s) "
                "[message suppressed: may contain request content]",
                type(exc).__name__,
            )

    def _scan_request(self, url: str, json_body: dict | None, content: str | bytes | None) -> None:
        """Scan outgoing request: destination block first, then A2A body scan.

        Additive / stricter-wins: ``_check_destination`` blocks a denied
        destination (blocked-URL list or deny-destination policy) even with a
        benign body; the existing body content scan still blocks a malicious
        body to an otherwise-allowed destination. Raises DelphiBlockedError on
        either.
        """
        self._check_destination(url, json_body)

        message = self._extract_message(json_body, content)
        if not message or len(message) < 3:
            return

        destination = self._extract_destination(url, json_body)

        result = self._sensor.scan_a2a(message, destination=destination)

        if result.action == 'blocked':
            raise DelphiBlockedError(result)

    def _scan_response(self, response: "httpx.Response") -> "httpx.Response":
        """Scan response body for output DLP.

        Labels the output scan with the LLM provider derived from the request
        host so downstream telemetry attributes an agent→LLM edge.
        """
        # Inbound A2A response path: record any task/context ids a peer
        # legitimately issued to us, so the local id tracker can later
        # distinguish a smuggled (never-issued) outbound reference. Non-A2A
        # (e.g. LLM) responses carry no such ids, so record_issued no-ops.
        try:
            rbody = response.json()
        except Exception:
            rbody = None
        if isinstance(rbody, dict):
            self._sensor._a2a_id_tracker.record_issued(rbody)

        text = self._extract_response_text(response)
        if text and len(text) >= 3:
            provider = self._extract_provider(str(response.url))
            result = self._sensor.scan(text, direction='output', provider=provider)
            if result.action == 'blocked':
                raise DelphiBlockedError(result)
        return response

    def post(self, url, *, json=None, content=None, headers=None, **kwargs):
        """POST with A2A scanning."""
        headers = dict(headers or {})
        headers['X-Delphi-Source-Agent'] = self._sensor.agent_id

        self._scan_request(str(url), json, content)
        response = self._client.post(url, json=json, content=content, headers=headers, **kwargs)
        return self._scan_response(response)

    def put(self, url, *, json=None, content=None, headers=None, **kwargs):
        """PUT with A2A scanning."""
        headers = dict(headers or {})
        headers['X-Delphi-Source-Agent'] = self._sensor.agent_id

        self._scan_request(str(url), json, content)
        response = self._client.put(url, json=json, content=content, headers=headers, **kwargs)
        return self._scan_response(response)

    def patch(self, url, *, json=None, content=None, headers=None, **kwargs):
        """PATCH with A2A scanning."""
        headers = dict(headers or {})
        headers['X-Delphi-Source-Agent'] = self._sensor.agent_id

        self._scan_request(str(url), json, content)
        response = self._client.patch(url, json=json, content=content, headers=headers, **kwargs)
        return self._scan_response(response)

    def get(self, url, **kwargs):
        """GET — destination-scanned (no body to content-scan).

        The blocked-URL list and deny-destination policy still apply, so a GET
        to a denied destination is blocked before the request leaves the host.
        """
        self._check_destination(str(url), None)
        return self._client.get(url, **kwargs)

    def delete(self, url, **kwargs):
        """DELETE — destination-scanned (no body to content-scan).

        Same destination enforcement as GET: a DELETE to a denied destination
        is blocked before it is sent.
        """
        self._check_destination(str(url), None)
        return self._client.delete(url, **kwargs)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
