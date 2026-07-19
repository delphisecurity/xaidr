"""DelphiSensor — main SDK entry point.

Standalone: local L1/L2/DLP + compositional scanning with a 3-state verdict
model (allow / flag / block). No account, no backend, no network escalation.
"""

from __future__ import annotations

import json
import logging
from typing import Optional
from uuid import uuid4

# NOTE: httpx is an OPTIONAL dependency, imported lazily only when the HTTP-
# intercept feature is used (protect_http / ProtectedHttpClient). It is NOT
# imported at module level so the open package imports in a bare environment.
# All httpx type hints in this module are string-quoted for the same reason.

from . import local_policy as _policy
from . import provenance as _prov
from . import provenance_chain as _chain
from .authz import classify, build_request, evaluate
from .reporters import Reporter
from .scanner.a2a_structural import A2AStructuralValidator, A2AIdTracker
from .scanner.l1 import scan_l1 as _scan_l1
from .scanner.local import LocalScanner
from .scanner.normalizer import TypoNormalizer
from .telemetry import SyncTelemetryQueue
from .trace_context import ParentContext
from .types import DelphiBlockedError, ScanResult, safe_content_hash

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


def _resolve_provenance(agent_id: str, per_call: dict | None = None) -> Optional[dict]:
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
    return _chain.build_provenance(agent_id, on_behalf_of=obo)


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
    ):
        if not agent_id:
            raise ValueError("agent_id is required")
        if enforcement_mode not in ("monitor", "block"):
            raise ValueError(
                f"enforcement_mode must be 'monitor' or 'block', got {enforcement_mode!r}"
            )

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
            resolved_reporter = StdoutReporter(schema=schema)
        self._telemetry = SyncTelemetryQueue(
            reporter=resolved_reporter,
            batch_size=telemetry_batch_size,
            flush_interval_sec=telemetry_flush_interval_sec,
        )
        self._closed = False

        self._quarantined = False
        self._quarantine_reason = None

        self._blocked_tools: set[str] = set(
            str(n) for n in (blocked_tools or ())
        )
        self._blocked_urls: list[str] = []

        self._action_policy: Optional[dict] = None
        self._trust_score: Optional[float] = None

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

    def _extract_a2a_content(self, body: Optional[dict], raw: Optional[str]) -> str:
        """Extract scannable text from a parsed A2A body (or raw fallback)."""
        if self._a2a_extractor is None:
            self._a2a_extractor = ProtectedHttpClient(None, self)
        return self._a2a_extractor._extract_message(
            body, None if body is not None else raw
        )

    def _evaluate_policy(self, context: dict) -> tuple[bool, Optional[str]]:
        """Always-allow stub for the optional AGT policy evaluator path.

        This distribution ships no AGT evaluator, so this has
        always returned ``(True, None)`` — its callers (scan_tool_call,
        protect_tools, ProtectedHttpClient._scan_request) already behave as
        "policy allows". The real, local authorization is the YAML policy
        (``self._policy`` via ``local_policy.compose``), which is a separate
        feature and is unaffected. Kept as a stub so those callers keep working
        without a dangling reference.
        """
        return (True, None)

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
        """In monitor mode, downgrade a returned 'blocked' to 'flagged'.
        Telemetry keeps the true verdict; only the returned action is softened
        so the agent does not hard-block in monitor mode. The local scanner
        already gates on enforcement_mode; this is a belt-and-suspenders guard.
        Quarantine is never downgraded."""
        if self.enforcement_mode == "monitor" and result.action == "blocked":
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
        new failure point."""
        try:
            logger.warning(
                "xaidr: scan failed open on %s (%s: %s)",
                direction, type(exc).__name__, exc,
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
                "scanId": uuid4().hex[:12],
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
        """
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
        prov = _resolve_provenance(self.agent_id, per_call=origin_context)
        if self._quarantined:
            result = ScanResult(
                action="blocked",
                score=1.0,
                category="quarantined",
                rules=["QUARANTINE_ENFORCED"],
                latency_ms=0,
            )
            data = {
                "scanId": uuid4().hex[:12],
                "agentId": self.agent_id,
                "action": "blocked",
                "score": 1.0,
                "category": "quarantined",
                "rules": ["QUARANTINE_ENFORCED"],
                "direction": direction,
                "destinationType": "external_api",
                "destinationIdentifier": destination or provider or "llm",
                "enforcementMode": self.enforcement_mode,
                "scanTimeMs": 0,
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
            return result

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
    ) -> ScanResult:
        """Scan an A2A delegation message (fail-open wrapper).

        An unexpected internal fault — e.g. ``json.dumps`` raising on a circular
        or pathologically deep envelope — fails OPEN with a signal instead of
        raising into the host. See ``_scan_a2a_impl`` for the logic.
        """
        try:
            return self._scan_a2a_impl(
                message, destination, origin_context, parent_context
            )
        except DelphiBlockedError:
            raise
        except Exception as exc:
            return self._emit_scan_error(
                "a2a", exc,
                prompt=message if isinstance(message, str) else None,
                destinationAgent=destination,
            )

    def _scan_a2a_impl(
        self,
        message: str,
        destination: str,
        origin_context: dict | None = None,
        parent_context: Optional[ParentContext] = None,
    ) -> ScanResult:
        """Core A2A scan implementation — see ``scan_a2a`` for the wrapper.

        ``message`` may be a JSON string, bytes, or a dict A2A envelope. Content
        is scanned via the A2A-aware field extractor (params.message.parts[].text,
        artifacts, metadata, with id/envelope noise filtered) — NOT the raw
        serialized JSON. The parsed dict is also used for structural validation.
        Other types fail open gracefully.

        ``parent_context`` is an OPTIONAL, read-only W3C Trace Context parent
        (host-resolved: inbound ``traceparent`` or an active OTel span). It is
        attached to telemetry as additive metadata ONLY — it does NOT alter the
        A2A extraction, the structural/id checks, or the verdict. Absent, the
        result is byte-identical to before.
        """
        # Crash guard. A dict envelope / JSON string is parsed so we can extract
        # the A2A text fields and validate structure. bytes are decoded.
        body_obj = message if isinstance(message, dict) else None
        if body_obj is not None:
            scan_message = json.dumps(message)
        else:
            scan_message = _coerce_scannable(message)
        if scan_message is None:
            return self._emit_not_scannable(
                direction="a2a",
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
            except (ValueError, TypeError):
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
        prov = _resolve_provenance(self.agent_id, per_call=origin_context)
        if self._quarantined:
            result = ScanResult(
                action="blocked",
                score=1.0,
                category="quarantined",
                rules=["QUARANTINE_ENFORCED"],
                latency_ms=0,
            )
            data = {
                "scanId": uuid4().hex[:12],
                "agentId": self.agent_id,
                "action": "blocked",
                "score": 1.0,
                "category": "quarantined",
                "rules": ["QUARANTINE_ENFORCED"],
                "direction": "a2a",
                "destinationAgent": destination,
                "enforcementMode": self.enforcement_mode,
                "scanTimeMs": 0,
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
            return result

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
            "direction": "a2a",
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
        """
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
        frameworks). Enforces the same blocked_tools + AGT policy rules that
        protect_tools() applies, and emits telemetry so the dashboard records
        the verdict. Honors enforcement mode (monitor downgrades block->flag).

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
        reason: Optional[str] = None

        # Action impact classification + local authz evaluation. Both never
        # raise; with no cached action_policy the decision is monitor-only.
        impact_class, impact_tier = classify(tool_name, arguments, mcp_server)
        authz = evaluate(
            self._action_policy,
            build_request(
                agent_id=self.agent_id,
                trust=self._trust_score,
                tool_name=tool_name,
                impact_class=impact_class,
                impact_tier=impact_tier,
                destination_type="mcp_server" if mcp_server else "tool_call",
                destination_identifier=mcp_server or tool_name,
                context={"mcp_server": mcp_server},
            ),
        )

        # Quarantine overrides everything
        if self._quarantined:
            action, score, category, rules = "blocked", 1.0, "quarantined", ["QUARANTINE_ENFORCED"]
        # Blocked-tools list
        elif tool_name in self._blocked_tools:
            action, score, category, rules = "blocked", 1.0, "blocked_tool", ["TOOL_BLOCKED"]
            reason = f"Tool '{tool_name}' blocked by local policy"
        else:
            # Per-agent AGT policy evaluation
            allowed, policy_reason = self._evaluate_policy({"tool_name": tool_name})
            if not allowed:
                action, score, category, rules = "blocked", 1.0, "policy", ["POLICY_DENY"]
                reason = policy_reason
            elif authz.decision == "blocked":
                action, score, category, rules = "blocked", 1.0, "action_policy", ["ACTION_POLICY_BLOCK"]
                reason = authz.reason or f"Tool '{tool_name}' blocked by action policy"
                print(f"[xaidr] TOOL BLOCKED by action policy: {tool_name} ({authz.policy_id})")
            elif authz.decision == "approval_required":
                # Approval flows are not local; block and flag for approval.
                action, score, category, rules = "blocked", 1.0, "action_policy", ["ACTION_POLICY_APPROVAL_REQUIRED"]
                reason = authz.reason or f"Tool '{tool_name}' requires approval"
                print(f"[xaidr] TOOL requires approval: {tool_name} ({authz.policy_id})")

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
            # data_exfiltration is surfaced too (BS2) but is FLAG-DEFAULT: agents
            # make legit outbound calls constantly, so an exfil signal in a tool
            # arg flags for review, it does not block by default. pii_detected
            # stays FILTERED — a benign email/PII value in a send_email arg must
            # not FP. The hard categories still block in block mode.
            danger = [
                t for t in _scan_l1(normalized_args).threats
                if t.category in (
                    "code_execution", "excessive_agency", "prompt_injection",
                    "data_exfiltration",
                )
            ]
            if danger:
                score = max(score, max(t.score for t in danger))
                hard = [t for t in danger if t.category != "data_exfiltration"]
                category = category or (hard[0].category if hard else danger[0].category)
                rules = rules + [t.rule for t in danger if t.rule not in rules]
                # Only the hard (destructive/injection) categories enforce a block;
                # data_exfiltration alone surfaces as a flag (monitor-default).
                if hard and self.enforcement_mode == "block":
                    action = "blocked"
                else:
                    action = "flagged"

        # Compose the local YAML policy as an overlay (STRICTER WINS), BEFORE the
        # enforcement_mode gate so the same gate (_apply_mode) sees the composed
        # action. Policy can only tighten the detection verdict, never weaken it.
        _local_policy_decision: Optional[str] = None
        _local_policy_id: Optional[str] = None
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
        prov = _resolve_provenance(self.agent_id, per_call=origin_context)
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
            "authzDecision": authz.decision,
            "authzPolicyId": authz.policy_id,
            "enforcementMode": self.enforcement_mode,
            "scanTimeMs": 0,
            "promptLength": 0,
            "promptHash": safe_content_hash(tool_name),
        }
        # surface the local policy decision on the event for audit (overrides the
        # legacy action_policy fields when a local policy was evaluated)
        if _local_policy_decision is not None:
            data["authzDecision"] = _local_policy_decision
            if _local_policy_id:
                data["authzPolicyId"] = _local_policy_id
        if prov:
            data["provenance"] = prov
        self._telemetry.enqueue({
            "type": "scan",
            "agentId": self.agent_id,
            "data": data,
        })

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

    def protect_tools(self, tools: list) -> list:
        """Wrap tools so every invocation is scanned and enforced before it runs.

        Each wrapped call runs ``scan_tool_call(tool_name, arguments)`` on the
        ACTUAL call arguments before invoking the original tool. That applies,
        in one pass: the blocked-tools list (``block_tools``), the L1 content
        scan of the tool name + argument values (destructive shell commands,
        code execution, injection, exfiltration), and the local YAML policy
        (``policy_file`` / ``set_policy``), and emits telemetry for the call.

        A "blocked" verdict short-circuits: the original tool is NOT invoked
        and a ``[BLOCKED]`` message string is returned instead. Detection and
        policy blocks honor ``enforcement_mode`` ("monitor" observes/flags,
        "block" enforces); tools explicitly named via ``block_tools`` are
        denied in both modes. An unexpected internal scan fault fails OPEN
        (the tool runs, with a degraded-telemetry signal) — see
        ``scan_tool_call`` — but a clean block verdict always stops the tool.

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
                    if result.action == "blocked":
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
        """Wrap an httpx.Client to auto-scan outgoing A2A HTTP calls.

        Every outgoing POST/PUT/PATCH request is scanned before sending.
        Message text is extracted from JSON body (message, prompt, content fields).
        Destination agent is inferred from URL (/agents/{id}/) or body (targetAgent, agentId).
        Response body is scanned for output DLP.

        Usage::

            import httpx
            from xaidr import Sensor

            sensor = Sensor(agent_id="orchestrator", ...)
            protected = sensor.protect_http(httpx.Client())

            # Every outgoing call is now scanned:
            resp = protected.post("http://billing:3002/ask", json={"message": task})

        Args:
            client: An httpx.Client instance to wrap.

        Returns:
            A ProtectedHttpClient that proxies all methods and scans POST/PUT/PATCH.
        """
        return ProtectedHttpClient(client, self)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._telemetry.close_sync()
        if hasattr(self._scanner, "close"):
            try:
                self._scanner.close()
            except Exception:
                pass

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
    # pathologically large body. Excess is truncated with a warning.
    _EXTRACT_CHAR_CAP = 50000

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
            except (ValueError, TypeError):
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

    def _scan_request(self, url: str, json_body: dict | None, content: str | bytes | None) -> None:
        """Scan outgoing request. Checks blocked URLs first, then A2A scan.

        Raises DelphiBlockedError if URL matches a blocked pattern or scan
        returns action=blocked.
        """
        url_str = str(url).lower()
        for blocked_url in self._sensor._blocked_urls:
            if blocked_url and blocked_url.lower() in url_str:
                result = ScanResult(
                    action="blocked",
                    score=1.0,
                    category="blocked_url",
                    rules=["URL_BLOCKED"],
                    latency_ms=0,
                )
                print(f"[xaidr] URL BLOCKED: {url} matches pattern '{blocked_url}'")
                raise DelphiBlockedError(result)

        allowed, reason = self._sensor._evaluate_policy({"url": str(url)})
        if not allowed:
            result = ScanResult(
                action="blocked",
                score=1.0,
                category="policy",
                rules=["POLICY_DENY"],
                latency_ms=0,
            )
            print(f"[xaidr] URL BLOCKED by policy: {url} ({reason})")
            raise DelphiBlockedError(result, message=f"URL '{url}' blocked by policy: {reason}")

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
        """GET — passthrough, no scanning (read-only)."""
        return self._client.get(url, **kwargs)

    def delete(self, url, **kwargs):
        """DELETE — passthrough, no scanning."""
        return self._client.delete(url, **kwargs)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
