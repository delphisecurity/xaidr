"""W3C Trace Context parent resolution — READING HALF ONLY.

The open sensor READS a parent trace context when the host provides one; it does
NOT provision its own. Two read sources, in precedence order:

  1. WIRE — an inbound ``traceparent`` header (per W3C Trace Context), parsed
     with :class:`TraceContextTextMapPropagator` from ``opentelemetry-api``.
  2. OTEL INTEROP — an already-active OpenTelemetry span in the current context
     (e.g. the host app opened a span before calling us).

Precedence: wire -> OTel active span -> None (fail-safe). Resolution never
raises: malformed headers, a missing OTel API, or no context at all all resolve
cleanly to ``None`` so the message is still scanned.

OPEN-CORE LINE (do not cross it):
  * Depends on ``opentelemetry-api`` ONLY. Never the SDK, never an exporter,
    never a batch span processor, and it NEVER installs or overrides the global
    tracer provider. It only *reads* whatever the host set up.
  * There is deliberately NO self-owned ContextVar parent stack here. The
    sensor does not push/pop its own parent spans — it only *reads* the host's
    active context, keeping this module a pure, dependency-light reader.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

# opentelemetry-api is the ONLY OTel dependency. Import lazily/guarded so the
# module degrades to a no-op (resolve -> None) if the API is absent, preserving
# the zero-hard-dependency, fail-safe posture.
try:  # pragma: no cover - import guard
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator as _TraceContextPropagator,
    )

    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover - otel-api not installed
    _otel_trace = None  # type: ignore[assignment]
    _TraceContextPropagator = None  # type: ignore[assignment]
    _OTEL_AVAILABLE = False


@dataclass(frozen=True)
class ParentContext:
    """A resolved parent trace context (read-only, additive metadata).

    Ids are lowercase hex, matching the W3C Trace Context on-wire form:
    ``trace_id`` is 32 hex chars, ``span_id`` 16, ``trace_flags`` 2. ``source``
    records where it came from (``"wire"`` or ``"otel"``).
    """

    trace_id: str
    span_id: str
    trace_flags: str
    source: str

    def as_metadata(self) -> dict[str, str]:
        """Additive metadata form for telemetry (never mutates scan logic)."""
        return {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "traceFlags": self.trace_flags,
            "source": self.source,
        }


def _from_span_context(span_context: Any, source: str) -> Optional[ParentContext]:
    """Convert an OTel ``SpanContext`` to a :class:`ParentContext` if valid."""
    if span_context is None or not getattr(span_context, "is_valid", False):
        return None
    return ParentContext(
        trace_id=format(span_context.trace_id, "032x"),
        span_id=format(span_context.span_id, "016x"),
        trace_flags=format(int(span_context.trace_flags), "02x"),
        source=source,
    )


def _from_wire(headers: Optional[dict]) -> Optional[ParentContext]:
    """Parse an inbound ``traceparent`` header via the W3C propagator.

    Case-insensitive: header keys are lowercased before extraction (the
    propagator looks up the lowercase ``traceparent``/``tracestate`` keys). Any
    parse failure fails safe to ``None``.
    """
    if not _OTEL_AVAILABLE or not isinstance(headers, dict) or not headers:
        return None
    try:
        carrier = {str(k).lower(): v for k, v in headers.items()}
        ctx = _TraceContextPropagator().extract(carrier=carrier)
        span = _otel_trace.get_current_span(ctx)
        return _from_span_context(span.get_span_context(), source="wire")
    except Exception:  # pragma: no cover - defensive: never raise
        return None


def _from_active_span() -> Optional[ParentContext]:
    """Read the OTel active span in the current context, if any is valid."""
    if not _OTEL_AVAILABLE:
        return None
    try:
        span = _otel_trace.get_current_span()
        return _from_span_context(span.get_span_context(), source="otel")
    except Exception:  # pragma: no cover - defensive: never raise
        return None


def resolve_parent(headers: Optional[dict] = None) -> Optional[ParentContext]:
    """Resolve the parent trace context to attach as OPTIONAL scan metadata.

    Precedence — the reading half only:
      1. inbound wire ``traceparent`` header (``headers``), then
      2. the OTel active span in the current context, then
      3. ``None`` (fail-safe — the message is still scanned).

    Never raises. Returns a :class:`ParentContext` or ``None``.
    """
    parent = _from_wire(headers)
    if parent is not None:
        return parent
    return _from_active_span()
