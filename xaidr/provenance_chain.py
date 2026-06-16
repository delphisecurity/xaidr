"""provenance_chain.py — Multi-hop delegation chain (OpenA2A provenance, phase 3c).

Extends the single-hop provenance (provenance.py) to a full, automatically
reconstructed delegation chain across many agent hops.

Two carriers, mirroring how distributed tracing works:

  * IN-PROCESS (contextvars): when agent A's code invokes agent B's code in the
    same process / shared async context, B's sensor sees the chain A accumulated
    and appends itself. No app effort — the execution context IS the carrier.
    This is the "observe forwarding from inside the process" approach. It is
    correct for sequential and awaited-async in-process delegation; it cannot
    cross a process/service boundary, because execution context does not.

  * CROSS-BOUNDARY (W3C Trace Context): to cross a process/service boundary the
    chain must travel ON the call, like an IP packet's header. We ride the W3C
    `traceparent` standard plus a companion `tracestate` entry carrying the
    correlation id, and a baggage-style header carrying the compact chain. This
    is the same mechanism OpenTelemetry uses to propagate trace context across
    services — we reuse it rather than invent a header.

      inject_context(headers)  -> writes traceparent / tracestate / chain header
      extract_context(headers) -> restores the chain so the next hop continues it

HONEST BOUNDARIES (documented, not hidden):
  * An UN-INSTRUMENTED hop (an agent with no sensor) does not append itself; the
    chain has a gap there. We never fabricate hops we did not observe.
  * A purely LLM-MEDIATED handoff (agent A's prose output becomes agent B's
    prompt, with no call/header) carries no metadata; the chain cannot continue
    across it unless the orchestration layer propagates context out-of-band.
  * Missing chain => emitted as a shorter chain, never a guessed one.
"""

from __future__ import annotations

import contextvars
import re
from typing import Any
from uuid import uuid4

# The accumulated delegation chain for the current in-process flow.
# Each hop: {"agent_id": str, "role": "principal"|"agent"|"tool"|"mcp_server"}.
_chain_ctx: contextvars.ContextVar[list[dict[str, Any]] | None] = contextvars.ContextVar(
    "xaidr_chain_ctx", default=None
)
# Chain-wide correlation id, stable across all hops of one flow.
_corr_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "xaidr_corr_ctx", default=None
)

_TRACEPARENT_RE = re.compile(
    r"^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$"
)


def _new_corr() -> str:
    return uuid4().hex[:16]


def begin_flow(
    *,
    principal: str | None = None,
    correlation_id: str | None = None,
) -> str:
    """Start a new delegation flow in the current context.

    Seeds the chain with the principal (if known) and establishes the
    correlation id shared by every hop. Typically called once at the entry
    point, alongside set_origin(). Returns the correlation id.
    """
    corr = correlation_id or _new_corr()
    _corr_ctx.set(corr)
    chain: list[dict[str, Any]] = []
    if principal:
        chain.append({"agent_id": principal, "role": "principal"})
    _chain_ctx.set(chain)
    return corr


def record_hop(agent_id: str, role: str = "agent") -> list[dict[str, Any]]:
    """Append this agent to the in-process chain (idempotent on the tail).

    Called by the sensor on each scan. If this agent is already the last hop,
    it is not duplicated (a single agent scanning many times is one hop). The
    accumulated chain becomes visible to any agent this one calls in the same
    context.
    """
    chain = _chain_ctx.get()
    if chain is None:
        chain = []
    # idempotent: don't double-append the same agent as the tail
    if not chain or chain[-1].get("agent_id") != agent_id:
        chain = chain + [{"agent_id": agent_id, "role": role}]
        _chain_ctx.set(chain)
    if _corr_ctx.get() is None:
        _corr_ctx.set(_new_corr())
    return chain


def is_flow_active() -> bool:
    """True iff a delegation flow was explicitly established in this context.

    A flow becomes active only after begin_flow() or extract_context() seeded
    the chain / correlation contextvars. A bare scan — no begin_flow, no
    extracted headers, no principal — does NOT make a flow active, and must not
    fabricate provenance. This is the gate that enforces the module's honest
    boundary: no principal in, no provenance out.
    """
    return _chain_ctx.get() is not None or _corr_ctx.get() is not None


def current_chain() -> list[dict[str, Any]] | None:
    chain = _chain_ctx.get()
    return list(chain) if chain else None


def current_correlation_id() -> str | None:
    return _corr_ctx.get()


def clear_flow() -> None:
    _chain_ctx.set(None)
    _corr_ctx.set(None)


def build_provenance(agent_id: str, on_behalf_of: str | None = None) -> dict[str, Any] | None:
    """Build the provenance block from the accumulated multi-hop chain.

    Records this agent as a hop, then returns the schema-shaped provenance dict
    (consumed by schema.to_openA2A via the `provenance` passthrough). Returns
    None only when there is genuinely no provenance (no chain, no principal).

    HONEST BOUNDARY (the fix): if no flow is active AND no principal (on_behalf_of)
    was supplied, return None WITHOUT recording a hop. record_hop() seeds the
    chain/correlation contextvars, so calling it here for a bare scan would both
    fabricate provenance for that scan and leak the seeded chain into later
    unrelated scans sharing this context. The gate must come before record_hop.
    """
    if not is_flow_active() and not on_behalf_of:
        return None

    chain = record_hop(agent_id, "agent")
    corr = current_correlation_id()

    # derive origin/actor from the chain
    origin_agent = None
    actor = None
    if chain:
        origin_agent = chain[0]["agent_id"]
        # actor = the hop immediately before this agent, if any
        if len(chain) >= 2 and chain[-1]["agent_id"] == agent_id:
            actor = chain[-2]["agent_id"]

    prov: dict[str, Any] = {}
    if on_behalf_of:
        prov["on_behalf_of"] = on_behalf_of
    elif chain and chain[0]["role"] == "principal":
        prov["on_behalf_of"] = chain[0]["agent_id"]
    if origin_agent:
        prov["origin_agent"] = origin_agent
    if actor:
        prov["actor"] = actor
    if corr:
        prov["correlation_id"] = corr
    if chain:
        prov["delegation_chain"] = chain
        prov["delegation_depth"] = max(len(chain) - 1, 0)

    return prov or None


# ---------------------------------------------------------------------------
# Cross-boundary propagation — W3C Trace Context (the "header on the call")
# ---------------------------------------------------------------------------
_CHAIN_HEADER = "x-openA2A-chain"   # compact chain carrier (companion to traceparent)
_CORR_HEADER = "x-openA2A-correlation"


def inject_context(headers: dict[str, str] | None = None) -> dict[str, str]:
    """Write the current flow's context into outbound call headers.

    Use when an agent calls another agent/service across a process boundary:
    pass these headers on the outbound request so the next hop continues the
    same chain. Rides W3C Trace Context (traceparent) plus companion headers
    for the correlation id and compact chain.
    """
    headers = dict(headers or {})
    corr = current_correlation_id() or _new_corr()
    chain = current_chain() or []

    # W3C traceparent: version-traceid-spanid-flags. We map correlation id into
    # the trace id space so the trace context and our correlation align.
    trace_id = (corr * 4)[:32].ljust(32, "0")
    span_id = uuid4().hex[:16]
    headers["traceparent"] = f"00-{trace_id}-{span_id}-01"
    headers[_CORR_HEADER] = corr
    # compact chain: "id:role>id:role>..."
    headers[_CHAIN_HEADER] = ">".join(
        f"{h['agent_id']}:{h.get('role','agent')}" for h in chain
    )
    return headers


def extract_context(headers: dict[str, str] | None) -> bool:
    """Restore flow context from inbound call headers (the next hop side).

    Reads the chain + correlation id a caller injected, and seeds this context
    so subsequent record_hop()/build_provenance() continue the same chain.
    Returns True if context was found and restored, False otherwise.
    """
    if not headers:
        return False
    # case-insensitive header lookup
    lower = {k.lower(): v for k, v in headers.items()}

    corr = lower.get(_CORR_HEADER.lower())
    if not corr:
        tp = lower.get("traceparent")
        if tp:
            m = _TRACEPARENT_RE.match(tp.strip())
            if m:
                corr = m.group(1)[:16]
    if not corr:
        return False
    _corr_ctx.set(corr)

    raw_chain = lower.get(_CHAIN_HEADER.lower())
    chain: list[dict[str, Any]] = []
    if raw_chain:
        for part in raw_chain.split(">"):
            if not part:
                continue
            if ":" in part:
                aid, role = part.rsplit(":", 1)
            else:
                aid, role = part, "agent"
            chain.append({"agent_id": aid, "role": role})
    _chain_ctx.set(chain)
    return True
