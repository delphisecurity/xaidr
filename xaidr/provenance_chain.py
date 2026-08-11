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
# PRIVILEGE TIERS, positionally aligned to _chain_ctx. Entry i is the tier
# claimed for hop i, or None when unknown (un-instrumented hop, absent header,
# malformed value).
#
# Parallel rather than a "tier" key on each hop dict, for two independent
# reasons. On the wire, the compact chain encodes "id:role" and is decoded with
# rsplit(":", 1), so a third field silently CORRUPTS it — "agent-a:agent:4"
# parses as agent_id="agent-a:agent", role="4". (Verified against the live
# decoder before this was built.) In process, the hop dicts are emitted verbatim
# inside provenance.delegation_chain and are asserted by exact equality
# downstream, so an extra key is an unannounced schema change. A parallel list
# has neither problem, and it keeps the in-process representation the same shape
# as the separate positional header it travels in.
_tiers_ctx: contextvars.ContextVar[list[int | None] | None] = contextvars.ContextVar(
    "xaidr_tiers_ctx", default=None
)
# True when this flow's context was RESTORED FROM AN INBOUND CALL rather than
# started locally. See is_delegated() for why the distinction decides whether an
# absent chain means "no delegation" or "delegation with no provenance".
_inbound_ctx: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "xaidr_inbound_ctx", default=False
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
    tiers: list[int | None] = []
    if principal:
        chain.append({"agent_id": principal, "role": "principal"})
        # The principal is the human/originating identity, not an agent, so it
        # has no privilege tier of its own until one is claimed for it.
        tiers.append(None)
    _chain_ctx.set(chain)
    _tiers_ctx.set(tiers)
    # begin_flow starts a LOCAL flow — this agent is the origin, not a callee.
    _inbound_ctx.set(False)
    return corr


def _aligned_tiers(chain_len: int) -> list[int | None]:
    """The tier list, forced to ``chain_len`` entries.

    Alignment is an invariant the rest of the module relies on, and a drifted
    list would silently attribute one hop's tier to another. Padding is with
    ``None`` (unknown -> lowest privilege), so a repair can only tighten.
    """
    tiers = list(_tiers_ctx.get() or [])
    if len(tiers) < chain_len:
        tiers.extend([None] * (chain_len - len(tiers)))
    elif len(tiers) > chain_len:
        tiers = tiers[:chain_len]
    return tiers


def record_hop(
    agent_id: str,
    role: str = "agent",
    tier: int | None = None,
) -> list[dict[str, Any]]:
    """Append this agent to the in-process chain (idempotent on the tail).

    Called by the sensor on each scan. If this agent is already the last hop,
    it is not duplicated (a single agent scanning many times is one hop). The
    accumulated chain becomes visible to any agent this one calls in the same
    context.

    ``tier`` records the agent's CONFIGURED privilege tier alongside the hop, in
    the parallel tier list. When the agent is already the tail, its tier is
    refreshed rather than appended, so re-scanning does not lose it.
    """
    chain = _chain_ctx.get()
    if chain is None:
        chain = []
    tiers = _aligned_tiers(len(chain))
    # idempotent: don't double-append the same agent as the tail
    if not chain or chain[-1].get("agent_id") != agent_id:
        chain = chain + [{"agent_id": agent_id, "role": role}]
        tiers = tiers + [tier]
        _chain_ctx.set(chain)
    elif tier is not None:
        tiers[-1] = tier
    _tiers_ctx.set(tiers)
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


def mark_inbound() -> None:
    """Mark the current context as having arrived from another agent.

    Called by the sensor when it scans a RECEIVED A2A message. Together with
    extract_context() this is what lets :func:`is_delegated` tell a stripped
    delegation from no delegation at all — see that function.
    """
    _inbound_ctx.set(True)


def is_delegated(self_agent_id: str | None = None) -> bool:
    """Did the work in this context arrive from somewhere else?

    THIS IS THE DISCRIMINATOR the whole feature turns on, so it is worth being
    explicit about what goes wrong without it.

    ``record_hop`` only extends a chain that a flow already established, so a
    cold start — no ``begin_flow``, no inbound headers — leaves the chain
    ``None`` even after a scan. That is the NORMAL state of most agents, which
    are not instrumented for provenance at all. If "no chain" were read as
    "unknown upstream, therefore 4", every un-instrumented tier-1 agent would
    compute ``max(1, 4) = 4``, exceed its own gate, and halt ALL of its own
    privileged work. The feature would break the majority of deployments the day
    it shipped.

    So absence is not one condition, it is two, and they get opposite answers:

      * NO DELEGATION — nothing arrived; the chain is empty or names only this
        agent. This is the agent's own work and only its OWN tier applies.
      * DELEGATION WITH NO PROVENANCE — something DID arrive (an A2A receive, or
        an inbound request context) but carries no usable chain. The upstream is
        real and unidentified, so it is tier 4. This is also exactly what header
        STRIPPING looks like, which is why stripping must land here: an attacker
        who removes the headers has to end up worse off, not invisible.

    True when any of:
      1. the context was restored from an inbound call (``extract_context``), or
      2. this scan is a received A2A message (``mark_inbound``), or
      3. the chain contains a hop that is not this agent — someone else is in it,
         whatever the transport was (covers in-process delegation, where no
         header ever existed).
    """
    if _inbound_ctx.get():
        return True
    chain = _chain_ctx.get() or []
    for hop in chain:
        if hop.get("agent_id") != self_agent_id:
            return True
    return False


def delegating_hop_tiers(self_agent_id: str | None = None) -> list[int | None]:
    """Tiers of the hops OTHER than this agent, in chain order.

    The caller supplies its own tier separately (from configuration, never from
    the wire), so this deliberately returns only the upstream claims.

    The FIRST hop is skipped when its role is ``principal`` AND no tier was
    claimed for it. That hop is the human or originating identity that
    ``begin_flow`` seeds — a person, not an agent, with no privilege tier. Left
    in, every ordinary flow that names its principal would inherit an unknown
    tier of 4 and gate its own work, which is the same over-block this feature
    exists to avoid. A tier explicitly claimed at position 0 is honoured, so a
    deployer who does tier their principals is not overridden.
    """
    chain = _chain_ctx.get() or []
    tiers = _aligned_tiers(len(chain))
    out: list[int | None] = []
    for idx, hop in enumerate(chain):
        if hop.get("agent_id") == self_agent_id:
            continue
        if idx == 0 and hop.get("role") == "principal" and tiers[idx] is None:
            continue
        out.append(tiers[idx])
    return out


def has_upstream_hop(self_agent_id: str | None = None) -> bool:
    """True when the chain names ANY hop other than this agent.

    Distinct from :func:`delegating_hop_tiers` being non-empty, and the
    difference is load-bearing. That function excludes an untiered principal,
    so a perfectly well-provenanced human-originated flow — chain
    ``[alice:principal, assistant:agent]`` — yields an EMPTY tier list. Without
    this predicate the caller cannot tell that from a chain that was stripped to
    nothing, and would apply its unknown-upstream fallback to both, gating every
    ordinary flow that names its principal.

    Here: the principal counts as an upstream hop (it is provenance, we simply
    do not tier humans), so only a genuinely empty or self-only chain is
    "nothing arrived that we can see".
    """
    for hop in _chain_ctx.get() or []:
        if hop.get("agent_id") != self_agent_id:
            return True
    return False


def current_tiers() -> list[int | None]:
    """The tier list aligned to the current chain (diagnostics/telemetry)."""
    return _aligned_tiers(len(_chain_ctx.get() or []))


def clear_flow() -> None:
    _chain_ctx.set(None)
    _corr_ctx.set(None)
    _tiers_ctx.set(None)
    _inbound_ctx.set(False)


def build_provenance(
    agent_id: str,
    on_behalf_of: str | None = None,
    tier: int | None = None,
) -> dict[str, Any] | None:
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

    chain = record_hop(agent_id, "agent", tier=tier)
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
# Privilege tiers, POSITIONALLY ALIGNED to _CHAIN_HEADER, comma-separated, with
# an empty field for an unknown hop: "4,,1".
#
# A SEPARATE header rather than a third field in the chain encoding, because the
# chain decodes with rsplit(":", 1): "agent-a:agent:4" would parse as
# agent_id="agent-a:agent", role="4", silently corrupting every hop rather than
# failing. A separate header is also the only version-safe option — an old
# sensor ignores an unknown header and keeps working, while a new sensor reading
# an old caller's headers simply finds it absent and defaults every hop to 4.
_TIERS_HEADER = "x-openA2A-tiers"


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
    # privilege tiers, positionally aligned to the chain above; empty = unknown
    tiers = _aligned_tiers(len(chain))
    headers[_TIERS_HEADER] = ",".join("" if t is None else str(t) for t in tiers)
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

    # Privilege tiers from the separate positional header. Every failure mode
    # resolves DOWNWARD to unknown (-> tier 4 at computation time); nothing here
    # can ever raise a hop's privilege, which is what makes stripping or
    # mangling the header a losing move for an attacker rather than a bypass.
    from .privilege_tiers import parse_claimed_tier

    raw_tiers = lower.get(_TIERS_HEADER.lower())
    tiers: list[int | None] = [None] * len(chain)
    if raw_tiers is not None:
        claimed = [parse_claimed_tier(p) for p in str(raw_tiers).split(",")]
        # A length mismatch means we cannot say WHICH hop each value belongs to.
        # Attributing them by position anyway would assign one agent's tier to
        # another, so every hop is unknown instead — the honest answer, and the
        # conservative one.
        if len(claimed) == len(chain):
            tiers = claimed
    _tiers_ctx.set(tiers)

    # This context was restored from an INBOUND call: whatever happens next is
    # work that arrived from another agent, even if the chain header was absent
    # or stripped. is_delegated() reads this to tell "no delegation" from
    # "delegation whose provenance was removed".
    _inbound_ctx.set(True)
    return True
