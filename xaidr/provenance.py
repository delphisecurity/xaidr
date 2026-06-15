"""provenance.py — OBO / delegation context capture (OpenA2A provenance).

Captures the provenance of an agent action: who initiated it, on whose behalf,
and the immediate caller. This is the cross-agent visibility layer — the part
gateways and identity providers cannot see, because it lives inside the agent
process.

Two kinds of provenance, with different sources:

  * APP-SUPPLIED: the human/principal an action is taken on behalf of
    (`on_behalf_of`) and the chain-wide correlation id. These originate at the
    application's auth boundary (an IdP token, a request principal) and the
    sensor cannot invent them — the app supplies them via `set_origin(...)` or a
    per-call `origin_context=`.

  * SENSOR-CAPTURED (single hop, this phase): the immediate caller (`actor`) and
    the current agent. Multi-hop chain reconstruction (full delegation_chain
    across many agents) is deferred to a later phase; the field is defined by the
    schema and emitted when present.

Propagation uses contextvars, so the origin context flows correctly across async
tasks and threads within a request — unlike a thread-local, which breaks under
asyncio.

Resolution order for a scan: per-call origin_context (if given)  >  the
context set via set_origin()/origin_scope()  >  nothing (fields omitted).
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Any, Iterator
from uuid import uuid4

# The active origin context for the current logical flow (async/thread-safe).
_origin_ctx: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "xaidr_origin_ctx", default=None
)


def set_origin(
    *,
    on_behalf_of: str | None = None,
    correlation_id: str | None = None,
    actor: str | None = None,
    **extra: Any,
) -> None:
    """Set the origin context for the current flow (set-once style).

    Typically called once at a request entry point with the authenticated
    principal, e.g. ``set_origin(on_behalf_of="user:alice")``. Applies to all
    subsequent scans in the same context until cleared or overridden.

    A correlation_id is generated if not supplied, so every event in the flow
    shares one chain id.
    """
    ctx = {
        "on_behalf_of": on_behalf_of,
        "correlation_id": correlation_id or uuid4().hex[:16],
        "actor": actor,
    }
    ctx.update(extra)
    _origin_ctx.set(ctx)


def clear_origin() -> None:
    """Clear the origin context for the current flow."""
    _origin_ctx.set(None)


@contextmanager
def origin_scope(
    *,
    on_behalf_of: str | None = None,
    correlation_id: str | None = None,
    actor: str | None = None,
    **extra: Any,
) -> Iterator[None]:
    """Scoped origin context. Restores the previous context on exit.

    Preferred over set_origin() when the principal applies to a bounded block::

        with origin_scope(on_behalf_of="user:alice"):
            agent.run(task)
    """
    ctx = {
        "on_behalf_of": on_behalf_of,
        "correlation_id": correlation_id or uuid4().hex[:16],
        "actor": actor,
    }
    ctx.update(extra)
    token = _origin_ctx.set(ctx)
    try:
        yield
    finally:
        _origin_ctx.reset(token)


def resolve(
    agent_id: str,
    per_call: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build the provenance block for one scan event.

    Merges (per-call override > set context), adds the single-hop fields this
    phase captures, and returns a dict shaped for the schema mapper's
    ``provenance`` passthrough. Returns None if there is no provenance at all
    (so the event simply omits provenance — never emits empty/guessed values).

    Multi-hop ``delegation_chain`` is NOT built here yet (deferred). A minimal
    single-hop chain (principal -> current agent) is emitted when a principal is
    known, which is honest and useful on its own.
    """
    base = _origin_ctx.get()
    if base is None and not per_call:
        return None

    merged: dict[str, Any] = {}
    if base:
        merged.update({k: v for k, v in base.items() if v is not None})
    if per_call:
        merged.update({k: v for k, v in per_call.items() if v is not None})

    if not merged:
        return None

    prov: dict[str, Any] = {}
    on_behalf_of = merged.get("on_behalf_of")
    actor = merged.get("actor")
    correlation_id = merged.get("correlation_id")

    if on_behalf_of:
        prov["on_behalf_of"] = on_behalf_of
    if actor:
        prov["actor"] = actor
    if correlation_id:
        prov["correlation_id"] = correlation_id

    # Single-hop chain when a principal is known: principal -> this agent.
    # (Multi-hop reconstruction across intermediate agents is a later phase.)
    if on_behalf_of:
        chain = [
            {"agent_id": on_behalf_of, "role": "principal"},
        ]
        if actor and actor != on_behalf_of:
            chain.append({"agent_id": actor, "role": "agent"})
        chain.append({"agent_id": agent_id, "role": "agent"})
        prov["delegation_chain"] = chain
        prov["delegation_depth"] = len(chain) - 1
        # origin = the principal that started the flow
        prov["origin_agent"] = on_behalf_of

    return prov or None
