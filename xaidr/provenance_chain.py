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

import contextlib
import contextvars
import dataclasses
import functools
import inspect
import re
import sys
import threading
from typing import Any
from uuid import uuid4
from . import value_origin as _vo
# xaidr.flow()'s save/restore seams are internal: value_origin's public interface
# (__all__) is pinned by tests/value_origin_conformance/test_interface.py.
from .value_origin import _ledger as _vo_ledger

import logging as _logging
_vo_log = _logging.getLogger("xaidr.provenance_chain")


def _vo_fault(where: str) -> None:
    """A value-origin binding fault at a flow seam (owner, after M7: the safety
    layer never crashes what it protects). Logged at ERROR; the flow seam
    carries on, and the call it guards reads ledger_absent / no_flow instead
    of a verdict the ledger could not support."""
    _vo_log.exception("xaidr: value origin's ledger binding faulted in %s; the flow "
                      "continues without a value-origin ledger", where)

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
    # A2 M5 (§1.4): every flow starts with a fresh EXPLICIT value-origin ledger,
    # so a request never inherits the caller's recorded sources.
    try:
        _vo.bind_fresh_ledger()
    except Exception:
        _vo_fault("begin_flow")
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
    # Ruling 3.1 CHANGED (owner, 2026-10-04): record_hop binds NO ledger. It
    # used to bind an explicit one iff none was bound, so a HOST that calls
    # record_hop / build_provenance itself with no begin_flow got a ledger with
    # no owner and no unbind, which outlived the request and, on a reused pool
    # thread, carried user A's principal authority to user B. (The sensor never
    # reaches record_hop without a flow: _resolve_provenance returns early.) Only begin_flow / extract_context
    # bind, and clear_flow unbinds.
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


def propagate_context(fn):
    """Bind `fn` to the CURRENT provenance context so a thread keeps it.

    `contextvars` follow `await`, and they do NOT follow a raw thread. A plain
    `ThreadPoolExecutor.submit(work)` starts with an empty context, so the chain,
    the tiers and the inbound mark are all gone in the worker — and a
    `min_chain_tier_above` policy that gated the action on the calling thread
    ALLOWS it in the pool. Measured: approval_required inline, allowed in the
    pool, approval_required again under `copy_context().run`.

    That is Python's threading semantics, not something this package can patch,
    so what it can do is make the correct form short::

        from xaidr import propagate_context

        with ThreadPoolExecutor() as pool:
            pool.submit(propagate_context(handle_request), payload)

    Equivalent to `contextvars.copy_context().run(fn, ...)`, captured at the
    moment `propagate_context` is called, which is the calling thread.
    """
    import functools

    ctx = contextvars.copy_context()

    @functools.wraps(fn)
    def runner(*args, **kwargs):
        return ctx.run(fn, *args, **kwargs)

    return runner


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
    try:
        _vo.unbind_ledger()                 # A2 M5: the request's ledger ends with it
    except Exception:
        _vo_fault("clear_flow")
    _chain_ctx.set(None)
    _corr_ctx.set(None)
    _tiers_ctx.set(None)
    _inbound_ctx.set(False)
    # The request is over: every xaidr.flow() scope still open in this context ends
    # with it, so none can outlive it into the next request on this thread.
    try:
        open_scopes = _SCOPES.get()
        if open_scopes:
            _close_scopes(open_scopes)
            _SCOPES.set(())
    except Exception:
        _vo_fault("clear_flow")


# ── the request scope (owner, D1, 2026-10-08) ────────────────────────────────
#
# Each open scope is an entry on a per-CONTEXT stack (a ContextVar).
#   * The first scope in a context is FRESH: it saves the five request vars'
#     values, starts a flow, and puts the values back when it exits.
#   * A scope opened while another is open in the same context JOINS it: the
#     same request, so it changes nothing and its exit only pops it. A decorated
#     handler inside middleware's request scope stays part of that request,
#     including the delegation evidence the privilege-tier gate reads.
#   * An exit closes its entry AND every entry opened inside it, so no scope of a
#     request outlives that request. clear_flow() closes them all the same way.
#     A scope closed like that exits later without effect or fault.
#   * An exit with no entry in the context it runs in (another thread or task, a
#     second exit) changes NOTHING there, which may be an unrelated request; it
#     is counted and logged.
#   * A scope held by a generator's body is refused at entry. That body runs
#     whenever, and wherever, the generator is resumed or collected, so its
#     exit could land in any request (P1 fresh-context reviews, 2026-10-08). A
#     generator driven by @contextmanager / @asynccontextmanager is exempt: the
#     with-statement drives it, in order.
# Values are restored, not ContextVar tokens reset: a token restores the state
# from when it was made, which an exit out of order must not bring back.


@dataclasses.dataclass(frozen=True)
class _ScopeEntry:
    owner: Any
    fresh: bool             # True: this scope started the flow and restores `saved` on exit
    saved: tuple | None     # (chain, correlation id, tiers, inbound mark, ledger) at entry
    request: Any = None     # a fresh scope's value-origin request (ruling 4)
    within: Any = None      # the request it was opened in: the entry ends with it
    ledger_only: bool = False   # opened over an active flow: only the ledger is its own
    alive: list = dataclasses.field(default_factory=lambda: [True])   # [False] once it ends


_SCOPES: contextvars.ContextVar[tuple] = contextvars.ContextVar("xaidr_flow_scopes", default=())
_NO_FLOW = (None, None, None, False, None)


def _tier_state_get() -> tuple:
    return (_chain_ctx.get(), _corr_ctx.get(), _tiers_ctx.get(), _inbound_ctx.get())


def _tier_state_put(state: tuple) -> None:
    chain, corr, tiers, inbound = state
    _chain_ctx.set(chain)
    _corr_ctx.set(corr)
    _tiers_ctx.set(tiers)
    _inbound_ctx.set(inbound)


# The chain, correlation id, tiers and inbound mark end with the request they are
# set in, as its value-origin ledger does (value_origin/_ledger.py, THE REQUEST).
_vo_ledger.register_request_state(_tier_state_get, _tier_state_put)
_scope_fault_count = 0
_scope_lock = threading.Lock()


def _scope_fault(what: str) -> None:
    """Count every scope fault; log the 1st, 10th, 100th, ... with the count, so a
    recurring one stays visible without flooding the log."""
    global _scope_fault_count
    with _scope_lock:
        _scope_fault_count += 1
        n = _scope_fault_count
    if str(n).rstrip("0") == "1":
        _vo_log.error("xaidr.flow(): %s (%d scope fault(s) in this process so far)", what, n)


def _saved_state() -> tuple:
    return (_chain_ctx.get(), _corr_ctx.get(), _tiers_ctx.get(), _inbound_ctx.get(),
            _vo_ledger.ledger_get())


def _put_back(saved: tuple) -> None:
    chain, corr, tiers, inbound, ledger = saved
    _vo_ledger.ledger_set(ledger)
    _chain_ctx.set(chain)
    _corr_ctx.set(corr)
    _tiers_ctx.set(tiers)
    _inbound_ctx.set(inbound)


_unexited_flow_warned = False


def _warn_unexited(entries) -> None:
    """Once per process: a scope entered and never exited, found after the request
    it ran in ended. Its flow's chain, tiers and correlation id stay in that
    context for whatever runs there next, so provenance outside a scope can name
    the earlier request's principal; the next outermost scope sets them aside."""
    global _unexited_flow_warned
    if _unexited_flow_warned:
        return
    if not any(e.alive[0] for e in entries):
        return                                # closed by clear_flow() or an outer exit
    _unexited_flow_warned = True
    _vo_log.warning(
        "xaidr.flow(): a scope was entered and never exited, and the request it ran "
        "in has ended. Its value-origin ledger is closed, but its flow's chain and "
        "correlation id stay in this context, so later provenance here can name that "
        "request's principal. Use `with xaidr.flow(...):` so every scope exits. "
        "Logged once per process.")


def _close_scopes(entries) -> None:
    """Mark these entries' scopes as closed by something else, so their own exits,
    whenever they come, change nothing else. Each one's value-origin request stays
    open until that exit, so a ledger bound in between (an input after a
    ``clear_flow()`` inside the scope) is registered with it and closes then."""
    with _scope_lock:
        for e in entries:
            e.owner._closed_elsewhere += 1
            e.alive[0] = False
            if e.request is not None:
                _vo_ledger.request_close(e.request)
                e.owner._pending_requests.append(e.request)


def _held_by_generator() -> bool:
    f = sys._getframe(3)                  # 0 here, 1 _check, 2 __enter__, 3 who entered
    while f is not None and f.f_code.co_filename == contextlib.__file__:
        f = f.f_back                      # ExitStack.enter_context and friends
    if f is None or not (f.f_code.co_flags & (inspect.CO_GENERATOR | inspect.CO_ASYNC_GENERATOR)):
        return False
    d = f.f_back
    return not (d is not None and d.f_code.co_filename == contextlib.__file__
                and d.f_code.co_name in ("__enter__", "__aenter__"))


def _check_not_held_by_generator() -> None:
    try:
        held = _held_by_generator()
    except Exception:
        held = False                      # cannot tell: do not refuse
    if held:
        raise TypeError(
            "xaidr.flow() cannot be opened inside a generator's body: that body runs "
            "whenever and wherever the generator is resumed or collected, so the scope "
            "could close inside an unrelated request. Open the scope around the code "
            "that consumes the generator.")


def _defers_its_body(result: Any) -> bool:
    """A call result whose body has NOT run yet. A Future/Task already runs, in a
    copy of the scope's context, so it is not refused; a sync generator returned by
    a function that did its work first (a WSGI app's body) is not refused either:
    only its iteration runs outside the scope, as the docs say."""
    if inspect.iscoroutine(result) or inspect.isasyncgen(result):
        return True
    return inspect.isawaitable(result) and not _is_future(result)


def _is_future(obj: Any) -> bool:
    try:
        import asyncio
        return asyncio.isfuture(obj)
    except Exception:
        return False


class _FlowScope(contextlib.ContextDecorator):
    """``xaidr.flow()``'s context manager. See :func:`flow`."""

    def __init__(self, principal: str | None, correlation_id: str | None) -> None:
        self._principal = principal
        self._correlation_id = correlation_id
        self._closed_elsewhere = 0
        self._pending_requests: list = []       # requests of entries closed elsewhere

    def __call__(self, func):
        # ContextDecorator wraps the CALL. For these kinds the call only creates a
        # coroutine or generator, and the body runs after the scope has closed.
        if (inspect.iscoroutinefunction(func) or inspect.isasyncgenfunction(func)
                or inspect.isgeneratorfunction(func)):
            raise TypeError(_cannot_decorate(func))

        @functools.wraps(func)
        def inner(*args, **kwds):
            with self:
                result = func(*args, **kwds)
            # What a check of the function itself cannot see (an object with an
            # async __call__, a sync wrapper around an async def) shows in what the
            # call RETURNED: a body that has not run, and will run unscoped.
            if _defers_its_body(result):
                if inspect.iscoroutine(result):
                    result.close()            # never awaited: it must not warn at GC
                raise TypeError(_cannot_decorate(func))
            return result
        return inner

    def __enter__(self) -> str | None:
        _check_not_held_by_generator()
        stack = ()
        try:
            # An entry whose scope has ended is not a request to join: it reaches
            # this context only through a copy made while it was open (a worker
            # task created inside it), and its request is over.
            found = _SCOPES.get()
            stack = tuple(e for e in found
                          if e.alive[0] and (e.within is None or e.within.live))
            if len(stack) != len(found):
                _warn_unexited(found)
            if stack:                                  # an open scope here: join it
                _SCOPES.set(stack + (_ScopeEntry(self, False, None),))
                return current_correlation_id()
            saved = _saved_state()
            dead = len(found) - len(stack)
        except Exception:
            self._open_inert(stack, "could not read the current flow to save it")
            return current_correlation_id()
        request = None
        try:
            # Q-G, decided 2026-10-23: the OUTERMOST scope starts fresh. A ledger,
            # a correlation id or a chain already here is set aside for the scope,
            # and put back on exit (D1). Delegation evidence (the inbound mark, or
            # a hop that is not the principal's own entry, which the tier gate reads
            # as an upstream) is kept with its chain, tiers and correlation id:
            # keeping it can only tighten the gate.
            leftover = _vo_ledger._current()
            delegated = saved[3] or any(isinstance(h, dict) and h.get("role") != "principal"
                                        for h in (saved[0] or ()))
            active = saved[0] is not None or saved[1] is not None
            _log_set_aside(leftover, saved, dead, keep_flow=active and delegated)
            request = _vo_ledger.request_enter(kind="flow")   # ruling 4: the flow is one request
            if active and delegated:
                # Delegation is active: its chain, tiers, correlation id and inbound
                # mark stay exactly as they are, on entry and on exit, so the scope
                # never loosens the tier gate. It gets its own value-origin ledger.
                _vo.bind_fresh_ledger()
                if saved[4] is not None and _vo_ledger.ledger_get() is saved[4]:
                    _vo_ledger.ledger_set(None)
                _SCOPES.set(stack + (_ScopeEntry(self, True, saved, request, ledger_only=True,
                                                 within=_vo_ledger._REQUEST.get()),))
                return current_correlation_id()
            corr = begin_flow(principal=self._principal,
                              correlation_id=self._correlation_id)
            # begin_flow keeps going if the fresh ledger did not bind. A scope must
            # not then run on the ledger it was entered in: run on none instead.
            if saved[4] is not None and _vo_ledger.ledger_get() is saved[4]:
                _vo_ledger.ledger_set(None)
            # Entered over an inbound or tier-delegated context that no scope owns
            # (the plain extract_context, say): keep its chain, tiers and inbound
            # mark, which only tightens the tier gate, and give it its own ledger.
            if saved[3] or any(t is not None for t in (saved[2] or ())):
                _chain_ctx.set(saved[0])
                _tiers_ctx.set(saved[2])
                _inbound_ctx.set(saved[3])
            _SCOPES.set(stack + (_ScopeEntry(self, True, saved, request,
                                             within=_vo_ledger._REQUEST.get()),))
            return corr
        except Exception:
            _vo_ledger.request_exit(request)
            try:
                _put_back(saved)
            except Exception:
                pass
            self._open_inert(stack, "opening the scope faulted")
            return current_correlation_id()
        except BaseException:
            _vo_ledger.request_exit(request)
            try:
                _put_back(saved)
            except Exception:
                pass
            raise

    def _open_inert(self, stack, what: str) -> None:
        _scope_fault(f"{what}; this scope did not open, and its body runs in the flow "
                     "it was entered in")
        try:                                   # so its exit is not a second fault
            _SCOPES.set(stack + (_ScopeEntry(self, False, None),))
        except Exception:
            pass

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            stack = _SCOPES.get()
            i = next((k for k in range(len(stack) - 1, -1, -1) if stack[k].owner is self), None)
            if i is None:
                with _scope_lock:
                    closed = self._closed_elsewhere > 0
                    if closed:
                        self._closed_elsewhere -= 1
                    pending = self._pending_requests.pop() if closed and self._pending_requests else None
                _vo_ledger.request_exit(pending, only=True)
                if not closed:
                    _scope_fault("a scope exited in a context it was not entered in, or "
                                 "exited twice; nothing was changed in the context it exited in")
                return False
            entry, inside = stack[i], stack[i + 1:]
            _close_scopes(inside)                      # opened inside this one: they end with it
            _SCOPES.set(stack[:i])
            entry.alive[0] = False
            _vo_ledger.request_exit(entry.request)     # its ledgers close with it
            if entry.fresh:
                try:
                    _put_back(entry.saved)
                except Exception:
                    try:
                        _put_back(_NO_FLOW)
                    except Exception:
                        pass
                    _scope_fault("putting the flow back faulted; this context was cleared "
                                 "to no flow")
        except Exception:
            _scope_fault("a scope's exit faulted; the flow was left as it was")
        return False                                   # the body's exception propagates


def _log_set_aside(ledger, saved: tuple, dead: int, *, keep_flow: bool) -> None:
    """One warning per occurrence: what an outermost scope found and set aside,
    by kind and count. Never a value: no principal, no correlation id, no
    destination."""
    try:
        parts = []
        if ledger is not None:
            kind = "explicit" if ledger.explicit else "implicit"
            parts.append(f"1 value-origin ledger ({kind}, {len(ledger.entries)} destination "
                         f"entries, {len(ledger.ngrams)} key n-grams)")
        if not keep_flow:
            chain, corr = saved[0], saved[1]
            if corr is not None:
                parts.append("a correlation id")
            if chain:
                parts.append(f"a chain of {len(chain)} entr{'y' if len(chain) == 1 else 'ies'}")
        if dead:
            parts.append(f"{dead} scope{'' if dead == 1 else 's'} left open by an earlier request")
        if parts:
            _vo_log.warning(
                "xaidr.flow(): the outermost scope started fresh and set aside what this "
                "context already held: %s. It is put back when the scope exits.%s",
                ", ".join(parts),
                " The delegation here (inbound mark, upstream hops, tiers) is kept."
                if keep_flow else "")
    except Exception:
        _scope_fault("logging what the scope set aside faulted")


def _cannot_decorate(func) -> str:
    return (f"xaidr.flow() cannot decorate {getattr(func, '__qualname__', func)!r}: calling it "
            "returns a coroutine or another body that has not run yet, and it would run "
            "after the call returns, outside the scope. For an async function, write "
            "`with xaidr.flow(...):` inside its body.")


def flow(*, principal: str | None = None,
         correlation_id: str | None = None) -> _FlowScope:
    """One request's scope: what :func:`begin_flow` starts, ended on exit.

    ::

        with xaidr.flow(principal="user:alice") as correlation_id:
            agent.invoke(...)

        @xaidr.flow(principal="service:billing")     # a SYNC handler
        def handle(request): ...

    On exit, whether the body returned or raised, the flow and its value-origin
    ledger are put back as they were before the scope, so a failed request does
    not leave its flow for the next request on the same worker thread. The plain
    :func:`begin_flow` / :func:`clear_flow` pair still works, but if
    ``clear_flow()`` is skipped, for example because the request raised, the next
    request on that thread inherits the flow.

    A scope opened inside another one JOINS it: it is the same request, so it
    changes nothing (its ``principal=`` is not applied) and yields that request's
    correlation id. The OUTERMOST scope starts fresh: a ledger, correlation id or
    chain the context already holds (a ``begin_flow()`` never cleared, a scope an
    earlier request left open) is set aside until its exit, and a warning names
    what by kind and count. Delegation evidence is kept: over an inbound mark or
    an upstream hop (an ``extract_context()``, a recorded hop) the chain, tiers,
    correlation id and inbound mark stay as they are, so it never loosens the
    privilege-tier gate, and its ``principal=`` is not applied; it gets its own
    value-origin ledger.

    As a decorator it scopes each call. It refuses an ``async def``, a generator or
    async-generator function, and any call that returns a coroutine, because that
    body would run after the call returns, outside the scope. A scope cannot be
    opened inside a generator's body; open it around the code that consumes the
    generator. A sync function's returned generator (a WSGI body, say) is iterated
    outside the scope. A decorated function does not receive the correlation id;
    it can read it with :func:`current_correlation_id`. ``set_origin()`` is not
    part of the flow; use ``origin_scope()`` for that.
    """
    return _FlowScope(principal, correlation_id)


_REQUEST_SCOPES: contextvars.ContextVar[tuple] = contextvars.ContextVar(
    "xaidr_request_scopes", default=())


class _RequestScope:
    """``xaidr.request_scope()``'s context manager. See :func:`request_scope`."""

    def __init__(self) -> None:
        self._opened: list = []              # its records, wherever it is exited

    def __enter__(self) -> None:
        try:
            rec = _vo_ledger.request_enter(accumulate=True, kind="scope")
            self._opened.append(rec)
            _REQUEST_SCOPES.set(_REQUEST_SCOPES.get() + ((self, rec),))
        except Exception:
            _scope_fault("request_scope(): opening it faulted; the body runs in the "
                         "request it was entered in")
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            stack = _REQUEST_SCOPES.get()
            i = next((k for k in range(len(stack) - 1, -1, -1) if stack[k][0] is self), None)
            if i is not None:
                _REQUEST_SCOPES.set(stack[:i])
                for _, rec in reversed(stack[i:]):     # and every one opened inside it
                    _vo_ledger.request_exit(rec)
                if stack[i][1] in self._opened:
                    self._opened.remove(stack[i][1])
            elif len(self._opened) == 1:
                # Exited in another context (a generator closed on another thread):
                # the request still ends, and its ledgers close. With more than one
                # open (one instance shared across threads), which one this exit
                # belongs to cannot be told, so none is ended here.
                _vo_ledger.request_exit(self._opened.pop())
        except Exception:
            _scope_fault("request_scope(): its exit faulted")
        return False                                   # the body's exception propagates

    async def __aenter__(self) -> None:
        return self.__enter__()

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return self.__exit__(exc_type, exc, tb)


def request_scope() -> _RequestScope:
    """One request, for a server that never begins a flow::

        with xaidr.request_scope():
            handle(request)

    Value origin's ledgers bound inside the block (by an input scan, a
    ``begin_flow()``, an ``extract_context()``) end when it exits, on return or
    raise: a closed ledger reads as not bound everywhere, including in work
    started inside the block that outlives it, so no later request reads this
    request's principal authority. It always starts a new request: a ledger
    bound outside it (a ``begin_flow()`` with no request around it, an enclosing
    request's) is hidden inside the block and back after it. A hooked framework
    run inside the block is a request of its own; a ``flow()`` inside it joins it.
    Every input inside the block keeps authorizing for the rest of the block. An
    exit in another context (a generator closed on another thread) still ends
    the request. The chain, correlation id, tiers and inbound mark set inside
    the block are put back at its exit; entry changes none of them, so a block
    inside a delegated request still sees the delegation.

    Each ``ThreadPoolExecutor`` work item, each CrewAI kickoff, each Agents SDK
    ``Runner.run`` and each fresh :func:`flow` is already a request; this is for
    the requests the sensor cannot see begin, such as a server loop that handles
    one request after another on one thread. ``with`` and ``async with`` both
    work; use it inside an ``async def`` handler's body.
    """
    return _RequestScope()


def build_provenance(
    agent_id: str,
    on_behalf_of: str | None = None,
    tier: int | None = None,
) -> dict[str, Any] | None:
    """Build the provenance block from the accumulated multi-hop chain.

    Records this agent as a hop, then returns the schema-shaped provenance dict
    (consumed by schema.to_openA2A via the `provenance` passthrough). Returns
    None only when there is genuinely no provenance (no chain, no principal).

    HONEST BOUNDARY: if no flow is active AND no principal (on_behalf_of)
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

    Calling this function is the trusted-ingress signal: the caller is
    processing a request that arrived from somewhere else. It binds a fresh
    value-origin ledger and sets the inbound mark first, before any header is
    read, and the mark stays set whether or not a chain is restored. With no
    chain, ``is_delegated()`` reports delegation with no provenance, which
    resolves the upstream to tier 4. So less header information never yields a
    looser tier verdict than more, as THREAT_MODEL.md states.
    """
    # An inbound request starts with a fresh ledger, before the inbound mark and
    # every early return, whatever its headers carry.
    try:
        _vo.bind_fresh_ledger()
    except Exception:
        # a raising bind must not skip the inbound mark below, the
        # security-critical half of this function (fault-isolation sweep)
        _vo_fault("extract_context")
    # Set before any early return (see the docstring).
    _inbound_ctx.set(True)
    # The inbound request's chain, tiers and correlation id are what its headers
    # carry and nothing else: a chain already in this context (a scope's
    # principal entry, an earlier request's hops on a reused thread) would name
    # an upstream the request never had, and stop a stripped request from
    # resolving to tier 4.
    _chain_ctx.set(None)
    _tiers_ctx.set(None)
    _corr_ctx.set(None)
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
    # resolves downward to unknown (tier 4 at computation time); nothing here
    # raises a hop's privilege.
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

    # Already set at the top of this function, where it cannot be skipped by an
    # early return. Kept as a no-op restatement so a reader of the success path
    # still sees that this context is inbound.
    _inbound_ctx.set(True)
    return True
