"""Driver: A2 P1, ``xaidr.flow()`` (owner rulings D1 and D3; docs/value-origin-a2-build-spec.md §4 P1).

Run in-process by ``tests/test_value_origin_flow_scope.py`` and from the built
wheel by ``tests/outside/test_p1_flow_scope_from_the_wheel.py``. Prints one JSON
line. Every case is measured, never asserted here, and one case raising does not
hide the others: its row carries the error instead.

``_state`` reads all five request vars (chain, correlation id, tiers, inbound
mark, ledger). Where the privilege-tier gate is at stake, the case reads the
gate's VERDICT on a privileged call, not only the inbound mark: two fresh-context
reviews found the mark kept while the gate opened.
"""
import asyncio
import contextlib
import functools
import gc
import io
import json
import logging
import sys
import sysconfig
import threading
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor

ALICE = "alice@corp.example"
TIER_POLICY = {"version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
               "rules": [{"id": "tier-gate", "effect": "require_approval",
                          "match": {"tools": ["deploy_prod"]},
                          "conditions": {"min_chain_tier_above": 2}}]}


class _Null:
    def report(self, *a, **k):
        pass


def _sensor(xaidr, agent_id, **kw):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return xaidr.Sensor(agent_id=agent_id, reporter=_Null(), **kw)


def _quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)


def _wire(sensor, to=ALICE):
    return _quiet(sensor.scan_tool_call, "send_email", {"to": to}).value_origin.wire.value


_GATE = {}


def _gate(xaidr):
    """The privilege-tier verdict on a privileged call by a tier-1 receiver."""
    if "s" not in _GATE:
        s = _sensor(xaidr, "p1-gate", enforcement_mode="block", privilege_tier=1)
        assert s.set_policy(TIER_POLICY) is True
        _GATE["s"] = s
    return _quiet(_GATE["s"].scan_tool_call, "deploy_prod", {"env": "production"}).action


def _state(xaidr):
    from xaidr import provenance_chain as pc
    from xaidr.value_origin import _ledger
    lg = _ledger._LEDGER.get()
    return {"flow_active": pc.is_flow_active(), "ledger": None if lg is None else id(lg),
            "corr": pc.current_correlation_id(), "chain": pc.current_chain(),
            "tiers": pc._tiers_ctx.get(), "inbound": pc._inbound_ctx.get()}


EMPTY = {"flow_active": False, "ledger": None, "corr": None, "chain": None,
         "tiers": None, "inbound": False}


def _faults(xaidr):
    from xaidr import provenance_chain as pc
    return getattr(pc, "_scope_fault_count", 0)     # absent before the counter existed


def _safe(fn, *a):
    try:
        return fn(*a)
    except BaseException as exc:               # one case's failure must not hide the rest
        return {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}


def _on_one_thread(fn):
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(fn).result()


def _inbound_headers(xaidr):
    """Headers an upstream agent at tier 4 would send, made on a throwaway thread."""
    from xaidr import provenance_chain as pc

    def make():
        pc.begin_flow(principal="upstream-user")
        pc.record_hop("upstream-agent", tier=4)
        h = dict(pc.inject_context())
        pc.clear_flow()
        return h
    return _on_one_thread(make)


def scope_that_raises(xaidr):
    """User A's request runs in a scope and RAISES; user B runs next on the same
    pool thread with no flow of its own and makes a tool call before any input."""
    s = _sensor(xaidr, "p1-raise", value_origin="record")
    boom = RuntimeError("user A's request failed")

    def user_a():
        with xaidr.flow(principal="a"):
            _quiet(s.scan, f"Email {ALICE} the quarterly report.", direction="input")
            boom.wire_inside = _wire(s)
            raise boom

    def user_b():
        return _state(xaidr), _wire(s)

    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            pool.submit(user_a).result()
            raised = None
        except BaseException as exc:
            raised = exc
        start, b = pool.submit(user_b).result()
    tail = traceback.extract_tb(raised.__traceback__)[-1] if raised is not None else None
    return {"a_inside": getattr(boom, "wire_inside", None),
            "a_raised_same_object": raised is boom,
            "a_traceback_tail": None if tail is None else [tail.name, tail.line],
            "b_start": start, "b": b}


def nested_joins(xaidr):
    """A scope inside an open scope is the same request: it changes nothing."""
    with xaidr.flow(principal="outer") as outer:
        before = _state(xaidr)
        with xaidr.flow(principal="inner") as inner:
            inside = _state(xaidr)
        after = _state(xaidr)
    return {"outer": outer, "inner_yielded": inner, "before": before, "inside": inside,
            "after": after, "after_all": _state(xaidr)}


def tier_gate(xaidr):
    """The tier gate's verdict on a privileged call in each composition a host
    reaches, against a tier-4 upstream. 'outside' is the request's own verdict."""
    from xaidr import provenance_chain as pc
    out = {}

    @xaidr.flow(principal="service:billing")
    def decorated_handler():
        return _gate(xaidr)

    def plain_inbound_then_decorated():
        pc.extract_context(_inbound_headers(xaidr))
        out["plain_inbound_outside"] = _gate(xaidr)
        out["plain_inbound_in_decorated_handler"] = decorated_handler()
        out["plain_inbound_after_handler"] = _gate(xaidr)
        pc.clear_flow()

    def request_scope_then_decorated():
        with xaidr.flow():
            pc.extract_context(_inbound_headers(xaidr))
            out["scope_inbound_outside"] = _gate(xaidr)
            out["scope_inbound_in_decorated_handler"] = decorated_handler()
            with xaidr.flow(principal="sub-step"):
                out["scope_inbound_in_nested_principal_scope"] = _gate(xaidr)
        out["scope_inbound_after_scope_state"] = _state(xaidr)

    def in_process_delegation():
        with xaidr.flow(principal="user"):
            pc.record_hop("upstream-agent", tier=4)
            out["delegation_outside"] = _gate(xaidr)
            out["delegation_in_decorated_handler"] = decorated_handler()

    def local_scope():
        with xaidr.flow(principal="user:alice"):
            out["local_inbound_mark"] = pc._inbound_ctx.get()
            out["local_verdict"] = _gate(xaidr)

    for fn in (plain_inbound_then_decorated, request_scope_then_decorated,
               in_process_delegation, local_scope):
        _on_one_thread(fn)
    return out


def inbound_restored(xaidr):
    """extract_context inside a fresh scope: the mark is the scope's, and leaves
    with it. The next local request on the thread is not gated as delegated."""
    from xaidr import provenance_chain as pc
    out = {}

    def request():
        with xaidr.flow():
            pc.extract_context(_inbound_headers(xaidr))
            out["inside_inbound"] = pc._inbound_ctx.get()
        out["after"] = _state(xaidr)
        out["next_local_verdict"] = _gate(xaidr)
    _on_one_thread(request)
    return out


def correlation_id(xaidr):
    with xaidr.flow(principal="x", correlation_id="corr-given-1") as corr:
        inside = _state(xaidr)["corr"]
    return {"yielded": corr, "inside": inside}


def threads(xaidr, n=8, calls=25):
    """One decorated sync handler on n threads at once, ``calls`` rounds. Top level
    it is a fresh request per call; inside a thread's own request scope it joins
    that request. Either way the thread ends clean."""
    gate = threading.Barrier(n)
    seen, errors, changed_outer = [], [], []
    lock = threading.Lock()
    faults0 = _faults(xaidr)

    @xaidr.flow(principal="svc")
    def handler():
        first = _state(xaidr)
        try:
            gate.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        return first, _state(xaidr)

    def run(i):
        for _ in range(calls):
            try:
                first, again = handler()               # top level: a fresh request
                with lock:
                    seen.append(("top", first, again))
            except BaseException as exc:
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}")
        with xaidr.flow(principal=f"request-{i}") as req:
            req_state = _state(xaidr)
            for _ in range(calls):
                try:
                    first, _again = handler()          # inside the request: joins it
                    with lock:
                        seen.append(("joined", first["corr"] == req, None))
                except BaseException as exc:
                    with lock:
                        errors.append(f"{type(exc).__name__}: {exc}")
                if _state(xaidr) != req_state:
                    with lock:
                        changed_outer.append(i)
        with lock:
            seen.append(("after", _state(xaidr), None))

    ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    top = [r for r in seen if r[0] == "top"]
    return {"top_calls": len(top),
            "top_distinct_corr": len({r[1]["corr"] for r in top}),
            "top_stable_within_call": all(r[1] == r[2] for r in top),
            "joined_calls_in_their_request": sum(1 for r in seen if r[0] == "joined" and r[1]),
            "joined_calls": sum(1 for r in seen if r[0] == "joined"),
            "request_changed_by_a_call": len(changed_outer),
            "state_after_in_threads": [r[1] for r in seen if r[0] == "after"],
            "faults": _faults(xaidr) - faults0,
            "errors": errors[:5], "error_count": len(errors)}


SHARED = None


def shared_instance(xaidr, n=8, rounds=50):
    """ONE flow() object, used with ``with`` by n threads at once, each inside its
    own request scope (joins) and at top level (fresh), e.g. a module-level SCOPE."""
    global SHARED
    SHARED = xaidr.flow(principal="service:billing")
    gate = threading.Barrier(n)
    bad, errors = [], []
    lock = threading.Lock()
    faults0 = _faults(xaidr)

    def run(i):
        for _ in range(rounds):
            try:
                with SHARED:
                    try:
                        gate.wait(timeout=10)
                    except threading.BrokenBarrierError:
                        pass
            except BaseException as exc:
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}")
            if _state(xaidr) != EMPTY:
                with lock:
                    bad.append(("top", i))
        with xaidr.flow(principal=f"request-{i}"):
            req = _state(xaidr)
            for _ in range(rounds):
                with SHARED:
                    pass
                if _state(xaidr) != req:
                    with lock:
                        bad.append(("joined", i))

    ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return {"rounds": 2 * n * rounds, "state_wrong": len(bad), "faults": _faults(xaidr) - faults0,
            "errors": errors[:5]}


def recursion(xaidr):
    """A recursive decorated handler re-enters ONE scope object."""
    states = []

    @xaidr.flow(principal="rec")
    def rec(depth):
        states.append(_state(xaidr))
        if depth:
            rec(depth - 1)
        states.append(_state(xaidr))
    rec(3)
    return {"all_in_one_request": len({s["corr"] for s in states}) == 1,
            "after": _state(xaidr)}


class _AsyncCallable:
    def __init__(self):
        self.ran = False

    async def __call__(self):
        self.ran = True


class _Awaitable:
    def __await__(self):
        yield from ()
        return 1


def refusals(xaidr):
    out = {}

    async def coro():
        return 1

    def gen():
        yield 1

    async def agen():
        yield 1

    for name, fn in (("coroutine_function", coro), ("generator_function", gen),
                     ("async_generator_function", agen)):
        try:
            xaidr.flow(principal="x")(fn)
            out[name] = None
        except TypeError as exc:
            out[name] = str(exc)

    ran = {"wrapped": False}

    async def body():
        ran["wrapped"] = True

    def sync_returning_coroutine():
        return body()

    @functools.wraps(body)
    def wraps_wrapper():
        return body()

    def returns_async_generator():
        return agen()

    def returns_custom_awaitable():
        return _Awaitable()

    obj = _AsyncCallable()
    for name, fn in (("async_callable_object", obj), ("sync_returning_coroutine", sync_returning_coroutine),
                     ("wraps_wrapper_of_async_def", wraps_wrapper),
                     ("returns_async_generator", returns_async_generator),
                     ("returns_custom_awaitable", returns_custom_awaitable)):
        try:
            xaidr.flow(principal="x")(fn)()
            out[name] = None
        except TypeError as exc:
            out[name] = str(exc)
    out["bodies_ran"] = ran["wrapped"] or obj.ran

    # NOT refused: a WSGI-style body (the work ran in the scope), a Future (it runs
    # in a copy of the scope's context), and a plain sync function.
    @xaidr.flow(principal="x")
    def wsgi_app():
        return (b for b in [b"ok"])           # the response body, iterated by the server
    out["wsgi_body_returned"] = list(wsgi_app()) == [b"ok"]

    async def future_case():
        loop = asyncio.get_running_loop()

        @xaidr.flow(principal="x")
        def schedules():
            return loop.create_task(asyncio.sleep(0, result="done"))
        return await schedules()
    try:
        out["future_returned"] = asyncio.run(future_case())
    except TypeError as exc:
        out["future_returned"] = f"refused: {exc}"

    @xaidr.flow(principal="x")
    def plain():
        return _state(xaidr)["flow_active"]
    out["plain_sync_ran_in_a_flow"] = plain()
    out["state_after"] = _state(xaidr)
    return out


def generator_held(xaidr):
    out = {}

    def g():
        with xaidr.flow(principal="lib"):
            yield 1

    try:
        next(g())
        out["sync_generator"] = None
    except TypeError as exc:
        out["sync_generator"] = str(exc)

    async def ag():
        with xaidr.flow(principal="lib"):
            yield 1

    async def drive():
        return await ag().__anext__()
    try:
        asyncio.run(drive())
        out["async_generator"] = None
    except TypeError as exc:
        out["async_generator"] = str(exc)

    def g_exitstack():
        with contextlib.ExitStack() as st:
            st.enter_context(xaidr.flow(principal="lib"))
            yield 1
    try:
        next(g_exitstack())
        out["exitstack_in_generator"] = None
    except TypeError as exc:
        out["exitstack_in_generator"] = str(exc)

    @contextlib.contextmanager
    def request_scope():
        with xaidr.flow(principal="cm") as corr:
            yield corr
    with request_scope() as corr:
        out["contextmanager_wrapper_works"] = _state(xaidr)["corr"] == corr and corr is not None
    out["after"] = _state(xaidr)
    return out


def foreign_exit(xaidr):
    """Enter in one asyncio task; exit in another task that is serving its OWN
    request inside its own scope. The stray exit must change nothing there."""
    from xaidr import provenance_chain as pc
    cm = xaidr.flow(principal="x")
    faults0 = _faults(xaidr)

    async def enter():
        cm.__enter__()

    async def leave():
        with xaidr.flow(principal="someone-else"):
            pc.extract_context(_inbound_headers(xaidr))
            verdict = _gate(xaidr)                    # the gate records its own hop: read it first
            mine = _state(xaidr)
            try:
                cm.__exit__(None, None, None)
                raised = None
            except BaseException as exc:
                raised = f"{type(exc).__name__}: {exc}"
            untouched = mine == _state(xaidr)
            return raised, untouched, verdict, _gate(xaidr)

    async def main():
        loop = asyncio.get_running_loop()
        await loop.create_task(enter())
        return await loop.create_task(leave())

    raised, untouched, before, after = asyncio.run(main())
    return {"raised": raised, "own_request_untouched": untouched, "verdict_before": before,
            "verdict_after": after, "faults": _faults(xaidr) - faults0}


def double_exit(xaidr):
    """A second exit of a finished scope, inside an inbound request that runs in its
    own scope: it must change nothing, the tier gate especially."""
    from xaidr import provenance_chain as pc
    out = {}
    faults0 = _faults(xaidr)

    def request():
        with xaidr.flow():
            pc.extract_context(_inbound_headers(xaidr))
            cm = xaidr.flow(principal="x")
            with cm:
                pass
            out["verdict_before"] = _gate(xaidr)      # the gate records its own hop: read it first
            before = _state(xaidr)
            try:
                cm.__exit__(None, None, None)
                out["raised"] = None
            except BaseException as exc:
                out["raised"] = f"{type(exc).__name__}: {exc}"
            out["untouched"] = _state(xaidr) == before
            out["verdict_after"] = _gate(xaidr)
    _on_one_thread(request)
    out["faults"] = _faults(xaidr) - faults0
    return out


def outer_closes_inner(xaidr):
    """Scopes closed out of order: an outer scope's exit closes everything opened
    inside it, and the inner exits later change nothing and are not faults."""
    faults0 = _faults(xaidr)
    pre = _state(xaidr)
    a, b, c = xaidr.flow(principal="A"), xaidr.flow(principal="B"), xaidr.flow(principal="C")
    a.__enter__()
    b.__enter__()
    c.__enter__()
    b.__exit__(None, None, None)              # closes B and C
    after_b = _state(xaidr)
    a_corr = after_b["corr"]
    c.__exit__(None, None, None)              # already closed by B
    after_c = _state(xaidr)
    a.__exit__(None, None, None)
    return {"a_still_open_after_b": a_corr is not None and after_b == after_c,
            "after_all": _state(xaidr), "pre": pre, "faults": _faults(xaidr) - faults0}


def request_raises_with_inner_open(xaidr):
    """User A's request scope raises while a scope opened inside it is still open
    (entered by hand, never exited). User B, next on the thread, starts clean."""
    s = _sensor(xaidr, "p1-inner-open", value_origin="record")

    def user_a():
        with xaidr.flow(principal="a"):
            xaidr.flow(principal="lib").__enter__()
            _quiet(s.scan, f"Email {ALICE} the quarterly report.", direction="input")
            raise RuntimeError("user A failed")

    def user_b():
        return _state(xaidr), _wire(s)

    def user_c():                             # opens a scope of its own: it must be FRESH
        with xaidr.flow(principal="c") as corr:
            return corr is not None and _state(xaidr)["corr"] == corr

    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            pool.submit(user_a).result()
        except RuntimeError:
            pass
        start, b = pool.submit(user_b).result()
        c_fresh = pool.submit(user_c).result()
    return {"b_start": start, "b": b, "c_scope_fresh": c_fresh}


def clear_flow_closes_scopes(xaidr):
    """A request opens a scope that never exits and ends by the plain clear_flow().
    The next request's scope must start FRESH, not join the leftover, and the
    leftover's late exit must change nothing and not be a fault."""
    from xaidr import provenance_chain as pc
    faults0 = _faults(xaidr)
    cm = xaidr.flow(principal="x")
    cm.__enter__()
    pc.clear_flow()                           # the request is over, by the plain API
    mid = _state(xaidr)
    with xaidr.flow(principal="next") as nxt:
        fresh = nxt is not None and _state(xaidr)["corr"] == nxt
        before = _state(xaidr)
        cm.__exit__(None, None, None)         # the closed scope's late exit
        untouched = _state(xaidr) == before
    return {"mid": mid, "next_is_fresh": fresh, "late_exit_untouched": untouched,
            "after": _state(xaidr), "faults": _faults(xaidr) - faults0}


def enter_faults(xaidr):
    from xaidr import provenance_chain as pc
    from xaidr.value_origin import _ledger
    out = {}
    for where, target, attr in (("save", _ledger, "ledger_get"), ("begin_flow", pc, "_new_corr")):
        orig = getattr(target, attr)
        faults0 = _faults(xaidr)

        def boom(*a, **k):
            raise RuntimeError("injected")
        setattr(target, attr, boom)
        try:
            with xaidr.flow(principal="x"):
                body_ran = True
            raised = None
        except BaseException as exc:
            raised, body_ran = f"{type(exc).__name__}: {exc}", False
        finally:
            setattr(target, attr, orig)
        out[where] = {"raised": raised, "body_ran": body_ran,
                      "faults": _faults(xaidr) - faults0, "after": _state(xaidr)}
    return out


def exit_fault(xaidr):
    """A fault while putting the flow back must not leave the closed scope's flow."""
    from xaidr.value_origin import _ledger as vo
    faults0 = _faults(xaidr)
    orig = vo.ledger_set
    with xaidr.flow(principal="x"):
        calls = {"n": 0}

        def flaky(v):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("injected")
            return orig(v)
        vo.ledger_set = flaky
    vo.ledger_set = orig
    return {"after": _state(xaidr), "faults": _faults(xaidr) - faults0}


def fault_log(xaidr):
    """The 1st scope fault in a process is logged at ERROR with the running count."""
    from xaidr import provenance_chain as pc
    records = []

    class H(logging.Handler):
        def emit(self, rec):
            records.append((rec.levelname, rec.getMessage()))
    h = H()
    logging.getLogger("xaidr").addHandler(h)
    saved = pc._scope_fault_count
    try:
        pc._scope_fault_count = 0
        cm = xaidr.flow()
        cm.__exit__(None, None, None)             # a stray exit: fault 1
        cm.__exit__(None, None, None)             # fault 2: not logged
    finally:
        pc._scope_fault_count = saved + 2
        logging.getLogger("xaidr").removeHandler(h)
    return {"records": records}


def bind_fault(xaidr):
    """If the fresh ledger cannot be bound, the scope must not run on a ledger that
    was bound before it (its records would outlive it there)."""
    from xaidr import provenance_chain as pc
    from xaidr import value_origin as vo
    from xaidr.value_origin import _ledger
    orig = vo.bind_fresh_ledger
    out = {}

    def run():
        pc.begin_flow(principal="plain")          # a plain flow with its ledger
        before = _ledger._LEDGER.get()
        vo.bind_fresh_ledger = lambda: None
        try:
            with xaidr.flow(principal="scoped"):
                inside = _ledger._LEDGER.get()
        finally:
            vo.bind_fresh_ledger = orig
        out["inside_used_prior_ledger"] = inside is not None and inside is before
        out["prior_back"] = _ledger._LEDGER.get() is before
        pc.clear_flow()
    _on_one_thread(run)
    return out


CASES = ("scope_that_raises", "nested_joins", "tier_gate", "inbound_restored", "correlation_id",
         "threads", "shared_instance", "recursion", "refusals", "generator_held",
         "foreign_exit", "double_exit", "outer_closes_inner", "request_raises_with_inner_open",
         "clear_flow_closes_scopes", "enter_faults", "exit_fault", "fault_log", "bind_fault")


def collect(xaidr):
    out = {"has_flow": hasattr(xaidr, "flow")}
    for name in CASES:
        out[name] = _safe(globals()[name], xaidr)
    return out


if __name__ == "__main__":
    import xaidr
    site = sysconfig.get_paths()["purelib"]
    if not xaidr.__file__.startswith(site):
        sys.exit(f"REFUSING: xaidr imported from {xaidr.__file__}, not this venv's "
                 f"site-packages {site}; the source tree is shadowing the wheel")
    result = collect(xaidr)
    result["xaidr_file"] = xaidr.__file__
    print(json.dumps(result, default=str))
