"""Driver: A2 P1, ``xaidr.flow()`` (owner rulings D1 and D3; docs/value-origin-a2-build-spec.md §4 P1).

Run in-process by ``tests/test_value_origin_flow_scope.py`` and from the built
wheel by ``tests/outside/test_p1_flow_scope_from_the_wheel.py``. Prints one JSON
line. Every case is measured, never asserted here, and one case raising does not
hide the others: its row carries the error instead.

The five request vars a scope saves and puts back: chain, correlation id, tiers,
the inbound mark and the value-origin ledger. ``_state`` reads all five, so a
scope that restores only some of them is visible in every case.
"""
import asyncio
import contextlib
import functools
import gc
import io
import json
import sys
import sysconfig
import threading
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor

ALICE = "alice@corp.example"


class _Null:
    def report(self, *a, **k):
        pass


def _sensor(xaidr, agent_id):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return xaidr.Sensor(agent_id=agent_id, value_origin="record", reporter=_Null())


def _quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)


def _wire(sensor, to=ALICE):
    return _quiet(sensor.scan_tool_call, "send_email", {"to": to}).value_origin.wire.value


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


def _inbound_headers(xaidr):
    """Headers an upstream agent at tier 4 would send, made on a throwaway thread."""
    from xaidr import provenance_chain as pc

    def make():
        pc.begin_flow(principal="upstream-user")
        pc.record_hop("upstream-agent", tier=4)
        h = dict(pc.inject_context())
        pc.clear_flow()
        return h
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(make).result()


def scope_that_raises(xaidr):
    """User A's request runs in a scope and RAISES; user B runs next on the same
    pool thread with no flow of its own and makes a tool call before any input."""
    s = _sensor(xaidr, "p1-raise")
    boom = RuntimeError("user A's request failed")

    def user_a():
        with xaidr.flow(principal="a"):
            _quiet(s.scan, f"Email {ALICE} the quarterly report.", direction="input")
            boom.wire_inside = _wire(s)
            raise boom

    def user_b():
        start = _state(xaidr)
        return start, _wire(s)

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


def nested(xaidr):
    with xaidr.flow(principal="outer") as outer:
        before_inner = _state(xaidr)
        with xaidr.flow(principal="inner") as inner:
            inside = _state(xaidr)
        after = _state(xaidr)
    return {"outer": outer, "inner": inner, "inside": inside,
            "before_inner": before_inner, "after_inner": after, "after_all": _state(xaidr)}


def nested_in_inbound(xaidr):
    """A scope opened inside a request that arrived from another agent must keep it
    inbound (privilege tiers), and give it back exactly on exit."""
    from xaidr import provenance_chain as pc
    out = {}

    def request():
        pc.extract_context(_inbound_headers(xaidr))
        out["before"] = _state(xaidr)
        with xaidr.flow(principal="svc"):
            out["inside_inbound"] = pc._inbound_ctx.get()
        out["after"] = _state(xaidr)
        pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(request).result()
    return out


def correlation_id(xaidr):
    with xaidr.flow(principal="x", correlation_id="corr-given-1") as corr:
        inside = _state(xaidr)["corr"]
    return {"yielded": corr, "inside": inside}


def threads(xaidr, n=8, calls=25):
    """One decorated sync handler, n threads at once through a barrier, ``calls``
    rounds, each thread inside its OWN outer flow. Each call must see only its own
    flow, and the thread's outer flow must be back after every call."""
    gate = threading.Barrier(n)
    seen, errors, lost_outer = [], [], []
    lock = threading.Lock()
    faults0 = _faults(xaidr)

    @xaidr.flow(principal="svc")
    def handler(i):
        first = _state(xaidr)
        try:
            gate.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        return first, _state(xaidr)

    def run(i):
        with xaidr.flow(principal=f"outer-{i}") as outer:
            outer_state = _state(xaidr)
            for _ in range(calls):
                try:
                    first, again = handler(i)
                    with lock:
                        seen.append((first, again, outer))
                except BaseException as exc:
                    with lock:
                        errors.append(f"{type(exc).__name__}: {exc}")
                if _state(xaidr) != outer_state:
                    with lock:
                        lost_outer.append(i)
        with lock:
            seen.append(("after", _state(xaidr)))

    ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    calls_seen = [r for r in seen if r[0] != "after"]
    return {"calls": len(calls_seen),
            "distinct_corr": len({r[0]["corr"] for r in calls_seen}),
            "inner_is_never_outer": all(r[0]["corr"] != r[2] for r in calls_seen),
            "stable_within_call": all(r[0] == r[1] for r in calls_seen),
            "outer_lost_after_a_call": len(lost_outer),
            "state_after_in_threads": [r[1] for r in seen if r[0] == "after"],
            "faults": _faults(xaidr) - faults0,
            "errors": errors[:5], "error_count": len(errors)}


SHARED = None


def shared_instance(xaidr, n=8, rounds=50):
    """ONE flow() object, used with ``with`` (not as a decorator) by n threads at
    once, each inside its own outer flow, e.g. a module-level ``SCOPE = flow(...)``."""
    global SHARED
    SHARED = xaidr.flow(principal="service:billing")
    gate = threading.Barrier(n)
    lost, errors = [], []
    lock = threading.Lock()
    faults0 = _faults(xaidr)

    def run(i):
        with xaidr.flow(principal=f"outer-{i}"):
            outer_state = _state(xaidr)
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
                if _state(xaidr) != outer_state:
                    with lock:
                        lost.append(i)

    ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return {"rounds": n * rounds, "outer_lost": len(lost), "faults": _faults(xaidr) - faults0,
            "errors": errors[:5]}


class _AsyncCallable:
    def __init__(self):
        self.ran = False

    async def __call__(self):
        self.ran = True


def refusals(xaidr):
    out = {}

    async def coro():
        return 1

    def gen():
        yield 1

    async def agen():
        yield 1

    for name, fn in (("coroutine", coro), ("generator", gen), ("async_generator", agen)):
        try:
            xaidr.flow(principal="x")(fn)
            out[name] = None
        except TypeError as exc:
            out[name] = str(exc)

    # Callables whose CALL returns a coroutine or generator, invisible to a check of
    # the function itself. The decoration is accepted; the CALL must refuse, and the
    # body must not have run.
    ran = {"wrapped": False}

    async def body():
        ran["wrapped"] = True

    def sync_returning_coroutine():
        return body()

    @functools.wraps(body)
    def wraps_wrapper():
        return body()

    def returns_genexpr():
        return (x for x in range(3))

    obj = _AsyncCallable()
    for name, fn in (("async_callable_object", obj), ("sync_returning_coroutine", sync_returning_coroutine),
                     ("wraps_wrapper_of_async_def", wraps_wrapper), ("returns_generator", returns_genexpr)):
        try:
            deco = xaidr.flow(principal="x")(fn)
            deco()
            out[name] = None
        except TypeError as exc:
            out[name] = str(exc)
    out["bodies_ran"] = ran["wrapped"] or obj.ran
    out["state_after"] = _state(xaidr)

    # a plain sync function is NOT refused
    @xaidr.flow(principal="x")
    def plain():
        return _state(xaidr)["flow_active"]
    out["plain_sync_ran_in_a_flow"] = plain()
    return out


def foreign_exit(xaidr):
    """Enter in one asyncio task; exit in another task that has its OWN flow. The
    exit must not raise and must change NOTHING in the context it runs in."""
    from xaidr import provenance_chain as pc
    cm = xaidr.flow(principal="x")
    faults0 = _faults(xaidr)

    async def enter():
        cm.__enter__()

    async def leave():
        pc.begin_flow(principal="someone-else")          # the exiting task's own request
        mine = _state(xaidr)
        try:
            cm.__exit__(None, None, None)
            raised = None
        except BaseException as exc:
            raised = f"{type(exc).__name__}: {exc}"
        return raised, mine, _state(xaidr)

    async def main():
        loop = asyncio.get_running_loop()
        await loop.create_task(enter())
        return await loop.create_task(leave())

    raised, mine, after = asyncio.run(main())
    return {"raised": raised, "own_flow_untouched": mine == after, "faults": _faults(xaidr) - faults0}


def double_exit(xaidr):
    """A second exit of a finished scope, inside a request that arrived from another
    agent: it must change nothing (the inbound mark especially)."""
    from xaidr import provenance_chain as pc
    out = {}
    faults0 = _faults(xaidr)

    def request():
        pc.extract_context(_inbound_headers(xaidr))
        cm = xaidr.flow(principal="x")
        with cm:
            pass
        before = _state(xaidr)
        try:
            cm.__exit__(None, None, None)
            out["raised"] = None
        except BaseException as exc:
            out["raised"] = f"{type(exc).__name__}: {exc}"
        out["untouched"] = _state(xaidr) == before
        out["inbound_after"] = pc._inbound_ctx.get()
        pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(request).result()
    out["faults"] = _faults(xaidr) - faults0
    return out


def out_of_order(xaidr):
    """A enters, B enters, A exits, B exits: B keeps its flow until it exits, and
    when both are closed the state is what it was before A, never A's."""
    pre = _state(xaidr)
    a, b = xaidr.flow(principal="A"), xaidr.flow(principal="B")
    a.__enter__()
    b_corr = b.__enter__()
    a.__exit__(None, None, None)
    b_still = _state(xaidr)["corr"] == b_corr
    b.__exit__(None, None, None)
    return {"b_kept_its_flow": b_still, "after_both": _state(xaidr), "pre": pre}


def interleaved_generators(xaidr):
    """Two generators, each with a scope in its body, consumed interleaved and then
    closed: the scopes exit out of order in one context."""
    pre = _state(xaidr)

    def g(name):
        with xaidr.flow(principal=name):
            yield 1
            yield 2

    ga, gb = g("user-a"), g("user-b")
    for _ in zip(ga, gb):
        pass
    gb.close()
    ga.close()
    return {"after": _state(xaidr), "pre": pre}


def gc_elsewhere(xaidr):
    """A generator holding an open scope is abandoned on one thread and collected
    by the garbage collector while ANOTHER thread is serving an inbound request.
    The collection must change nothing in that request."""
    from xaidr import provenance_chain as pc
    holder = {}

    def make_and_abandon():
        def g():
            with xaidr.flow(principal="abandoned"):
                yield 1
        it = g()
        next(it)
        cycle = [it]
        cycle.append(cycle)                      # only the cycle collector can free it
        holder["cycle"] = cycle
        pc.clear_flow()                          # this worker thread moves on
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(make_and_abandon).result()

    out = {}
    faults0 = _faults(xaidr)

    def inbound_request():
        pc.extract_context(_inbound_headers(xaidr))
        before = _state(xaidr)
        holder.clear()
        gc.collect()
        out["untouched"] = _state(xaidr) == before
        out["inbound_after"] = pc._inbound_ctx.get()
        pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(inbound_request).result()
    out["faults"] = _faults(xaidr) - faults0
    return out


def enter_fault(xaidr):
    """A fault while saving the flow at entry must not reach the host."""
    from xaidr import value_origin as vo
    orig = vo.ledger_get
    faults0 = _faults(xaidr)

    def boom():
        raise RuntimeError("injected")
    vo.ledger_get = boom
    try:
        with xaidr.flow(principal="x"):
            body_ran = True
        raised = None
    except BaseException as exc:
        raised, body_ran = f"{type(exc).__name__}: {exc}", False
    finally:
        vo.ledger_get = orig
    return {"raised": raised, "body_ran": body_ran, "faults": _faults(xaidr) - faults0,
            "after": _state(xaidr)}


def bind_fault(xaidr):
    """If the fresh ledger cannot be bound, the scope must not run on the ledger it
    was entered in (its records would outlive it there)."""
    from xaidr import value_origin as vo
    from xaidr.value_origin import _ledger
    orig = vo.bind_fresh_ledger
    with xaidr.flow(principal="outer"):
        outer_ledger = id(_ledger._LEDGER.get())
        vo.bind_fresh_ledger = lambda: None
        try:
            with xaidr.flow(principal="inner"):
                inner = _ledger._LEDGER.get()
        finally:
            vo.bind_fresh_ledger = orig
        back = id(_ledger._LEDGER.get()) == outer_ledger
    return {"inner_used_outer_ledger": inner is not None and id(inner) == outer_ledger,
            "outer_back": back}


def collect(xaidr):
    out = {"has_flow": hasattr(xaidr, "flow")}
    for name, fn in (("scope_that_raises", scope_that_raises), ("nested", nested),
                     ("nested_in_inbound", nested_in_inbound), ("correlation_id", correlation_id),
                     ("threads", threads), ("shared_instance", shared_instance),
                     ("refusals", refusals), ("foreign_exit", foreign_exit),
                     ("double_exit", double_exit), ("out_of_order", out_of_order),
                     ("interleaved_generators", interleaved_generators),
                     ("gc_elsewhere", gc_elsewhere), ("enter_fault", enter_fault),
                     ("bind_fault", bind_fault)):
        out[name] = _safe(fn, xaidr)
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
