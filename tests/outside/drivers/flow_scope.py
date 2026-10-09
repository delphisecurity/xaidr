"""Driver: A2 P1, ``xaidr.flow()`` (owner rulings D1 and D3; docs/value-origin-a2-build-spec.md §4 P1).

Run in-process by ``tests/test_value_origin_flow_scope.py`` and from the built
wheel by ``tests/outside/test_p1_flow_scope_from_the_wheel.py``. Prints one JSON
line. Every case is measured, never asserted here, and one case raising does not
hide the others: its row carries the error instead.
"""
import asyncio
import contextlib
import io
import json
import logging
import sys
import sysconfig
import threading
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
    from xaidr.value_origin import ledger_bound
    return {"flow_active": pc.is_flow_active(), "ledger_bound": ledger_bound(),
            "corr": pc.current_correlation_id(), "chain": pc.current_chain()}


def _safe(fn, *a):
    try:
        return fn(*a)
    except BaseException as exc:               # one case's failure must not hide the rest
        return {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}


def scope_that_raises(xaidr):
    """User A's request runs in a scope and RAISES; user B runs next on the same
    pool thread with no flow of its own and makes a tool call before any input."""
    s = _sensor(xaidr, "p1-raise")
    boom = RuntimeError("user A's request failed")

    def user_a():
        with xaidr.flow(principal="a"):
            _quiet(s.scan, f"Email {ALICE} the quarterly report.", direction="input")
            a = _wire(s)
            boom.wire_inside = a
            raise boom

    def user_b():
        start = _state(xaidr)
        return start, _wire(s)

    with ThreadPoolExecutor(max_workers=1) as pool:
        fa = pool.submit(user_a)
        try:
            fa.result()
            raised = None
        except BaseException as exc:
            raised = exc
        start, b = pool.submit(user_b).result()
    return {"a_inside": getattr(boom, "wire_inside", None),
            "a_raised_same_object": raised is boom,
            "b_start": start, "b": b}


def nested(xaidr):
    from xaidr.value_origin import _ledger
    with xaidr.flow(principal="outer") as outer:
        outer_ledger = id(_ledger._LEDGER.get())
        with xaidr.flow(principal="inner") as inner:
            inside = {"corr": inner, "chain_head": _state(xaidr)["chain"][0]["agent_id"],
                      "ledger_is_outer": id(_ledger._LEDGER.get()) == outer_ledger}
        after = _state(xaidr)
        after_ledger_is_outer = id(_ledger._LEDGER.get()) == outer_ledger
    return {"outer": outer, "inside": inside,
            "after_corr_is_outer": after["corr"] == outer,
            "after_chain_head": (after["chain"] or [{}])[0].get("agent_id"),
            "after_ledger_is_outer": after_ledger_is_outer,
            "after_all": _state(xaidr)}


def threads(xaidr, n=8, calls=25):
    """One decorated sync handler, n threads at once through a barrier, ``calls``
    rounds, each thread inside its OWN outer flow. Each call must see only its own
    flow, and the thread's outer flow must be back after every call. A scope
    instance shared across calls cannot do that: its exits would pop another
    thread's tokens, fail to restore, and fall back to clearing (an ERROR log)."""
    from xaidr import provenance_chain as pc
    from xaidr.value_origin import _ledger
    gate = threading.Barrier(n)
    seen, errors, lost_outer, records = [], [], [], []
    lock = threading.Lock()

    class H(logging.Handler):
        def emit(self, rec):
            with lock:
                records.append(rec.levelname)

    @xaidr.flow(principal="svc")
    def handler(i):
        corr, lg = pc.current_correlation_id(), id(_ledger._LEDGER.get())
        try:
            gate.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        # read again after every thread has entered: a shared token or a shared
        # instance would show here as another call's id
        return corr, lg, pc.current_correlation_id(), id(_ledger._LEDGER.get())

    def run(i):
        with xaidr.flow(principal=f"outer-{i}") as outer:
            outer_ledger = id(_ledger._LEDGER.get())
            for _ in range(calls):
                try:
                    c1, l1, c2, l2 = handler(i)
                    with lock:
                        seen.append((c1, l1, c2, l2, outer))
                except BaseException as exc:
                    with lock:
                        errors.append(f"{type(exc).__name__}: {exc}")
                if (pc.current_correlation_id() != outer
                        or id(_ledger._LEDGER.get()) != outer_ledger):
                    with lock:
                        lost_outer.append(i)
        with lock:
            seen.append(("after", _state(xaidr)["flow_active"]))

    h = H()
    logging.getLogger("xaidr").addHandler(h)
    try:
        ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    finally:
        logging.getLogger("xaidr").removeHandler(h)
    calls_seen = [r for r in seen if r[0] != "after"]
    return {"calls": len(calls_seen),
            "distinct_corr": len({r[0] for r in calls_seen}),
            "inner_is_never_outer": all(r[0] != r[4] for r in calls_seen),
            "stable_within_call": all(r[0] == r[2] and r[1] == r[3] for r in calls_seen),
            "outer_lost_after_a_call": len(lost_outer),
            "flow_after_in_any_thread": any(r[1] for r in seen if r[0] == "after"),
            "errors_logged": sum(1 for lvl in records if lvl == "ERROR"),
            "errors": errors[:5], "error_count": len(errors)}


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
    return out


def cross_context_exit(xaidr):
    """Enter in one asyncio task, exit in another: exit must not raise and must
    leave the exiting context with no flow."""
    from xaidr import provenance_chain as pc
    pc._scope_exit_fault_logged = False      # the ERROR is once per PROCESS; make this case order-independent
    cm = xaidr.flow(principal="x")
    records = []

    class H(logging.Handler):
        def emit(self, rec):
            records.append((rec.levelname, rec.name))

    h = H()
    logging.getLogger("xaidr").addHandler(h)
    try:
        async def enter():
            cm.__enter__()

        async def leave():
            pc._corr_ctx.set("stale")                 # something the exit must not keep
            try:
                cm.__exit__(None, None, None)
                return None, _state(xaidr)
            except BaseException as exc:
                return f"{type(exc).__name__}: {exc}", _state(xaidr)

        async def main():
            await asyncio.get_running_loop().create_task(enter())
            return await asyncio.get_running_loop().create_task(leave())

        raised, state = asyncio.run(main())
    finally:
        logging.getLogger("xaidr").removeHandler(h)
    return {"raised": raised, "state_after": state,
            "errors_logged": sum(1 for lvl, _ in records if lvl == "ERROR")}


def collect(xaidr):
    out = {"has_flow": hasattr(xaidr, "flow")}
    for name, fn in (("scope_that_raises", scope_that_raises), ("nested", nested),
                     ("threads", threads), ("refusals", refusals),
                     ("cross_context_exit", cross_context_exit)):
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
