"""Driver: A2 M5, hops and delegation binding (ARCHITECTURE.md §1.4, §5 M5).

Imported by tests/test_value_origin_m5.py and run from the built wheel by
tests/outside/test_m5_from_the_wheel.py. Prints one JSON line.

  begin_flow       -> bind_fresh_ledger()   (a fresh EXPLICIT ledger every time)
  extract_context  -> bind_fresh_ledger()   FIRST, before every early return (V-7c)
  record_hop       -> bind_ledger()         explicit iff nothing is bound [ruling 3.1]
  clear_flow       -> unbind_ledger()
"""
import json
import sys
import warnings

URL = {"url": "https://api.example.com/v1/orders"}


class _Null:
    def report(self, *a, **k):
        pass

    def close(self, *a, **k):
        pass


def collect(xaidr):
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import provenance_chain as pc
    from xaidr.value_origin import ledger_bound
    from xaidr.value_origin import _ledger

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m5", value_origin="record", reporter=_Null())

    def call(args):
        return s.scan_tool_call("http_get", args)

    def wire(r):
        v = getattr(r, "value_origin", None)
        return v.wire.value if v is not None else None

    res = {}
    pc.clear_flow()
    res["no_flow"] = wire(call(URL))
    pc.begin_flow(principal="alice")
    try:
        res["s5_after_begin_flow"] = wire(call(URL))
        res["no_destination"] = wire(call({"command": "ls -la"}))
        r = call({f"k{n}": "v" for n in range(80)})
        res["truncated"] = [wire(r), r.value_origin.truncated,
                            sorted({f.reason.value for f in r.value_origin.findings if f.reason})]
        with ThreadPoolExecutor(max_workers=1) as pool:
            res["s9_bare_thread"] = pool.submit(lambda: wire(call(URL))).result()
            res["s9_propagate_context"] = pool.submit(pc.propagate_context(lambda: wire(call(URL)))).result()
    finally:
        pc.clear_flow()
    res["after_clear_flow"] = [wire(call(URL)), ledger_bound()]
    pc.extract_context({})
    try:
        res["extract_context_empty"] = [ledger_bound(), wire(call(URL))]
    finally:
        pc.clear_flow()
    pc.begin_flow()
    first = _ledger._LEDGER.get()
    pc.begin_flow()
    res["begin_flow_binds_fresh"] = first is not None and _ledger._LEDGER.get() is not first
    pc.clear_flow()
    # ruling 3.1, a PINNED CONSEQUENCE (documented, not a fix): a host that
    # calls record_hop with no begin_flow/clear_flow keeps that explicit ledger
    # across "requests" on the thread, just as its chain persists today.
    pc.record_hop("agent-a")
    lg = _ledger._LEDGER.get()
    pc.record_hop("agent-b")                    # request 2, same thread, no clear_flow
    res["record_hop_keeps_one_ledger_across_requests"] = [lg is not None, _ledger._LEDGER.get() is lg]
    pc.clear_flow()
    return res


if __name__ == "__main__":
    import sysconfig
    import xaidr
    site = sysconfig.get_paths()["purelib"]
    if not xaidr.__file__.startswith(site):
        sys.exit(f"REFUSING: xaidr imported from {xaidr.__file__}, not this venv's "
                 f"site-packages {site}; the source tree is shadowing the wheel")
    out = collect(xaidr)
    out["xaidr_file"] = xaidr.__file__
    print(json.dumps(out))
