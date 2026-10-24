"""Driver: A2 M4, tool-call evaluation in RECORD, through the INSTALLED sensor.

Imported by tests/test_value_origin_m4.py (in-tree) and run by
tests/outside/harness.py with ``python -I`` in a fresh venv (from the wheel):
one code path, two vantage points. Prints one JSON line.

What it observes, per ARCHITECTURE.md §5 M4:
  * every tool-call exit carries ``ScanResult.value_origin`` (C-13): the main
    path and the five non-normal ones, each FIRST shown to have reached its own
    marker, so a fault that never reached its path cannot pass;
  * OFF attaches nothing;
  * ``no_flow`` with no flow; ``ledger_absent`` after ``begin_flow()`` (nothing
    binds a ledger until M5, and the wire says so);
  * Q6 as the owner ruled it: the FIRST tool call a sensor sees under
    ``no_flow`` logs ONE warning naming ``begin_flow()``; later ones, and calls
    inside a flow, log none.
"""
import json
import logging
import sys
import warnings

PATHS = ("main", "circuit", "gate", "bounds", "scan_error", "not_scannable")
MARK = {"main": None, "circuit": "CIRCUIT_BREAKER_OPEN", "gate": "M4_GATE",
        "bounds": "fail_closed", "scan_error": "SCAN_FAILED_OPEN", "not_scannable": "NOT_SCANNABLE"}
EMITTER = {"main": "_scan_tool_call_impl/_post_scan_gate",
           "circuit": "_emit_circuit_open_verdict", "gate": "_emit_gate_verdict",
           "bounds": "_emit_fail_closed", "scan_error": "_emit_scan_error",
           "not_scannable": "_emit_not_scannable"}


class _Null:
    def report(self, *a, **k):
        pass

    def close(self, *a, **k):
        pass


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


def _line(r):
    return f"{r.action} {r.category or '-'} {','.join(r.rules or [])}"


def _wire(r):
    v = getattr(r, "value_origin", None)
    return getattr(getattr(v, "wire", None), "value", None) if v is not None else None


def collect(xaidr):
    from xaidr import CircuitBreaker, ScanResult, SensorExtension
    import xaidr.sensor as sensor_module
    from xaidr.provenance_chain import begin_flow, clear_flow

    def sensor(mode, **kw):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return xaidr.Sensor(agent_id="m4", value_origin=mode, reporter=_Null(), **kw)

    class _Gate(SensorExtension):
        name = "m4-gate"

        def gate(self, req):
            if req.direction == "tool_call":
                return ScanResult(action="blocked", score=1.0, category="m4_gate", rules=["M4_GATE"])
            return None

    def exits(mode):
        clear_flow()
        out = {}
        out["main"] = sensor(mode).scan_tool_call("http_get", {"url": "https://api.example.com/v1"})
        # an open circuit gates only in block mode (ARCHITECTURE.md M8 note)
        breaker = sensor(mode, enforcement_mode="block",
                         circuit_breaker=CircuitBreaker(rate_threshold=1, cooldown_sec=None))
        breaker.scan_tool_call("warm_up", {"command": "ls"})
        out["circuit"] = breaker.scan_tool_call("run_command", {"command": "ls"})
        out["gate"] = sensor(mode, extensions=[_Gate()]).scan_tool_call("run_command", {"command": "ls"})
        wide = {f"k{n}": "v" for n in range(80)}
        out["bounds"] = sensor(mode, fail_closed=("bounds",)).scan_tool_call("run_command", wide)
        real = sensor_module.classify

        def boom(*a, **k):
            raise RuntimeError("m4 injected classify fault")

        sensor_module.classify = boom
        try:
            out["scan_error"] = sensor(mode).scan_tool_call("run_command", {"command": "ls"})
        finally:
            sensor_module.classify = real
        out["not_scannable"] = sensor(mode).scan_tool_call(12345, {"command": "ls"})
        return {p: {"marker": MARK[p] is None or MARK[p] in _line(r), "line": _line(r),
                    "wire": _wire(r)} for p, r in out.items()}

    res = {"paths": {m: exits(m) for m in ("off", "record", "enforce")}}

    clear_flow()
    s = sensor("record")
    res["no_flow"] = _wire(s.scan_tool_call("http_get", {"url": "https://api.example.com/"}))
    begin_flow(principal="alice")
    try:
        res["after_begin_flow"] = _wire(s.scan_tool_call("http_get", {"url": "https://api.example.com/"}))
    finally:
        clear_flow()

    cap = _Capture()
    lg = logging.getLogger("xaidr")
    old = lg.level
    lg.addHandler(cap)
    lg.setLevel(logging.WARNING)
    try:
        def no_flow_warnings():
            return [m for m in cap.records if "begin_flow()" in m]
        w = sensor("record")
        for _ in range(3):
            w.scan_tool_call("http_get", {"url": "https://api.example.com/"})
        res["warn_after_three_no_flow"] = len(no_flow_warnings())
        begin_flow(principal="alice")
        try:
            fresh = sensor("record")
            fresh.scan_tool_call("http_get", {"url": "https://api.example.com/"})
        finally:
            clear_flow()
        res["warn_after_flow_call_on_fresh_sensor"] = len(no_flow_warnings()) - res["warn_after_three_no_flow"]
        before = len(no_flow_warnings())
        off = sensor("off")
        for _ in range(3):
            off.scan_tool_call("http_get", {"url": "https://api.example.com/"})
        res["warn_off"] = len(no_flow_warnings()) - before
        res["warning_text"] = (no_flow_warnings() or [None])[0]
    finally:
        lg.removeHandler(cap)
        lg.setLevel(old)
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
