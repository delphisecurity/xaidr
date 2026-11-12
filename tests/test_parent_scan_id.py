"""``parentScanId`` on tool-call events: the input scan that authorised the call.

The rule, ported from the paid sensor exactly:

* a ContextVar holds the ``scanId`` of the most recent INPUT scan in the
  execution context;
* it is cleared at the start of each input scan, so an input event has no
  parent;
* output scans do not set it;
* it is put on every ``tool_call`` event, refusal exits included, and on the
  attestation (``ScanView.parent_scan_id``);
* absent means not evaluated, and never "search wider";
* the request scope resets it on entry.

Inputs are plain text and committed corpus rows. No attack string.
"""

from __future__ import annotations

import json
import os
import threading

import pytest

import xaidr
from xaidr import Sensor, SensorExtension
from xaidr.types import ScanResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _sensor(**kw):
    sink = _Sink()
    return Sensor(agent_id="parent", reporter=sink, **kw), sink


def _events(sensor, sink, direction=None):
    sensor.flush()
    out = [e["data"] for e in sink.events if e.get("type") == "scan"]
    return [e for e in out if direction is None or e.get("direction") == direction]


def test_turn_one_tool_call_names_the_input_that_authorised_it():
    s, sink = _sensor()
    inp = s.scan("please open ticket T-1", direction="input")
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    tool = _events(s, sink, "tool_call")
    assert tool[0]["parentScanId"] == inp.scan_id, (
        f"tool_call.parentScanId={tool[0].get('parentScanId')!r}, input scanId={inp.scan_id!r}")


def test_the_input_event_itself_has_no_parent():
    s, sink = _sensor()
    s.scan("first request", direction="input")
    s.scan("second request", direction="input")
    for e in _events(s, sink, "input"):
        assert "parentScanId" not in e, "an input event names a parent; the parent is cleared first"


def test_turn_two_tool_call_names_the_turn_two_input():
    s, sink = _sensor()
    s.scan("turn one", direction="input")
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    inp2 = s.scan("turn two", direction="input")
    s.scan_tool_call("get_ticket", {"ticket_id": "T-2"})
    tool = _events(s, sink, "tool_call")
    assert tool[1]["parentScanId"] == inp2.scan_id, (
        "the turn-2 tool call names turn 1 as the request that authorised it")


def test_an_output_scan_does_not_set_the_parent():
    s, sink = _sensor()
    inp = s.scan("a request", direction="input")
    s.scan_output("a model answer")
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    tool = _events(s, sink, "tool_call")
    assert tool[0]["parentScanId"] == inp.scan_id
    for e in _events(s, sink, "output"):
        assert "parentScanId" not in e


def test_with_no_input_scan_the_key_is_absent():
    s, sink = _sensor()
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    tool = _events(s, sink, "tool_call")
    assert "parentScanId" not in tool[0], (
        "absent means not evaluated; a value here was fabricated")


class _Gate(SensorExtension):
    name = "gate"

    def gate(self, req):
        if req.direction == "tool_call":
            return ScanResult(action="blocked", score=1.0, category="quarantine", rules=["Q"])
        return None


class _RaisingGate(SensorExtension):
    name = "raising"

    def gate(self, req):
        if req.direction == "tool_call":
            raise RuntimeError("down")
        return None


def _attack_command():
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"]
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    for e in attacks:
        if probe.scan_tool_call("run_command", {"command": e["command"]}).action == "blocked":
            return e["command"]
    pytest.skip("no committed attack row blocks on the tool path")   # pragma: no cover


@pytest.mark.parametrize("exit_name", ["main-blocked", "gate", "fail_closed", "not_scannable",
                                       "scan_error", "blocked_tool"])
def test_every_tool_call_exit_carries_the_parent(exit_name, monkeypatch):
    kw = {}
    if exit_name == "gate":
        kw["extensions"] = [_Gate()]
    if exit_name == "fail_closed":
        kw["extensions"] = [_RaisingGate()]
        kw["fail_closed"] = ("controls",)
    if exit_name == "blocked_tool":
        kw["blocked_tools"] = ["rm_rf"]
    if exit_name == "main-blocked":
        kw["enforcement_mode"] = "block"
    s, sink = _sensor(**kw)
    inp = s.scan("a request", direction="input")
    if exit_name == "scan_error":
        monkeypatch.setattr(s, "_scan_tool_call_impl",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    if exit_name == "main-blocked":
        s.scan_tool_call("run_command", {"command": _attack_command()})
    elif exit_name == "not_scannable":
        s.scan_tool_call(12345, {"a": "b"})
    elif exit_name == "blocked_tool":
        s.scan_tool_call("rm_rf", {"path": "/tmp"})
    else:
        s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    tool = _events(s, sink, "tool_call")
    assert len(tool) == 1, f"{exit_name}: expected one tool_call event, got {len(tool)}"
    assert tool[0]["parentScanId"] == inp.scan_id, (
        f"{exit_name}: a refused call reached Core with no parent scan "
        f"({tool[0].get('parentScanId')!r})")


def test_request_scope_resets_the_parent_on_entry():
    s, sink = _sensor()
    s.scan("a request outside any scope", direction="input")
    with xaidr.request_scope():
        s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    tool = _events(s, sink, "tool_call")
    assert "parentScanId" not in tool[0], (
        "a new request inherited the previous request's input as its parent")


def test_the_parent_is_per_execution_context():
    """Each thread's tool call names THAT thread's input: the tool call carries
    its ticket id in its arguments, and the event's promptHash is the hash of
    those arguments, so every tool event is joined to the thread that made it."""
    from xaidr.sensor import _canonical_arguments
    from xaidr.types import safe_content_hash

    s, sink = _sensor()
    seen = {}
    barrier = threading.Barrier(4)

    def worker(label):
        inp = s.scan(f"request {label}", direction="input")
        barrier.wait(timeout=10)          # every input is recorded before any tool call
        s.scan_tool_call("get_ticket", {"ticket_id": label})
        seen[safe_content_hash(_canonical_arguments({"ticket_id": label}))] = inp.scan_id

    threads = [threading.Thread(target=worker, args=(f"T-{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    tool = _events(s, sink, "tool_call")
    assert len(tool) == 4
    for e in tool:
        assert e["parentScanId"] == seen[e["promptHash"]], (
            "a tool call named another thread's input as its parent")


def test_a_node_that_runs_in_a_context_copy_sees_the_requests_parent():
    """LangGraph runs each node in a COPY of the context. The parent is a cell
    the request opens outside every node, so an input scan inside one copy is
    the parent of a tool call inside another copy."""
    import contextvars

    s, sink = _sensor()
    with xaidr.request_scope():                       # the request, outside the nodes
        inp = contextvars.copy_context().run(lambda: s.scan("a request", direction="input"))
        contextvars.copy_context().run(lambda: s.scan_tool_call("get_ticket", {"ticket_id": "T-1"}))
    tool = _events(s, sink, "tool_call")
    assert tool[0]["parentScanId"] == inp.scan_id, (
        "the tools node did not see the input scanned in the before_model node")


def test_without_a_request_a_context_copy_has_no_parent():
    """The honest boundary: in a fresh context with no request opened around
    them, two context copies share nothing, and the tool call has no parent
    rather than a wrong one."""
    import contextvars

    s, sink = _sensor()

    def fresh_thread():
        contextvars.copy_context().run(lambda: s.scan("a request", direction="input"))
        contextvars.copy_context().run(lambda: s.scan_tool_call("get_ticket", {"ticket_id": "T-1"}))

    t = threading.Thread(target=fresh_thread)           # a new thread: no cell yet
    t.start()
    t.join()
    tool = _events(s, sink, "tool_call")
    assert "parentScanId" not in tool[0]


def test_the_mapped_event_carries_the_parent():
    from xaidr.schema import to_openA2A

    s, sink = _sensor()
    inp = s.scan("a request", direction="input")
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    ev = _events(s, sink, "tool_call")[0]
    assert to_openA2A({"type": "scan", "agentId": "parent", "data": ev})[
        "gen_ai.security.parent_scan_id"] == inp.scan_id


def test_parent_scan_id_rides_the_attestation(monkeypatch):
    httpx = pytest.importorskip("httpx")
    from xaidr.extensions import EgressView

    views = []

    class _Rec(SensorExtension):
        name = "rec"

        def attest_egress(self, view):
            views.append(view)
            return {}

    s, sink = _sensor(extensions=[_Rec()])
    inp = s.scan("please open ticket T-1", direction="input")
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
    try:
        with httpx.Client(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json={}))) as c:
            c.post("https://mcp.example/mcp", json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "get_ticket", "arguments": {"ticket_id": "T-1"}}})
    finally:
        xaidr.unprotect()
    tool = [sc for sc in views[-1].scans if sc.direction == "tool_call"]
    assert tool and tool[0].parent_scan_id == inp.scan_id
