"""``traceParent`` on tool-call events.

``scan_tool_call(..., parent_context=None)`` takes the same keyword ``scan``
and ``scan_a2a`` take. When the caller passes none, the sensor reads the
ACTIVE OTel span in the current context, and never the wire: an inbound
``traceparent`` header this process received describes the request that
arrived, not the tool call this agent is about to make. With no span and no
explicit parent the key is absent. Refusal exits carry it too.

Needs the ``trace`` extra (opentelemetry-api). Inputs are plain text and a
committed corpus row. No attack string.
"""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("opentelemetry")

from opentelemetry import context as otel_context                       # noqa: E402
from opentelemetry import trace as otel_trace                           # noqa: E402
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags  # noqa: E402

import xaidr                                                            # noqa: E402
from xaidr import Sensor, SensorExtension                               # noqa: E402
from xaidr.trace_context import ParentContext                           # noqa: E402
from xaidr.types import ScanResult                                      # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")

SPAN_TRACE_ID = "0af7651916cd43dd8448eb211c80319c"
SPAN_SPAN_ID = "b7ad6b7169203331"
WIRE_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
WIRE_TRACEPARENT = f"00-{WIRE_TRACE_ID}-00f067aa0ba902b7-01"


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _sensor(**kw):
    sink = _Sink()
    return Sensor(agent_id="trace", reporter=sink, **kw), sink


def _tool_events(sensor, sink):
    sensor.flush()
    return [e["data"] for e in sink.events if e["data"].get("direction") == "tool_call"]


@pytest.fixture
def active_span():
    span = NonRecordingSpan(SpanContext(
        trace_id=int(SPAN_TRACE_ID, 16), span_id=int(SPAN_SPAN_ID, 16),
        is_remote=False, trace_flags=TraceFlags(TraceFlags.SAMPLED)))
    token = otel_context.attach(otel_trace.set_span_in_context(span))
    try:
        yield span
    finally:
        otel_context.detach(token)


def test_inside_an_active_span_the_tool_call_carries_its_trace_id(active_span):
    s, sink = _sensor()
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    ev = _tool_events(s, sink)[0]
    assert ev["traceParent"]["traceId"] == SPAN_TRACE_ID, ev.get("traceParent")
    assert ev["traceParent"]["spanId"] == SPAN_SPAN_ID
    assert ev["traceParent"]["source"] == "otel"


def test_an_explicit_parent_context_wins_over_the_span(active_span):
    s, sink = _sensor()
    explicit = ParentContext(trace_id=WIRE_TRACE_ID, span_id="00f067aa0ba902b7",
                             trace_flags="01", source="wire")
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"}, parent_context=explicit)
    ev = _tool_events(s, sink)[0]
    assert ev["traceParent"]["traceId"] == WIRE_TRACE_ID


def test_with_no_span_the_key_is_absent():
    s, sink = _sensor()
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    ev = _tool_events(s, sink)[0]
    assert "traceParent" not in ev, "a tool call fabricated a trace parent"


def test_an_inbound_wire_header_is_never_the_tool_calls_parent():
    """The wire describes the request that ARRIVED. With no active span, a
    tool call made while an inbound traceparent is known carries nothing."""
    s, sink = _sensor()
    xaidr.extract_context({"traceparent": WIRE_TRACEPARENT,
                           "x-openA2A-correlation": "abcdef0123456789"})
    try:
        s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    finally:
        xaidr.clear_flow()
    ev = _tool_events(s, sink)[0]
    assert "traceParent" not in ev, (
        "a tool call took its trace id from an inbound header it never received")


def test_inside_a_span_an_inbound_wire_header_still_loses(active_span):
    s, sink = _sensor()
    xaidr.extract_context({"traceparent": WIRE_TRACEPARENT,
                           "x-openA2A-correlation": "abcdef0123456789"})
    try:
        s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    finally:
        xaidr.clear_flow()
    ev = _tool_events(s, sink)[0]
    assert ev["traceParent"]["traceId"] == SPAN_TRACE_ID, (
        "a tool call took its trace id from an inbound header it never received")


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
def test_every_tool_call_exit_carries_the_trace_parent(exit_name, active_span, monkeypatch):
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
    tool = _tool_events(s, sink)
    assert len(tool) == 1, f"{exit_name}: expected one tool_call event, got {len(tool)}"
    assert tool[0].get("traceParent", {}).get("traceId") == SPAN_TRACE_ID, (
        f"{exit_name}: a refused call reached Core with no trace parent")


def test_the_mapped_event_carries_the_trace_fields(active_span):
    from xaidr.schema import to_openA2A

    s, sink = _sensor()
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    ev = _tool_events(s, sink)[0]
    mapped = to_openA2A({"type": "scan", "agentId": "trace", "data": ev})
    assert mapped.get("trace_id") == SPAN_TRACE_ID
