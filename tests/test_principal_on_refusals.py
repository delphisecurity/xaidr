"""The principal on refused-call rows.

Every event the main scan path emits carries the ``provenance`` block
(``on_behalf_of``, the actor, the correlation id, the chain). The refusal
emitters carry the same block: a call refused by a fail-closed group, an open
circuit, an S5 gate, a not-scannable input, a scan fault or a destination
block is a row Core keys on its principal like any other, and a refusal with
no principal is the row an operator can least afford to lose.

The block is resolved ONCE per call and shared by every exit, because resolving
it records a hop on the delegation chain.

Inputs are plain text and a committed corpus row. No attack string.
"""

from __future__ import annotations

import json
import os

import pytest

import xaidr
from xaidr import Sensor, SensorExtension
from xaidr.circuit_breaker import CircuitBreaker
from xaidr.types import ScanResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
PRINCIPAL = "principal-1"


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _sensor(**kw):
    sink = _Sink()
    return Sensor(agent_id="refusals", reporter=sink, **kw), sink


def _events(sensor, sink):
    sensor.flush()
    return [e["data"] for e in sink.events if e.get("type") == "scan"]


class _Gate(SensorExtension):
    name = "gate"

    def gate(self, req):
        return ScanResult(action="blocked", score=1.0, category="quarantine", rules=["Q"])


class _RaisingGate(SensorExtension):
    name = "raising"

    def gate(self, req):
        raise RuntimeError("down")


def _attack_command():
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"]
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    for e in attacks:
        if probe.scan_tool_call("run_command", {"command": e["command"]}).action == "blocked":
            return e["command"]
    pytest.skip("no committed attack row blocks on the tool path")   # pragma: no cover


EMITTERS = ["fail_closed", "circuit_open", "gate", "not_scannable", "scan_error",
            "destination_block"]


def _refuse(emitter, monkeypatch):
    """Drive one refusal emitter under the principal scope. Returns (sensor, sink)."""
    kw = {}
    if emitter == "fail_closed":
        kw = {"fail_closed": ("controls",), "extensions": [_RaisingGate()]}
    if emitter == "gate":
        kw = {"extensions": [_Gate()]}
    if emitter == "circuit_open":
        kw = {"enforcement_mode": "block",
              "circuit_breaker": CircuitBreaker(violation_threshold=1, violation_window_sec=60)}
    s, sink = _sensor(**kw)
    with xaidr.origin_scope(on_behalf_of=PRINCIPAL):
        if emitter == "circuit_open":
            s.scan_tool_call("run_command", {"command": _attack_command()})   # trips it
            assert s.circuit_state == "open"
            sink.events.clear()
            s.scan("a plain request", direction="input")
        elif emitter == "not_scannable":
            s.scan(12345, direction="input")
        elif emitter == "scan_error":
            monkeypatch.setattr(s._scanner, "scan",
                                lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
            s.scan("a plain request", direction="input")
        elif emitter == "destination_block":
            httpx = pytest.importorskip("httpx")
            s.block_urls(["denied.example"])
            client = s.protect_http(httpx.Client(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json={}))))
            with pytest.raises(xaidr.DelphiBlockedError):
                client.get("https://denied.example/x")
        else:
            s.scan("a plain request", direction="input")
    return s, sink


@pytest.mark.parametrize("emitter", EMITTERS)
def test_every_refusal_emitter_carries_the_principal(emitter, monkeypatch):
    s, sink = _refuse(emitter, monkeypatch)
    events = [e for e in _events(s, sink) if e.get("direction") != "tool_call" or emitter != "circuit_open"]
    assert len(events) == 1, f"{emitter}: expected one refused event, got {len(events)}"
    prov = events[0].get("provenance")
    assert prov and prov.get("on_behalf_of") == PRINCIPAL, (
        f"a call refused by {emitter} reached Core with no principal: {events[0]}")


def test_the_main_path_still_carries_it():
    s, sink = _sensor()
    with xaidr.origin_scope(on_behalf_of=PRINCIPAL):
        s.scan("a plain request", direction="input")
        s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
        s.scan_a2a("a plain message", destination="peer")
    for e in _events(s, sink):
        assert e["provenance"]["on_behalf_of"] == PRINCIPAL


def test_a_refusal_records_no_hop_on_the_chain():
    """The main path records this agent as a hop when it resolves provenance; a
    refusal exit reads the chain and records nothing. So a sensor whose only scan
    is refused does not become an upstream hop of a sensor downstream in the same
    flow, and the tier gate there decides exactly as it did before this key."""
    a, sink_a = _sensor(extensions=[_Gate()])
    b_sink = _Sink()
    b = Sensor(agent_id="worker-B", reporter=b_sink, privilege_tier=1)
    xaidr.begin_flow(principal=PRINCIPAL)
    try:
        a.scan("a request", direction="input")          # refused by the gate
        b.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    finally:
        xaidr.clear_flow()
    refused = _events(a, sink_a)[0]
    assert refused["provenance"]["on_behalf_of"] == PRINCIPAL
    b.flush()
    chain = [h["agent_id"] for h in b_sink.events[0]["data"]["provenance"]["delegation_chain"]]
    assert "refusals" not in chain, (
        f"a refused call recorded a hop and became B's upstream: {chain}")
    assert chain == [PRINCIPAL, "worker-B"], chain


def test_a_per_call_principal_reaches_the_refusal_exit():
    s, sink = _sensor(extensions=[_Gate()])
    s.scan("a plain request", direction="input", origin_context={"on_behalf_of": "per-call"})
    ev = _events(s, sink)[0]
    assert ev["provenance"]["on_behalf_of"] == "per-call"


def test_with_no_principal_no_block_is_fabricated():
    s, sink = _sensor(extensions=[_Gate()])
    s.scan("a plain request", direction="input")
    ev = _events(s, sink)[0]
    assert "provenance" not in ev
