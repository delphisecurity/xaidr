"""Guard for the set_origin provenance-loss fix (Option 1) — locks both directions.

Bug: the four emission sites called provenance.resolve() (which returns the
correct block: actor + supplied correlation_id + principal origin) but kept only
on_behalf_of, then rebuilt the emitted block from provenance_chain.build_provenance
— a different module whose contextvars set_origin never populates. Result:
actor dropped, correlation_id replaced with a random one, origin_agent = the
agent instead of the principal.

Fix: _resolve_provenance() emits resolve()'s complete block when an origin
context is set and no begin_flow chain is active; otherwise falls through to
build_provenance so begin_flow's multi-hop path is unchanged.

Both directions guarded: set_origin now emits actor/supplied-corr/principal-origin
on all four surfaces AND begin_flow still emits correctly.
"""

from __future__ import annotations

import json

from xaidr import Sensor
from xaidr.provenance import set_origin
from xaidr.provenance_chain import begin_flow

PRINCIPAL = "user:alice"
ACTOR = "agent:orch"
CORR = "corr-XYZ"


def _prov(cap, wait_events, n=1):
    ev = wait_events(cap, n)[-1]
    data = ev.get("data", ev)
    return data.get("provenance")


def test_set_origin_scan(cap, wait_events):
    set_origin(on_behalf_of=PRINCIPAL, actor=ACTOR, correlation_id=CORR)
    Sensor(agent_id="test", reporter=cap).scan("hello")
    p = _prov(cap, wait_events)
    assert p["on_behalf_of"] == PRINCIPAL
    assert p["actor"] == ACTOR
    assert p["correlation_id"] == CORR      # supplied, NOT random
    assert p["origin_agent"] == PRINCIPAL   # principal, NOT the agent


def test_set_origin_scan_output(cap, wait_events):
    set_origin(on_behalf_of=PRINCIPAL, actor=ACTOR, correlation_id=CORR)
    Sensor(agent_id="test", reporter=cap).scan_output("model output text")
    p = _prov(cap, wait_events)
    assert (p["actor"], p["correlation_id"], p["origin_agent"]) == (ACTOR, CORR, PRINCIPAL)


def test_set_origin_scan_tool_call(cap, wait_events):
    set_origin(on_behalf_of=PRINCIPAL, actor=ACTOR, correlation_id=CORR)
    Sensor(agent_id="test", reporter=cap).scan_tool_call("get_weather", {"city": "Toronto"})
    p = _prov(cap, wait_events)
    assert (p["actor"], p["correlation_id"], p["origin_agent"]) == (ACTOR, CORR, PRINCIPAL)


def test_set_origin_protect_tools(cap, wait_events):
    set_origin(on_behalf_of=PRINCIPAL, actor=ACTOR, correlation_id=CORR)
    s = Sensor(agent_id="test", reporter=cap)

    def mytool(x):
        return x

    s.protect_tools([mytool])[0]("hi")
    p = _prov(cap, wait_events)
    assert (p["actor"], p["correlation_id"], p["origin_agent"]) == (ACTOR, CORR, PRINCIPAL)


def test_correlation_stable_across_scans(cap, wait_events):
    set_origin(on_behalf_of=PRINCIPAL, actor=ACTOR, correlation_id=CORR)
    s = Sensor(agent_id="test", reporter=cap)
    s.scan("a")
    s.scan("b")
    s.scan("c")
    evs = wait_events(cap, 3)
    corrs = {(e.get("data", e)).get("provenance", {}).get("correlation_id") for e in evs}
    assert corrs == {CORR}   # one shared id, SIEM-stitchable


def test_begin_flow_unbroken(cap, wait_events):
    """The path that was already correct must stay correct."""
    begin_flow(principal=PRINCIPAL, correlation_id="corr-flow")
    Sensor(agent_id="agent-a", reporter=cap).scan("step1")
    p = _prov(cap, wait_events)
    assert p["correlation_id"] == "corr-flow"
    assert p["origin_agent"] == PRINCIPAL
    assert p["delegation_chain"][0] == {"agent_id": PRINCIPAL, "role": "principal"}


def test_no_context_emits_no_provenance(cap, wait_events):
    """Neither set_origin nor begin_flow → no fabricated provenance."""
    Sensor(agent_id="bare", reporter=cap).scan("hello")
    assert _prov(cap, wait_events) is None
