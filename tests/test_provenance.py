"""Provenance coverage (xaidr/provenance.py + provenance_chain.py).

Promotes the positive cases of ``_phase1/verify_provenance.py``: a set principal
is carried, and a multi-hop chain accumulates. The no-fabrication invariant lives
in ``test_security_invariants.py``.
"""

from __future__ import annotations

from xaidr import Sensor, begin_flow
from xaidr import provenance as prov
from xaidr import provenance_chain as chain
from xaidr.schema import to_openA2A


def _chain_ids(mapped):
    dc = mapped["gen_ai.security.provenance.delegation_chain"]
    return [hop["agent_id"] for hop in dc]


# ── direct API ───────────────────────────────────────────────────────────────
def test_resolve_none_without_origin():
    assert prov.resolve("agentX") is None


def test_set_origin_carries_principal():
    prov.set_origin(on_behalf_of="user:zoe")
    resolved = prov.resolve("agentX")
    assert resolved is not None
    assert resolved["on_behalf_of"] == "user:zoe"


def test_build_provenance_none_without_flow():
    assert chain.build_provenance("a1") is None


def test_build_provenance_accumulates_chain():
    begin_flow(principal="user:pat")
    prov_block = chain.build_provenance("a1")
    assert prov_block is not None
    ids = [h["agent_id"] for h in prov_block["delegation_chain"]]
    assert ids == ["user:pat", "a1"]


# ── end-to-end through the sensor + schema mapping ───────────────────────────
def test_active_flow_emits_correct_chain(cap, wait_events):
    begin_flow(principal="user:alice")
    a = Sensor(agent_id="agent-a", reporter=cap)
    b = Sensor(agent_id="agent-b", reporter=cap)
    a.scan("route this")
    b.scan("process this")
    wait_events(cap, 2)

    evs = [e for e in cap.events if e["data"]["agentId"] == "agent-b"]
    assert evs, "no event for agent-b"
    mapped = to_openA2A(evs[-1])
    assert mapped["gen_ai.security.provenance.on_behalf_of"] == "user:alice"
    assert _chain_ids(mapped) == ["user:alice", "agent-a", "agent-b"]
