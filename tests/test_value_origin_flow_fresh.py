"""Q-G, decided 2026-10-23: the OUTERMOST ``xaidr.flow()`` scope starts fresh.

Whatever ledger, chain or tier state the context already holds when the first
scope is entered (a leftover implicit ledger, a flow ``begin_flow()`` started and
never cleared, a scope entered and never exited) is set aside for the scope, and
one warning per occurrence names what was set aside by kind and count, never by
value. Delegation evidence (an inbound mark, or a hop that is not the principal's
own entry) is kept, because keeping it can only tighten the privilege-tier gate.
Nested scopes still join. On exit the scope puts back what it found (D1).
"""
from __future__ import annotations

import contextvars
import logging

import xaidr
from xaidr import provenance_chain as pc
from xaidr.value_origin import (bind_fresh_ledger, evaluate_call, record_principal_input,
                                unbind_ledger)

LEFTOVER_HOST = "https://collector.attacker.test/upload"


def _run(fn):
    return contextvars.Context().run(fn)


def _flow_logs(caplog):
    return [r.getMessage() for r in caplog.records if "outermost scope" in r.getMessage()]


def test_a_leftover_flow_does_not_survive_into_a_new_outermost_scope(caplog):
    def run():
        leftover = pc.begin_flow(principal="user:alice")          # never cleared
        record_principal_input(f"send it to {LEFTOVER_HOST}", None, input_clean=True)
        with xaidr.flow(principal="user:bob") as corr:
            chain = pc.current_chain()
            wire = evaluate_call("http_post", {"url": LEFTOVER_HOST}, flow_active=True).wire.value
        return leftover, corr, chain, wire, pc.current_correlation_id()
    with caplog.at_level(logging.WARNING, logger="xaidr.provenance_chain"):
        leftover, corr, chain, wire, after = _run(run)
    assert chain and chain[0]["agent_id"] == "user:bob", (
        f"the new request's chain is {chain}: the leftover flow survived into it")
    assert corr != leftover, "the new request kept the leftover correlation id"
    assert wire == "unresolved", f"the leftover principal authority reached the new request: {wire}"
    assert after == leftover, "on exit the scope did not put back what it found (D1)"
    logs = _flow_logs(caplog)
    assert len(logs) == 1, logs
    assert "1 value-origin ledger" in logs[0] and "a correlation id" in logs[0], logs[0]


def test_the_set_aside_line_names_kinds_and_counts_never_values(caplog):
    def run():
        corr = pc.begin_flow(principal="user:alice@corp.example")
        record_principal_input(f"send it to {LEFTOVER_HOST} and ops@corp.example", None,
                               input_clean=True)
        with xaidr.flow(principal="user:bob"):
            pass
        return corr
    with caplog.at_level(logging.WARNING, logger="xaidr.provenance_chain"):
        corr = _run(run)
    logs = _flow_logs(caplog)
    assert logs, "no line named what the outermost scope set aside"
    for value in (corr, "alice", "corp.example", "collector", "attacker", "upload", "ops@"):
        assert value not in logs[0], f"the line carries a value ({value!r}): {logs[0]}"


def test_a_scope_entered_and_never_exited_is_set_aside_by_the_next_request(caplog):
    def run():
        with xaidr.request_scope():
            xaidr.flow(principal="user:alice").__enter__()     # never exited
        with xaidr.flow(principal="user:bob"):
            return pc.current_chain()
    with caplog.at_level(logging.WARNING, logger="xaidr.provenance_chain"):
        chain = _run(run)
    assert chain and chain[0]["agent_id"] == "user:bob", chain
    assert any("1 scope left open by an earlier request" in m for m in _flow_logs(caplog)), (
        _flow_logs(caplog))


def test_delegation_evidence_is_kept_so_the_gate_never_loosens():
    def run():
        pc.extract_context({})                    # an inbound request, no headers: tier 4
        pc.record_hop("upstream-agent")           # an untiered upstream hop
        with xaidr.flow(principal="user:bob"):
            return pc._inbound_ctx.get(), [h["agent_id"] for h in pc.current_chain()]
    inbound, hops = _run(run)
    assert inbound is True and "upstream-agent" in hops, (inbound, hops)


def test_a_nested_scope_still_joins(caplog):
    def run():
        with xaidr.flow(principal="user:bob") as outer:
            with xaidr.flow(principal="user:carol") as inner:
                return outer, inner, pc.current_chain()[0]["agent_id"]
    with caplog.at_level(logging.WARNING, logger="xaidr.provenance_chain"):
        outer, inner, who = _run(run)
    assert outer == inner and who == "user:bob", (outer, inner, who)
    assert not _flow_logs(caplog), "an outermost scope over nothing set something aside"


def test_a_fresh_context_sets_nothing_aside(caplog):
    def run():
        bind_fresh_ledger()
        unbind_ledger()
        with xaidr.flow(principal="user:bob"):
            pass
    with caplog.at_level(logging.WARNING, logger="xaidr.provenance_chain"):
        _run(run)
    assert not _flow_logs(caplog), _flow_logs(caplog)
