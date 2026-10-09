"""Owner, 2026-10-06, ruling 1: a reused worker thread must not carry user A's
ledger into user B's request. "Bind on entry, not on the next input scan. A
ledger whose lifetime depends on when the next request happens to scan is
owned by nothing." Same defect class as ruling 3.1 (record_hop), on another path.

STOPPED, per the owner's own condition ("if this cannot be done without a seam
change, STOP and tell me"). The only entries that bind a ledger are begin_flow()
and extract_context(). A host that never begins a flow gets an implicit ledger
from its INPUT SCAN (S-2), replaced only at the NEXT input scan (V-27's fix). The
sensor receives no signal at all when B's request starts. Binding on entry for
such hosts needs a new entry seam (a request scope) or an S-2/V-27 change
(a flow-less call never reads an implicit ledger). Both are seam changes.
"""
from __future__ import annotations

import warnings
from concurrent.futures import ThreadPoolExecutor

import pytest

import xaidr

AUTHORITY = {"principal", "principal_undeclared_span", "trusted_source"}


class _Null:
    def report(self, *a, **k):
        pass


def test_a_reused_pool_thread_does_not_carry_user_as_ledger_into_user_bs_call():
    # D2 (owner, 2026-10-08): no implicit ledgers. This was a strict xfail while S-2 bound
    # an implicit ledger at user A's input scan and it survived into user B's request on
    # the same pool thread. Under D2 a flow-less request binds NOTHING, so there is no
    # ledger for B to inherit. The precondition changed with it: A, flow-less too, has no
    # authority either (it used to assert A's call was authorized).
    from xaidr.value_origin import ledger_bound
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="reuse", value_origin="record", reporter=_Null())

    def user_a():
        s.scan("Email alice@corp.example the quarterly report.", direction="input")
        return ledger_bound(), s.scan_tool_call(
            "send_email", {"to": "alice@corp.example"}).value_origin.wire.value

    def user_b():          # B never named alice; its tool call precedes any input of B's own
        return ledger_bound(), s.scan_tool_call(
            "send_email", {"to": "alice@corp.example"}).value_origin.wire.value

    with ThreadPoolExecutor(max_workers=1) as pool:      # ONE worker: B runs on A's thread
        a = pool.submit(user_a).result()
        b = pool.submit(user_b).result()
    assert a == (False, "no_flow"), (
        f"user A opened no flow, and its input scan still bound a ledger (ledger_bound, wire) "
        f"= {a!r}: an implicit ledger exists, which D2 removed")
    assert b == (False, "no_flow"), (
        f"user B's call to an address only user A typed read {b!r}: request state from A's "
        "flow-less request reached B on a reused pool thread")


def test_a_flow_less_input_binds_no_ledger():
    # D2 (owner, 2026-10-08): bind on entry only. An input scan with no flow records
    # nothing, so nothing outlives the request to be carried.
    from xaidr import provenance_chain as pc
    from xaidr.value_origin import ledger_bound
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="reuse-bind", value_origin="record", reporter=_Null())
    pc.clear_flow()
    s.scan("Email alice@corp.example the quarterly report.", direction="input")
    assert not ledger_bound(), (
        "an input scan with no flow bound a value-origin ledger: an implicit ledger "
        "outlives the request that bound it (D2)")


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "the plain begin_flow()/clear_flow() pair's documented limitation (owner, D3, "
    "2026-10-08): begin_flow for A without clear_flow keeps A's EXPLICIT ledger, and an "
    "explicit ledger is never replaced, so it survives even user B's own input scan. The "
    "asserting test is the scoped form: tests/test_value_origin_flow_scope.py::"
    "test_flow_scope[scope_that_raises]"))
def test_a_flow_left_open_by_user_a_is_not_user_bs_ledger():
    # WHAT WOULD MAKE THIS ASSERTING (owner, D3: no deprecation of the plain pair in A2).
    # Between user A's last statement and user B's tool call, the only call xaidr gets is
    # B's own input scan, and an explicit ledger deliberately survives an input scan
    # (ruling 3.1: one flow spans many inputs; that is how a multi-turn request works).
    # So nothing xaidr sees can end A's flow. This becomes asserting only if begin_flow()
    # stops binding past the request when clear_flow() is skipped, that is, if
    # begin_flow() itself becomes a scope that ends with its caller.
    # Two other changes would also flip it, and both are wrong:
    #   * letting an input scan replace an explicit ledger: it breaks multi-turn flows;
    #   * removing the plain pair: this test then fails with AttributeError, which
    #     pytest reports as FAILED (raises=AssertionError), not XPASS.
    # If this XPASSes, find which change did it before converting it. Only if it was
    # begin_flow() becoming a scope: make it asserting, and update the three places
    # that state the limitation: docs/api.md, README.md and the no_flow warning
    # (xaidr/sensor.py, Sensor._value_origin_verdict).
    from xaidr import provenance_chain as pc
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="reuse-open", value_origin="record", reporter=_Null())

    def user_a():
        pc.begin_flow(principal="a")                  # ...and the host never clears it
        s.scan("Email alice@corp.example the quarterly report.", direction="input")
        return s.scan_tool_call("send_email", {"to": "alice@corp.example"}).value_origin.wire.value

    def user_b():
        s.scan("Send the minutes to the team.", direction="input")       # B's OWN input first
        return s.scan_tool_call("send_email", {"to": "alice@corp.example"}).value_origin.wire.value

    with ThreadPoolExecutor(max_workers=1) as pool:
        a = pool.submit(user_a).result()
        b = pool.submit(user_b).result()
    assert a in AUTHORITY, a
    assert b not in AUTHORITY, (
        f"user B scanned its own input first and still read {b!r}: user A's open flow kept "
        "its explicit ledger across requests. This is the plain pair's documented limitation; "
        "it becomes asserting only if begin_flow() itself becomes a scope that ends with its "
        "caller (NOT by letting an input scan replace an explicit ledger: that breaks "
        "multi-turn flows)")
