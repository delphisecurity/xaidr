"""A2 M5: hops and delegation binding (ARCHITECTURE.md §1.4, §5 M5). The checks
live in tests/outside/drivers/m5_binding.py, run here in-process and from the
built wheel in tests/outside/test_m5_from_the_wheel.py."""
from __future__ import annotations

import importlib.util
import os
import warnings

import pytest

import xaidr

_spec = importlib.util.spec_from_file_location(
    "m5_binding", os.path.join(os.path.dirname(__file__), "outside", "drivers", "m5_binding.py"))
m5 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m5)


@pytest.fixture(scope="module")
def seen():
    return m5.collect(xaidr)


EXPECT = {
    "no_flow": "no_flow",
    "s5_after_begin_flow": "unresolved",
    "no_destination": "no_destination",
    "truncated": ["argument_bound", True, ["walk_bound"]],   # RULING 1+2 after M8: was "unresolved"
    "s9_bare_thread": "no_flow",
    "s9_propagate_context": "unresolved",
    "after_clear_flow": ["no_flow", False],
    "extract_context_empty": [True, "unresolved"],
    "begin_flow_binds_fresh": True,
    "record_hop_binds_no_ledger": [False, False],
}
WHY = {
    "s5_after_begin_flow": "begin_flow() bound no ledger (S5 should flip ledger_absent -> unresolved)",
    "extract_context_empty": "extract_context({}) did not bind before its early return (V-7c)",
    "after_clear_flow": "clear_flow() left a ledger bound",
    "s9_propagate_context": "propagate_context did not carry the ledger into the worker thread (S9)",
    "begin_flow_binds_fresh": "begin_flow() reused the caller's ledger",
}


def check(seen):
    bad = [f"{k}: got {seen[k]!r}, want {v!r} -- {WHY.get(k, '')}"
           for k, v in EXPECT.items() if seen[k] != v]
    assert not bad, "M5 binding: " + "; ".join(bad)


def test_m5_binding(seen):
    check(seen)


# S25 was a strict xfail at M5 (open gave (no_flow, no_flow)). M6's input seam
# binds an IMPLICIT ledger per input (S-2), so the second call reads unresolved.
# Stated plainly (M6 review): set_origin plays no part in the flip. The same
# calls without set_origin give the same pair, so this pins the input seam's
# bind, not set_origin's semantics. Matching paid's (no_flow, unresolved) cannot
# be checked against paid's spec from this repo.
def test_s25_origin_without_a_flow():
    from xaidr import provenance_chain as pc
    from xaidr.provenance import set_origin
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m5-s25", value_origin="record", reporter=m5._Null())
    pc.clear_flow()
    set_origin(principal="alice")
    try:
        w1 = s.scan_tool_call("http_get", m5.URL).value_origin.wire.value
        s.scan("email bob@corp.example", direction="input")
        w2 = s.scan_tool_call("http_get", m5.URL).value_origin.wire.value
    finally:
        pc.clear_flow()
    # D2 (owner, 2026-10-08): set_origin is not a flow, and an input scan with no flow
    # binds no ledger, so both calls read no_flow. Until D2 the input scan bound an
    # implicit ledger and the second call read "unresolved".
    assert (w1, w2) == ("no_flow", "no_flow"), (
        f"set_origin without a flow, then a flow-less input scan, read {(w1, w2)!r}: a "
        "ledger was bound outside any flow (D2)")


def _carry_on_a_reused_thread():
    """Two requests, two users, ONE worker thread reused by the pool (as every
    pool does). Each request is a host that records its own hop through the
    PUBLIC provenance_chain.build_provenance (which calls record_hop) with a
    per-call principal and no begin_flow. That is the path that reaches the old
    ruling's pinned consequence. The SENSOR does not: _resolve_provenance returns
    early when a per-call principal is set and no flow is active (measured below).
    User A's prompt is recorded through the core's record_principal_input (the
    input seam M6 wires); user B then calls A's address. Returns B's wire, and
    the wires and warnings of the sensor's own per-call-principal path."""
    import logging
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import value_origin as vo
    from xaidr import provenance_chain as pc

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m5-carry", value_origin="record", reporter=m5._Null())

    def request(user, prompt, to):
        pc.build_provenance("host-agent", on_behalf_of=user)
        vo.record_principal_input(prompt, input_clean=True)
        return s.scan_tool_call("send_email", {"to": to},
                                origin_context={"on_behalf_of": user}).value_origin.wire.value

    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(pc.clear_flow).result()
        pool.submit(request, "user-a", "send the invoice to alice@a.example", "alice@a.example").result()
        b = pool.submit(request, "user-b", "hello", "alice@a.example").result()
        pool.submit(pc.clear_flow).result()

    seen = []

    class H(logging.Handler):
        def emit(self, r):
            seen.append(r.getMessage())
    h = H(logging.WARNING)
    logging.getLogger("xaidr").addHandler(h)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:      # a FRESH thread
            def only_hops():
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    t = xaidr.Sensor(agent_id="m5-hops", value_origin="record", reporter=m5._Null())
                return [t.scan_tool_call("lookup", {"q": "x"}, origin_context={"on_behalf_of": "u"})
                        .value_origin.wire.value for _ in range(2)]
            hops = pool.submit(only_hops).result()
            pool.submit(pc.clear_flow).result()
    finally:
        logging.getLogger("xaidr").removeHandler(h)
    return b, hops, sum("begin_flow()" in m for m in seen)


def test_ruling_3_1_changed_user_a_authority_never_reaches_user_b_on_a_reused_thread():
    """Ruling 3.1 CHANGED (owner, 2026-10-04): record_hop binds no ledger. A
    ledger with no owner and no unbind outlived the request, and pools reuse
    threads by design. Under the old 3.1, user B's call to user A's address
    came back AUTHORIZED on A's principal input (V-27's cross-request carry).
    The provenance-chain tests cannot see this class: it lives in the ledger,
    not in the chain they check."""
    b, hops, warned = _carry_on_a_reused_thread()
    assert b not in ("principal", "principal_undeclared_span", "trusted_source"), (
        f"user B's call to user A's address came back {b!r}: user A's principal authority "
        "reached user B on a reused thread (record_hop bound a ledger nobody owns)")
    # the sensor's own per-call-principal path, measured: it never reaches
    # record_hop with no flow active, so every call reads no_flow and the Q6
    # warning fires once
    assert hops == ["no_flow", "no_flow"] and warned == 1, (hops, warned)
