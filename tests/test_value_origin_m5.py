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
    "truncated": ["unresolved", True, ["walk_bound"]],
    "s9_bare_thread": "no_flow",
    "s9_propagate_context": "unresolved",
    "after_clear_flow": ["no_flow", False],
    "extract_context_empty": [True, "unresolved"],
    "begin_flow_binds_fresh": True,
    "record_hop_keeps_one_ledger_across_requests": [True, True],
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


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "V-7's S25, pinned as planned: set_origin + a principal-only emit is not a flow in "
    "open, so both calls are no_flow; paid's reference gives (no_flow, unresolved)"))
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
    assert (w1, w2) == ("no_flow", "unresolved"), (w1, w2)
