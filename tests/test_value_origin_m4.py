"""A2 M4: tool-call evaluation, RECORD only (ARCHITECTURE.md §1.3, §5 M4).

`evaluate_call` runs FIRST in `scan_tool_call`, before the gates and before
`_resolve_provenance` (V-7a), and its verdict is attached to the ScanResult of
EVERY tool-call exit (C-13), after `_post_scan_gate`, so an S6
`transform_verdict` never sees it (C-28). No `should_block` yet (M8), no
telemetry key yet (M9). The checks live in ``tests/outside/drivers/
m4_tool_call_eval.py`` and run here in-process and in
``tests/outside/test_m4_from_the_wheel.py`` from the built wheel.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

import xaidr

_spec = importlib.util.spec_from_file_location(
    "m4_tool_call_eval", os.path.join(os.path.dirname(__file__), "outside", "drivers", "m4_tool_call_eval.py"))
m4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m4)


@pytest.fixture(scope="module")
def seen():
    return m4.collect(xaidr)


def check_paths(seen):
    """Shared with the outside test. Each path's marker first, then its wire."""
    bad = []
    for mode in ("record", "enforce"):
        for p in m4.PATHS:
            row = seen["paths"][mode][p]
            assert row["marker"], f"[{mode}] the {p} call never reached its path: {row['line']}"
            if row["wire"] != "no_flow":
                bad.append(f"[{mode}] {p} exit ({m4.EMITTER[p]}): value_origin wire="
                           f"{row['wire']!r}, want 'no_flow'")
    assert not bad, ("C-13: every tool-call exit carries the verdict, and these do not: "
                     + "; ".join(bad))
    off = {p: r["wire"] for p, r in seen["paths"]["off"].items() if r["wire"] is not None}
    assert not off, f"OFF attached a value_origin: {off}"


def check_flow(seen):
    assert seen["no_flow"] == "no_flow", seen["no_flow"]
    # M4 pinned ledger_absent here, "the honest answer until M5 binds a ledger in
    # begin_flow". M5 does, so the same call is now unresolved.
    assert seen["after_begin_flow"] == "unresolved", (
        f"after begin_flow() the wire is {seen['after_begin_flow']!r}; M5 binds a ledger there")


def check_q6(seen):
    assert seen["warn_after_three_no_flow"] == 1, (
        f"Q6: three no_flow calls on one sensor logged {seen['warn_after_three_no_flow']} "
        "begin_flow() warnings; the owner's ruling is exactly one")
    assert seen["warn_after_flow_call_on_fresh_sensor"] == 0
    assert seen["warn_off"] == 0
    assert "begin_flow()" in seen["warning_text"] and "extract_context()" in seen["warning_text"]
    # D1/D3 (owner, 2026-10-08): the scoped form is named first, and the plain pair's
    # limitation is stated where an operator meets it, not only in a test name.
    assert "xaidr.flow(" in seen["warning_text"], seen["warning_text"]
    assert "clear_flow() is skipped" in seen["warning_text"], seen["warning_text"]


def test_every_tool_call_exit_carries_value_origin(seen):
    check_paths(seen)


def test_no_flow_then_ledger_absent_after_begin_flow(seen):
    check_flow(seen)


def test_q6_the_first_no_flow_call_warns_once_naming_begin_flow(seen):
    check_q6(seen)


def test_the_attach_never_raises_into_the_host_on_a_non_dataclass_result(caplog):
    """M4 silent-failure review: the attach sits outside scan_tool_call's
    fail-open body, and an S6 transform_verdict may hand back any object whose
    `.action` is valid (only that is checked). dataclasses.replace() raises on
    a non-dataclass, which would turn every tool call into an exception. The
    result must come back unmodified, and the fault must be logged once."""
    import logging
    import warnings
    from xaidr.provenance_chain import clear_flow

    class _Duck:                              # what a careless extension returns
        def __init__(self, r):
            self._r = r

        def __getattr__(self, k):
            return getattr(self._r, k)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m4-duck", value_origin="record", reporter=m4._Null())
    real = s._scan_tool_call_unattached
    s._scan_tool_call_unattached = lambda *a, **k: _Duck(real(*a, **k))
    clear_flow()
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        r1 = s.scan_tool_call("http_get", {"url": "https://api.example.com/"})
        r2 = s.scan_tool_call("http_get", {"url": "https://api.example.com/"})
    assert isinstance(r1, _Duck) and r1.action == "allowed" and isinstance(r2, _Duck)
    faults = [x for x in caplog.records if "value origin" in x.getMessage() and x.levelno >= logging.ERROR]
    assert len(faults) == 1, f"the attach fault should be logged exactly once, got {len(faults)}"


def test_autopatch_tool_blocked_result_keeps_the_verdict():
    """autopatch.tool_verdict builds a FRESH TOOL_BLOCKED result after the
    wrapper; it must carry the verdict (M4 review: this claim had no test)."""
    import warnings
    from xaidr.autopatch.core import tool_verdict
    from xaidr.provenance_chain import clear_flow
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m4-autopatch", value_origin="record", reporter=m4._Null())
    s._blocked_tools = ("wipe_disk",)
    clear_flow()
    r = tool_verdict(s, "wipe_disk", {"path": "/"})
    assert r is not None and r.rules == ["TOOL_BLOCKED"], r
    assert r.value_origin is not None and r.value_origin.wire.value == "no_flow", (
        f"the TOOL_BLOCKED exit lost value_origin: {r.value_origin!r}")
