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
    assert seen["after_begin_flow"] == "ledger_absent", (
        f"after begin_flow() the wire is {seen['after_begin_flow']!r}; ledger_absent is the "
        "honest answer until M5 binds a ledger in begin_flow")


def check_q6(seen):
    assert seen["warn_after_three_no_flow"] == 1, (
        f"Q6: three no_flow calls on one sensor logged {seen['warn_after_three_no_flow']} "
        "begin_flow() warnings; the owner's ruling is exactly one")
    assert seen["warn_after_flow_call_on_fresh_sensor"] == 0
    assert seen["warn_off"] == 0
    assert "begin_flow()" in seen["warning_text"] and "extract_context()" in seen["warning_text"]


def test_every_tool_call_exit_carries_value_origin(seen):
    check_paths(seen)


def test_no_flow_then_ledger_absent_after_begin_flow(seen):
    check_flow(seen)


def test_q6_the_first_no_flow_call_warns_once_naming_begin_flow(seen):
    check_q6(seen)
