"""A2 P1: ``xaidr.flow()``, the request scope (owner rulings D1 and D3,
2026-10-08; docs/value-origin-a2-build-spec.md §1 and §4 P1).

A scope restores the five request ContextVars to what they were before it, on
return AND on raise, so a request that fails cannot leave its flow, and its
ledger's authority, for the next request on the same worker thread. The checks
live in ``tests/outside/drivers/flow_scope.py`` and run here in-process and in
``tests/outside/test_p1_flow_scope_from_the_wheel.py`` from the built wheel.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

import xaidr

_spec = importlib.util.spec_from_file_location(
    "flow_scope", os.path.join(os.path.dirname(__file__), "outside", "drivers", "flow_scope.py"))
fs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fs)

AUTHORITY = {"principal", "principal_undeclared_span", "trusted_source"}


@pytest.fixture(scope="module")
def seen():
    return fs.collect(xaidr)


def _row(seen, case):
    assert seen["has_flow"], "xaidr.flow does not exist: there is no request scope to test"
    row = seen[case]
    assert "error" not in row, f"{case} raised inside the driver: {row['error']}"
    return row


def check_scope_that_raises(seen):
    r = _row(seen, "scope_that_raises")
    assert r["a_inside"] in AUTHORITY, (
        f"precondition: inside its own scope user A's call is authorized, got {r['a_inside']!r}")
    assert r["a_raised_same_object"], "the body's exception did not propagate unchanged"
    assert not r["b_start"]["ledger_bound"] and not r["b_start"]["flow_active"], (
        f"user A's scope RAISED and still left request state on the worker thread for "
        f"user B: {r['b_start']}")
    assert r["b"] == "no_flow", (
        f"user B's tool call to an address only user A typed read {r['b']!r}: A's "
        "authority outlived a scope that raised")


def check_nested(seen):
    r = _row(seen, "nested")
    assert r["inside"]["chain_head"] == "inner" and r["inside"]["corr"] != r["outer"]
    assert not r["inside"]["ledger_is_outer"], "the inner scope did not bind its own ledger"
    assert r["after_corr_is_outer"] and r["after_chain_head"] == "outer", (
        f"the inner scope's exit did not hand the outer flow back: {r}")
    assert r["after_ledger_is_outer"], "the inner scope's exit did not restore the outer ledger"
    assert not r["after_all"]["flow_active"] and not r["after_all"]["ledger_bound"], (
        f"leaving both scopes left request state behind: {r['after_all']}")


def check_threads(seen):
    r = _row(seen, "threads")
    assert r["error_count"] == 0, (
        f"a decorated handler run on concurrent threads raised {r['error_count']} times, "
        f"e.g. {r['errors']}: the decorator form is unsafe in thread-pool hosts")
    assert r["distinct_corr"] == r["calls"], (
        f"{r['calls']} decorated calls saw only {r['distinct_corr']} correlation ids: "
        "concurrent calls shared a flow")
    assert r["inner_is_never_outer"], "a decorated call ran in its caller's flow, not its own"
    assert r["stable_within_call"], "a call's flow changed while another thread entered"
    assert r["outer_lost_after_a_call"] == 0 and r["errors_logged"] == 0, (
        f"after a decorated call, {r['outer_lost_after_a_call']} calls left their thread "
        f"without the outer flow it had, and {r['errors_logged']} restores failed: "
        "concurrent calls shared one scope and could not hand each thread's flow back")
    assert not r["flow_after_in_any_thread"], "a worker thread kept a flow after its calls"


def check_refusals(seen):
    r = _row(seen, "refusals")
    for kind in ("coroutine", "generator", "async_generator"):
        assert r[kind] and "with xaidr.flow(" in r[kind], (
            f"decorating a {kind} function with xaidr.flow() was not refused "
            f"({r[kind]!r}): its body would run after the scope closed, unscoped")


def check_cross_context_exit(seen):
    r = _row(seen, "cross_context_exit")
    assert r["raised"] is None, f"the scope's exit raised into the host: {r['raised']}"
    assert not r["state_after"]["flow_active"] and not r["state_after"]["ledger_bound"], (
        f"an exit that could not restore left request state behind: {r['state_after']}")
    assert r["errors_logged"] == 1, f"expected one ERROR naming the fault, got {r['errors_logged']}"


def test_scope_that_raises_leaves_nothing_for_the_next_request(seen):
    check_scope_that_raises(seen)


def test_nested_scope_restores_the_outer_flow(seen):
    check_nested(seen)


def test_decorated_sync_handler_is_scoped_per_call_across_threads(seen):
    check_threads(seen)


def test_decorating_a_coroutine_generator_or_async_generator_is_refused(seen):
    check_refusals(seen)


def test_exit_in_a_different_context_does_not_raise_and_is_inert(seen):
    check_cross_context_exit(seen)


def test_flow_is_exported():
    assert "flow" in xaidr.__all__
