"""A2 P1: ``xaidr.flow()``, the request scope (owner rulings D1 and D3,
2026-10-08; docs/value-origin-a2-build-spec.md §1 and §4 P1).

A scope saves the five request vars (chain, correlation id, tiers, inbound mark,
value-origin ledger) on entry and puts them back on exit, on return AND on raise,
so a request that fails cannot leave its flow, and its ledger's authority, for
the next request on the same worker thread. An exit acts only in the context it
was entered in; anywhere else it changes nothing. The checks live in
``tests/outside/drivers/flow_scope.py`` and run here in-process and in
``tests/outside/test_p1_flow_scope_from_the_wheel.py`` from the built wheel.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib

import pytest

import xaidr

_spec = importlib.util.spec_from_file_location(
    "flow_scope", os.path.join(os.path.dirname(__file__), "outside", "drivers", "flow_scope.py"))
fs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fs)

AUTHORITY = {"principal", "principal_undeclared_span", "trusted_source"}
EMPTY = fs.EMPTY
REPO = pathlib.Path(__file__).resolve().parent.parent


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
    assert r["a_traceback_tail"] and r["a_traceback_tail"][0] == "user_a", (
        f"the propagated traceback ends in {r['a_traceback_tail']!r}, not at the body's raise")
    assert r["b_start"] == EMPTY, (
        f"user A's scope RAISED and still left request state on the worker thread for "
        f"user B: {r['b_start']}")
    assert r["b"] == "no_flow", (
        f"user B's tool call to an address only user A typed read {r['b']!r}: A's "
        "authority outlived a scope that raised")


def check_nested(seen):
    r = _row(seen, "nested")
    assert r["inside"]["chain"][0]["agent_id"] == "inner" and r["inner"] != r["outer"]
    assert r["inside"]["ledger"] not in (None, r["before_inner"]["ledger"]), (
        "the inner scope ran on the outer scope's ledger instead of its own")
    assert r["after_inner"] == r["before_inner"], (
        f"the inner scope's exit did not hand all five vars of the outer flow back: "
        f"before {r['before_inner']} after {r['after_inner']}")
    assert r["after_all"] == EMPTY, f"leaving both scopes left request state: {r['after_all']}"


def check_nested_in_inbound(seen):
    r = _row(seen, "nested_in_inbound")
    assert r["before"]["inbound"], "precondition: extract_context marked the request inbound"
    assert r["inside_inbound"] is True, (
        "a scope opened inside a request that arrived from another agent lowered its "
        "inbound mark: privileged calls in the scope would be gated as local work")
    assert r["after"] == r["before"], (
        f"the scope's exit did not give the inbound request back exactly: "
        f"before {r['before']} after {r['after']}")


def check_correlation_id(seen):
    r = _row(seen, "correlation_id")
    assert r["yielded"] == r["inside"] == "corr-given-1", f"correlation_id= was not honoured: {r}"


def check_threads(seen):
    r = _row(seen, "threads")
    assert r["error_count"] == 0, (
        f"a decorated handler on concurrent threads raised {r['error_count']} times, "
        f"e.g. {r['errors']}: the decorator form is unsafe in thread-pool hosts")
    assert r["distinct_corr"] == r["calls"], (
        f"{r['calls']} decorated calls saw only {r['distinct_corr']} correlation ids: "
        "concurrent calls shared a flow")
    assert r["inner_is_never_outer"], "a decorated call ran in its caller's flow, not its own"
    assert r["stable_within_call"], "a call's flow changed while another thread entered"
    assert r["outer_lost_after_a_call"] == 0 and r["faults"] == 0, (
        f"{r['outer_lost_after_a_call']} decorated calls left their thread without the "
        f"outer flow it had ({r['faults']} scope faults counted)")
    assert all(s == EMPTY for s in r["state_after_in_threads"]), (
        "a worker thread kept request state after its scopes closed")


def check_shared_instance(seen):
    r = _row(seen, "shared_instance")
    assert not r["errors"], f"one flow() object shared across threads raised: {r['errors']}"
    assert r["outer_lost"] == 0 and r["faults"] == 0, (
        f"one flow() object used with `with` on {r['rounds'] // 50} threads lost the "
        f"thread's outer flow {r['outer_lost']} times in {r['rounds']} rounds "
        f"({r['faults']} faults): an exit restored another thread's state")


def check_refusals(seen):
    r = _row(seen, "refusals")
    for kind in ("coroutine", "generator", "async_generator", "async_callable_object",
                 "sync_returning_coroutine", "wraps_wrapper_of_async_def", "returns_generator"):
        assert r[kind] and "outside the scope" in r[kind], (
            f"xaidr.flow() did not refuse a {kind} ({r[kind]!r}): its body would run "
            "after the scope closed, unscoped")
    assert not r["bodies_ran"], "a refused coroutine's body ran anyway"
    assert r["state_after"] == EMPTY, f"a refusal left request state: {r['state_after']}"
    assert r["plain_sync_ran_in_a_flow"] is True, "a plain sync function was not scoped"


def check_foreign_exit(seen):
    r = _row(seen, "foreign_exit")
    assert r["raised"] is None, f"an exit in another task raised into the host: {r['raised']}"
    assert r["own_flow_untouched"], (
        "an exit in a context the scope was not entered in changed that context's own "
        "request state: an unrelated request was altered")
    assert r["faults"] == 1, f"the foreign exit was not counted as a fault: {r['faults']}"


def check_double_exit(seen):
    r = _row(seen, "double_exit")
    assert r["raised"] is None, f"a second exit raised into the host: {r['raised']}"
    assert r["untouched"] and r["inbound_after"] is True, (
        "a second exit of a finished scope changed the inbound request it ran in "
        f"(inbound mark now {r['inbound_after']!r}): the tier gate would open")
    assert r["faults"] == 1


def check_out_of_order(seen):
    r = _row(seen, "out_of_order")
    assert r["b_kept_its_flow"], "closing an outer scope first took the inner scope's flow away"
    assert r["after_both"] == r["pre"], (
        f"after two scopes closed out of order the state is {r['after_both']}, not what it "
        "was before them: a scope that had already closed was brought back")


def check_interleaved_generators(seen):
    r = _row(seen, "interleaved_generators")
    assert r["after"] == r["pre"], (
        f"two generators with scopes, consumed interleaved and closed, left {r['after']}: "
        "a closed scope's flow (and its ledger's authority) remains for later work")


def check_gc_elsewhere(seen):
    r = _row(seen, "gc_elsewhere")
    assert r["untouched"] and r["inbound_after"] is True, (
        "collecting an abandoned generator's scope on another thread changed the "
        f"inbound request running there (inbound mark now {r['inbound_after']!r})")
    assert r["faults"] == 1


def check_enter_fault(seen):
    r = _row(seen, "enter_fault")
    assert r["raised"] is None and r["body_ran"], (
        f"a fault while the scope opened reached the host: {r['raised']}")
    assert r["faults"] == 1, (
        f"a scope that could not open counted {r['faults']} faults, not 1: its exit was "
        "logged again as a foreign or second exit, which tells an operator something false")
    assert r["after"] == EMPTY


def check_bind_fault(seen):
    r = _row(seen, "bind_fault")
    assert not r["inner_used_outer_ledger"], (
        "a scope whose fresh ledger could not be bound ran on the outer flow's ledger: "
        "its records would outlive it there")
    assert r["outer_back"]


CHECKS = (check_scope_that_raises, check_nested, check_nested_in_inbound, check_correlation_id,
          check_threads, check_shared_instance, check_refusals, check_foreign_exit,
          check_double_exit, check_out_of_order, check_interleaved_generators,
          check_gc_elsewhere, check_enter_fault, check_bind_fault)


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.__name__[len("check_"):])
def test_flow_scope(seen, check):
    check(seen)


def test_flow_is_exported():
    assert "flow" in xaidr.__all__


def test_the_plain_pair_s_limitation_is_stated_where_users_read():
    # D3 (owner, 2026-10-08): not only in a test name.
    for rel in ("docs/api.md", "README.md"):
        text = (REPO / rel).read_text(encoding="utf-8")
        assert "xaidr.flow(" in text, f"{rel} does not name the scoped form"
        assert "`clear_flow()` is skipped" in text, (
            f"{rel} does not state that a skipped clear_flow() carries the flow to the "
            "next request on the thread")
