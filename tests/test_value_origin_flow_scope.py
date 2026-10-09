"""A2 P1: ``xaidr.flow()``, the request scope (owner rulings D1 and D3,
2026-10-08; docs/value-origin-a2-build-spec.md §1 and §4 P1).

The first scope in a context saves the five request vars and puts them back on
exit, on return AND on raise; a scope inside it joins it; an exit closes
everything opened inside it; an exit anywhere else changes nothing. So a request
that fails cannot leave its flow, and its ledger's authority, for the next
request on the same worker thread, and nothing a scope does can lower the
privilege-tier gate. The checks live in ``tests/outside/drivers/flow_scope.py``
and run here in-process and in
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
GATED, OPEN = "approval_required", "allowed"
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


def check_nested_joins(seen):
    r = _row(seen, "nested_joins")
    assert r["inner_yielded"] == r["outer"], "a nested scope did not join the open request"
    assert r["inside"] == r["before"], (
        f"a scope opened inside an open request changed it: before {r['before']}, "
        f"inside {r['inside']}")
    assert r["after"] == r["before"], "a joined scope's exit changed the request"
    assert r["after_all"] == EMPTY, f"leaving the request left state: {r['after_all']}"


def check_tier_gate(seen):
    r = _row(seen, "tier_gate")
    # positive control: local work is not gated, so GATED below is the upstream's tier
    assert r["local_inbound_mark"] is False and r["local_verdict"] == OPEN, (
        f"a local scope gated its own work (inbound {r['local_inbound_mark']!r}, "
        f"verdict {r['local_verdict']!r}): it marked local work as delegated")
    for key in ("plain_inbound_outside", "scope_inbound_outside", "delegation_outside"):
        assert r[key] == GATED, f"precondition {key}: the tier-4 upstream gates the call, got {r[key]!r}"
    for key in ("plain_inbound_in_decorated_handler", "plain_inbound_after_handler",
                "scope_inbound_in_decorated_handler", "scope_inbound_in_nested_principal_scope",
                "delegation_in_decorated_handler"):
        assert r[key] == GATED, (
            f"{key}: a tier-4 upstream's privileged call read {r[key]!r} through xaidr.flow(): "
            "the scope dropped the delegation evidence and opened the tier gate")
    assert r["scope_inbound_after_scope_state"] == EMPTY


def check_inbound_restored(seen):
    r = _row(seen, "inbound_restored")
    assert r["inside_inbound"] is True
    assert r["after"] == EMPTY, f"the inbound request's state outlived its scope: {r['after']}"
    assert r["next_local_verdict"] == OPEN, (
        "after an inbound request's scope, the next local request on the thread was gated "
        f"as delegated ({r['next_local_verdict']!r}): the inbound mark outlived the scope")


def check_correlation_id(seen):
    r = _row(seen, "correlation_id")
    assert r["yielded"] == r["inside"] == "corr-given-1", f"correlation_id= was not honoured: {r}"


def check_threads(seen):
    r = _row(seen, "threads")
    assert r["error_count"] == 0, (
        f"a decorated handler on concurrent threads raised {r['error_count']} times, "
        f"e.g. {r['errors']}: the decorator form is unsafe in thread-pool hosts")
    assert r["top_distinct_corr"] == r["top_calls"], (
        f"{r['top_calls']} top-level decorated calls saw {r['top_distinct_corr']} ids: "
        "concurrent requests shared a flow")
    assert r["top_stable_within_call"], "a call's flow changed while another thread entered"
    assert r["joined_calls_in_their_request"] == r["joined_calls"], (
        "a decorated call inside a request scope did not run in that request")
    assert r["request_changed_by_a_call"] == 0 and r["faults"] == 0, (
        f"{r['request_changed_by_a_call']} decorated calls changed the request they ran "
        f"in ({r['faults']} faults)")
    assert all(s == EMPTY for s in r["state_after_in_threads"]), (
        "a worker thread kept request state after its scopes closed")


def check_shared_instance(seen):
    r = _row(seen, "shared_instance")
    assert not r["errors"], f"one flow() object shared across threads raised: {r['errors']}"
    assert r["state_wrong"] == 0 and r["faults"] == 0, (
        f"one flow() object used with `with` on several threads left a thread in the "
        f"wrong state {r['state_wrong']} times in {r['rounds']} rounds ({r['faults']} faults)")


def check_recursion(seen):
    r = _row(seen, "recursion")
    assert r["all_in_one_request"] and r["after"] == EMPTY, (
        f"a recursive decorated handler left one call in another's flow: {r}")


def check_refusals(seen):
    r = _row(seen, "refusals")
    for kind in ("coroutine_function", "generator_function", "async_generator_function",
                 "async_callable_object", "sync_returning_coroutine", "wraps_wrapper_of_async_def",
                 "returns_async_generator", "returns_custom_awaitable"):
        assert r[kind] and "outside the scope" in r[kind], (
            f"xaidr.flow() did not refuse a {kind} ({r[kind]!r}): its body would run "
            "after the scope closed, unscoped")
    assert not r["bodies_ran"], "a refused coroutine's body ran anyway"
    assert r["wsgi_body_returned"] is True, "a WSGI-style app returning its body was refused"
    assert r["future_returned"] == "done", (
        f"a handler returning a Future was refused ({r['future_returned']!r}), though the "
        "task runs in a copy of the scope's context")
    assert r["plain_sync_ran_in_a_flow"] is True and r["state_after"] == EMPTY


def check_generator_held(seen):
    r = _row(seen, "generator_held")
    for kind in ("sync_generator", "async_generator", "exitstack_in_generator"):
        assert r[kind] and "inside a generator's body" in r[kind], (
            f"a scope opened in a {kind} was not refused ({r[kind]!r}): its exit would run "
            "whenever the generator is resumed or collected, in any request")
    assert r["contextmanager_wrapper_works"] is True, (
        "a scope inside a @contextmanager wrapper, which the with-statement drives in "
        "order, was refused or did not open")
    assert r["after"] == EMPTY


def check_foreign_exit(seen):
    r = _row(seen, "foreign_exit")
    assert r["raised"] is None, f"an exit in another task raised into the host: {r['raised']}"
    assert r["own_request_untouched"] and r["verdict_before"] == r["verdict_after"] == GATED, (
        "an exit in a context its scope was not entered in changed the request running "
        f"there (tier verdict {r['verdict_before']!r} -> {r['verdict_after']!r})")
    assert r["faults"] == 1, f"the foreign exit was not counted as a fault: {r['faults']}"


def check_double_exit(seen):
    r = _row(seen, "double_exit")
    assert r["raised"] is None, f"a second exit raised into the host: {r['raised']}"
    assert r["untouched"] and r["verdict_before"] == r["verdict_after"] == GATED, (
        "a second exit of a finished scope changed the inbound request it ran in (tier "
        f"verdict {r['verdict_before']!r} -> {r['verdict_after']!r}): the gate would open")
    assert r["faults"] == 1


def check_outer_closes_inner(seen):
    r = _row(seen, "outer_closes_inner")
    assert r["a_still_open_after_b"], "closing an inner scope took the outer request away"
    assert r["after_all"] == r["pre"], (
        f"after scopes closed out of order the state is {r['after_all']}, not what it was "
        "before them: a closed scope's flow remains")
    assert r["faults"] == 0, "a scope closed by its enclosing scope was counted as a fault"


def check_request_raises_with_inner_open(seen):
    r = _row(seen, "request_raises_with_inner_open")
    assert r["b_start"] == EMPTY and r["b"] == "no_flow", (
        f"user A's request scope raised with a scope still open inside it, and user B "
        f"started in {r['b_start']} and read {r['b']!r}: the request did not end")
    assert r["c_scope_fresh"], (
        "after a request scope ended with a scope still open inside it, the next request's "
        "scope JOINED the leftover instead of starting fresh: it ran with no flow of its own")


def check_clear_flow_closes_scopes(seen):
    r = _row(seen, "clear_flow_closes_scopes")
    assert r["mid"] == EMPTY and r["after"] == EMPTY
    assert r["next_is_fresh"], (
        "after a request ended by clear_flow() with a scope still open, the next request's "
        "scope JOINED the finished one and ran with no flow of its own")
    assert r["late_exit_untouched"], "the closed scope's late exit changed the next request"
    assert r["faults"] == 0, "a scope closed by clear_flow() was counted as a fault on exit"


def check_enter_faults(seen):
    r = _row(seen, "enter_faults")
    for where in ("save", "begin_flow"):
        row = r[where]
        assert row["raised"] is None and row["body_ran"], (
            f"a fault while the scope opened ({where}) reached the host: {row['raised']}")
        assert row["faults"] == 1, (
            f"a scope that could not open ({where}) counted {row['faults']} faults, not 1")
        assert row["after"] == EMPTY, f"a scope that could not open ({where}) left state"


def check_exit_fault(seen):
    r = _row(seen, "exit_fault")
    assert r["after"] == EMPTY, (
        f"a fault while putting the flow back left the closed scope's state: {r['after']}")
    assert r["faults"] == 1


def check_fault_log(seen):
    r = _row(seen, "fault_log")
    errors = [m for lvl, m in r["records"] if lvl == "ERROR"]
    assert len(errors) == 1 and "(1 scope fault(s)" in errors[0], (
        f"the first scope fault was not logged once with its count: {r['records']}")


def check_bind_fault(seen):
    r = _row(seen, "bind_fault")
    assert not r["inside_used_prior_ledger"], (
        "a scope whose fresh ledger could not be bound ran on the ledger bound before it: "
        "its records would outlive it there")
    assert r["prior_back"]


CHECKS = {name: globals()[f"check_{name}"] for name in fs.CASES}


@pytest.mark.parametrize("case", fs.CASES)
def test_flow_scope(seen, case):
    CHECKS[case](seen)


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
