"""The two HIGH findings that are not parser differentials.

F1 (URL host) and F2 (SQL predicate boundedness) are pinned in
tests/test_differential_parsers.py, against the transport and against SQLite —
they are exactly the shape that file exists for. The two here are relations
between facts, not readings of a string, so their oracle is behaviour:

    F4  a filter key ANYWHERE suppressed privilege detection
    F3  a second sensor inherited the first sensor's wrapper and enforced nothing
"""
from __future__ import annotations

import asyncio
import logging
import warnings

import pytest

from xaidr import Sensor
from xaidr.scanner.privilege_action import scan_privileged_action


def _rules(args, tool="grant_role"):
    return sorted(f["rule"] for f in scan_privileged_action(tool, args))


# ═══════════════════════════════════════════════════════════════════════════
# F4a. A SUPPRESSOR MUST BE A SIBLING
# ═══════════════════════════════════════════════════════════════════════════
#
# `_FILTER_KEYS` holds fourteen of the commonest key names in any API — `state`,
# `type`, `query`, `page`, `sort`. Read from the FLATTENED argument tree, one of
# them anywhere in the call, at any nesting depth, in any unrelated object,
# turned the admin-escalation predicate off. That is not a relation between two
# arguments; it is a switch the caller can flip from anywhere.

@pytest.mark.parametrize("args, why", [
    ({"role": "org-admin", "context": {"ui": {"sort": "name"}}},
     "a UI sort hint three levels down"),
    ({"role": "admin", "metadata": {"type": "grant"}},
     "a `type` key inside an unrelated metadata blob"),
    ({"role": "admin", "pagination": {"page": 2, "per_page": 50}},
     "pagination for a different part of the request"),
    ({"principal": "agent://self", "role": "org-admin",
      "audit": {"ticket": "T-1"}},
     "a governance marker in a sibling record, not on the grant"),
])
def test_a_filter_or_governance_key_in_another_record_does_not_excuse_a_grant(args, why):
    assert "ASI03_admin_escalation" in _rules(args), why


@pytest.mark.parametrize("args", [
    {"visibility": "all", "role": "admin"},
    {"role": "admin", "state": "open", "per_page": 100},
    {"role": "admin", "ticket": "CHG-2291"},
    {"role": "admin", "approval": "AP-4471"},
])
def test_a_filter_or_governance_key_in_the_SAME_record_still_excuses_it(args):
    """The 1.14.1 carve-outs are relations between SIBLING arguments and they
    still hold. Narrowing the scope must not have deleted them."""
    assert "ASI03_admin_escalation" not in _rules(args)


# ═══════════════════════════════════════════════════════════════════════════
# F4b. A READ-ONLY WORD EXCUSES ITS OWN SCOPE, NOT THE STRING
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("value", [
    "admin,readonly",
    "read-only,root",
    "viewer, superuser",
    "reader;org-admin",
    "admin.directory.user.readonly,admin",
])
def test_a_read_only_scope_does_not_excuse_an_admin_scope_beside_it(value):
    assert "ASI03_admin_escalation" in _rules({"scopes": value}), value


@pytest.mark.parametrize("value", [
    "admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "viewer",
    "admin-readonly",
])
def test_a_genuinely_read_only_scope_is_still_excused(value):
    """The carve-out exists because `admin` in an OAuth scope names the API
    SURFACE, not the power taken. Splitting on separators must not break it."""
    assert "ASI03_admin_escalation" not in _rules({"scope": value}), value


def test_the_battery_widening_shape_still_fires():
    """ASI03-A03 widens a token to `read,write,admin,billing`. The split must
    not turn the leading `read` into an excuse."""
    assert "ASI03_admin_escalation" in _rules(
        {"scopes": "read,write,admin,billing"})


# ═══════════════════════════════════════════════════════════════════════════
# F4c. camelCase IS THE SAME KEY
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("camel, snake, rule", [
    ({"accessLevel": "admin"}, {"access_level": "admin"},
     "ASI03_admin_escalation"),
    ({"requireApproval": False}, {"require_approval": False},
     "ASI03_disable_control"),
    ({"safetyChecks": "off"}, {"safety_checks": "off"},
     "ASI03_disable_control"),
    ({"retentionDays": 0}, {"retention_days": 0},
     "ASI03_disable_control"),
    ({"flag": "requireApproval", "value": False},
     {"flag": "require_approval", "value": False},
     "ASI03_disable_control"),
])
def test_camel_and_snake_spellings_of_one_key_get_one_answer(camel, snake, rule):
    """Every JS and Java SDK emits camelCase. `access_level` was in
    `_ROLE_KEYS` and `accessLevel` lowercased to `accesslevel`, which is in
    nothing, so the whole predicate was one naming convention away from
    silent."""
    assert rule in _rules(camel), f"{camel} missed"
    assert _rules(camel) == _rules(snake), f"{camel} != {snake}"


# ── the 1.14.1 false-positive carve-outs, unchanged ─────────────────────────

@pytest.mark.parametrize("tool, args", [
    ("get_agent_profile", {"user": "self"}),
    ("panel_query", {"panel": "monitoring", "offset": 0}),
    ("list_repos", {"visibility": "all", "role": "admin"}),
    ("es_search", {"index": "logs", "size": 0}),
    ("oauth_request", {"scope": "admin.directory.user.readonly"}),
])
def test_the_1_14_1_false_positives_stay_silent(tool, args):
    assert _rules(args, tool) == []


# ═══════════════════════════════════════════════════════════════════════════
# F3. A SECOND SENSOR MUST NOT INHERIT THE FIRST SENSOR'S WRAPPER
# ═══════════════════════════════════════════════════════════════════════════
#
# This is the staged rollout docs/rollout.md recommends, in two lines: run in
# monitor, then add a block-mode sensor once the stream is clean. The marker on
# the wrapper said only "some sensor wrapped this", so the block-mode sensor got
# the monitor-mode wrapper back unchanged and enforced nothing.


def _sensor(agent_id, mode, blocked=()):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = Sensor(agent_id=agent_id, enforcement_mode=mode)
    if blocked:
        s.block_tools(list(blocked))
    return s


def test_a_block_sensor_enforces_on_a_tool_a_monitor_sensor_already_wrapped(capsys):
    ran = []

    def danger(cmd: str):
        ran.append(cmd)
        return "RAN " + cmd

    monitor = _sensor("A", "monitor")
    blocker = _sensor("B", "block", blocked=["danger"])

    monitored = monitor.protect_tools([danger])[0]
    staged = blocker.protect_tools([monitored])[0]

    assert staged is not monitored, (
        "the block-mode sensor returned the monitor-mode sensor's wrapper; "
        "its enforcement_mode, its blocked-tool list and its policy all apply "
        "to nothing")
    out = staged("rm -rf /")
    assert out.startswith("[BLOCKED]"), out
    assert ran == [], "the blocked tool executed"


def test_the_outer_sensor_halts_first_and_the_strictest_verdict_wins():
    """Rebinding, not refusing: both sensors scan, the outer one halts first.
    If the outer sensor ALLOWS, the inner one still gets its verdict."""
    ran = []

    def tool_a(cmd: str):
        ran.append(cmd)
        return "ok"

    inner = _sensor("inner", "block", blocked=["tool_a"])
    outer = _sensor("outer", "block")           # blocks nothing of its own

    layered = outer.protect_tools([inner.protect_tools([tool_a])[0]])[0]
    assert layered("anything").startswith("[BLOCKED]")
    assert ran == []


def test_the_foreign_wrapper_is_reported_not_silently_returned(caplog):
    def tool_b(cmd: str):
        return "ok"

    a = _sensor("A", "monitor")
    b = _sensor("B", "block")
    with caplog.at_level(logging.INFO, logger="xaidr.sensor"):
        b.protect_tools([a.protect_tools([tool_b])[0]])
    assert any("already protected by sensor" in r.getMessage()
               for r in caplog.records), (
        "a second sensor layering over a first is a configuration the operator "
        "should be able to see; a silent return is the one option that is wrong")


def test_one_sensor_wrapping_twice_is_still_idempotent():
    """The dedup the marker was introduced for. `xaidr.protect()` can reach the
    same tool as a manual `protect_tools` call, and one sensor must not emit two
    telemetry events for one action."""
    def tool_c(cmd: str):
        return "ok"

    s = _sensor("S", "monitor")
    once = s.protect_tools([tool_c])[0]
    twice = s.protect_tools([once])[0]
    assert twice is once


def test_idempotency_survives_another_sensor_layering_in_between():
    """Idempotency is about the CHAIN, not the outermost mark. Checking only
    the top layer makes it depend on layering order: with `a(b(a(f)))` the
    outermost mark belongs to `b`, so `a` concludes it has not wrapped this and
    takes a second layer — two scans and two telemetry events from one sensor
    for one action, the exact miscount the marker exists to prevent."""
    def tool_d(cmd: str):
        return "ok"

    a = _sensor("A", "monitor")
    b = _sensor("B", "monitor")

    once_a = a.protect_tools([tool_d])[0]
    layered = b.protect_tools([once_a])[0]
    again = a.protect_tools([layered])[0]

    assert again is layered, "sensor A took a second layer over its own wrapper"

    depth, fn = 0, again
    while hasattr(fn, "_xaidr_protect_original"):
        depth += 1
        fn = fn._xaidr_protect_original
    assert depth == 2, f"wrapper chain is {depth} deep, expected one per sensor"


# ── the second half of the same marker bug: the halves shared one answer ────

class _LCish:
    """Shaped like a LangChain StructuredTool: name, func, coroutine,
    model_copy. Hand-rolled so the seam is exercised without the optional
    langchain-core dependency (the framework tests that need the real class
    skip when it is absent, which is exactly when this hole would ship)."""

    def __init__(self, name, func=None, coroutine=None):
        self.name, self.func, self.coroutine = name, func, coroutine

    def model_copy(self, update=None):
        t = _LCish(self.name, self.func, self.coroutine)
        for k, v in (update or {}).items():
            setattr(t, k, v)
        return t


def test_an_unwrapped_coroutine_is_wrapped_even_when_func_already_was():
    """`already` was an OR across the three implementation halves, so a tool
    whose `func` this sensor had wrapped and whose `coroutine` it had not was
    reported protected — and `ainvoke` went straight to the raw coroutine."""
    ran = []

    def sync_impl(cmd: str):
        ran.append(("sync", cmd))
        return "SYNC"

    async def async_impl(cmd: str):
        ran.append(("async", cmd))
        return "ASYNC"

    s = _sensor("S", "block", blocked=["danger"])
    protected = s.protect_tools([_LCish("danger", sync_impl, async_impl)])[0]

    # Rebuild with this sensor's wrapped `func` and a FRESH coroutine.
    mixed = _LCish("danger", protected.func, async_impl)
    out = s.protect_tools([mixed])[0]

    assert out.func is protected.func, "the already-wrapped half was re-wrapped"
    assert asyncio.run(out.coroutine("x")).startswith("[BLOCKED]")
    assert ("async", "x") not in ran, "the async half executed a blocked tool"
