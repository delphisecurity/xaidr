"""Inert-stubs audit: no silent-inert paid-tier feature ships on the open surface.

A-11 trust_below: a policy condition needing a per-agent trust score (platform
tier) must be LOUDLY REJECTED at load in open, never silently no-op.
A-12 quarantine: the paid-tier quarantine state has no open setter and its dead
checks are removed — the sensor exposes no quarantine attribute implying it.
A-3 AGT evaluator: the always-allow AGT stub (_evaluate_policy) and its
_action_policy/_trust_score state are removed; only the local YAML policy is the
open authorization mechanism (and it still enforces).
"""
import pytest

from xaidr import Sensor
from xaidr.authz.policy import parse_action_policy


# ── A-11 ─────────────────────────────────────────────────────────────────────

def test_trust_below_policy_is_rejected_not_silently_ignored():
    policy = {
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{
            "id": "untrusted", "effect": "block",
            "match": {"destination_type": ["external_api"]},
            "conditions": {"trust_below": 0.5},
        }],
    }
    # Loud reject: the whole policy is refused (None), not accepted-but-inert.
    assert parse_action_policy(policy) is None


def test_policy_without_trust_below_still_parses():
    policy = {
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{"id": "no-wire", "effect": "block",
                   "match": {"tools": ["wire_transfer"]}}],
    }
    parsed = parse_action_policy(policy)
    assert parsed is not None and len(parsed["rules"]) == 1


def test_local_yaml_policy_still_enforces_without_trust():
    s = Sensor(agent_id="a11", enforcement_mode="block")
    assert s.set_policy({
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{"id": "no-wire", "effect": "block",
                   "match": {"tools": ["wire_transfer"]}}],
    })
    assert s.scan_tool_call("wire_transfer", {"amount": 1000}).action == "blocked"
    assert s.scan_tool_call("get_weather", {"city": "Toronto"}).action == "allowed"


# ── A-11 regression: trust_below is rejected in EITHER placement ─────────────
#
# The load-time guard originally inspected only `conditions:`. A rule that put
# trust_below under `match:` loaded fine, and at evaluation time
# rule["conditions"].get("trust_below") returned None — so the trust check never
# ran and the policy looked enforced while doing nothing. `match:` is the
# placement the README documents, so it was the common case. These tests drive
# the public API (Sensor.set_policy) so they exercise the real user path.

def _sensor():
    return Sensor(agent_id="a11-regression", enforcement_mode="block")


def test_trust_below_under_conditions_rejected_via_set_policy():
    """(a) trust_below under `conditions:` → policy rejected."""
    assert _sensor().set_policy({
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{
            "id": "untrusted-conditions", "effect": "block",
            "match": {"destination_type": ["external_api"]},
            "conditions": {"trust_below": 0.5},
        }],
    }) is False


def test_trust_below_under_match_alone_rejected_via_set_policy():
    """(b) trust_below under `match:` alone → policy rejected (the bug)."""
    assert _sensor().set_policy({
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{
            "id": "untrusted-match-only", "effect": "block",
            "match": {"trust_below": 0.5},
        }],
    }) is False


def test_trust_below_under_match_with_valid_matcher_rejected_via_set_policy():
    """(c) trust_below under `match:` next to a valid matcher → still rejected.

    The dangerous shape: `tools:` makes the rule look live, so the inert
    trust_below hides behind a matcher that really does fire.
    """
    assert _sensor().set_policy({
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{
            "id": "untrusted-match-mixed", "effect": "block",
            "match": {"tools": ["wire_transfer"], "trust_below": 0.5},
        }],
    }) is False


def test_policy_without_trust_below_still_accepted_via_set_policy():
    """(d) no trust_below anywhere → accepted; the guard does not over-reject."""
    assert _sensor().set_policy({
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{
            "id": "no-wire", "effect": "block",
            "match": {
                "tools": ["wire_transfer"],
                "impact_tier": ["tier_1"],
                "destination_type": ["external_api"],
            },
        }],
    }) is True


# ── A-12 ─────────────────────────────────────────────────────────────────────

def test_no_quarantine_state_on_open_sensor():
    s = Sensor(agent_id="a12")
    assert not hasattr(s, "_quarantined")
    assert not hasattr(s, "_quarantine_reason")


def test_scan_paths_never_emit_quarantine_category():
    s = Sensor(agent_id="a12b", enforcement_mode="block")
    for r in (
        s.scan("hello world"),
        s.scan_output("some model output"),
        s.scan_a2a("hi peer", destination="peer"),
        s.scan_tool_call("get_weather", {"city": "Toronto"}),
    ):
        assert r.category != "quarantined"
        assert "QUARANTINE_ENFORCED" not in (r.rules or [])


# ── A-3 ──────────────────────────────────────────────────────────────────────

def test_no_agt_stub_or_state_on_open_sensor():
    s = Sensor(agent_id="a3")
    assert not hasattr(s, "_evaluate_policy")
    assert not hasattr(s, "_action_policy")
    assert not hasattr(s, "_trust_score")


def test_blocked_tools_and_arg_scan_still_work():
    s = Sensor(agent_id="a3b", enforcement_mode="block")
    s.block_tools(["danger"])
    assert s.scan_tool_call("danger", {}).action == "blocked"
    # tool-arg content scan (the working open signal) still fires
    assert s.scan_tool_call(
        "run_command", {"command": "rm -rf / --no-preserve-root"}
    ).action == "blocked"
