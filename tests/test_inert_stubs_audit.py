"""Inert-stubs audit: no silent-inert paid-tier feature ships on the open surface.

A-11 trust_below: a policy condition needing a per-agent trust score (platform
tier) must be LOUDLY REJECTED at load in open, never silently no-op.
A-12 quarantine: the paid-tier quarantine state has no open setter and its dead
checks are removed — the sensor exposes no quarantine attribute implying it.
A-3 AGT evaluator: the always-allow AGT stub (_evaluate_policy) and its
_action_policy/_trust_score state are removed; only the local YAML policy is the
open authorization mechanism (and it still enforces).
"""
import logging

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


# ── ADV-2 / ADV-3: an unknown match/conditions key disarms the rule ──────────
# Same failure class as trust_below above, found by an artifact audit: a typo'd
# match key (`tool` for `tools`) parsed as a VALID policy, set_policy returned
# True, and the rule then matched nothing. The operator sees a loaded policy and
# believes the rule is enforcing. Unknown keys now join trust_below in being
# rejected loudly at load rather than silently ignored.

UNKNOWN_MATCH_KEYS = [
    ("tool", "tools"),                  # (a) singular typo — the one that was found
    ("tool_name", "tools"),             # (b) the internal request key, not the match field
    ("mcp_servers", "mcp_server"),      # (c) plural typo
    ("destination", "destination_type"),
    ("agent", "agents"),
    ("totally_made_up_key", None),      # no near-match: must still reject
]


@pytest.mark.parametrize("bad_key,near", UNKNOWN_MATCH_KEYS)
def test_unknown_match_key_is_rejected_not_silently_ignored(bad_key, near, caplog):
    """(a)(b)(c) an unrecognized `match:` key → policy REJECTED, error names it."""
    with caplog.at_level(logging.ERROR, logger="xaidr.authz"):
        accepted = _sensor().set_policy({
            "version": "1", "defaults": {"effect": "allow"},
            "rules": [{"id": "typo-rule", "effect": "block",
                       "match": {bad_key: ["export_*"]}}],
        })
    assert accepted is False, f"{bad_key!r} loaded as a valid policy — rule is silently dead"
    text = caplog.text
    assert bad_key in text, f"error does not name the offending key: {text!r}"
    assert "typo-rule" in text, f"error does not name the rule id: {text!r}"
    if near:
        assert near in text, f"error does not suggest the near-match {near!r}: {text!r}"


def test_unknown_match_key_rejected_even_beside_a_valid_matcher(caplog):
    """The dangerous shape: a typo hiding next to a matcher that really fires.

    Without this, the rule looks like it gates two things and gates only one.
    """
    with caplog.at_level(logging.ERROR, logger="xaidr.authz"):
        accepted = _sensor().set_policy({
            "version": "1", "defaults": {"effect": "allow"},
            "rules": [{"id": "half-armed", "effect": "block",
                       "match": {"tools": ["wire_transfer"], "mcp_servers": ["srv"]}}],
        })
    assert accepted is False
    assert "mcp_servers" in caplog.text


@pytest.mark.parametrize("bad_key", ["max_calls", "time_of_day", "only_if_amount_over"])
def test_unknown_conditions_key_is_rejected(bad_key, caplog):
    """(d) an unrecognized `conditions:` key → rejected.

    Silently ignoring it is worse than a dead rule: the rule fires in the cases
    the author believed the condition excluded.
    """
    with caplog.at_level(logging.ERROR, logger="xaidr.authz"):
        accepted = _sensor().set_policy({
            "version": "1", "defaults": {"effect": "allow"},
            "rules": [{"id": "cond-rule", "effect": "block",
                       "match": {"tools": ["export_*"]},
                       "conditions": {bad_key: 5}}],
        })
    assert accepted is False, f"conditions:{bad_key} loaded — the condition is ignored at runtime"
    assert bad_key in caplog.text
    assert "cond-rule" in caplog.text


def test_every_documented_match_field_still_loads_and_fires():
    """(e) control: the validator must not over-reject any real field.

    Derived from _MATCH_FIELDS so a newly added field is covered automatically
    rather than silently untested.
    """
    from xaidr.authz.policy import _MATCH_FIELDS

    values = {
        "tools": ["query_db"], "agents": ["inert-audit"], "impact_class": ["read"],
        "impact_tier": ["low", "medium", "high", "critical"],
        "destination_type": ["mcp_server"], "destination_identifier": ["srv-a"],
        "mcp_server": ["srv-a"],
    }
    assert set(values) == set(_MATCH_FIELDS), (
        "a match field was added/removed without updating this control test"
    )
    for field, val in values.items():
        s = Sensor(agent_id="inert-audit", enforcement_mode="block")
        assert s.set_policy({
            "version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
            "rules": [{"id": "ok", "effect": "block", "match": {field: val}}],
        }) is True, f"valid match field {field!r} was rejected"
        r = s.scan_tool_call("query_db", {"table": "customers"}, mcp_server="srv-a")
        assert r.action == "blocked", f"valid match field {field!r} loaded but did not fire"


def test_all_documented_match_fields_together_still_load_and_fire():
    """(e) control: every field at once, the full documented matrix in one rule."""
    s = Sensor(agent_id="inert-audit", enforcement_mode="block")
    assert s.set_policy({
        "version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": "all", "effect": "block", "match": {
            "tools": ["query_db"], "agents": ["inert-audit"], "impact_class": ["read"],
            "impact_tier": ["low", "medium", "high", "critical"],
            "destination_type": ["mcp_server"], "destination_identifier": ["srv-a"],
            "mcp_server": ["srv-a"],
        }}],
    }) is True
    assert s.scan_tool_call("query_db", {"table": "customers"},
                            mcp_server="srv-a").action == "blocked"


def test_rule_with_no_match_block_still_loads():
    """(f) control: a rule with no match: at all is still a valid load."""
    assert _sensor().set_policy({
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{"id": "bare", "effect": "allow"}],
    }) is True


def test_empty_match_and_empty_conditions_still_load():
    """(f) control: empty blocks are not 'unknown keys'."""
    assert _sensor().set_policy({
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{"id": "empty", "effect": "block", "match": {}, "conditions": {}}],
    }) is True


def test_unknown_keys_outside_match_are_still_ignored():
    """Scope guard: only match:/conditions: keys disarm a rule, so only they are
    rejected. An unknown key at rule or top level stays ignored as documented."""
    assert _sensor().set_policy({
        "version": "1", "defaults": {"effect": "allow"}, "some_future_field": 1,
        "rules": [{"id": "x", "effect": "block", "match": {"tools": ["t"]},
                   "description": "unknown rule-level key, harmless"}],
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
