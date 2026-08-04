"""The `mcp_server:` policy match field must actually match.

It is documented as a match field but read from the request CONTEXT, which
``evaluate_policy`` never populated — so a rule keyed on it silently matched
nothing, in every path, even for a tool call made with ``mcp_server="srv"``.
That is the ``trust_below`` footgun class: an advertised control that does
nothing, minus the load-time rejection.

The controls here matter as much as the fix: ``destination_type: ["mcp_server"]``
was the working alternative people were told to use, so it gets a regression
guard, and a policy-free MCP call must still run.
"""
from __future__ import annotations

from xaidr.sensor import DelphiSensor

TOOL = "query_db"
ARGS = {"table": "customers"}


def _policy(match: dict) -> dict:
    return {
        "version": "1",
        "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": "gate-mcp", "effect": "block", "match": match}],
    }


def _sensor(match: dict | None = None) -> DelphiSensor:
    s = DelphiSensor(agent_id="mcp-policy-test", enforcement_mode="block")
    if match is not None:
        assert s.set_policy(_policy(match)) is True, "policy failed to parse"
    return s


# (a) it matches the named server ─────────────────────────────────────────
def test_mcp_server_field_blocks_matching_server():
    s = _sensor({"mcp_server": ["srv-a"]})
    r = s.scan_tool_call(TOOL, ARGS, mcp_server="srv-a")
    assert r.action == "blocked", (
        f"mcp_server rule did not fire: {r.action} {r.rules} — the field is inert"
    )
    assert "policy:gate-mcp" in r.rules


def test_mcp_server_field_supports_globs():
    s = _sensor({"mcp_server": ["srv-*"]})
    assert s.scan_tool_call(TOOL, ARGS, mcp_server="srv-a").action == "blocked"


def test_mcp_server_field_matches_via_server_name_alias():
    """`server_name=` is the documented alias for `mcp_server=`."""
    s = _sensor({"mcp_server": ["srv-a"]})
    assert s.scan_tool_call(TOOL, ARGS, server_name="srv-a").action == "blocked"


# (b) it does NOT over-match a different server ───────────────────────────
def test_mcp_server_field_does_not_match_other_server():
    s = _sensor({"mcp_server": ["srv-a"]})
    r = s.scan_tool_call(TOOL, ARGS, mcp_server="srv-b")
    assert r.action == "allowed", f"over-matched a different server: {r.rules}"


# (c) it does NOT match a plain tool call ─────────────────────────────────
def test_mcp_server_field_does_not_match_call_without_mcp_server():
    s = _sensor({"mcp_server": ["srv-a"]})
    r = s.scan_tool_call(TOOL, ARGS)
    assert r.action == "allowed", (
        f"matched a non-MCP tool call: {r.rules} — an absent server must not match"
    )


# (d) control: the working alternative still works ────────────────────────
def test_destination_type_mcp_server_still_blocks():
    """Regression guard on what people were told to use instead."""
    s = _sensor({"destination_type": ["mcp_server"]})
    assert s.scan_tool_call(TOOL, ARGS, mcp_server="srv-a").action == "blocked"
    # ...and still does not catch a plain tool call.
    assert s.scan_tool_call(TOOL, ARGS).action == "allowed"


def test_destination_identifier_still_targets_the_server():
    s = _sensor({"destination_identifier": ["srv-a"]})
    assert s.scan_tool_call(TOOL, ARGS, mcp_server="srv-a").action == "blocked"
    assert s.scan_tool_call(TOOL, ARGS, mcp_server="srv-b").action == "allowed"


# (e) control: no policy, the call runs ───────────────────────────────────
def test_policy_free_mcp_tool_call_executes_normally():
    canary = {"ran": 0}

    class _Tool:
        name = TOOL

        @staticmethod
        def func(**kwargs):
            canary["ran"] += 1
            return "tool executed"

    s = _sensor()
    assert s.scan_tool_call(TOOL, ARGS, mcp_server="srv-a").action == "allowed"

    out = s.protect_tools([_Tool()])[0](**ARGS)
    assert canary["ran"] == 1, "a policy-free MCP tool call did not execute"
    assert out == "tool executed"


# the wiring itself ───────────────────────────────────────────────────────
def test_context_reaches_the_key_the_matcher_reads():
    """Pin the key path: build_request's context lands where _rule_matches looks."""
    from xaidr.authz.policy import _MATCH_FIELDS, build_request

    section, key = _MATCH_FIELDS["mcp_server"]
    request = build_request(
        agent_id="a", trust=None, tool_name="t",
        impact_class="read", impact_tier="low",
        destination_type="mcp_server", destination_identifier="srv-a",
        context={"mcp_server": "srv-a"},
    )
    assert request[section][key] == "srv-a", (
        f"matcher reads {section}.{key}, which build_request did not populate"
    )
