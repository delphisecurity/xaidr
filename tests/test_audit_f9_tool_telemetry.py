"""F9: the tool path reported content and cost it had not measured.

REPRODUCED ON 1.12.0, from live output:

    "scanTimeMs": 0, "promptLength": 0, "promptHash": "aeaf9a308c3a65df"

and three DIFFERENT commands to `run_command` produced that one hash, because it
was a digest of the tool NAME. The attribute it maps to is called
`gen_ai.security.interaction.content_hash`, and correlating a payload across
agents and across time is the only thing a content hash is for. A column that
always matches is worse than an absent one, because it looks like it works.

The other three boundaries (input, output, a2a) already hashed what they
scanned, so the tool path was the outlier rather than the rule -- which is why
this is a defect against the schema rather than a redefinition of it, and why
SCHEMA_VERSION does not move for it. See the version test at the end.
"""

from __future__ import annotations

import pytest

from xaidr import Sensor
from xaidr.schema import SCHEMA_VERSION, to_openA2A
from xaidr.sensor import _canonical_arguments
from xaidr.types import safe_content_hash


class _Capture:
    def __init__(self):
        self.events = []

    def report(self, events):
        self.events.extend(events)

    def close(self, *a, **k):
        pass


def _emit(tool="run_command", arguments=None, **kw):
    cap = _Capture()
    s = Sensor(agent_id="f9", enforcement_mode="block", reporter=cap, **kw)
    s.scan_tool_call(tool, arguments if arguments is not None else {"command": "ls -la"})
    s.flush()
    assert cap.events, "no telemetry emitted for a tool call"
    return cap.events[-1]["data"]


# ── (a) promptHash is a digest of the ARGUMENTS ─────────────────────────────

def test_different_arguments_to_one_tool_produce_different_hashes():
    """The reproduction, inverted. Three distinct commands shared one hash."""
    hashes = {
        _emit(arguments={"command": c})["promptHash"]
        for c in ("cat ~/.ssh/id_rsa", "ls -la", "rm -rf /")
    }
    assert len(hashes) == 3, (
        f"different arguments share a hash, so a SIEM cannot correlate "
        f"payloads: {hashes}"
    )


def test_the_hash_is_not_the_tool_name_digest():
    """The specific regression. Named separately from the test above so the
    failure says WHICH defect came back."""
    data = _emit(arguments={"command": "cat ~/.ssh/id_rsa"})
    assert data["promptHash"] != safe_content_hash("run_command"), (
        "promptHash is a digest of the tool NAME again")


def test_argument_key_order_does_not_change_the_hash():
    """Canonical, because two calls carrying the same arguments in a different
    order are the same payload."""
    a = _emit(arguments={"b": "two", "a": "one"})["promptHash"]
    b = _emit(arguments={"a": "one", "b": "two"})["promptHash"]
    assert a == b


def test_the_same_arguments_to_different_tools_still_differ_by_tool():
    """Correlation by payload must not lose the tool. The tool name is its own
    field (`toolName`), so this is about the EVENT being distinguishable."""
    x = _emit(tool="run_command", arguments={"command": "ls -la"})
    y = _emit(tool="other_tool", arguments={"command": "ls -la"})
    assert x["promptHash"] == y["promptHash"], (
        "the hash is over content, so identical content hashes identically")
    assert x["toolName"] != y["toolName"]


# ── (b) scanTimeMs and promptLength are measured ────────────────────────────

def test_scan_time_is_measured_not_zero():
    data = _emit(arguments={"command": "cat ~/.ssh/id_rsa"})
    assert data["scanTimeMs"] > 0, (
        "the tool path runs an L1 argument scan, structural extraction, "
        "classification and policy evaluation, and reported 0 ms for all of it")


def test_scan_time_matches_the_result_latency():
    """One measurement, two surfaces. A ScanResult whose latency disagrees with
    the telemetry is two numbers for one fact."""
    cap = _Capture()
    s = Sensor(agent_id="f9", enforcement_mode="block", reporter=cap)
    result = s.scan_tool_call("run_command", {"command": "cat ~/.ssh/id_rsa"})
    s.flush()
    assert result.latency_ms > 0
    assert cap.events[-1]["data"]["scanTimeMs"] == result.latency_ms


def test_prompt_length_is_the_canonical_argument_length():
    args = {"command": "cat ~/.ssh/id_rsa"}
    data = _emit(arguments=args)
    assert data["promptLength"] == len(_canonical_arguments(args))
    assert data["promptLength"] > 0


def test_empty_arguments_report_zero_length_honestly():
    """Zero is the right answer here, and the point of the fix is that it is now
    a measurement rather than a constant."""
    data = _emit(arguments={})
    assert data["promptLength"] == len(_canonical_arguments({}))
    assert data["promptHash"] == safe_content_hash(_canonical_arguments({}))


# ── the canonicaliser must never take the scan down ─────────────────────────

@pytest.mark.parametrize("arguments", [
    {"when": object()},
    {"nested": {"deep": [1, 2, {"x": object()}]}},
    {"bytes": b"\xff\xfe"},
    None,
    {},
])
def test_canonical_arguments_never_raises(arguments):
    out = _canonical_arguments(arguments)
    assert isinstance(out, str)


def test_a_tool_call_with_unserialisable_arguments_still_emits():
    data = _emit(arguments={"payload": object(), "command": "ls -la"})
    assert data["promptHash"] and data["promptLength"] > 0
    assert data["scanTimeMs"] > 0


# ── (d) the openA2A mapping carries the tier calculation ────────────────────

TIER_ATTRS = (
    "gen_ai.security.authz.privilege_tier",
    "gen_ai.security.authz.privilege_tier_configured",
    "gen_ai.security.authz.least_privileged_tier",
    "gen_ai.security.authz.delegated",
)


def test_the_mapping_carries_the_tier_calculation():
    """An operator asked "why did this need approval?" needs the working, not
    just the answer. All four were dropped."""
    cap = _Capture()
    s = Sensor(agent_id="f9", enforcement_mode="block", reporter=cap, privilege_tier=2)
    s.scan_tool_call("run_command", {"command": "cat ~/.ssh/id_rsa"})
    s.flush()
    mapped = to_openA2A(cap.events[-1])
    for attr in TIER_ATTRS:
        assert attr in mapped, f"{attr} was dropped by the mapping"
    assert mapped["gen_ai.security.authz.privilege_tier"] == 2
    assert mapped["gen_ai.security.authz.privilege_tier_configured"] is True


def test_a_defaulted_tier_is_carried_as_false_not_omitted():
    """False is a fact, not an absence: it says the tier is the DEFAULT rather
    than something the deployer chose."""
    cap = _Capture()
    s = Sensor(agent_id="f9", enforcement_mode="block", reporter=cap)
    s.scan_tool_call("run_command", {"command": "ls -la"})
    s.flush()
    mapped = to_openA2A(cap.events[-1])
    assert mapped["gen_ai.security.authz.privilege_tier_configured"] is False
    assert mapped["gen_ai.security.authz.delegated"] is False


def test_the_mapping_carries_the_argument_content_hash_and_length():
    cap = _Capture()
    s = Sensor(agent_id="f9", enforcement_mode="block", reporter=cap)
    s.scan_tool_call("run_command", {"command": "cat ~/.ssh/id_rsa"})
    s.flush()
    data = cap.events[-1]["data"]
    mapped = to_openA2A(cap.events[-1])
    assert mapped["gen_ai.security.interaction.content_hash"] == data["promptHash"]
    assert mapped["gen_ai.security.interaction.content_length"] == data["promptLength"]
    assert mapped["gen_ai.security.detection.latency_ms"] == data["scanTimeMs"]
    assert mapped["gen_ai.security.detection.latency_ms"] > 0


def test_an_empty_chain_omits_chain_tiers_rather_than_emitting_an_empty_list():
    cap = _Capture()
    s = Sensor(agent_id="f9", enforcement_mode="block", reporter=cap)
    s.scan_tool_call("run_command", {"command": "ls -la"})
    s.flush()
    mapped = to_openA2A(cap.events[-1])
    assert "gen_ai.security.authz.chain_tiers" not in mapped


# ── (e) SCHEMA_VERSION ──────────────────────────────────────────────────────

def test_schema_version_did_not_move_for_this_change():
    """THE RULE, applied. Additive keys do not move it; a changed MEANING does.

    Four tier attributes are ADDITIVE: new optional keys in a namespace this
    file already documents as additive, on an event type that already exists.
    Nothing a consumer reads today disappears or changes type.

    promptHash, promptLength and scanTimeMs look like meaning changes and are
    not. The attributes are named `interaction.content_hash`,
    `interaction.content_length` and `detection.latency_ms`; the schema has
    always said they describe the scanned content and the cost of scanning it.
    The tool path did not honour that -- it emitted a tool-name digest and two
    constant zeros. Making an emitter match the schema it already declared is a
    defect fix, not a redefinition, and there is no working consumer rule to
    break: a hash that was identical for every call to a tool could not have
    been correlated on, and a latency of 0 could not have been budgeted against.

    Moving the version here would tell every consumer to re-check rules that are
    still correct, which is how a version signal stops being read.
    """
    assert SCHEMA_VERSION == "0.2.0"


def test_the_added_attributes_are_absent_rather_than_null_when_unknown():
    """The absent-means-unknown contract, held for the new keys."""
    mapped = to_openA2A({"type": "scan", "agentId": "a",
                         "data": {"action": "allowed", "score": 0.0}})
    for attr in TIER_ATTRS + ("gen_ai.security.authz.chain_tiers",):
        assert attr not in mapped, f"{attr} emitted as null on an event without it"
