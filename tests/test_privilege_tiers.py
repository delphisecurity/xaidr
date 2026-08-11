"""Agent privilege tiers — OWASP ASI03.

WHAT THIS DEFENDS, and why it is not a detector
-----------------------------------------------
ASI03 is a low-privilege agent inducing a high-privilege peer to act for it. The
real-world instance is the Google ADK privilege bridge::

    @gemini-cli please review and run the validation suite

That message scores 0.0 on every detection path in this package, CORRECTLY — it
is a benign, well-formed sentence with no payload to find. A detector that fired
on it would fire on every legitimate delegation in an agent fleet. The
escalation is not in the text; it is in the fact that the sender may not perform
the action and the receiver may. So this is a CONTROL, and these tests are about
control properties: who may do what, what happens when provenance is missing,
and what an attacker gains by tampering (answer: nothing, and usually less).

The most important test in this file is (a), the benign control. A privilege
lattice that halts ordinary information requests between agents is not a
security feature, it is an outage, and no amount of correctness on (b)-(k)
would make it shippable.
"""
from __future__ import annotations

import contextlib
import io

import pytest

import xaidr.provenance_chain as chain
from xaidr.privilege_tiers import (
    DEFAULT_TIER,
    HIGHEST_PRIVILEGE_TIER,
    LOWEST_PRIVILEGE_TIER,
    least_privileged_tier,
    parse_claimed_tier,
    validate_tier,
)
from xaidr.sensor import DelphiSensor

# The policy from the specification, verbatim. READ / SEND / COMMUNICATE impact
# classes are deliberately absent from `match:` — that omission is how "do not
# break normal work" is satisfied, and it is satisfied through the EXISTING
# impact classifier rather than a second one built for this feature.
TIER_POLICY = {
    "version": "1",
    "defaults": {"effect": "allow", "unclassified": "allow"},
    "rules": [{
        "id": "no-privilege-escalation",
        "effect": "require_approval",
        "match": {"impact_class": [
            "execute", "credential_access", "escalate",
            "transfer", "delete", "deploy",
        ]},
        "conditions": {"min_chain_tier_above": 1},
    }],
}

BLOCK_POLICY = {
    **TIER_POLICY,
    "rules": [{**TIER_POLICY["rules"][0], "effect": "block"}],
}

PRIVILEGED_CALL = ("run_command", {"command": "bash -c 'id'"})
INFO_CALL = ("read_file", {"path": "README.md"})


class _Recorder:
    """Reporter that keeps every emitted event so telemetry can be asserted."""

    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch if isinstance(batch, list) else [batch])

    def close(self):
        pass


@pytest.fixture(autouse=True)
def _isolate_flow():
    """Chain state is a contextvar; a leaked flow would silently couple tests."""
    chain.clear_flow()
    yield
    chain.clear_flow()


def _quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)


def _sensor(agent_id, tier=None, policy=TIER_POLICY, mode="block", reporter=None):
    s = DelphiSensor(
        agent_id=agent_id,
        enforcement_mode=mode,
        reporter=reporter or _Recorder(),
        privilege_tier=tier,
    )
    if policy is not None:
        assert s.set_policy(policy) is True, "policy was rejected at load"
    return s


def _hop(agent_id, tier, inbound_headers=None):
    """Run one agent's hop and return the headers it would send downstream."""
    chain.clear_flow()
    if inbound_headers is not None:
        chain.extract_context(inbound_headers)
    else:
        chain.begin_flow()
    s = _sensor(agent_id, tier)
    _quiet(s.scan, "doing my part of the work")
    return chain.inject_context({})


def _arrive(headers):
    chain.clear_flow()
    chain.extract_context(headers)


# ── (a) BENIGN CONTROL — the usability question ──────────────────────────────

def test_a_low_priv_agent_asking_a_high_priv_agent_for_info_is_not_halted():
    """A tier-4 agent asking a tier-1 agent to READ something must go through.

    If this fails the feature is unusable regardless of its security properties:
    agents ask each other for information constantly, and that is not
    escalation. The gate holds because `read` is not in the policy's
    impact_class list — enforced by the existing classifier, not by a new one.
    """
    _arrive(_hop("low-agent", 4))
    s = _sensor("high-agent", 1)
    r = _quiet(s.scan_tool_call, *INFO_CALL)
    assert r.action == "allowed", f"{r.action} {r.rules}"


@pytest.mark.parametrize("tool,args", [
    ("read_file", {"path": "README.md"}),
    ("send_email", {"to": "ops@acme.com", "body": "deploy finished"}),
    ("publish_post", {"body": "release notes"}),
    ("get_status", {"service": "api"}),
])
def test_a_non_privileged_impact_classes_are_never_gated(tool, args):
    """The whole read/send/communicate surface stays open under a maximal gap."""
    _arrive(_hop("low-agent", 4))
    s = _sensor("high-agent", 1)
    assert _quiet(s.scan_tool_call, tool, args).action != "approval_required"


# ── (b) THE ATTACK ───────────────────────────────────────────────────────────

def test_b_low_priv_inducing_high_priv_to_execute_requires_approval():
    _arrive(_hop("low-agent", 4))
    s = _sensor("high-agent", 1)
    r = _quiet(s.scan_tool_call, *PRIVILEGED_CALL)
    assert r.action == "approval_required", f"{r.action} {r.rules}"
    assert "policy:no-privilege-escalation" in r.rules
    assert s._least_privileged_tier() == 4


def test_b_approval_is_the_right_verdict_not_a_block():
    """A low-priv agent asking a high-priv one to act is a routine event needing
    adjudication, not an attack — so the default verdict is a halting APPROVAL,
    which protect_tools and the middleware already route to a human."""
    _arrive(_hop("low-agent", 4))
    s = _sensor("high-agent", 1)
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "approval_required"


# ── (c) effect: block, for deployers with no approval workflow ───────────────

def test_c_effect_block_halts_identically():
    _arrive(_hop("low-agent", 4))
    s = _sensor("high-agent", 1, policy=BLOCK_POLICY)
    r = _quiet(s.scan_tool_call, *PRIVILEGED_CALL)
    assert r.action == "blocked", f"{r.action} {r.rules}"
    assert "policy:no-privilege-escalation" in r.rules


# ── (d) NO DELEGATION — the catastrophic over-block case ─────────────────────

def test_d_a_tier1_agent_with_no_chain_does_its_own_privileged_work():
    """THE case that would break most deployments if the absence semantics were
    wrong. `record_hop` only extends an already-active flow, so a cold start
    leaves chain=None even after a scan — the normal state of an
    un-instrumented agent. Reading that as "unknown upstream, therefore 4" would
    make every tier-1 agent compute max(1,4)=4 and halt ALL of its own work."""
    assert chain.current_chain() is None
    s = _sensor("solo-high", 1)
    r = _quiet(s.scan_tool_call, *PRIVILEGED_CALL)
    assert r.action == "allowed", f"{r.action} {r.rules}"
    assert s._least_privileged_tier() == 1


def test_d_own_tier_applies_when_the_chain_contains_only_self():
    s = _sensor("solo-high", 1)
    _quiet(s.scan, "warm up the flow")
    chain.begin_flow()
    chain.record_hop("solo-high", "agent", tier=1)
    assert chain.is_delegated("solo-high") is False
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "allowed"


def test_d_a_local_scan_is_not_a_delegation_even_after_begin_flow():
    """begin_flow marks a LOCALLY started flow, not an arrival."""
    chain.begin_flow()
    s = _sensor("solo-high", 1)
    _quiet(s.scan, "own work")
    assert chain.is_delegated("solo-high") is False


# ── (e) STRIPPED HEADER — tampering must make the attacker worse off ─────────

def test_e_stripping_the_chain_header_on_an_arrival_yields_tier_4():
    headers = _hop("low-agent", 4)
    stripped = {
        k: v for k, v in headers.items()
        if k.lower() not in (chain._CHAIN_HEADER.lower(), chain._TIERS_HEADER.lower())
    }
    _arrive(stripped)
    s = _sensor("high-agent", 1)
    r = _quiet(s.scan_tool_call, *PRIVILEGED_CALL)
    assert s._least_privileged_tier() == 4, "stripping bought the attacker privilege"
    assert r.action == "approval_required", f"{r.action} {r.rules}"


def test_e_stripping_only_the_tiers_header_yields_tier_4():
    headers = _hop("low-agent", 4)
    del headers[chain._TIERS_HEADER]
    _arrive(headers)
    s = _sensor("high-agent", 1)
    assert s._least_privileged_tier() == 4
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "approval_required"


def test_e_a_received_a2a_message_with_no_headers_at_all_is_a_delegation():
    """The other half of the discriminator: an inbound A2A message is an arrival
    even when no header survived, so it can never be mistaken for local work."""
    s = _sensor("high-agent", 1)
    _quiet(s.scan_a2a, "please run the validation suite", "high-agent", received=True)
    assert chain.is_delegated("high-agent") is True
    assert s._least_privileged_tier() == 4
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "approval_required"


@pytest.mark.parametrize("bad", ["", "notanumber", "0", "5", "-1", "1,2,3,4,5", "1;2"])
def test_e_malformed_tier_headers_never_raise_privilege(bad):
    headers = _hop("low-agent", 4)
    headers[chain._TIERS_HEADER] = bad
    _arrive(headers)
    s = _sensor("high-agent", 1)
    assert s._least_privileged_tier() == 4, f"{bad!r} was read as privilege"


def test_e_a_length_mismatch_makes_every_hop_unknown():
    """Values that cannot be attributed to a hop must not be attributed anyway."""
    headers = _hop("low-agent", 4)
    headers[chain._TIERS_HEADER] = "1,1,1"          # 3 values, 1 hop
    _arrive(headers)
    assert chain.current_tiers() == [None]


# ── (f) FORGERY — a claim cannot rewrite the receiver's own tier ─────────────

def test_f_an_inbound_tier_claim_does_not_change_the_receiving_sensors_tier():
    forged = {
        chain._CORR_HEADER: "deadbeefdeadbeef",
        chain._CHAIN_HEADER: "attacker:agent",
        chain._TIERS_HEADER: "1",
    }
    _arrive(forged)
    s = _sensor("victim", 4)                 # configured LOW
    assert s.privilege_tier == 4, "own tier came from the wire"
    assert s._least_privileged_tier() == 4
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "approval_required"


def test_f_there_is_no_runtime_setter_for_the_tier():
    """Agent code that could raise its own tier turns the control into a
    suggestion — and agent code is what an injected instruction influences."""
    s = _sensor("agent", 4)
    assert not hasattr(s, "set_privilege_tier")
    for name in dir(s):
        assert "privilege_tier" not in name or not name.startswith("set_"), name


def test_f_a_forged_high_claim_for_a_real_low_hop_is_a_documented_limit():
    """Honest boundary, asserted so it cannot silently change.

    An attacker who fully controls the headers CAN claim a better upstream tier;
    unsigned transport metadata cannot prevent that and this feature does not
    pretend to. What IS guaranteed is the pair below: the receiver's own tier is
    untouchable, and every tampering that REMOVES information tightens rather
    than loosens the decision.
    """
    forged = {
        chain._CORR_HEADER: "cafecafecafecafe",
        chain._CHAIN_HEADER: "low-agent:agent",
        chain._TIERS_HEADER: "1",             # lying: low-agent is really 4
    }
    _arrive(forged)
    s = _sensor("high-agent", 1)
    assert s._least_privileged_tier() == 1     # the lie works — documented
    # ...and the two real guarantees still hold:
    assert s.privilege_tier == 1               # config-sourced, unforgeable
    forged[chain._TIERS_HEADER] = ""           # removing information
    _arrive(forged)
    assert _sensor("high-agent", 1)._least_privileged_tier() == 4


# ── (g) LAUNDERING — the full three-hop chain ────────────────────────────────

def test_g_a_high_priv_middle_hop_cannot_launder_a_low_priv_origin():
    """tier4 -> tier1 -> tier1. The origin's tier survives both hops, because
    the computation is a MAX over the whole chain and not a look at the caller."""
    h_a = _hop("a-low", 4)
    h_b = _hop("b-high", 1, inbound_headers=h_a)
    assert h_b[chain._CHAIN_HEADER] == "a-low:agent>b-high:agent"
    assert h_b[chain._TIERS_HEADER] == "4,1"

    _arrive(h_b)
    s = _sensor("c-high", 1)
    r = _quiet(s.scan_tool_call, *PRIVILEGED_CALL)
    assert [h["agent_id"] for h in chain.current_chain()] == ["a-low", "b-high", "c-high"]
    assert s._least_privileged_tier() == 4, "the tier-4 origin was laundered away"
    assert r.action == "approval_required", f"{r.action} {r.rules}"


def test_g_least_privileged_tier_is_a_numeric_max():
    """Named so the 1=highest inversion cannot be misread at a call site."""
    assert least_privileged_tier(1, [4]) == 4
    assert least_privileged_tier(4, [1]) == 4
    assert least_privileged_tier(1, [2, 3]) == 3
    assert least_privileged_tier(1, []) == 1
    assert least_privileged_tier(1, [None]) == DEFAULT_TIER
    assert HIGHEST_PRIVILEGE_TIER < LOWEST_PRIVILEGE_TIER


# ── (h) cross-process survival ───────────────────────────────────────────────

def test_h_tiers_survive_inject_then_extract():
    h_a = _hop("a-low", 4)
    h_b = _hop("b-mid", 2, inbound_headers=h_a)
    _arrive(h_b)
    assert [x["agent_id"] for x in chain.current_chain()] == ["a-low", "b-mid"]
    assert chain.current_tiers() == [4, 2]


def test_h_the_tiers_header_is_separate_from_the_chain_header():
    """A third field inside the chain encoding would CORRUPT it: the decoder
    uses rsplit(':', 1), so 'agent-a:agent:4' parses as agent_id='agent-a:agent',
    role='4'. This asserts the carriage stayed separate."""
    _arrive({
        chain._CORR_HEADER: "abc123abc123abc1",
        chain._CHAIN_HEADER: "agent-a:agent:4",
    })
    assert chain.current_chain()[0]["agent_id"] == "agent-a:agent"   # the corruption
    h = _hop("a-low", 4)
    assert chain._TIERS_HEADER in h
    assert ":" not in h[chain._TIERS_HEADER]
    _arrive(h)
    assert chain.current_chain()[0]["agent_id"] == "a-low"           # uncorrupted


def test_h_an_old_sensor_ignores_the_new_header():
    """Forward compatibility: the tiers header is additive, so a sensor that
    does not know about it still parses the chain exactly as before."""
    h = _hop("a-low", 4)
    without = {k: v for k, v in h.items() if k.lower() != chain._TIERS_HEADER.lower()}
    _arrive(without)
    assert [x["agent_id"] for x in chain.current_chain()] == ["a-low"]
    assert chain.current_tiers() == [None]


# ── (i) TELEMETRY — BUG-1: never halt without a record ───────────────────────

def test_i_a_tier_halt_emits_an_audit_event_with_the_rule_id_and_computed_tier():
    rec = _Recorder()
    _arrive(_hop("low-agent", 4))
    s = _sensor("high-agent", 1, reporter=rec)
    r = _quiet(s.scan_tool_call, *PRIVILEGED_CALL)
    assert r.action == "approval_required"
    s._telemetry.flush_sync()

    halts = [
        e for e in rec.events
        if (e.get("data") or {}).get("authzPolicyId") == "no-privilege-escalation"
    ]
    assert halts, f"a tier halt emitted no audit event: {rec.events}"
    d = halts[-1]["data"]
    assert d["authzDecision"] == "approval_required"
    assert d["authzPolicyId"] == "no-privilege-escalation"
    assert d["leastPrivilegedTier"] == 4
    assert d["privilegeTier"] == 1
    assert d["delegated"] is True
    ids = [h["agent_id"] for h in d["provenance"]["delegation_chain"]]
    assert ids == ["low-agent", "high-agent"], ids
    assert d["chainTiers"] == [4, 1]


def test_i_the_tier_is_recorded_even_when_nothing_is_gated():
    """An audit trail that only exists on a halt cannot answer "why did this
    NOT fire?", which is the question after an incident."""
    rec = _Recorder()
    s = _sensor("solo", 1, reporter=rec)
    _quiet(s.scan_tool_call, *INFO_CALL)
    s._telemetry.flush_sync()
    d = [e for e in rec.events if e.get("type") == "scan"][-1]["data"]
    assert d["leastPrivilegedTier"] == 1
    assert d["privilegeTier"] == 1
    assert d["privilegeTierConfigured"] is True


def test_i_an_unconfigured_tier_is_reported_as_unconfigured():
    rec = _Recorder()
    s = DelphiSensor(agent_id="plain", enforcement_mode="block", reporter=rec)
    _quiet(s.scan_tool_call, *INFO_CALL)
    s._telemetry.flush_sync()
    d = [e for e in rec.events if e.get("type") == "scan"][-1]["data"]
    assert d["privilegeTier"] == DEFAULT_TIER
    assert d["privilegeTierConfigured"] is False


# ── (j) an un-instrumented middle hop leaves an honest gap ───────────────────

def test_j_an_uninstrumented_middle_hop_is_tier_4_never_a_guess():
    h_a = _hop("a-low", 4)
    chain.clear_flow()
    chain.extract_context(h_a)
    mid = DelphiSensor(agent_id="mid-unknown", enforcement_mode="block",
                       reporter=_Recorder())            # NO privilege_tier
    _quiet(mid.scan, "passing it along")
    h_mid = chain.inject_context({})

    # The gap is published as an EMPTY field, not a fabricated 4: "declared
    # lowest" and "never declared" are different facts.
    assert h_mid[chain._TIERS_HEADER] == "4,"
    _arrive(h_mid)
    assert chain.current_tiers() == [4, None]

    s = _sensor("end-high", 1)
    assert s._least_privileged_tier() == 4
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "approval_required"


def test_j_an_unknown_hop_resolves_to_lowest_privilege_not_highest():
    assert least_privileged_tier(1, [None, None]) == LOWEST_PRIVILEGE_TIER


# ── (k) construction-time validation, ADV-2 style ────────────────────────────

@pytest.mark.parametrize("bad", [0, 5, -1, 99, "1", "high", 1.0, 2.5, True, False,
                                 [1], {"tier": 1}, object()])
def test_k_an_invalid_privilege_tier_is_rejected_loudly_at_construction(bad):
    with pytest.raises(ValueError) as exc:
        DelphiSensor(agent_id="x", reporter=_Recorder(), privilege_tier=bad)
    assert "privilege_tier" in str(exc.value)


@pytest.mark.parametrize("good", [1, 2, 3, 4])
def test_k_valid_tiers_are_accepted(good):
    assert DelphiSensor(agent_id="x", reporter=_Recorder(),
                        privilege_tier=good).privilege_tier == good


def test_k_bool_is_rejected_because_it_would_silently_mean_tier_1():
    """`True` is an int subclass, so an unguarded check would accept
    privilege_tier=True as tier 1 — the HIGHEST privilege. That is the worst
    possible way for a typo to fail, so it is called out on its own."""
    with pytest.raises(ValueError):
        validate_tier(True)
    assert validate_tier(None) == DEFAULT_TIER


def test_k_a_wire_claim_never_raises_where_config_does():
    """Asymmetry on purpose: a deployer's value is a config error and must be
    loud; an attacker's value is untrusted input and must never crash us."""
    for hostile in [None, "", "abc", "99", -5, 3.7, True, [], {}, object()]:
        assert parse_claimed_tier(hostile) in (None, 1, 2, 3, 4)
    assert parse_claimed_tier("3") == 3
    assert parse_claimed_tier(2) == 2


# ── policy plumbing ──────────────────────────────────────────────────────────

def test_the_condition_is_numeric_and_lives_beside_trust_below():
    from xaidr.authz.policy import _CONDITION_FIELDS, _MATCH_FIELDS

    assert "min_chain_tier_above" in _CONDITION_FIELDS
    assert "min_chain_tier_above" not in _MATCH_FIELDS, (
        "match fields are resolved through _glob_any (fnmatch over strings); a "
        "numeric comparison there would silently never do '>'"
    )


def test_a_typo_in_the_condition_is_rejected_at_load_not_silently_disarmed():
    """Inherits the ADV-2 unknown-key validator, which is the point of putting
    it under `conditions:`."""
    s = DelphiSensor(agent_id="x", reporter=_Recorder())
    bad = {**TIER_POLICY, "rules": [{
        **TIER_POLICY["rules"][0],
        "conditions": {"min_chain_tier_abov": 1},
    }]}
    assert s.set_policy(bad) is False


@pytest.mark.parametrize("threshold,own,expect_gate", [
    (1, 1, False), (1, 2, True), (1, 4, True),
    (2, 2, False), (2, 3, True), (3, 4, True), (4, 4, False),
])
def test_the_threshold_is_strictly_greater_than(threshold, own, expect_gate):
    """`min_chain_tier_above: N` fires when the computed tier is > N."""
    pol = {**TIER_POLICY, "rules": [{
        **TIER_POLICY["rules"][0],
        "conditions": {"min_chain_tier_above": threshold},
    }]}
    s = _sensor("solo", own, policy=pol)
    gated = _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "approval_required"
    assert gated is expect_gate


# ── HARD GATE 4: inert unless configured ─────────────────────────────────────

def test_gate4_a_sensor_with_no_privilege_tier_and_no_policy_is_unaffected():
    s = DelphiSensor(agent_id="plain", enforcement_mode="block", reporter=_Recorder())
    assert _quiet(s.scan_tool_call, "read_file", {"path": "x"}).action == "allowed"
    assert _quiet(s.scan_tool_call, "some_tool", {"note": "hello"}).action == "allowed"
    assert _quiet(s.scan, "hello there").action == "allowed"


def test_gate4_the_condition_is_inert_when_no_policy_uses_it():
    """The feature is opt-in through POLICY. With no rule naming
    min_chain_tier_above, a maximal tier gap changes nothing."""
    _arrive(_hop("low-agent", 4))
    s = _sensor("high-agent", 1, policy={
        "version": "1",
        "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": "unrelated", "effect": "block",
                   "match": {"tools": ["definitely_not_this"]}}],
    })
    assert s._least_privileged_tier() == 4
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "allowed"


def test_gate4_an_unpopulated_condition_cannot_fire():
    """If the tier context is absent the rule does NOT match — the inert
    direction, so an un-upgraded caller never starts halting traffic."""
    from xaidr.authz.policy import build_request, evaluate, parse_action_policy

    pol = parse_action_policy(TIER_POLICY)
    req = build_request(
        agent_id="x", trust=None, tool_name="run_command",
        impact_class="execute", impact_tier="critical",
        destination_type="tool_call", destination_identifier="run_command",
        context={},                       # no least_privileged_tier
    )
    assert evaluate(pol, req).decision == "allowed"


def test_monitor_mode_downgrades_a_tier_halt_like_any_other():
    _arrive(_hop("low-agent", 4))
    s = _sensor("high-agent", 1, mode="monitor")
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "flagged"


# ── the human principal, and why it is not a low-privilege agent ─────────────
# Found by probing rather than by the spec: the first draft excluded an untiered
# principal from the tier list (right — a human is not an agent with a ring
# number), and then the "no identified upstream" fallback fired on the resulting
# empty list and forced 4. Net effect: begin_flow(principal=...) — the DOCUMENTED
# way to start a flow — gated every privileged action a tier-1 agent took on its
# owner's behalf. That is the same over-block the absence semantics exist to
# prevent, arriving through a different door.

def test_a_human_principal_does_not_gate_the_agent_acting_for_them():
    chain.begin_flow(principal="alice@acme.com")
    s = _sensor("assistant", 1)
    r = _quiet(s.scan_tool_call, *PRIVILEGED_CALL)
    assert [h["agent_id"] for h in chain.current_chain()] == ["alice@acme.com", "assistant"]
    assert s._least_privileged_tier() == 1, "the human principal was tiered as an agent"
    assert r.action == "allowed", f"{r.action} {r.rules}"


def test_a_tier_explicitly_claimed_for_the_principal_is_still_honoured():
    """Excluding untiered principals is a default, not a veto: a deployer who
    does tier their principals is not overridden."""
    _arrive({
        chain._CORR_HEADER: "aaaabbbbccccdddd",
        chain._CHAIN_HEADER: "alice@acme.com:principal",
        chain._TIERS_HEADER: "3",
    })
    s = _sensor("assistant", 1)
    assert s._least_privileged_tier() == 3
    assert _quiet(s.scan_tool_call, *PRIVILEGED_CALL).action == "approval_required"


def test_the_principal_exemption_does_not_reopen_the_stripping_hole():
    """The two must not be confused: a named-but-untiered principal is provenance
    we chose not to tier, while an empty chain on an arrival is provenance that
    was REMOVED. Only the second gets the unknown-upstream fallback."""
    assert chain.has_upstream_hop("self") is False
    chain.begin_flow(principal="alice@acme.com")
    chain.record_hop("self", "agent", tier=1)
    assert chain.has_upstream_hop("self") is True     # principal counts as a hop
    assert chain.delegating_hop_tiers("self") == []   # ...but is not tiered

    headers = _hop("low-agent", 4)
    stripped = {
        k: v for k, v in headers.items()
        if k.lower() not in (chain._CHAIN_HEADER.lower(), chain._TIERS_HEADER.lower())
    }
    _arrive(stripped)
    assert chain.has_upstream_hop("high-agent") is False
    assert _sensor("high-agent", 1)._least_privileged_tier() == 4
