"""F5 · a policy rule must never load successfully and silently never match.

The audit finding: `match: {tools: "deploy"}` — a scalar where a list belongs —
parsed without error, logged `loaded local policy (1 rules)`, and then matched
nothing, because `_glob_any` returns False for any non-list. The operator writes
a control, it validates, and it does nothing. That is the worst failure mode a
policy engine has, so this file asserts the property directly:

    for every field in the schema, a wrong-typed value is either REJECTED at
    load or the rule FIRES. Never accepted-and-inert.

`test_property_no_field_is_accepted_and_inert` is that sentence as code, over
the cross product of every match field and every wrong shape. The named tests
around it exist so a failure says WHICH mistake regressed; the property test is
what makes the file non-vacuous if someone adds a field and forgets a case.

Both directions of the field list are derived from `_MATCH_FIELDS`, the
evaluator's own source of truth, so a field added there is covered here without
anyone remembering to. `_request()` asserts that derivation actually holds —
without it the "still fires" control would pass vacuously for a new field.
"""
import logging

import pytest

from xaidr import Sensor
from xaidr.authz.policy import (
    _MATCH_FIELDS,
    build_request,
    evaluate,
    parse_action_policy,
)

AUTHZ = "xaidr.authz"

# One distinct value per match field, so a rule keyed on any single field can be
# shown to fire, and a wrong-typed one shown not to.
_VALUE = {f: f"v-{f}" for f in _MATCH_FIELDS}


def _request():
    r = build_request(
        agent_id=_VALUE["agents"],
        trust=None,
        tool_name=_VALUE["tools"],
        impact_class=_VALUE["impact_class"],
        impact_tier=_VALUE["impact_tier"],
        destination_type=_VALUE["destination_type"],
        destination_identifier=_VALUE["destination_identifier"],
        context={"mcp_server": _VALUE["mcp_server"]},
        category=_VALUE["category"],
    )
    for field, (section, key) in _MATCH_FIELDS.items():
        assert r[section].get(key) == _VALUE[field], (
            f"match field {field!r} is not populated in this fixture's request, "
            f"so every 'still fires' assertion for it would pass vacuously. "
            f"A field was added to _MATCH_FIELDS without extending _request()."
        )
    return r


def _policy(rule, defaults=None):
    return {
        "version": "1",
        "defaults": defaults if defaults is not None else {"effect": "allow"},
        "rules": [rule],
    }


def _rule(match=..., conditions=..., **kw):
    r = {"id": "the-rule", "effect": "block", "message": "denied"}
    if match is not ...:
        r["match"] = match
    if conditions is not ...:
        r["conditions"] = conditions
    r.update(kw)
    return r


# Every shape a match value can wrongly take. Each maps the correct value to a
# wrong one, so the cases stay meaningful per-field.
WRONG_MATCH_VALUES = [
    ("scalar-str", lambda good: good),            # the reported F5 case
    ("scalar-int", lambda good: 42),
    ("null", lambda good: None),                  # YAML `tools:` with no value
    ("empty-list", lambda good: []),
    ("mapping", lambda good: {"name": good}),
    ("list-of-bool", lambda good: [True]),        # unquoted YAML yes/on
    ("nested-list", lambda good: [[good]]),
]

ALL_CASES = [
    (field, shape, make)
    for field in sorted(_MATCH_FIELDS)
    for shape, make in WRONG_MATCH_VALUES
]


# ── (a) the reproduction, verbatim ───────────────────────────────────────────

def test_reported_case_scalar_tools_is_rejected(caplog):
    """The exact rule from the finding: `tools: "deploy"` instead of ["deploy"]."""
    raw = _policy(_rule({"tools": "deploy"}))
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy(raw)
    assert parsed is None, (
        "the reported F5 rule loaded successfully; it will now be reported to "
        "the operator as an active control and will match nothing"
    )
    text = caplog.text
    assert "tools" in text and "the-rule" in text
    assert '["deploy"]' in text, f"error does not show the correction: {text!r}"


def test_reported_case_correct_form_still_fires():
    """The discriminating control: the LIST form must be untouched."""
    parsed = parse_action_policy(_policy(_rule({"tools": [_VALUE["tools"]]})))
    assert parsed is not None
    assert evaluate(parsed, _request()).decision == "blocked"


# ── (e) every match field × every wrong shape ────────────────────────────────

@pytest.mark.parametrize("field,shape,make", ALL_CASES,
                         ids=[f"{f}-{s}" for f, s, _ in ALL_CASES])
def test_wrong_typed_match_value_is_rejected(field, shape, make, caplog):
    raw = _policy(_rule({field: make(_VALUE[field])}))
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy(raw)
    assert parsed is None, (
        f"match.{field} = {make(_VALUE[field])!r} ({shape}) loaded as a valid "
        f"policy — the rule is silently dead and the operator is not told"
    )
    text = caplog.text
    assert field in text, f"error does not name the field: {text!r}"
    assert "the-rule" in text, f"error does not name the rule id: {text!r}"
    assert "REJECTED" in text


@pytest.mark.parametrize("field", sorted(_MATCH_FIELDS))
def test_correctly_typed_match_value_still_fires(field):
    """(e) control against over-rejection: the validator must not eat real rules.

    Derived from _MATCH_FIELDS, so a newly added field is covered here without
    anyone remembering to add it.
    """
    parsed = parse_action_policy(_policy(_rule({field: [_VALUE[field]]})))
    assert parsed is not None, f"a correct {field}: [..] rule was rejected"
    assert evaluate(parsed, _request()).decision == "blocked", (
        f"a correct {field}: [..] rule loaded but did not fire"
    )


@pytest.mark.parametrize("field,shape,make", ALL_CASES,
                         ids=[f"{f}-{s}" for f, s, _ in ALL_CASES])
def test_property_no_field_is_accepted_and_inert(field, shape, make):
    """(d) THE PROPERTY, stated once over the whole cross product.

    Independent of mechanism: whatever the loader decides to do with a wrong
    type, the one outcome it may not produce is a policy that loads and cannot
    act. Rejecting satisfies this; so would coercing. Accepting does not.
    """
    parsed = parse_action_policy(_policy(_rule({field: make(_VALUE[field])})))
    if parsed is None:
        return  # rejected — loud, safe
    decision = evaluate(parsed, _request()).decision
    assert decision == "blocked", (
        f"match.{field} = {make(_VALUE[field])!r} ({shape}) was ACCEPTED "
        f"({parsed['rules']!r}) and then did not fire on input it names "
        f"(decision={decision!r}). This is the F5 failure mode: the operator "
        f"believes a control is active and it is inert."
    )


@pytest.mark.parametrize("field", [f for f in sorted(_MATCH_FIELDS) if f != "tools"])
def test_null_field_does_not_silently_widen_a_rule(field, caplog):
    """The `null` shape does not go inert — it goes the other way.

    `_rule_matches` SKIPS a None field, so `match: {tools: , agents: [a]}` drops
    the tools narrower and blocks everything agent `a` does. The rule fires, so
    the accepted-and-inert property above would not catch it; this asserts the
    load is refused rather than the rule silently widened.
    """
    raw = _policy(_rule({"tools": None, field: [_VALUE[field]]}))
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy(raw)
    assert parsed is None, (
        f"`tools:` with no value loaded beside {field}: the rule now fires on "
        f"every tool, not the ones the operator listed"
    )
    assert "WIDENS" in caplog.text, caplog.text


# ── (b) the match:/conditions: BLOCKS themselves ─────────────────────────────

@pytest.mark.parametrize("block", ["match", "conditions"])
@pytest.mark.parametrize("value,shape", [
    ("tools: deploy", "scalar-str"),      # one missed indent turns it into a string
    (["tools"], "list"),
    (42, "int"),
])
def test_non_mapping_block_is_rejected(block, value, shape, caplog):
    rule = _rule({"tools": [_VALUE["tools"]]})
    rule[block] = value
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy(_policy(rule))
    assert parsed is None, (
        f"a {shape} '{block}:' block loaded; it is discarded, so the rule runs "
        f"with no {block} at all"
    )
    assert block in caplog.text and "the-rule" in caplog.text


def test_scalar_conditions_block_cannot_smuggle_trust_below_past_its_guard(caplog):
    """The nastiest of the block cases, and why it is not just cosmetic.

    A-11 rejects `conditions: {trust_below: ...}` because it can never fire in
    open. One missed indent makes `conditions:` a STRING, the block is replaced
    with {} before the guard reads it, and the rule loads — armed, with the
    condition the operator wrote to narrow it silently gone.
    """
    rule = _rule({"tools": [_VALUE["tools"]]})
    rule["conditions"] = "trust_below: 0.5"
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy(_policy(rule))
    assert parsed is None, (
        "a stringified conditions: block bypassed the trust_below rejection AND "
        "dropped the condition — the rule fires where the operator excluded it"
    )


# ── (b) conditions: VALUES ───────────────────────────────────────────────────

@pytest.mark.parametrize("value,shape", [
    ("high", "non-numeric-str"),
    ([1], "list"),
    (None, "null"),
    ({"tier": 1}, "mapping"),
    (True, "bool"),
])
def test_non_numeric_min_chain_tier_above_is_rejected(value, shape, caplog):
    """`int(value)` is wrapped in try/except at evaluation time and returns
    False — another load-clean, never-fires rule."""
    raw = _policy(_rule({"tools": [_VALUE["tools"]]},
                        {"min_chain_tier_above": value}))
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy(raw)
    assert parsed is None, f"min_chain_tier_above={value!r} ({shape}) loaded"
    assert "min_chain_tier_above" in caplog.text


@pytest.mark.parametrize("value", [1, 0, "1"])
def test_numeric_min_chain_tier_above_still_loads_and_fires(value):
    """Control: including the numeric-string form, which works today."""
    parsed = parse_action_policy(
        _policy(_rule({"tools": [_VALUE["tools"]]}, {"min_chain_tier_above": value})))
    assert parsed is not None
    req = _request()
    req["context"]["least_privileged_tier"] = 4
    assert evaluate(parsed, req).decision == "blocked"


# ── (d) the general case: a rule with nothing to match on ────────────────────

@pytest.mark.parametrize("rule", [
    {"id": "bare", "effect": "block"},
    {"id": "bare", "effect": "block", "match": {}},
    {"id": "bare", "effect": "block", "match": {}, "conditions": {}},
])
def test_rule_with_no_matchers_at_all_is_rejected(rule, caplog):
    """Catches the shapes nobody enumerated. `_rule_matches` already returns
    False for these — at evaluation time, invisibly. Same verdict, moved to
    load, where there is an operator to read it."""
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy(_policy(rule))
    assert parsed is None
    assert "NEVER fire" in caplog.text


# ── (b) defaults: — the block with no rule to attach the blame to ────────────

@pytest.mark.parametrize("defaults,shape", [
    ("block", "scalar-str"),
    (["block"], "list"),
    (0, "int"),
])
def test_non_mapping_defaults_is_rejected(defaults, shape, caplog):
    """The highest-consequence case in the file, and it involves no rule at all.

    A non-mapping `defaults:` was discarded and the policy fell back to the
    SHIPPED defaults, so `defaults: block` silently turned a deny-by-default
    deployment into an allow-by-default one.
    """
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy({
            "version": "1", "defaults": defaults, "rules": [],
        })
    assert parsed is None, (
        f"defaults: {defaults!r} ({shape}) loaded as allow-by-default; the "
        f"operator wrote a deny-by-default policy and got the opposite"
    )
    assert "allow-by-default" in caplog.text


def test_unknown_defaults_key_is_rejected(caplog):
    """`defaults: {efect: block}` — same consequence, via a typo instead."""
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy({
            "version": "1", "defaults": {"efect": "block"}, "rules": [],
        })
    assert parsed is None
    assert "efect" in caplog.text and "effect" in caplog.text


@pytest.mark.parametrize("key", ["effect", "unclassified"])
@pytest.mark.parametrize("value", ["BLOCK", "blok", ["block"], None, 1])
def test_invalid_defaults_effect_is_rejected_loudly(key, value, caplog):
    """These were already rejected — but SILENTLY, with the reason logged only
    as a generic 'malformed' by the caller. The reason is now named."""
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy({
            "version": "1", "defaults": {key: value}, "rules": [],
        })
    assert parsed is None
    assert key in caplog.text, f"rejection does not say which key was bad: {caplog.text!r}"


def test_defaults_only_policy_still_loads_and_enforces():
    """Control: a rules-less deny-by-default posture is legitimate."""
    parsed = parse_action_policy({
        "version": "1", "defaults": {"effect": "block"}, "rules": [],
    })
    assert parsed is not None
    assert evaluate(parsed, _request()).decision == "blocked"


def test_policy_that_can_do_nothing_is_loud_without_being_rejected(caplog):
    """(d) applied to the whole file rather than one rule.

    No rules plus the shipped defaults enforces nothing the operator wrote, and
    is indistinguishable from a policy whose `rules:` was lost to an indent.
    Not a rejection — a defaults-only policy is valid and this one is merely
    empty — but it must not load in silence.
    """
    with caplog.at_level(logging.WARNING, logger=AUTHZ):
        parsed = parse_action_policy({"version": "1"})
    assert parsed is not None
    assert "cannot change any decision" in caplog.text


# ── (b) top level ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("rules,shape", [
    ({"a": {}}, "mapping"), ("no-deploy", "scalar-str"), (None, "null"), (7, "int"),
])
def test_non_list_rules_is_rejected_loudly(rules, shape, caplog):
    """Already rejected, but with nothing logged from this module — the operator
    saw only the caller's generic 'malformed or unsupported'."""
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy({"version": "1", "rules": rules})
    assert parsed is None
    assert "rules" in caplog.text, f"rejection reason not logged: {caplog.text!r}"


def test_non_mapping_policy_is_rejected_loudly(caplog):
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        assert parse_action_policy("version: 1") is None
    assert "must be a mapping" in caplog.text


# ── every error path must actually RENDER ────────────────────────────────────

def test_every_rejection_message_formats():
    """A guard the fix itself needed.

    `logger.error(fmt, *args)` formats lazily: a %-placeholder/argument count
    mismatch is swallowed by the logging module and printed to stderr, so the
    rejection is silent to anyone reading logs — the exact failure class this
    file exists to close, reintroduced in the code that closes it. (Three of
    these were present in the first draft of the fix and found by a probe, not
    by a test.) This forces every rejection message through getMessage().
    """
    bad_policies = [
        "version: 1",
        {"version": "1", "rules": "x"},
        {"version": "1", "defaults": "block", "rules": []},
        {"version": "1", "defaults": {"efect": "block"}, "rules": []},
        {"version": "1", "defaults": {"effect": "nope"}, "rules": []},
        _policy(_rule({}, {})),
        _policy(_rule("tools: x")),
        _policy(_rule({"tools": [_VALUE["tools"]]}, "trust_below: 1")),
        _policy(_rule({"tools": [_VALUE["tools"]]}, {"min_chain_tier_above": "hi"})),
        _policy(_rule({"tools": [_VALUE["tools"]]}, {"trust_below": 0.5})),
        _policy(_rule({"tool": ["x"]})),
    ] + [_policy(_rule({f: make(_VALUE[f])})) for f, _, make in ALL_CASES]

    records = []
    handler = logging.Handler()
    handler.emit = records.append
    log = logging.getLogger(AUTHZ)
    log.addHandler(handler)
    try:
        for raw in bad_policies:
            assert parse_action_policy(raw) is None, raw
    finally:
        log.removeHandler(handler)

    assert len(records) >= len(bad_policies)
    for rec in records:
        try:
            rendered = rec.getMessage()
        except Exception as exc:  # pragma: no cover - the thing being prevented
            pytest.fail(
                f"a rejection message cannot be formatted ({exc!r}) — logging "
                f"would swallow it and the policy would be refused in silence. "
                f"fmt={rec.msg!r} args={rec.args!r}"
            )
        assert "%s" not in rendered and "%r" not in rendered, rendered


# ── (a) end to end, the way an operator meets it ─────────────────────────────

MALFORMED_YAML = """\
version: "1"
defaults:
  effect: allow
rules:
  - id: no-deploy
    effect: block
    message: "deploy is not permitted"
    match:
      tools: "deploy"
"""


def _load(tmp_path, text):
    from xaidr.local_policy import load_policy
    p = tmp_path / "xaidr-policy.yaml"
    p.write_text(text, encoding="utf-8")
    return load_policy(str(p), auto_default=False)


def test_end_to_end_yaml_file_is_refused_not_reported_as_loaded(tmp_path, caplog):
    yaml = pytest.importorskip("yaml")  # noqa: F841 - policy extra
    with caplog.at_level(logging.INFO):
        policy = _load(tmp_path, MALFORMED_YAML)
    assert policy is None, (
        "the malformed policy FILE loaded — this is what the operator actually "
        "does, and the sensor is now enforcing a rule that cannot match"
    )
    assert "loaded local policy" not in caplog.text, (
        "the loader still reports SUCCESS for a policy whose only rule cannot "
        f"fire: {caplog.text!r}"
    )
    assert "tools" in caplog.text


def test_end_to_end_corrected_yaml_loads_and_blocks(tmp_path):
    pytest.importorskip("yaml")
    policy = _load(tmp_path, MALFORMED_YAML.replace('"deploy"', '["deploy"]'))
    assert policy is not None
    from xaidr.local_policy import evaluate_policy
    assert evaluate_policy(
        policy, agent_id="a", trust=None, tool_name="deploy",
        impact_class="deployment", impact_tier="destructive",
        destination_type="internal", destination_identifier="prod",
    ).decision == "blocked"


def test_sensor_set_policy_reports_false_for_the_malformed_rule():
    """The programmatic path returns a boolean the caller can act on."""
    s = Sensor(agent_id="f5", enforcement_mode="monitor")
    assert s.set_policy(_policy(_rule({"tools": "deploy"}))) is False
    assert s.set_policy(_policy(_rule({"tools": ["deploy"]}))) is True
