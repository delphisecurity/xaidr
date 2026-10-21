"""Refuse, never drop: every part of an ActionPolicy v1 document is either read
by the engine or the document is refused.

Each case is a document carrying a part the engine does not read, and it is
refused with an error naming that part. The paired control is the same
document with only that part removed, and it must still load, so every refusal
is attributable to the one field under test.

With keep-last-good (see test_policy_keep_last_good.py) a refusal leaves the
previous policy enforcing; at startup it leaves the sensor detection-only.
"""
import logging
import math

import pytest

from xaidr.authz.policy import parse_action_policy

AUTHZ = "xaidr.authz"

BLOCK = {"id": "no-deploy", "effect": "block", "match": {"tools": ["deploy"]}}


def _doc(**top):
    return {"version": "1", "rules": [dict(BLOCK)], **top}


def _with_rule(**extra):
    return {"version": "1", "rules": [{**BLOCK, **extra}]}


TIER_RULE = {"id": "tier", "effect": "block", "match": {"tools": ["deploy"]},
             "conditions": {"min_chain_tier_above": 2}}

# label -> (refused document, control document, text the error must contain)
CASES = {
    # 1. Unknown top-level key, including typos of `rules:` and `defaults:`.
    "top-level-unknown-key": (_doc(some_future_field=1), _doc(), "some_future_field"),
    "top-level-typo-rule": ({"version": "1", "rule": [BLOCK]}, _doc(), "'rule'"),
    "top-level-typo-default": (_doc(default={"effect": "block"}),
                               _doc(defaults={"effect": "block"}), "'default'"),
    # 2. Unknown rule-level key, including a typo of `conditions:`.
    "rule-unknown-key": (_with_rule(description="d"), _with_rule(), "description"),
    "rule-typo-conditions": (
        {"version": "1", "rules": [{**BLOCK, "conditons": {"min_chain_tier_above": 2}}]},
        {"version": "1", "rules": [TIER_RULE]}, "'conditons'"),
    "rule-enabled-flag": (_with_rule(enabled=False), _with_rule(), "'enabled'"),
    "rule-priority": (_with_rule(priority=5), _with_rule(), "'priority'"),
    # 3. A block key present with no value.
    "match-null": (
        {"version": "1", "rules": [{**TIER_RULE, "match": None}]},
        {"version": "1", "rules": [{k: v for k, v in TIER_RULE.items() if k != "match"}]},
        "'match:'"),
    "conditions-null": (_with_rule(conditions=None), _with_rule(), "'conditions:'"),
    # 4. `defaults:` present with no value.
    "defaults-null": (_doc(defaults=None), _doc(), "'defaults:'"),
    # 5. A non-finite numeric condition.
    "tier-inf": (
        {"version": "1", "rules": [
            {**TIER_RULE, "conditions": {"min_chain_tier_above": math.inf}}, BLOCK]},
        {"version": "1", "rules": [TIER_RULE, BLOCK]}, "min_chain_tier_above"),
    "tier-nan": (
        {"version": "1", "rules": [
            {**TIER_RULE, "conditions": {"min_chain_tier_above": math.nan}}]},
        {"version": "1", "rules": [TIER_RULE]}, "min_chain_tier_above"),
    "tier-inf-string": (
        {"version": "1", "rules": [
            {**TIER_RULE, "conditions": {"min_chain_tier_above": "inf"}}]},
        {"version": "1", "rules": [
            {**TIER_RULE, "conditions": {"min_chain_tier_above": "2"}}]},
        "min_chain_tier_above"),
    # 6. A boolean version (`version: yes`).
    "version-bool": ({**_doc(), "version": True}, _doc(), "version"),
}


@pytest.mark.parametrize("label", sorted(CASES))
def test_dropped_field_is_refused(label, caplog):
    refused, control, needle = CASES[label]
    assert parse_action_policy(control) is not None, (
        f"{label}: the CONTROL document was refused, so this case cannot show "
        "that the field under test is what causes the refusal"
    )
    with caplog.at_level(logging.ERROR, logger=AUTHZ):
        parsed = parse_action_policy(refused)
    assert parsed is None, (
        f"{label}: the parser accepted the document and silently dropped or "
        f"misread {needle} — the policy in force is not the one written. "
        f"Parsed as: {parsed!r}"
    )
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(needle in m for m in errors), (
        f"{label}: refused, but no ERROR names {needle}: {errors!r}"
    )
    assert any("REJECTED" in m for m in errors)


def test_every_documented_rule_key_still_loads():
    """Scope guard: refusing unknown keys must not refuse a supported one."""
    rule = {"id": "r", "effect": "block", "message": "m",
            "match": {"tools": ["deploy"]}, "conditions": {"min_chain_tier_above": 1}}
    assert parse_action_policy({
        "version": "1", "defaults": {"effect": "allow", "unclassified": "monitor"},
        "rules": [rule],
    }) is not None


# ── 7. YAML duplicate keys in a policy FILE ─────────────────────────────────

DUP_RULES = """\
version: "1"
rules:
  - id: no-deploy
    effect: block
    match:
      tools: ["deploy"]
rules:
  - id: no-read
    effect: block
    match:
      tools: ["read"]
"""

DUP_MATCH = """\
version: "1"
rules:
  - id: r
    effect: block
    match:
      tools: ["deploy"]
      tools: ["read"]
"""


@pytest.mark.parametrize("label,text,needle", [
    ("duplicate-top-level-key", DUP_RULES, "rules"),
    ("duplicate-match-key", DUP_MATCH, "tools"),
])
def test_yaml_duplicate_key_is_refused(tmp_path, caplog, label, text, needle):
    pytest.importorskip("yaml")
    from xaidr.local_policy import load_policy
    path = tmp_path / "xaidr-policy.yaml"
    path.write_text(text, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        policy = load_policy(str(path), auto_default=False)
    assert policy is None, (
        f"{label}: a duplicate {needle!r} key loaded, so one of the two values "
        f"written is not enforced. Loaded: {policy!r}"
    )
    assert "duplicate" in caplog.text and needle in caplog.text, caplog.text


def test_yaml_without_duplicates_still_loads(tmp_path):
    pytest.importorskip("yaml")
    from xaidr.local_policy import load_policy
    path = tmp_path / "xaidr-policy.yaml"
    path.write_text(DUP_MATCH.replace('      tools: ["read"]\n', ""), encoding="utf-8")
    policy = load_policy(str(path), auto_default=False)
    assert policy is not None and policy["rules"][0]["match"] == {"tools": ["deploy"]}
