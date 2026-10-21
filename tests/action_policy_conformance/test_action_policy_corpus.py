"""ActionPolicy v1 conformance: corpus_v1.json is the authority.

Every case in the corpus is a policy document and the verdict the open parser
must give it: accept with an exact normalized form (plus evaluation probes), or
refuse with a reason code and the path of the refused part. Another
implementation of ActionPolicy v1 conforms when it gives the same verdict on
every case.

The coverage checks below derive the v1 vocabulary from the parser's own tables
(`_MATCH_FIELDS`, `_CONDITION_FIELDS`, `EFFECTS`, `REFUSAL_REASONS`) and require
each field to be decisive in a probe, so a field or reason added to the parser
without a corpus case fails here.
"""
import json
import logging
import math
from pathlib import Path

import pytest

from xaidr.authz.policy import (
    _CONDITION_FIELDS,
    _MATCH_FIELDS,
    EFFECTS,
    REFUSAL_REASONS,
    _rule_matches,
    evaluate,
    explain_action_policy,
)

CORPUS_PATH = Path(__file__).with_name("corpus_v1.json")

# The catch-all for an unexpected exception inside the parser. No corpus case
# pins it, because a document that reaches it is a parser defect to fix.
_UNREACHABLE_FROM_JSON = {"parse_error"}


def _decode(value):
    if isinstance(value, dict):
        if set(value) == {"$float"}:
            return float(value["$float"])
        return {k: _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
CASES = CORPUS["cases"]


@pytest.fixture(autouse=True)
def _quiet_parser():
    # Refusals log at ERROR by design; 90 of them would bury a real failure.
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_open_parser_gives_the_corpus_verdict(case):
    expect = case["expect"]
    verdict = explain_action_policy(_decode(case["document"]))

    if expect["verdict"] == "refuse":
        assert verdict.policy is None, (
            f"{case['id']}: the corpus says REFUSE ({expect['reason']} at "
            f"{expect['field']!r}) and the parser accepted it as {verdict.policy!r}"
        )
        assert (verdict.reason, verdict.field) == (expect["reason"], expect["field"]), (
            f"{case['id']}: refused for {verdict.reason!r} at {verdict.field!r}; the "
            f"corpus says {expect['reason']!r} at {expect['field']!r}"
        )
        return

    assert verdict.policy is not None, (
        f"{case['id']}: the corpus says ACCEPT and the parser refused it "
        f"({verdict.reason!r} at {verdict.field!r})"
    )
    assert verdict.policy == expect["normalized"], (
        f"{case['id']}: normalized form differs from the corpus.\n"
        f"  parser: {verdict.policy!r}\n  corpus: {expect['normalized']!r}"
    )
    for i, p in enumerate(expect["probes"]):
        got = evaluate(verdict.policy, p["request"])
        assert (got.decision, got.policy_id) == (p["decision"], p["policy_id"]), (
            f"{case['id']} probe {i}: {p['request']['action']['tool_name']!r} "
            f"decided {got.decision!r} by {got.policy_id!r}; the corpus says "
            f"{p['decision']!r} by {p['policy_id']!r}"
        )


# ── the corpus covers the whole v1 vocabulary ───────────────────────────────

def _accepted():
    return [c for c in CASES if c["expect"]["verdict"] == "accept"]


def test_case_ids_are_unique():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids))


def test_every_refusal_reason_has_a_case():
    seen = {c["expect"]["reason"] for c in CASES if c["expect"]["verdict"] == "refuse"}
    assert seen <= REFUSAL_REASONS, f"corpus uses unknown reasons: {seen - REFUSAL_REASONS}"
    missing = REFUSAL_REASONS - _UNREACHABLE_FROM_JSON - seen
    assert not missing, f"no corpus case is refused for: {sorted(missing)}"


_DECISION = {"allow": "allowed", "block": "blocked", "monitor": "monitor",
             "require_approval": "approval_required"}


def _decided(case):
    """(rule, probe) for every probe a rule decided, located by the rule's id."""
    rules = case["expect"]["normalized"]["rules"]
    for p in case["expect"]["probes"]:
        idx = [i for i, r in enumerate(rules) if r["id"] == p["policy_id"]]
        if p["policy_id"] is not None and idx:
            yield idx[0], rules, p


def _matches_without(rule, block, key, request):
    """Would the rule match `request` with this one match field or condition
    removed? A rule left with nothing to test is unrestricted, so it matches."""
    variant = {**rule, "match": dict(rule["match"]), "conditions": dict(rule["conditions"])}
    del variant[block][key]
    if not variant["match"] and not variant["conditions"]:
        return True
    return _rule_matches(variant, request)


def _excluded_only_by(rule, block, key, case):
    """Some probe in the case that the rule fails to match ONLY because of this
    field or condition. An evaluator that ignored it would decide that probe
    differently, which a probe the rule matches cannot show."""
    return any(not _rule_matches(rule, p["request"])
               and _matches_without(rule, block, key, p["request"])
               for p in case["expect"]["probes"])


def test_every_match_field_is_decisive_in_an_accepted_case():
    """For each field, a rule using it decides some probe, and some probe in the
    same case is excluded by that field alone."""
    decisive = set()
    for c in _accepted():
        deciding = {rules[i]["id"] for i, rules, _ in _decided(c)}
        for r in c["expect"]["normalized"]["rules"]:
            if r["id"] in deciding:
                decisive |= {f for f in r["match"] if _excluded_only_by(r, "match", f, c)}
    missing = set(_MATCH_FIELDS) - decisive
    assert not missing, f"match fields never decisive in an accepted case: {sorted(missing)}"


def test_every_match_field_has_a_refused_wrong_type_case():
    tagged = {t.split(".", 1)[1] for c in CASES if c["expect"]["verdict"] == "refuse"
              and c["expect"]["reason"] == "invalid_match_value"
              for t in c["covers"] if t.startswith("match.")}
    missing = set(_MATCH_FIELDS) - tagged
    assert not missing, f"match fields with no wrong-type refusal: {sorted(missing)}"


def test_every_condition_field_is_decisive_or_pinned_as_refused():
    """Decisive as for match fields. Fields open does not support
    (`trust_below`) are covered by a refusal case pinning
    `unsupported_condition` instead."""
    covered = set()
    for c in _accepted():
        rules = c["expect"]["normalized"]["rules"]
        deciding = {rules[i]["id"] for i, rules, _ in _decided(c)}
        for r in rules:
            if r["id"] in deciding:
                covered |= {k for k in r["conditions"]
                            if _excluded_only_by(r, "conditions", k, c)}
    for c in CASES:
        e = c["expect"]
        if e["verdict"] == "refuse" and e["reason"] == "unsupported_condition":
            covered.add(e["field"].rsplit(".", 1)[1])
    missing = set(_CONDITION_FIELDS) - covered
    assert not missing, f"condition fields with no decisive or refused case: {sorted(missing)}"


def test_every_effect_is_reached_as_rule_effect_and_through_both_defaults():
    rule_effects, default_effects, unclassified = set(), set(), set()
    for c in _accepted():
        n = c["expect"]["normalized"]
        for i, rules, p in _decided(c):
            if p["decision"] == _DECISION[rules[i]["effect"]]:
                rule_effects.add(rules[i]["effect"])
        for p in c["expect"]["probes"]:
            if p["policy_id"] is not None or any(
                    _rule_matches(r, p["request"]) for r in n["rules"]):
                continue  # decided by a rule, not by the defaults
            key = ("unclassified" if p["request"]["action"]["impact_class"] == "unknown"
                   else "effect")
            if p["decision"] == _DECISION[n["defaults"][key]]:
                (unclassified if key == "unclassified" else default_effects).add(
                    n["defaults"][key])
    for name, seen in [("rule effect", rule_effects), ("defaults.effect", default_effects),
                       ("defaults.unclassified", unclassified)]:
        assert seen == EFFECTS, f"{name} never reached by a probe for: {EFFECTS - seen}"


def test_ordering_cases_pin_first_match_not_deny_wins():
    """A probe decided by an allow when a LATER block rule also matches it."""
    for c in _accepted():
        if "ordering" not in c["covers"]:
            continue
        for i, rules, p in _decided(c):
            if rules[i]["effect"] == "allow" and any(
                    r["effect"] == "block" and _rule_matches(r, p["request"])
                    for r in rules[i + 1:]):
                return
    pytest.fail("no ordering case has an allow decide over a later block that also matches")


def test_non_finite_encoding_round_trips():
    assert math.isinf(_decode({"$float": "inf"}))
    assert math.isnan(_decode({"$float": "nan"}))
