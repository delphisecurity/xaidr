"""S9 · subject trust.

Open computes no per-agent trust score. That is not an oversight — it is the
reason `trust_below` is rejected at policy-parse time (A-11): a condition that
reads a score nobody computes would load cleanly and never fire, which is a
control that looks enforced and does nothing.

S9 is the seam that makes the score real, and S2 is what lets the same extension
register the condition NAME. Neither is useful without the other, so the last
test here composes them: an extension that supplies both gets a `trust_below`
rule that actually parses and actually fires.

With no extension attached every path here returns None and the two
`evaluate_policy` call sites pass exactly the `None` they hardcoded before.
"""

import logging

import pytest

from xaidr import Sensor, SensorExtension


class _Trust(SensorExtension):
    name = "trust-source"

    def __init__(self, score=0.1):
        self._score = score
        self.asked = []

    def subject_trust(self, agent_id):
        self.asked.append(agent_id)
        return self._score


# ── the bare sensor: unchanged ───────────────────────────────────────────────

def test_bare_sensor_has_no_trust():
    assert Sensor(agent_id="s9-bare")._subject_trust("s9-bare") is None


def test_bare_sensor_stores_no_trust_attribute():
    s = Sensor(agent_id="s9-attr")
    assert not hasattr(s, "_trust_score")


# ── the seam ─────────────────────────────────────────────────────────────────

def test_an_extension_supplies_the_score():
    ext = _Trust(0.25)
    s = Sensor(agent_id="s9-ext", extensions=[ext])
    assert s._subject_trust("s9-ext") == 0.25
    assert ext.asked == ["s9-ext"]


def test_the_agent_id_is_passed_through():
    ext = _Trust()
    Sensor(agent_id="who-am-i", extensions=[ext])._subject_trust("who-am-i")
    assert ext.asked == ["who-am-i"]


def test_first_non_none_wins_and_later_extensions_are_not_asked():
    class Declines(SensorExtension):
        name = "declines"

        def __init__(self):
            self.asked = []

        def subject_trust(self, agent_id):
            self.asked.append(agent_id)
            return None

    first, second, third = Declines(), _Trust(0.7), _Trust(0.9)
    second.name, third.name = "second", "third"
    s = Sensor(agent_id="s9-order", extensions=[first, second, third])
    assert s._subject_trust("s9-order") == 0.7
    assert first.asked == ["s9-order"], "a declining extension is still asked"
    assert third.asked == [], "nobody is asked after the first real answer"


def test_a_score_of_zero_is_an_answer_not_a_decline():
    """0.0 is falsy and is the LOWEST possible trust — the one value a
    truthiness check would silently discard, turning 'completely untrusted'
    into 'no opinion'."""
    s = Sensor(agent_id="s9-zero", extensions=[_Trust(0.0)])
    assert s._subject_trust("s9-zero") == 0.0


def test_a_raising_extension_is_fail_safe_and_logged_once(caplog):
    class Broken(SensorExtension):
        name = "broken-trust"

        def subject_trust(self, agent_id):
            raise RuntimeError("trust service down")

    s = Sensor(agent_id="s9-broken", extensions=[Broken(), _Trust(0.3)])
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        assert s._subject_trust("s9-broken") == 0.3, (
            "a broken link must not stop a later extension from answering"
        )
        s._subject_trust("s9-broken")
        s._subject_trust("s9-broken")
    errors = [r for r in caplog.records if "broken-trust" in r.getMessage()]
    assert len(errors) == 1, "once per extension per hook per sensor"


# ── the two call sites actually use it ───────────────────────────────────────

def _trust_policy():
    """A policy whose ONLY rule fires on trust_below, so it can only match when
    a trust score is both supplied and threaded to the evaluator."""
    return {
        "version": "1",
        "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": "untrusted", "effect": "block",
                   "match": {"tools": ["wire_transfer"]},
                   "conditions": {"trust_below": 0.5}}],
    }


class _TrustAndCondition(SensorExtension):
    """S9 + S2 together: supplies the score AND registers the condition name.

    Either alone is inert — the condition would be rejected at parse time
    without S2, and would read None and never fire without S9.
    """

    name = "trust-platform"

    def __init__(self, score):
        self._score = score

    def subject_trust(self, agent_id):
        return self._score

    def policy_conditions(self):
        # Registering the NAME is what lifts A-11's parse-time rejection. The
        # evaluator here is never called: `trust_below` is a BUILT-IN condition,
        # and the built-in comparison reads `request.subject.trust` — which is
        # precisely the value S9 now supplies. Built-in names keep built-in
        # semantics; registration means "I provide the input", not "I replace
        # the comparison". See the `handled` tuple in authz/policy.py.
        return {"trust_below": lambda request, threshold: True}


def test_trust_below_is_still_rejected_on_a_bare_sensor():
    """A-11, unchanged. S9 does not loosen it."""
    assert Sensor(agent_id="s9-a11").set_policy(_trust_policy()) is False


def test_the_tool_path_threads_the_score_into_policy_evaluation():
    """The `sensor.py` tool-call `evaluate_policy` site. Without S9 this rule
    reads trust=None and can never fire, which is exactly the silent no-op
    A-11 exists to prevent."""
    s = Sensor(agent_id="s9-tool", enforcement_mode="block",
               extensions=[_TrustAndCondition(0.1)])
    assert s.set_policy(_trust_policy()) is True
    r = s.scan_tool_call("wire_transfer", {"amount": 100})
    assert r.action == "blocked", (
        "a trust_below rule with a supplied score of 0.1 must fire at "
        "threshold 0.5"
    )


def test_the_same_rule_does_not_fire_when_trust_is_above_the_threshold():
    """The discriminating half: the rule must key on the SCORE, not merely on
    an extension being present."""
    s = Sensor(agent_id="s9-tool-hi", enforcement_mode="block",
               extensions=[_TrustAndCondition(0.9)])
    assert s.set_policy(_trust_policy()) is True
    r = s.scan_tool_call("wire_transfer", {"amount": 100})
    assert r.action != "blocked"
