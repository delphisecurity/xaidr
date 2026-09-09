"""S2 · extension-supplied policy condition fields.

The seam lets an enterprise package add names to a rule's ``conditions:`` block
without forking the parser. What matters most is the case that ships to every
open user — no extensions — where the parser must behave EXACTLY as it did
before this seam existed: an unrecognised condition key still rejects the whole
policy, and ``trust_below`` is still rejected in both placements.

So every test here comes in pairs. The registered half proves the seam works;
the unregistered half proves open did not move. A test that only demonstrates
the first is indistinguishable from one asserting something already true.

THREE ENTRY POINTS, not the two the design doc named. `parse_action_policy` is
reached by `load_policy` (a policy FILE) and by `set_policy_dict` (the public
`Sensor.set_policy()` runtime API). The doc listed only the first; wiring only
that one would leave `Sensor(extensions=[...]).set_policy({...})` rejecting the
extension's own condition. That is the S7 census lesson: enumerate from the
tree, never from a document's line list.
"""

import pytest

from xaidr import Sensor, SensorExtension
from xaidr.authz.policy import parse_action_policy
from xaidr.local_policy import set_policy_dict

CUSTOM = "geo_outside"


def _policy(conditions, rule_id="r1"):
    return {
        "version": "1",
        "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": rule_id, "effect": "block", "match": {"tools": ["deploy"]},
                   "conditions": conditions}],
    }


class _GeoExtension(SensorExtension):
    """Registers one condition name that is NOT trust_below."""

    name = "geo"

    def __init__(self):
        self.evaluated = []

    def policy_conditions(self):
        def evaluate(ctx, value):
            self.evaluated.append((ctx, value))
            return True
        return {CUSTOM: evaluate}


# ── the parser, directly ─────────────────────────────────────────────────────

def test_unregistered_condition_key_is_rejected():
    """Open's behaviour, unchanged. This is the half that must not move."""
    assert parse_action_policy(_policy({CUSTOM: "EU"})) is None


def test_registered_condition_key_is_accepted():
    parsed = parse_action_policy(
        _policy({CUSTOM: "EU"}), extra_conditions={CUSTOM: lambda ctx, v: True}
    )
    assert parsed is not None
    assert parsed["rules"][0]["conditions"][CUSTOM] == "EU"


def test_a_key_registered_by_no_one_still_rejects_alongside_a_registered_one():
    """Registering one name must not open the gate for every other name."""
    assert parse_action_policy(
        _policy({CUSTOM: "EU", "totally_unknown": 1}),
        extra_conditions={CUSTOM: lambda ctx, v: True},
    ) is None


def test_builtin_condition_fields_still_parse_with_extensions_registered():
    assert parse_action_policy(
        _policy({"min_chain_tier_above": 2}),
        extra_conditions={CUSTOM: lambda ctx, v: True},
    ) is not None


# ── trust_below: the rejection that must survive ─────────────────────────────

@pytest.mark.parametrize("placement", ["conditions", "match"])
def test_trust_below_still_rejected_with_no_extensions(placement):
    """A-11 restated for S2. The existing A-11 tests in
    test_inert_stubs_audit.py are left untouched; this one pins the same
    behaviour through the new code path."""
    doc = _policy({"trust_below": 0.5}) if placement == "conditions" else {
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{"id": "r", "effect": "block", "match": {"trust_below": 0.5}}],
    }
    assert parse_action_policy(doc) is None


@pytest.mark.parametrize("placement", ["conditions", "match"])
def test_trust_below_still_rejected_when_a_DIFFERENT_condition_is_registered(placement):
    """The discriminating case: registering `geo_outside` must not exempt
    `trust_below`. An exemption keyed on "any extension present" rather than on
    the KEY would pass every other test in this file and fail this one."""
    doc = _policy({"trust_below": 0.5}) if placement == "conditions" else {
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{"id": "r", "effect": "block", "match": {"trust_below": 0.5}}],
    }
    assert parse_action_policy(
        doc, extra_conditions={CUSTOM: lambda ctx, v: True}
    ) is None


def test_an_extension_that_registers_trust_below_may_use_it():
    """S9 is what supplies the score; this only proves the guard is keyed on the
    name, so the enterprise package can take ownership of it."""
    assert parse_action_policy(
        _policy({"trust_below": 0.5}),
        extra_conditions={"trust_below": lambda ctx, v: True},
    ) is not None


# ── the sensor, through both runtime entry points ────────────────────────────

def test_bare_sensor_has_no_policy_conditions():
    assert Sensor(agent_id="s2-bare").policy_conditions == {}


def test_sensor_collects_conditions_from_its_extensions():
    s = Sensor(agent_id="s2-ext", extensions=[_GeoExtension()])
    assert list(s.policy_conditions) == [CUSTOM]


def test_set_policy_accepts_an_extension_condition():
    """The entry point the design doc missed. `set_policy` goes through
    `set_policy_dict`, not `load_policy`."""
    s = Sensor(agent_id="s2-set", extensions=[_GeoExtension()])
    assert s.set_policy(_policy({CUSTOM: "EU"})) is True


def test_set_policy_rejects_the_same_policy_on_a_bare_sensor():
    """The negative half of the test above, and the one that shows the seam is
    doing the work rather than the key having become globally valid."""
    assert Sensor(agent_id="s2-set-bare").set_policy(_policy({CUSTOM: "EU"})) is False


def test_set_policy_dict_forwards_extra_conditions():
    assert set_policy_dict(_policy({CUSTOM: "EU"})) is None
    assert set_policy_dict(
        _policy({CUSTOM: "EU"}), extra_conditions={CUSTOM: lambda ctx, v: True}
    ) is not None


def test_policy_file_path_forwards_extra_conditions(tmp_path):
    """The entry point the doc DID name, proved separately from set_policy."""
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "xaidr-policy.yaml"
    # load_policy hands the file's top-level document straight to the parser.
    path.write_text(yaml.safe_dump(_policy({CUSTOM: "EU"})), encoding="utf-8")
    from xaidr.local_policy import load_policy
    assert load_policy(str(path)) is None
    assert load_policy(
        str(path), extra_conditions={CUSTOM: lambda ctx, v: True}
    ) is not None


# ── duplicate condition names across extensions ──────────────────────────────

def test_two_extensions_declaring_the_same_condition_raise_at_construction():
    class Alpha(SensorExtension):
        name = "alpha"

        def policy_conditions(self):
            return {"shared": lambda ctx, v: True}

    class Beta(SensorExtension):
        name = "beta"

        def policy_conditions(self):
            return {"shared": lambda ctx, v: True}

    with pytest.raises(ValueError) as exc:
        Sensor(agent_id="s2-dup", extensions=[Alpha(), Beta()])
    message = str(exc.value)
    assert "alpha" in message and "beta" in message, (
        "the error must name BOTH extensions, or the operator cannot tell which "
        "pair collided"
    )
    assert "shared" in message


def test_distinct_condition_names_across_extensions_merge():
    class Alpha(SensorExtension):
        name = "alpha"

        def policy_conditions(self):
            return {"cond_a": lambda ctx, v: True}

    class Beta(SensorExtension):
        name = "beta"

        def policy_conditions(self):
            return {"cond_b": lambda ctx, v: True}

    s = Sensor(agent_id="s2-merge", extensions=[Alpha(), Beta()])
    assert sorted(s.policy_conditions) == ["cond_a", "cond_b"]


def test_policy_conditions_returning_a_non_mapping_raises():
    class Bad(SensorExtension):
        name = "bad"

        def policy_conditions(self):
            return ["not", "a", "mapping"]

    with pytest.raises(ValueError, match="policy_conditions"):
        Sensor(agent_id="s2-bad", extensions=[Bad()])


def test_the_property_is_a_copy():
    s = Sensor(agent_id="s2-copy", extensions=[_GeoExtension()])
    s.policy_conditions["injected"] = lambda ctx, v: True
    assert "injected" not in s.policy_conditions


# ── S2 completion: the evaluator must actually RUN ───────────────────────────
#
# S2 as first merged threaded `extra_conditions` into `parse_action_policy` and
# stopped there. `evaluate()` never received them and matched only the two
# built-in conditions, so a registered condition parsed cleanly and was then
# DROPPED at evaluation. That does not merely fail to fire — it WIDENS the rule.

def test_a_registered_condition_is_actually_evaluated():
    calls = []

    class Geo(SensorExtension):
        name = "geo-eval"

        def policy_conditions(self):
            def outside(request, value):
                calls.append(value)
                return False            # declines -> the rule must NOT fire
            return {"geo_outside": outside}

    s = Sensor(agent_id="s2-eval", enforcement_mode="block",
               extensions=[Geo()])
    assert s.set_policy(_policy({CUSTOM: "EU"}, rule_id="geo")) is True
    r = s.scan_tool_call("deploy", {"env": "prod"})
    assert calls == ["EU"], "the registered evaluator was never called"
    assert r.action != "blocked", (
        "a declining condition must NARROW the rule; dropping it makes a "
        "`tools:` match fire unconditionally"
    )


def test_a_matching_condition_lets_the_rule_fire():
    """The other direction, so the test above cannot pass by the rule being
    broken outright."""
    class Geo(SensorExtension):
        name = "geo-eval-yes"

        def policy_conditions(self):
            return {CUSTOM: lambda request, value: True}

    s = Sensor(agent_id="s2-eval-yes", enforcement_mode="block",
               extensions=[Geo()])
    assert s.set_policy(_policy({CUSTOM: "EU"}, rule_id="geo")) is True
    assert s.scan_tool_call("deploy", {"env": "prod"}).action == "blocked"


def test_an_evaluator_that_raises_fails_CLOSED():
    """A condition that cannot answer must not widen the rule it narrows."""
    class Broken(SensorExtension):
        name = "geo-broken"

        def policy_conditions(self):
            def boom(request, value):
                raise RuntimeError("geo service down")
            return {CUSTOM: boom}

    s = Sensor(agent_id="s2-eval-boom", enforcement_mode="block",
               extensions=[Broken()])
    assert s.set_policy(_policy({CUSTOM: "EU"}, rule_id="geo")) is True
    assert s.scan_tool_call("deploy", {"env": "prod"}).action != "blocked"


def test_the_evaluator_receives_the_request_and_the_configured_value():
    seen = {}

    class Geo(SensorExtension):
        name = "geo-args"

        def policy_conditions(self):
            def outside(request, value):
                seen["request"] = request
                seen["value"] = value
                return True
            return {CUSTOM: outside}

    s = Sensor(agent_id="s2-eval-args", enforcement_mode="block",
               extensions=[Geo()])
    s.set_policy(_policy({CUSTOM: "EU"}, rule_id="geo"))
    s.scan_tool_call("deploy", {"env": "prod"})
    assert seen["value"] == "EU"
    assert seen["request"]["subject"]["agent_id"] == "s2-eval-args"
