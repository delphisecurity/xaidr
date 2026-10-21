"""Keep-last-good: a refused policy never removes the policy that is enforcing.

`Sensor.set_policy()` parses first and swaps only on success. A policy the
parser refuses leaves the previous policy in force, the call it blocked stays
blocked, and the refusal is logged at ERROR naming what stayed in force.

Covered sources of the policy in force before the bad input arrives:

  * an earlier `set_policy()` call;
  * a policy FILE loaded at construction (the startup policy);
  * nothing (detection-only), which a bad input must leave as detection-only.

`set_policy(None)` is an explicit clear, not a bad input, and still clears.
"""
import logging

import pytest

from xaidr import Sensor

GOOD = {
    "version": "1",
    "defaults": {"effect": "allow", "unclassified": "monitor"},
    "rules": [
        {"id": "no-deploy", "effect": "block", "match": {"tools": ["deploy_prod"]}},
    ],
}

GOOD_YAML = """\
version: "1"
defaults:
  effect: allow
  unclassified: monitor
rules:
  - id: no-deploy
    effect: block
    match:
      tools: ["deploy_prod"]
"""

# Each one is refused by the parser. Together they reach every refusal family:
# wrong root type, unsupported version, bad rules container, bad effect, bad
# match value, unknown match key, unknown condition, bad defaults.
MALFORMED = {
    "not-a-mapping": "version: 1\nrules: []",
    "unsupported-version": {**GOOD, "version": "2"},
    "rules-not-a-list": {**GOOD, "rules": {"id": "x"}},
    "bad-effect": {**GOOD, "rules": [{**GOOD["rules"][0], "effect": "deny"}]},
    "scalar-match-value": {**GOOD, "rules": [
        {**GOOD["rules"][0], "match": {"tools": "deploy_prod"}}]},
    "unknown-match-key": {**GOOD, "rules": [
        {**GOOD["rules"][0], "match": {"tool": ["deploy_prod"]}}]},
    "unknown-condition": {**GOOD, "rules": [
        {**GOOD["rules"][0], "conditions": {"min_chain_tier_abov": 1}}]},
    "bad-defaults": {**GOOD, "defaults": "block"},
}


class _Recorder:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch if isinstance(batch, list) else [batch])

    def close(self):
        pass


def _sensor(**kw):
    return Sensor(agent_id="keep-last-good", enforcement_mode="block",
                  reporter=_Recorder(), **kw)


def _assert_good_policy_enforcing(s, label):
    blocked = s.scan_tool_call("deploy_prod", {})
    assert blocked.action == "blocked", (
        f"{label}: deploy_prod is {blocked.action!r} — the good policy that "
        "blocked it is no longer the one enforcing, so the deployment's block "
        "rule was switched off by an input that never passed validation"
    )
    assert any("policy:no-deploy" in str(r) for r in blocked.rules), (
        f"{label}: deploy_prod was blocked, but not by the good policy's rule "
        f"(rules={blocked.rules!r})"
    )
    allowed = s.scan_tool_call("read_file", {"path": "notes.txt"})
    assert allowed.action == "allowed", (
        f"{label}: read_file is {allowed.action!r}; the retained policy must be "
        "the GOOD one, not a block-all"
    )


@pytest.mark.parametrize("label", sorted(MALFORMED))
def test_refused_policy_keeps_the_previous_set_policy_enforcing(label, caplog):
    s = _sensor()
    assert s.set_policy(GOOD) is True
    _assert_good_policy_enforcing(s, "control")

    with caplog.at_level(logging.ERROR):
        assert s.set_policy(MALFORMED[label]) is False, (
            f"{label}: the parser accepted a malformed policy"
        )
    _assert_good_policy_enforcing(s, label)
    assert "previous policy remains in force" in caplog.text, (
        f"{label}: the refusal was not reported as keeping the previous "
        f"policy: {caplog.text!r}"
    )


def test_repeated_refusals_never_erode_the_good_policy():
    s = _sensor()
    assert s.set_policy(GOOD) is True
    for label in sorted(MALFORMED):
        assert s.set_policy(MALFORMED[label]) is False
    _assert_good_policy_enforcing(s, "after every refusal in a row")


def test_a_later_good_policy_still_replaces_the_retained_one():
    s = _sensor()
    assert s.set_policy(GOOD) is True
    assert s.set_policy(MALFORMED["bad-effect"]) is False
    replacement = {**GOOD, "rules": [
        {"id": "no-read", "effect": "block", "match": {"tools": ["read_file"]}}]}
    assert s.set_policy(replacement) is True
    assert s.scan_tool_call("read_file", {"path": "notes.txt"}).action == "blocked"
    assert s.scan_tool_call("deploy_prod", {}).action != "blocked"


def test_refused_policy_keeps_the_startup_policy_file_enforcing(tmp_path, caplog):
    pytest.importorskip("yaml")
    path = tmp_path / "xaidr-policy.yaml"
    path.write_text(GOOD_YAML, encoding="utf-8")
    s = _sensor(policy_file=str(path))
    _assert_good_policy_enforcing(s, "startup control")

    with caplog.at_level(logging.ERROR):
        assert s.set_policy(MALFORMED["scalar-match-value"]) is False
    _assert_good_policy_enforcing(s, "startup policy file")
    assert "previous policy remains in force" in caplog.text


def test_refused_policy_with_nothing_in_force_stays_detection_only(caplog):
    s = _sensor()
    with caplog.at_level(logging.ERROR):
        assert s.set_policy(MALFORMED["bad-effect"]) is False
    assert s.scan_tool_call("deploy_prod", {}).action != "blocked"
    assert "no policy was in force" in caplog.text, caplog.text


def test_explicit_none_is_a_clear_not_a_bad_input():
    s = _sensor()
    assert s.set_policy(GOOD) is True
    assert s.set_policy(None) is False
    assert s.scan_tool_call("deploy_prod", {}).action != "blocked"


def test_the_enforcing_policy_does_not_alias_the_callers_input():
    """Validation happens once, at set_policy(). If the parsed policy shared the
    caller's dicts, editing the input afterwards would change what is enforcing
    without any validation, which is the bad-input-drops-the-policy failure by
    another route."""
    import copy
    s = _sensor()
    mine = copy.deepcopy(GOOD)
    assert s.set_policy(mine) is True
    mine["rules"][0]["match"]["tools"] = "deploy_prod"   # scalar: inert if live
    mine["rules"][0]["match"]["tool"] = ["x"]
    _assert_good_policy_enforcing(s, "caller mutated its input after set_policy")


# ── a refusal racing another set_policy() ───────────────────────────────────
#
# The bad document's parse is held open on an Event, so the interleaving is
# deterministic: a second call completes while the refused one is mid-parse.

NEWER = {**GOOD, "rules": [
    {"id": "no-read", "effect": "block", "match": {"tools": ["read_file"]}}]}


def _hold_bad_parse(monkeypatch, bad):
    import threading
    import xaidr.local_policy as lp
    real = lp.parse_action_policy
    entered, release = threading.Event(), threading.Event()

    def held(raw, **kw):
        if raw is bad:
            entered.set()
            assert release.wait(5), "test harness: the held parse was never released"
        return real(raw, **kw)

    monkeypatch.setattr(lp, "parse_action_policy", held)
    return entered, release


@pytest.mark.parametrize("racer", ["accepted-policy", "explicit-clear"])
def test_a_refusal_never_overwrites_a_concurrent_set_policy(monkeypatch, racer):
    import threading
    s = _sensor()
    assert s.set_policy(GOOD) is True
    bad = dict(MALFORMED["bad-effect"])
    entered, release = _hold_bad_parse(monkeypatch, bad)
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("bad", s.set_policy(bad)))
    t.start()
    assert entered.wait(5)
    if racer == "accepted-policy":
        assert s.set_policy(NEWER) is True
    else:
        assert s.set_policy(None) is False
    release.set()
    t.join(5)
    assert result.get("bad") is False

    deploy = s.scan_tool_call("deploy_prod", {}).action
    read = s.scan_tool_call("read_file", {"path": "notes.txt"}).action
    if racer == "accepted-policy":
        assert (deploy, read) == ("allowed", "blocked"), (
            f"the refused call finished after set_policy(NEWER) and the old policy "
            f"is back in force (deploy_prod={deploy!r}, read_file={read!r}): a bad "
            "input replaced a policy that had passed validation"
        )
    else:
        assert deploy != "blocked", (
            "the refused call finished after set_policy(None) and restored the "
            "policy that was explicitly cleared"
        )
