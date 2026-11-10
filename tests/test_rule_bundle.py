"""The rule bundle loader: whole or nothing, versioned, read once at attach.

``Sensor.load_rule_bundle(bundle)`` takes a complete rule set (the seven
packaged JSON shapes under an integer ``version``) and adopts it whole or not at
all, the way ``set_policy`` does. The version rides every event as
``bundleVersion`` while the bundle is in force and is absent otherwise. S15
``SensorExtension.rule_bundle()`` hands one in at attach. Open never fetches or
verifies a bundle; that stays in the overlay.

Zero movement, two ways: with no bundle nothing changes, and a bundle equal to
the packaged rules moves no verdict on the committed corpus.

Every input is a committed corpus row. No attack string is written here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os

import pytest

from xaidr import Sensor, SensorExtension
from xaidr import rule_bundle
from xaidr.authz import classifier as _classifier
from xaidr.scanner import l1 as _l1
from xaidr.scanner import l2 as _l2
from xaidr.scanner import normalizer as _normalizer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


@pytest.fixture(autouse=True)
def _packaged_rules_after():
    yield
    rule_bundle._reset()
    assert rule_bundle.version() is None


def _tables():
    return (_l1.INPUT_RULES, _l1.OUTPUT_RULES, _l2.INTENTS, _l2.COMPOSITES, _l2.CHAINS,
            _normalizer._TYPO_CONFIG, _classifier._RULESET)


def _digest(sensor):
    """Verdicts over the shell corpus on four boundaries, as one digest."""
    with open(SHELL, encoding="utf-8") as fh:
        shell = json.load(fh)
    lines = []
    for e in shell["attacks"] + shell["benign"]:
        r = sensor.scan_tool_call("run_command", {"command": e["command"]})
        lines.append(f"tool {r.action} {r.score:.4f} {r.category} {','.join(r.rules)}")
    for e in shell["benign_prose"]:
        r = sensor.scan(e["text"], direction="input")
        lines.append(f"in {r.action} {r.score:.4f} {r.category} {','.join(r.rules)}")
        r = sensor.scan_a2a(e["text"], destination="peer")
        lines.append(f"a2a {r.action} {r.score:.4f} {r.category} {','.join(r.rules)}")
        r = sensor.scan_output(e["text"])
        lines.append(f"out {r.action} {r.score:.4f} {r.category} {','.join(r.rules)}")
    return hashlib.sha256("\n".join(lines).encode()).hexdigest(), len(lines)


def _attack_command():
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"]
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    for e in attacks:
        if probe.scan_tool_call("run_command", {"command": e["command"]}).action == "blocked":
            return e["command"]
    pytest.skip("no committed attack row blocks on the tool path")   # pragma: no cover


# ── refused bundles install nothing ──────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    None, "bundle", 7, [], {}, {"version": 7}, {"files": {}},
    {"version": 0, "files": {}}, {"version": "7", "files": {}}, {"version": True, "files": {}},
], ids=["none", "str", "int", "list", "empty", "no-files", "no-version", "zero", "str-version", "bool"])
def test_a_malformed_bundle_is_refused_and_nothing_moves(bad):
    before = _tables()
    s = Sensor(agent_id="bundle", enforcement_mode="block", reporter=_Sink())
    assert s.load_rule_bundle(bad) is False
    assert all(a is b for a, b in zip(before, _tables())), "a refused bundle replaced a rule file"
    assert rule_bundle.version() is None
    assert s.scan_tool_call("run_command", {"command": _attack_command()}).action == "blocked"


def test_a_bundle_with_one_file_absent_is_refused():
    bundle = rule_bundle.packaged(7)
    del bundle["files"]["attack-chains.json"]
    before = _tables()
    assert rule_bundle.install(bundle) is False
    assert all(a is b for a, b in zip(before, _tables()))


def test_a_bundle_with_an_unknown_file_is_refused():
    bundle = rule_bundle.packaged(7)
    bundle["files"]["extra.json"] = []
    assert rule_bundle.install(bundle) is False


def test_one_bad_file_refuses_the_whole_bundle_and_replaces_none():
    """Whole or nothing: the first six files are valid (the L1 list is EMPTY, so a
    partial adoption would be visible), the seventh does not compile."""
    bundle = rule_bundle.packaged(7)
    bundle["files"]["all-l1-rules.json"] = []
    bad = copy.deepcopy(bundle["files"]["impact-classes.json"])
    bad["command_classifiers"]["rules"].append({"id": "broken", "match": {"args_pattern": "("}})
    bundle["files"]["impact-classes.json"] = bad
    before = _tables()
    assert rule_bundle.install(bundle) is False
    after = _tables()
    replaced = [name for name, a, b in zip(rule_bundle.FILES, before, after) if a is not b]
    assert not replaced, f"a refused bundle left {len(replaced)} of 7 rule files replaced: {replaced}"
    assert rule_bundle.version() is None


@pytest.mark.parametrize("name", rule_bundle.FILES)
def test_a_rule_that_would_be_dropped_refuses_the_bundle(name):
    """The import path drops a rule that does not compile and records a fault; a
    bundle is held to the stricter rule: every rule it names must load."""
    bundle = rule_bundle.packaged(7)
    files = bundle["files"]
    if name in ("all-l1-rules.json", "output-l1-rules.json"):
        files[name] = files[name] + [{"id": "broken", "pattern": "(", "score": 0.5,
                                      "category": files[name][0]["category"]}]
    elif name == "dangerous-intents.json":
        files[name] = files[name] + [{"name": "broken", "actions": "(", "targets": "x",
                                      "category": "prompt_injection"}]
    elif name in ("composite-rules.json", "attack-chains.json"):
        files[name] = files[name] + ["not an object"]
    elif name == "typo-keywords.json":
        files[name] = {"all_keywords": "not a list"}
    else:
        bad = copy.deepcopy(files[name])
        bad["argument_escalations"] = [{"id": "broken", "value_pattern": "("}]
        files[name] = bad
    before = _tables()
    assert rule_bundle.install(bundle) is False, f"{name}: a bundle with a rule that cannot load was adopted"
    assert all(a is b for a, b in zip(before, _tables()))


# ── a valid bundle: versioned, in force, byte-identical when equal to the packaged rules ──

def test_the_packaged_rules_as_a_bundle_move_no_verdict_and_stamp_the_version():
    sink = _Sink()
    s = Sensor(agent_id="bundle", enforcement_mode="block", reporter=sink)
    before, n = _digest(s)
    s.flush()
    assert n > 500
    assert all("bundleVersion" not in e["data"] for e in sink.events), "a version with no bundle"
    sink.events.clear()
    assert s.load_rule_bundle(rule_bundle.packaged(7)) is True
    assert rule_bundle.version() == 7
    after, _ = _digest(s)
    assert after == before, "a bundle equal to the packaged rules moved a verdict"
    s.flush()
    assert sink.events and all(e["data"].get("bundleVersion") == 7 for e in sink.events), (
        "an event while the bundle is in force carries no bundleVersion")


def test_every_emitter_stamps_the_version():
    from xaidr.circuit_breaker import CircuitBreaker
    from xaidr.types import ScanResult

    class _Gate(SensorExtension):
        name = "gate"

        def gate(self, req):
            return ScanResult(action="blocked", score=1.0, category="q", rules=["Q"]) \
                if req.direction == "a2a" else None

    class _Raising(SensorExtension):
        name = "raising"

        def gate(self, req):
            if req.direction == "output":
                raise RuntimeError("down")
            return None

    sink = _Sink()
    s = Sensor(agent_id="bundle", enforcement_mode="block", reporter=sink,
               fail_closed=("controls",), extensions=[_Gate(), _Raising()],
               circuit_breaker=CircuitBreaker(violation_threshold=1, violation_window_sec=60))
    assert s.load_rule_bundle(rule_bundle.packaged(9)) is True
    s.scan("a plain request", direction="input")                      # main
    s.scan_a2a("a plain message", destination="peer")                 # gate
    s.scan_output("a plain answer")                                   # fail-closed
    s.scan(12345, direction="input")                                  # not scannable
    s.scan_tool_call("run_command", {"command": _attack_command()})   # main, trips the breaker
    s.scan("a plain request", direction="input")                      # circuit open
    s.flush()
    kinds = {(e["type"], e["data"].get("category")) for e in sink.events}
    assert len(kinds) >= 5
    for e in sink.events:
        assert e["data"].get("bundleVersion") == 9, (e["type"], e["data"].get("category"))


def test_an_empty_rule_set_is_a_valid_bundle_and_takes_effect():
    """Positive control: the swap is real. With every rule list empty, a committed
    attack row scans allowed."""
    cmd = _attack_command()
    bundle = rule_bundle.packaged(3)
    for name in ("all-l1-rules.json", "output-l1-rules.json", "dangerous-intents.json",
                 "composite-rules.json", "attack-chains.json"):
        bundle["files"][name] = []
    bundle["files"]["impact-classes.json"] = {"version": 1, "default": {}, "rules": [],
                                             "argument_escalations": []}
    s = Sensor(agent_id="bundle", enforcement_mode="block", reporter=_Sink())
    assert s.scan_tool_call("run_command", {"command": cmd}).action == "blocked"
    assert s.load_rule_bundle(bundle) is True
    assert s.scan_tool_call("run_command", {"command": cmd}).action == "allowed"
    rule_bundle._reset()
    assert s.scan_tool_call("run_command", {"command": cmd}).action == "blocked"


def test_every_sensor_reads_the_bundles_typo_table_from_its_next_scan():
    """The normaliser in force is one per process and every scanner reads it at
    call time: a sensor built before the install, one built after, and the
    encoding-evasion layer's module all see the bundle's table."""
    from xaidr.scanner import encoding_evasion, normalizer

    before = Sensor(agent_id="bundle-before", reporter=_Sink())
    old = normalizer.current()
    assert before._scanner._normalizer is old and old.keywords
    bundle = rule_bundle.packaged(7)
    bundle["files"]["typo-keywords.json"] = {"all_keywords": [], "denylist": []}
    assert before.load_rule_bundle(bundle) is True
    after = Sensor(agent_id="bundle-after", reporter=_Sink())
    for s in (before, after):
        assert s._scanner._normalizer is normalizer.current()
        assert s._scanner._normalizer.keywords == [], "a sensor kept the old typo table"
        assert s._arg_normalizer().keywords == []
    assert encoding_evasion._normalizer_mod.current().keywords == [], (
        "the encoding-evasion layer kept its own normaliser")


@pytest.mark.parametrize("typo", [
    {"all_keywords": [1], "denylist": []},
    {"all_keywords": [], "denylist": [1]},
    {"all_keywords": ["ignore"], "denylist": [], "min_token_length": "4"},
], ids=["int-keyword", "int-denylist", "str-min-length"])
def test_a_typo_file_a_normaliser_cannot_build_from_refuses_the_bundle(typo):
    """The typo file is staged the way it is used. A bad table that passed a
    shape check and installed would break every sensor built afterwards."""
    from xaidr.scanner import normalizer

    bundle = rule_bundle.packaged(7)
    bundle["files"]["typo-keywords.json"] = typo
    before = _tables()
    current = normalizer.current()
    s = Sensor(agent_id="bundle", enforcement_mode="block", reporter=_Sink())
    assert s.load_rule_bundle(bundle) is False, "a typo table that does not build was adopted"
    assert all(a is b for a, b in zip(before, _tables()))
    assert normalizer.current() is current
    Sensor(agent_id="bundle-after", reporter=_Sink())      # still constructs
    assert rule_bundle.version() is None


@pytest.mark.parametrize("name", rule_bundle.FILES)
def test_a_null_file_is_refused(name):
    bundle = rule_bundle.packaged(7)
    bundle["files"][name] = None
    before = _tables()
    assert rule_bundle.install(bundle) is False, f"{name}: a null file was accepted"
    assert all(a is b for a, b in zip(before, _tables()))


def test_s15_refusal_log_line_says_what_happened(caplog):
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        Sensor(agent_id="bundle", reporter=_Sink(),
               extensions=[_BundleExt({"version": 7, "files": {}})])
    hits = [r.getMessage() for r in caplog.records if "bundle-ext" in r.getMessage()]
    assert len(hits) == 1
    assert "REFUSED" in hits[0] and "packaged rules keep scanning" in hits[0]
    assert "raised" not in hits[0] and "open verdict" not in hits[0]


# ── S15: the bundle an extension hands in at attach ──────────────────────────

class _BundleExt(SensorExtension):
    name = "bundle-ext"

    def __init__(self, bundle):
        self._bundle = bundle

    def rule_bundle(self):
        return self._bundle


def test_s15_installs_the_extensions_bundle_at_attach():
    sink = _Sink()
    s = Sensor(agent_id="bundle", reporter=sink, extensions=[_BundleExt(rule_bundle.packaged(11))])
    assert rule_bundle.version() == 11
    s.scan("a plain request", direction="input")
    s.flush()
    assert sink.events[0]["data"]["bundleVersion"] == 11


def test_s15_refuses_an_invalid_bundle_logs_once_and_keeps_scanning(caplog):
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        s = Sensor(agent_id="bundle", enforcement_mode="block", reporter=_Sink(),
                   extensions=[_BundleExt({"version": 7, "files": {}})])
    assert rule_bundle.version() is None
    assert s.scan_tool_call("run_command", {"command": _attack_command()}).action == "blocked"
    hits = [r for r in caplog.records if "bundle-ext" in r.getMessage() and "rule_bundle" in r.getMessage()]
    assert len(hits) == 1


def test_s15_declining_installs_nothing():
    Sensor(agent_id="bundle", reporter=_Sink(), extensions=[_BundleExt(None)])
    assert rule_bundle.version() is None


def test_s15_fault_fails_construction():
    class _Raising(SensorExtension):
        name = "raising-bundle"

        def rule_bundle(self):
            raise RuntimeError("fetch failed")

    with pytest.raises(RuntimeError, match="fetch failed"):
        Sensor(agent_id="bundle", reporter=_Sink(), extensions=[_Raising()])


def test_s15_first_bundle_wins():
    Sensor(agent_id="bundle", reporter=_Sink(),
           extensions=[_BundleExt(rule_bundle.packaged(5)), _BundleExt(rule_bundle.packaged(6))])
    assert rule_bundle.version() == 5
