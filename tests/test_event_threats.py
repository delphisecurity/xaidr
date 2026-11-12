"""``threats`` on scan, a2a and tool-call events: one entry per rule.

Each entry is ``{rule, category, score, layer}``, one per id in ``rules`` and
in the same order, at most 50, with ``threatsCut`` naming how many more rules
there are when the list is cut. ``layer`` is one of ``l1``, ``l2``, ``dlp``,
``composite``, ``nano``, ``authz`` or ``gate``. Never ``matched``: no scanned
content reaches the wire through this key. The key name ``threats`` is the one
Core reads first, and every entry passes Core's ``sanitizeFinding`` key set
with nothing dropped.

Inputs are committed corpus rows. No attack string.
"""

from __future__ import annotations

import json
import os

import pytest

from xaidr import Sensor, SensorExtension
from xaidr.types import ScanResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
BENIGN_TC = os.path.join(ROOT, "benign_toolcalls", "corpus.jsonl")

LAYERS = {"l1", "l2", "dlp", "composite", "nano", "authz", "gate"}
#: Core's sanitizeFinding keeps these keys and sets matched to "" (evidence.ts).
CORE_FINDING_KEYS = {"rule", "category", "score", "severity", "layer", "evaluated",
                     "proposedEffect", "appliedEffect", "description", "evidence"}


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _sensor(**kw):
    sink = _Sink()
    return Sensor(agent_id="threats", reporter=sink, **kw), sink


def _events(sensor, sink):
    sensor.flush()
    return [e["data"] for e in sink.events if e.get("type") == "scan"]


def _shell():
    with open(SHELL, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def rows():
    """(input text, event) over the committed rows, on three boundaries."""
    shell = _shell()
    s, sink = _sensor(enforcement_mode="block")
    inputs = []
    for e in shell["benign_prose"]:
        s.scan(e["text"], direction="input")
        inputs.append(e["text"])
    for e in shell["benign_templates"]:
        s.scan(e["template"], direction="input")
        inputs.append(e["template"])
    for e in shell["attacks"][:120] + shell["benign"]:
        s.scan_tool_call("run_command", {"command": e["command"]})
        inputs.append(e["command"])
    for e in shell["benign_prose"][:40]:
        s.scan_a2a(e["text"], destination="peer")
        inputs.append(e["text"])
    with open(BENIGN_TC, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                e = json.loads(line)
                s.scan_tool_call(e["tool"], e["args"])
                inputs.append(json.dumps(e["args"]))
    events = _events(s, sink)
    assert len(events) == len(inputs)
    return list(zip(inputs, events))


def test_threats_mirror_rules_in_order(rows):
    with_rules = [(i, e) for i, e in rows if e["rules"]]
    assert len(with_rules) >= 100, "vacuous: too few rows carry a rule"
    for _, e in rows:
        assert "threats" in e, f"no threats key on a {e['direction']} event"
        assert [t["rule"] for t in e["threats"]] == list(e["rules"])[:50], (
            f"threats do not mirror rules on {e['direction']}: "
            f"{[t['rule'] for t in e['threats']]} != {e['rules']}")


def test_every_entry_has_the_four_keys_and_a_known_layer(rows):
    seen_layers = set()
    for _, e in rows:
        for t in e["threats"]:
            assert set(t) == {"rule", "category", "score", "layer"}, t
            assert isinstance(t["rule"], str) and t["rule"]
            assert t["category"] is None or isinstance(t["category"], str)
            assert isinstance(t["score"], (int, float))
            assert t["layer"] in LAYERS, t
            seen_layers.add(t["layer"])
    assert {"l1", "dlp"} <= seen_layers or {"l1", "authz"} <= seen_layers, seen_layers


def test_every_entry_passes_cores_key_set_with_nothing_dropped(rows):
    for _, e in rows:
        for t in e["threats"]:
            dropped = set(t) - CORE_FINDING_KEYS
            assert not dropped, f"Core's sanitizeFinding would drop {dropped} from {t}"


def test_no_entry_carries_matched_text(rows):
    for _, e in rows:
        for t in e["threats"]:
            assert "matched" not in t, "scanned content reached the wire in threats[i]"


def test_entry_values_come_from_a_closed_vocabulary(rows):
    """No content: every value is an identifier from a fixed vocabulary. A rule
    id is one token of identifier characters; a category is one short token; a
    score is a number. (The prose pool quotes rule ids by name, so a substring
    check against the input is not a content check; the shape is.)"""
    import re
    ident = re.compile(r"^[A-Za-z0-9_:.\-]{1,120}$")
    categories = set()
    for _, e in rows:
        for t in e["threats"]:
            assert ident.match(t["rule"]), f"a rule id that is not an identifier: {t['rule']!r}"
            if t["category"] is not None:
                assert ident.match(t["category"]) and len(t["category"]) <= 64, t
                categories.add(t["category"])
            assert isinstance(t["score"], (int, float)) and 0.0 <= float(t["score"]) <= 1.5, t
    assert categories and len(categories) < 80, (
        f"{len(categories)} distinct categories: content is leaking through the field")


def test_at_most_fifty_with_a_cut_marker():
    s, sink = _sensor()
    many = {f"k{i}": f"value {i}" for i in range(400)}
    r = s.scan_tool_call("send_message", many)
    ev = _events(s, sink)[0]
    if len(ev["rules"]) <= 50:
        pytest.skip("the row carries 50 rules or fewer; the cut is exercised below by construction")
    assert len(ev["threats"]) == 50
    assert ev["threatsCut"] == len(ev["rules"]) - 50


def test_the_cut_marker_is_built_from_the_result(monkeypatch):
    """Construct the cut directly: a gate result with 60 rules."""
    class _ManyRules(SensorExtension):
        name = "many"

        def gate(self, req):
            return ScanResult(action="blocked", score=1.0, category="quarantine",
                              rules=[f"Q{i:03d}" for i in range(60)])

    s, sink = _sensor(extensions=[_ManyRules()])
    s.scan("a plain request", direction="input")
    ev = _events(s, sink)[0]
    assert len(ev["threats"]) == 50
    assert [t["rule"] for t in ev["threats"]] == [f"Q{i:03d}" for i in range(50)]
    assert ev["threatsCut"] == 10
    assert all(t["layer"] == "gate" for t in ev["threats"])


def test_refusal_emitters_carry_threats_too():
    s, sink = _sensor(fail_closed=("controls",), extensions=[_Raising()])
    s.scan("a plain request", direction="input")
    ev = _events(s, sink)[0]
    assert ev["threats"] == [{"rule": ev["rules"][0], "category": ev["category"],
                              "score": ev["score"], "layer": "gate"}]


class _Raising(SensorExtension):
    name = "raising"

    def gate(self, req):
        raise RuntimeError("down")


def test_a_cut_list_never_exceeds_fifty_anywhere(rows):
    for _, e in rows:
        assert len(e["threats"]) <= 50
        if len(e["rules"]) > 50:
            assert e["threatsCut"] == len(e["rules"]) - 50
        else:
            assert "threatsCut" not in e


def test_the_autopatch_tool_result_seam_carries_the_same_detail():
    """The framework seams scan a tool's RESULT through ``_scan_tool_result``;
    its events carry the per-rule detail the public ``scan`` carries."""
    shell = _shell()
    s_pub, sink_pub = _sensor()
    s_seam, sink_seam = _sensor()
    for e in shell["benign_prose"]:
        s_pub.scan(e["text"], direction="tool_result")
        s_seam._scan_tool_result(e["text"], tool="web_fetch", arguments={}, raw_result=e["text"])
    pub = [e["threats"] for e in _events(s_pub, sink_pub)]
    seam = [e["threats"] for e in _events(s_seam, sink_seam)]
    assert pub == seam, "the tool-result seam carries a different threats list"
    layers = {t["layer"] for ts in seam for t in ts}
    assert len(layers) >= 2, f"the seam reports one layer for everything: {layers}"


def test_the_mapped_event_carries_threats_as_json():
    from xaidr.schema import to_openA2A

    s, sink = _sensor()
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    cmd = next(e["command"] for e in _shell()["attacks"]
               if probe.scan_tool_call("run_command", {"command": e["command"]}).rules)
    s.scan_tool_call("run_command", {"command": cmd})
    ev = _events(s, sink)[0]
    assert ev["threats"], "precondition: the row carries a rule"
    out = to_openA2A({"type": "scan", "agentId": "threats", "data": ev})
    assert json.loads(out["gen_ai.security.threats"]) == ev["threats"]
    assert "gen_ai.security.threats_cut" not in out
