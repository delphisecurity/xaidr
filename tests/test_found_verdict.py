"""``ScanResult.found_action``: what a block-mode sensor returns, on every result.

A monitor sensor softens a halting verdict to ``flagged`` before the host sees
it. The gateway attestation (1.22.0) carries what the sensor FOUND, before that
softening, so ``found_action`` is captured where the verdict is decided, at the
five softening sites, and never after ``_apply_mode``.

THE TEST IS A DIFFERENTIAL OVER THE COMMITTED CORPORA. A block sensor and a
monitor sensor scan every committed row, and for every row:

    monitor.found_action == block.action        (the definition of found)
    monitor.action       == MONITOR.downgrade(block.action)
                                                (monitor's action did not move)
    block.found_action   == block.action        (block mode is its own found)

The vacuity guard prints how many rows monitor softened, per boundary, and
fails if any boundary with a halting block-mode row softened none: a found
verdict that never differs from the action proves nothing.

found applies the documentary-prose cap, as block mode does (ruling Q6): a tool
argument that QUOTES a command inside a documentary frame is ``flagged`` in block
mode and ``flagged`` in found, never ``blocked``. The attack corpus is out of the
cap's reach by construction (a shell-argument key disables it).

No attack string is written here. Every input is read from a committed file.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace

import pytest

from xaidr import DelphiBlockedError, Sensor, SensorExtension
from xaidr.attestation import CORE_VERDICTS, core_verdict
from xaidr.enforcement import BLOCK, MONITOR
from xaidr.types import ScanResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
BENIGN_TC = os.path.join(ROOT, "benign_toolcalls")
ASI = os.path.join(ROOT, "asi_battery")
BOUNDARIES = ("input", "output", "a2a", "tool_call")


class _Null:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass


def _jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _step(sensor, boundary, step):
    if boundary == "input":
        return sensor.scan(step["text"], direction="input")
    if boundary == "output":
        return sensor.scan_output(step["text"])
    if boundary == "a2a":
        return sensor.scan_a2a(step["text"], destination="peer-agent")
    if boundary == "tool_call":
        return sensor.scan_tool_call(step["tool"], step.get("args") or {})
    raise ValueError(boundary)                      # pragma: no cover


def _rows():
    """(row_id, boundary, scan) for every committed row. ``scan(sensor)`` runs it."""
    with open(SHELL, encoding="utf-8") as fh:
        shell = json.load(fh)
    for i, e in enumerate(shell["attacks"]):
        yield (f"shell.attack/{i:03d}", "tool_call",
               lambda s, c=e["command"]: s.scan_tool_call("run_command", {"command": c}))
    for i, e in enumerate(shell["benign"]):
        yield (f"shell.benign/{i:03d}", "tool_call",
               lambda s, c=e["command"]: s.scan_tool_call("run_command", {"command": c}))
    for e in shell["benign_prose"]:
        yield (f"shell.prose/{e['id']}", "input",
               lambda s, t=e["text"]: s.scan(t, direction="input"))
        # The tool surface of the prose pool is where the documentary cap decides.
        yield (f"shell.prose/{e['id']}#tool", "tool_call",
               lambda s, t=e["text"]: s.scan_tool_call("send_message", {"body": t}))
    for e in shell["benign_templates"]:
        yield (f"shell.template/{e['id']}", "input",
               lambda s, t=e["template"]: s.scan(t, direction="input"))
    for pool, name in (("benign_tc", "corpus.jsonl"),
                       ("benign_disc", "discriminator.jsonl"),
                       ("benign_dml", "sql_dml.jsonl")):
        for e in _jsonl(os.path.join(BENIGN_TC, name)):
            yield (f"{pool}/{e['id']}", "tool_call",
                   lambda s, t=e["tool"], a=e["args"]: s.scan_tool_call(t, a))
    if os.path.isdir(ASI):                          # not in the sdist (conftest)
        for pool, name in (("asi.attacks", "attacks.jsonl"), ("asi.benign", "benign.jsonl")):
            for e in _jsonl(os.path.join(ASI, name)):
                if e["boundary"] == "sequence":
                    for i, st in enumerate(e["steps"]):
                        yield (f"{pool}/{e['id']}#{i}", st["boundary"],
                               lambda s, b=st["boundary"], st=st: _step(s, b, st))
                else:
                    yield (f"{pool}/{e['id']}", e["boundary"],
                           lambda s, b=e["boundary"], e=e: _step(s, b, e))
                    if e["boundary"] == "input":
                        # The same committed text as an OUTBOUND A2A message: the
                        # battery's own a2a rows never reach the block band, and
                        # the a2a path has its own softening site to exercise.
                        yield (f"{pool}/{e['id']}#a2a", "a2a",
                               lambda s, t=e["text"]: s.scan_a2a(t, destination="peer-agent"))


@pytest.fixture(scope="module")
def differential():
    """[(row_id, boundary, block_result, monitor_result)] over every row."""
    block = Sensor(agent_id="found-block", enforcement_mode="block", reporter=_Null())
    monitor = Sensor(agent_id="found-monitor", enforcement_mode="monitor", reporter=_Null())
    out = []
    for row_id, boundary, scan in _rows():
        try:
            b = scan(block)
        except DelphiBlockedError as exc:         # a raised block IS the block verdict
            b = exc.result
        m = scan(monitor)
        out.append((row_id, boundary, b, m))
    assert len(out) > 1000, f"the corpora read {len(out)} rows; expected > 1000"
    return out


def test_monitor_found_equals_block_action(differential):
    """The definition: a monitor sensor's found verdict is block mode's action."""
    refused_hidden = [(r, m.found_action) for r, _, b, m in differential
                      if b.action == "blocked" and m.found_action != "blocked"]
    over_found = [(r, m.found_action) for r, _, b, m in differential
                  if b.action == "flagged" and m.found_action == "blocked"]
    other = [(r, b.action, m.found_action) for r, _, b, m in differential
             if m.found_action != b.action
             and (r, m.found_action) not in refused_hidden
             and (r, m.found_action) not in over_found]
    problems = []
    if refused_hidden:
        problems.append(
            f"monitor sensor records found={refused_hidden[0][1]!r} for "
            f"{len(refused_hidden)} rows that block mode refuses "
            f"(first: {refused_hidden[0][0]})")
    if over_found:
        problems.append(
            f"found='blocked' where block mode returns 'flagged' on {len(over_found)} "
            f"rows (the documentary-prose cap applies to found as to block mode; "
            f"first: {over_found[0][0]})")
    if other:
        problems.append(f"{len(other)} other rows differ (first: {other[0]})")
    assert not problems, "\n".join(problems)


def test_monitor_action_is_the_softened_block_action(differential):
    """Pins today's monitor action: M1 adds a field and moves no verdict."""
    moved = [(r, b.action, m.action) for r, _, b, m in differential
             if m.action != MONITOR.downgrade(b.action)]
    assert not moved, (
        f"{len(moved)} rows: monitor's action is no longer block's action softened "
        f"(first: {moved[0]})")


def test_block_mode_found_is_its_own_action(differential):
    off = [(r, b.action, b.found_action) for r, _, b, _ in differential
           if b.found_action != b.action]
    assert not off, f"{len(off)} block-mode rows carry a found that is not their action: {off[:3]}"


def test_vacuity_guard_monitor_softened_at_least_one_row_per_boundary(differential):
    """A found that never differs from the action proves nothing. Count the rows
    where monitor softened, per boundary, and print them."""
    softened = {b: 0 for b in BOUNDARIES}
    halting = {b: 0 for b in BOUNDARIES}
    for _, boundary, b, m in differential:
        if b.action != m.action:
            softened[boundary] += 1
        if b.action in ("blocked", "approval_required"):
            halting[boundary] += 1
    for boundary in BOUNDARIES:
        print(f"monitor rows softened: {softened[boundary]} ({boundary}, "
              f"{halting[boundary]} halting in block mode)")
    assert all(softened[b] >= 1 for b in BOUNDARIES if halting[b]), softened
    # The three boundaries the corpora exercise with refusals must each show one.
    for boundary in ("input", "tool_call", "a2a"):
        assert softened[boundary] >= 1, (
            f"vacuous: no {boundary} row was softened, so found == action on every "
            f"{boundary} row and this differential tests nothing there")


def test_found_action_is_not_part_of_equality_or_repr():
    a = ScanResult(action="flagged", score=0.9, category="c", rules=["R"], found_action="blocked")
    b = ScanResult(action="flagged", score=0.9, category="c", rules=["R"])
    assert a == b, "found_action takes part in equality; it is telemetry, not identity"
    assert "found_action" not in repr(a)
    assert a.found_action == "blocked" and b.found_action is None


def test_apply_mode_softens_action_and_keeps_found():
    s = Sensor(agent_id="found", enforcement_mode="monitor", reporter=_Null())
    before = ScanResult(action="blocked", score=0.9, found_action="blocked")
    after = s._apply_mode(before)
    assert after.action == "flagged"
    assert after.found_action == "blocked", "_apply_mode rewrote found"


class _SoftenAll(SensorExtension):
    """An S6 transform that returns a fresh allowed result for every verdict."""

    name = "soften-all"

    def transform_verdict(self, req, result):
        return ScanResult(action="allowed", score=0.0, category=None, rules=[])


def test_s6_transform_cannot_erase_found(differential):
    """The host's result carries found through an S6 transform that rebuilt it."""
    soft = Sensor(agent_id="found-soft", enforcement_mode="monitor",
                  reporter=_Null(), extensions=[_SoftenAll()])
    checked = 0
    with open(SHELL, encoding="utf-8") as fh:
        shell = json.load(fh)
    # The first 25 attack rows are enough: this is about the transform, not the corpus.
    for e in shell["attacks"][:25]:
        r = soft.scan_tool_call("run_command", {"command": e["command"]})
        assert r.action == "allowed", "precondition: the transform softened"
        if r.found_action == "blocked":
            checked += 1
    assert checked >= 1, "no attack row reached found='blocked' through the transform"


class _RaisingGate(SensorExtension):
    name = "raising-gate"

    def gate(self, req):
        raise RuntimeError("control plane unreachable")


def test_fail_closed_in_monitor_carries_found_blocked():
    """``controls`` closed: the refusal is softened to flagged in monitor, and
    found keeps the verdict a block sensor would have returned."""
    s = Sensor(agent_id="found-fc", enforcement_mode="monitor", reporter=_Null(),
               fail_closed=("controls",), extensions=[_RaisingGate()])
    r = s.scan("hello there", direction="input")
    assert r.input_status == "fail_closed"
    assert r.action == "flagged"
    assert r.found_action == "blocked", (
        "a monitor sensor's fail-closed refusal lost its found verdict")


def test_blocked_tool_verdict_carries_found():
    from xaidr.autopatch.core import tool_verdict

    s = Sensor(agent_id="found-bt", enforcement_mode="monitor", reporter=_Null(),
               blocked_tools=["rm_rf"])
    r = tool_verdict(s, "rm_rf", {"path": "/tmp/x"})
    assert r is not None and r.action == "blocked"
    assert r.found_action == "blocked"


def test_not_scannable_and_scan_error_results_carry_found_allowed():
    s = Sensor(agent_id="found-ns", enforcement_mode="monitor", reporter=_Null())
    r = s.scan(12345, direction="input")                 # not scannable: fail open
    assert r.input_status == "not_scannable"
    assert r.found_action == "allowed"


@pytest.mark.parametrize("action,verdict", [
    ("allowed", "allowed"), ("flagged", "flagged"), ("approval_required", "held"),
    ("blocked", "blocked"), ("escalated", "flagged"),
])
def test_core_verdict_mapping(action, verdict):
    assert core_verdict(action) == verdict
    assert verdict in CORE_VERDICTS


@pytest.mark.parametrize("bad", [None, "", "quarantine", 1, "BLOCKED"])
def test_core_verdict_unknown_is_none(bad):
    assert core_verdict(bad) is None


def test_replace_carries_found():
    r = ScanResult(action="blocked", score=1.0, found_action="blocked")
    assert replace(r, action="flagged").found_action == "blocked"


# ── the sites the differential's default configuration never reaches ─────────

from xaidr.escalation import Escalator                              # noqa: E402

_APPROVAL_POLICY = {
    "version": "1",
    "defaults": {"effect": "allow", "unclassified": "allow"},
    "rules": [{"id": "needs-approval", "effect": "require_approval",
               "match": {"tools": ["issue_refund"]}}],
}


class _LinkBlocks(Escalator):
    """A second-opinion link that answers by REPLACING the local result's
    action, which carries the local found along with it."""

    name = "link-blocks"

    def scan(self, req, local_result):
        return replace(local_result, action="blocked")


class _EscExt(SensorExtension):
    name = "esc"

    def escalators(self):
        return (_LinkBlocks(),)


def _flag_band_text():
    """A committed row on which a link is consulted: the scanner's verdict is in
    the flag band and no cap put it there."""
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Null(),
                   extensions=[_EscExt()])
    for row_id, boundary, scan in _rows():
        if boundary != "input":
            continue
        r = scan(probe)
        if r.escalation == "applied":
            return row_id
    pytest.skip("no committed input row reaches a link")   # pragma: no cover


def _scan_row(sensor, row_id):
    for rid, _, scan in _rows():
        if rid == row_id:
            return scan(sensor)
    raise KeyError(row_id)                                 # pragma: no cover


def test_an_escalator_links_verdict_is_the_found_verdict():
    """A link has no mode: its verdict is applied in both modes, so it is found.
    Red when found is CARRIED from the local result instead of set from the
    link's action (M1 review)."""
    row_id = _flag_band_text()
    for mode in ("block", "monitor"):
        s = Sensor(agent_id="found-esc", enforcement_mode=mode, reporter=_Null(),
                   extensions=[_EscExt()])
        r = _scan_row(s, row_id)
        assert r.escalation == "applied", "precondition: the link answered"
        assert r.found_action == "blocked", (
            f"{mode}: the link said blocked, found says {r.found_action!r}; a monitor "
            "sensor would attest the stale local verdict for a call the link refused")
        assert r.action == ("blocked" if mode == "block" else "flagged")


def test_bounds_fail_closed_decides_on_found_not_the_softened_action():
    """``fail_closed=("bounds",)``: a verdict that halts in block mode is returned
    untouched there; monitor must not relabel the same verdict as fail_closed
    because it reads the softened action (M1 review)."""
    long_url = "https://h.example/" + "a" * 4_100      # past MAX_URL_CHARS: a bound fault
    res = {}
    for mode in ("block", "monitor"):
        s = Sensor(agent_id="found-bounds", enforcement_mode=mode, reporter=_Null(),
                   fail_closed=("bounds",), blocked_tools=["fetch"])
        res[mode] = s.scan_tool_call("fetch", {"url": long_url})
    assert res["block"].action == "blocked" and res["block"].category == "blocked_tool"
    assert res["monitor"].found_action == "blocked", res["monitor"]
    assert res["monitor"].category == "blocked_tool", (
        "monitor relabelled a verdict block mode returns untouched: "
        f"{res['monitor'].category}")
    assert res["monitor"].action == "flagged"


def test_policy_require_approval_found_is_approval_required():
    res = {}
    for mode in ("block", "monitor"):
        s = Sensor(agent_id="found-policy", enforcement_mode=mode, reporter=_Null())
        assert s.set_policy(_APPROVAL_POLICY) is True
        res[mode] = s.scan_tool_call("issue_refund", {"amount": 10})
    assert res["block"].action == "approval_required"
    assert res["monitor"].action == "flagged"
    assert res["monitor"].found_action == "approval_required"
    assert res["block"].found_action == "approval_required"
    assert core_verdict(res["monitor"].found_action) == "held"


def test_scan_error_result_carries_found_allowed(monkeypatch):
    s = Sensor(agent_id="found-err", enforcement_mode="monitor", reporter=_Null())

    def boom(*a, **k):
        raise RuntimeError("scanner fault")

    monkeypatch.setattr(s._scanner, "scan", boom)
    r = s.scan("hello there", direction="input")
    assert r.input_status == "scan_error"
    assert r.found_action == "allowed"


def test_destination_block_results_carry_found():
    httpx = pytest.importorskip("httpx")
    s = Sensor(agent_id="found-dest", enforcement_mode="monitor", reporter=_Null())
    s.block_urls(["denied.example"])
    client = s.protect_http(httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={}))))
    with pytest.raises(DelphiBlockedError) as exc:
        client.get("https://denied.example/x")
    assert exc.value.result.found_action == "blocked"
