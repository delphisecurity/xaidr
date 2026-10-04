"""C-11 — RECORD mode never changes an action. A2's FIRST gate (BRIEF), built
before any seam is wired, so every later wiring milestone is measured against it.

WHY NOT JUST tests/test_seam_zero_movement.py. That oracle digests 456 rows of
``scan(direction="input")`` and nothing else, so it can never see a change to
``scan_tool_call``, where value origin acts, or to ``url_parse``, which only the
tool path reads (ARCHITECTURE.md F4). It also compares a bare sensor with one
carrying a no-op extension, both under the DEFAULT mode, so a regression that
RECORD itself causes moves both digests equally and stays green. This gate
compares OFF with RECORD, over five passes (``tests/outside/drivers/c11_oracle.py``
says what each one does) and both enforcement modes.

WHAT IS VACUOUS NOW, said by the gate rather than hidden. Before any seam is
wired, RECORD ≡ OFF holds trivially on tool calls. The assertions that prove
the gate COULD see a difference are strict xfails and flip when the milestone
that makes them true lands:

  4a-I   RECORD produces untrusted_source on input-derived calls     at M6 (input recording)
  4a-R   RECORD produces untrusted_source on result-derived calls    at M7 (result recording)
  4b     ENFORCE moves an action that OFF and RECORD do not          at M8 (ENFORCE)

The cross-commit half (§3.2 item 3: OFF at HEAD == the pre-A2 sensor) runs the
same module as a driver against wheels built from base and HEAD, outside the
process. CI checks out with depth 1, so that half is milestone evidence in
PROGRESS.md, not a CI test.
"""
from __future__ import annotations

import collections
import importlib.util
import logging
import os

import pytest

import xaidr
from xaidr import Sensor
from xaidr.value_origin import MatchKind, SourceDesignation

_spec = importlib.util.spec_from_file_location(
    "c11_oracle", os.path.join(os.path.dirname(__file__), "outside", "drivers", "c11_oracle.py"))
oracle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oracle)

TEXTS = oracle.corpus_texts()
PASSES = ("P-input", "P-flow-I", "P-flow-R", "P-seam", "P-fault")
FLOW_PASSES = ("P-flow-I", "P-flow-R", "P-seam")


@pytest.fixture(scope="module")
def runs():
    cache = {}

    def get(mode, enforcement):
        if (mode, enforcement) not in cache:
            cache[(mode, enforcement)] = oracle.run_passes(xaidr, mode, enforcement, TEXTS)
        return cache[(mode, enforcement)]
    return get


def _first_differences(a, b, n=3):
    return [f"OFF={x!r} RECORD={y!r}" for x, y in zip(a, b) if x != y][:n]


# ── the constructor: validated loudly, inert until the seams land ───────────

def test_value_origin_is_validated_loudly_at_construction():
    with pytest.raises(ValueError, match="enforec"):
        Sensor(agent_id="c11", value_origin="enforec")
    with pytest.raises(ValueError, match=r"designations\[0\]"):
        Sensor(agent_id="c11", value_origin_sources=["not a designation"])
    Sensor(agent_id="c11", value_origin="off")
    Sensor(agent_id="c11", value_origin="record", value_origin_sources=[
        SourceDesignation(tool="order_lookup", match=MatchKind.ANY, label="orders")])


_ORDERS = SourceDesignation(tool="order_lookup", match=MatchKind.ANY, label="orders")


@pytest.mark.parametrize("kwargs,want", [
    ({}, 0), ({"value_origin": "off"}, 0), ({"value_origin": "record"}, 0),
    ({"value_origin": "enforce"}, 1),
    ({"value_origin": "enforce", "value_origin_sources": [_ORDERS]}, 1),
])
def test_construction_warns_only_for_enforce_and_says_what_is_true(caplog, kwargs, want):
    """ENFORCE logs exactly ONE warning, and nothing else logs any. A warning
    on every default construction would be a regression for every existing
    user (the M1 review showed the first version of this test could not catch
    one). The text says what is TRUE: value origin is not yet wired, so
    'enforce' changes no action today (a silently inert setting is the defect
    the owner overrode Q6 to prevent); and, with no designations, once it
    enforces every destination a tool result names is blocked (C-11)."""
    with caplog.at_level(logging.WARNING, logger="xaidr.sensor"):
        Sensor(agent_id="c11", **kwargs)
    hits = [r.getMessage() for r in caplog.records if "value_origin" in r.getMessage()]
    assert len(hits) == want, hits
    if want:
        # A2 M8 wired ENFORCE: the "NOT YET WIRED" clause is gone, the warning says it blocks
        assert "ENFORCES" in hits[0] and "blocked" in hits[0] and "NOT YET WIRED" not in hits[0], hits[0]
        assert ("designation" in hits[0]) is not bool(kwargs.get("value_origin_sources"))


# ── 1 · the denominator, and every fault path actually reached ──────────────

def test_the_corpus_and_the_calls_are_the_size_this_gate_claims(runs):
    """A gate over an empty set passes vacuously."""
    assert len(TEXTS) == 456
    calls = collections.Counter(tool for _, _, t in TEXTS for tool, _ in oracle.calls_for(t))
    # Measured from calls_for() on this corpus (2026-10-03), pinned exactly so a
    # change to the corpus or to the stdlib extractor is a visible re-count. An
    # earlier floor of 39, written from a scratch script, was wrong: 38.
    assert calls == {"run_command": 456, "http_post": 36, "send_email": 2}, calls


@pytest.mark.parametrize("enforcement", oracle.ENFORCEMENT)
def test_every_fault_path_was_reached(runs, enforcement):
    got = oracle.markers(runs("record", enforcement)["P-fault"][1])
    want = {"gate": 456, "scan_error": 456, "not_scannable": 456}
    if enforcement == "block":
        want["circuit"] = 456                     # an open circuit gates in block mode only
    assert {p: got[p] for p in want} == want, got
    assert got["bounds"] >= 1, got                # only rows that do not already halt


def test_p_input_is_the_existing_456_row_oracle_byte_for_byte(runs):
    """P-input IS the oracle C-11 names, computed by that oracle's OWN function
    (tests/test_seam_zero_movement.py::_digest), not by a copy of it that
    could drift (the M1 review)."""
    spec = importlib.util.spec_from_file_location(
        "zero_movement", os.path.join(os.path.dirname(__file__), "test_seam_zero_movement.py"))
    zero = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(zero)
    existing, n = zero._digest(())
    assert n == 456
    assert runs("record", "block")["P-input"][0] == existing


# ── 2 · C-11 proper ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("enforcement", oracle.ENFORCEMENT)
@pytest.mark.parametrize("p", PASSES)
def test_record_moves_no_verdict_score_or_rule(runs, p, enforcement):
    off, rec = runs("off", enforcement)[p], runs("record", enforcement)[p]
    assert rec[0] == off[0], (
        f"C-11: RECORD moved a verdict, score or rule in {p} ({enforcement} mode) — "
        f"RECORD must never change an action. {_first_differences(off[1], rec[1])}")


# ── 4 · non-vacuity: strict xfails until the milestone that makes them true ─

# Strict xfail until M6 (the red is in PROGRESS.md). K_I = 26, measured at M6 on
# the 456-row corpus: the flagged attack inputs (V-9) whose destinations the
# calls built from them then name.
K_I = 26


def test_4a_I_record_reports_untrusted_source_on_input_derived_calls(runs):
    wires = runs("record", "block")["P-flow-I"][2]
    assert wires.count("untrusted_source") >= K_I, collections.Counter(wires)


# One assertion PER PASS (the M1 review): the public scan(direction=
# "tool_result") records by itself at M7, so a pooled count would flip on
# P-flow-R alone and prove nothing about the protect_tools seam.
# Strict xfails until M7 (their unexpected passes are in PROGRESS.md). K_R measured
# at M7 on the 456-row corpus, PER PASS: P-flow-R through the public
# scan(direction="tool_result") seam (V-26), P-seam through protect_tools' result
# position, which C-11 could not check from M1 until M7 built it.
K_R = {"P-flow-R": 37, "P-seam": 37}


@pytest.mark.parametrize("p", ("P-flow-R", "P-seam"))
def test_4a_R_record_reports_untrusted_source_on_result_derived_calls(runs, p):
    wires = runs("record", "block")[p][2]
    assert wires.count("untrusted_source") >= K_R[p], collections.Counter(wires)


# Strict xfail until M8 (its unexpected pass is in PROGRESS.md): the discriminating
# case, proving the instrument sees the axis RECORD must not move.
@pytest.mark.parametrize("p", FLOW_PASSES)
def test_4b_enforce_moves_an_action_that_off_and_record_do_not(runs, p):
    assert runs("enforce", "block")[p][0] != runs("off", "block")[p][0]


# ── §3.3 · the adversarial re-run: corpora this gate was NOT built on ───────

@pytest.fixture(scope="module")
def adversarial():
    cache = {}

    def get(mode, enforcement):
        if (mode, enforcement) not in cache:
            cache[(mode, enforcement)] = oracle.run_adversarial(xaidr, mode, enforcement)
        return cache[(mode, enforcement)]
    return get


def test_the_adversarial_corpora_are_the_size_this_gate_claims():
    # Measured 2026-10-03 and pinned exactly. asi_battery holds THREE row shapes
    # per file: 64 text, 30 tool-call and 26 multi-turn (`steps`), so every one
    # of its 240 rows is driven by exactly one pass. (An earlier count, 56
    # tool-call rows per file, was the number of rows WITHOUT `text`, not the
    # number WITH `tool`.)
    assert len(oracle.adversarial_texts()) == 228          # heldout 100 + asi_battery text 128
    assert len(oracle.adversarial_calls()) == 470          # benign_toolcalls 410 + asi_battery tool 60
    steps = oracle.adversarial_steps()
    assert len(steps) == 52 and sum(len(st) for _, _, st in steps) == 105


@pytest.mark.parametrize("enforcement", oracle.ENFORCEMENT)
@pytest.mark.parametrize("p", ("A-flow-I", "A-flow-R", "A-calls", "A-steps"))
def test_record_moves_no_action_on_the_adversarial_corpora(adversarial, p, enforcement):
    off, rec = adversarial("off", enforcement)[p], adversarial("record", enforcement)[p]
    assert rec[0] == off[0], (
        f"C-11 on a corpus the gate was not built on: RECORD moved an action in {p} "
        f"({enforcement} mode). {_first_differences(off[1], rec[1])}")
