"""BENCHMARKS.md states the shell-corpus split, and the split is derived.

The detection denominator is every attack in tests/fixtures/shell_corpus.json
minus the entries marked ``detection_intent: INTENDED``. BENCHMARKS.md states
that exclusion count in prose, twice in the detection section and once where it
points the reader to the README. A typed count drifts when the corpus moves, so
each mention is compared with the fixture here, and the published denominator
must equal attacks minus exclusions.

`tests/test_audit_sep05_bypasses.py` pins the same count in README.md and
docs/; this file covers BENCHMARKS.md, which that gate does not read.
"""

from __future__ import annotations

import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _corpus():
    with open(os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json"),
              encoding="utf-8") as fh:
        return json.load(fh)


def _benchmarks() -> str:
    with open(os.path.join(ROOT, "BENCHMARKS.md"), encoding="utf-8") as fh:
        return " ".join(fh.read().split())


def _live_split():
    attacks = _corpus()["attacks"]
    intended = sum(1 for e in attacks if e.get("detection_intent") == "INTENDED")
    return len(attacks), intended


def test_every_stated_exclusion_count_is_the_live_one():
    total, intended = _live_split()
    text = _benchmarks()
    stated = [int(n) for n in re.findall(
        r"\b(\d+) (?:entries marked `detection_intent: INTENDED`|attacks are "
        r"excluded|carries its reason)", text)]
    stated += [int(n) for n in re.findall(r"Every one of those (\d+)", text)]
    assert stated, (
        "no exclusion count found in BENCHMARKS.md; if the wording changed, "
        "update the patterns here so the count stays checked")
    wrong = sorted({n for n in stated if n != intended})
    assert not wrong, (
        f"BENCHMARKS.md states {wrong} attacks excluded as INTENDED, but the "
        f"corpus marks {intended} of {total}. A reader computing the "
        f"denominator from the stated count gets {total - wrong[0]}, not "
        f"{total - intended}.")


def test_the_published_denominator_is_attacks_minus_exclusions():
    total, intended = _live_split()
    text = _benchmarks()
    assert f"of {total - intended}" in text, (
        f"BENCHMARKS.md does not state the detection denominator "
        f"{total - intended} (= {total} attacks - {intended} INTENDED)")
