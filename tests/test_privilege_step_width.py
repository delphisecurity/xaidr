"""The README's "14 of the battery's 48 tool-call steps" must be true.

The ASI03 row of README.md's OWASP Agentic Top 10 table publishes:

    it fires on **14 of the battery's 48 tool-call steps** (30 whole
    `tool_call` cases plus the 18 tool-call steps inside `sequence` cases)

Four figures: 14, 48, 30 and 18. Until `scripts/privilege_step_report.py` none
of them had a regenerator, and no other instrument in the tree could produce
them. `scripts/asi_battery_report.py` measures whole CASES and stops a sequence
at its first detection, so it cannot see a tool-call step that sits after the
catching step, nor one inside a case some other rule already caught. The ratio
was therefore unrecomputable, which is what U-1 forbids — and it is the shape
this branch fixed four times over.

THE DIRECTION THIS TEST RUNS IN MATTERS, and it is the same device
`tests/test_policy_width.py` uses for the policy table: the numbers are PARSED
OUT OF THE README and compared to a live measurement rather than hardcoded here.
So it fails in both directions:

  * a detector narrowing that moves the count and leaves the README alone -> red
  * a README edit that changes the count with no re-measurement           -> red

The second is the one that gets skipped, and the second is the one F7 made
likely: F7 narrowed four predicates in this exact detector. The claim survived
it, which is a fact worth having a check behind rather than a sentence.

THE DENOMINATOR IS ALSO PINNED, separately from the ratio. 30 + 18 = 48 is
asserted against the battery file itself, because a denominator that silently
became "the steps we expected to fire on" would turn a 14/48 reach claim into a
14/14 tautology while every number in the sentence still looked plausible.

AND IT IS PINNED AS RELABEL-INVARIANT. F9 moved 28 cases between categories
without touching a single `tool` or `args`, so a whole-battery step count cannot
move under a relabelling. The README says as much in prose; the last test here
is that sentence made checkable.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
ATTACKS = REPO / "asi_battery" / "attacks.jsonl"

sys.path.insert(0, str(REPO / "scripts"))


@pytest.fixture(scope="module")
def measured():
    import privilege_step_report
    return privilege_step_report.measure()


#: `**14 of the battery's 48 tool-call steps** (30 whole `tool_call` cases plus
#: the 18 tool-call steps inside `sequence` cases)`. The bolding is optional so
#: an editor dropping the asterisks does not silently disarm the gate.
_CLAIM = re.compile(
    r"fires on \*{0,2}(?P<fired>\d+) of the battery's (?P<total>\d+) "
    r"tool-call steps\*{0,2}\s*\((?P<whole>\d+) whole `tool_call` cases plus "
    r"the (?P<seq>\d+) tool-call steps inside `sequence` cases\)"
)


@pytest.fixture(scope="module")
def claim():
    m = _CLAIM.search(README.read_text(encoding="utf-8"))
    assert m is not None, (
        "README.md no longer contains the privilege-action step claim in the "
        "form this gate reads ('fires on N of the battery's M tool-call steps "
        "(X whole `tool_call` cases plus the Y tool-call steps inside "
        "`sequence` cases)'). If the sentence was reworded, reword this regex "
        "with it — otherwise the gate stops constraining the README and the "
        "figure can go stale exactly as the policy table and BOUNDARY_GAP's "
        "21/120 both did."
    )
    return {k: int(v) for k, v in m.groupdict().items()}


def test_the_readme_publishes_the_reach_the_detector_actually_has(claim, measured):
    """14. The figure itself, against a live run of the detector."""
    assert claim["fired"] == measured["fired"], (
        f"README.md says the privilege-action detector fires on "
        f"{claim['fired']} of the battery's tool-call steps; "
        f"scripts/privilege_step_report.py measures {measured['fired']}.\n"
        f"Regenerate with `python scripts/privilege_step_report.py`. A reach "
        f"claim that overstates what the detector reaches is a coverage claim "
        f"the detector is not performing."
    )


def test_the_readme_publishes_the_denominator_the_battery_actually_has(
        claim, measured):
    """48, and the 30 + 18 it is made of — each against the battery file.

    Pinned as three numbers rather than one, because a total that stayed 48
    while its halves drifted in opposite directions would be a denominator
    nobody could reproduce standing in for one that was measured.
    """
    assert claim["total"] == measured["total_steps"], (
        f"README.md says the battery has {claim['total']} tool-call steps; "
        f"asi_battery/attacks.jsonl has {measured['total_steps']}"
    )
    assert (claim["whole"], claim["seq"]) == (
        measured["from_whole_cases"], measured["from_sequences"]), (
        f"README.md breaks the denominator down as {claim['whole']} whole "
        f"`tool_call` cases + {claim['seq']} steps inside sequences; the "
        f"battery has {measured['from_whole_cases']} + "
        f"{measured['from_sequences']}"
    )
    assert claim["whole"] + claim["seq"] == claim["total"], (
        f"README.md's own arithmetic does not close: {claim['whole']} + "
        f"{claim['seq']} != {claim['total']}"
    )


def test_the_denominator_is_every_tool_call_step_not_the_firing_ones(measured):
    """The reach claim must stay a reach claim.

    If the denominator ever becomes the set of steps the detector fires on, the
    ratio reads as rigour and measures nothing — it would be 14/14 forever, and
    would go on looking like a measurement. The README's own sentence says the
    detector "is not aimed at the other 34"; this is that sentence checked.
    """
    assert measured["missed"] > 0, (
        "every tool-call step in the battery fires the privilege-action "
        "detector, so '14 of 48' has stopped distinguishing anything. Either "
        "the detector has widened enormously or the step enumeration has "
        "narrowed to the firing set."
    )
    assert measured["fired"] + measured["missed"] == measured["total_steps"]


def test_the_step_count_does_not_depend_on_the_category_labels(measured):
    """F9 relabelled 28 cases and moved no `tool` and no `args`.

    So this figure is invariant under the relabelling, and the README says so.
    Re-deriving the total from the per-category breakdown is the cheap check
    that nothing here is secretly keyed on a category name — the failure that
    broke `test_f7_domain_generality.py` with `KeyError: 'ASI04-A02'` when the
    two branches first met.
    """
    from_categories = sum(v["steps"] for v in measured["per_category"].values())
    assert from_categories == measured["total_steps"], (
        f"the per-category step counts sum to {from_categories} but the "
        f"battery has {measured['total_steps']} tool-call steps — a category "
        f"is being dropped or double-counted"
    )
    fired_from_categories = sum(
        v["fired"] for v in measured["per_category"].values())
    assert fired_from_categories == measured["fired"]


def test_every_firing_step_names_a_privilege_action_rule(measured):
    """A step counted as 'fired' must carry a rule from this detector.

    Otherwise the count could be inflated by a finding from somewhere else and
    still add up.
    """
    assert measured["fired_steps"], "no firing steps recorded at all"
    for s in measured["fired_steps"]:
        assert s["rules"], f"{s['case']} counted as fired with no rule named"
        assert all(r.startswith("ASI03_") for r in s["rules"]), (
            f"{s['case']} fired {s['rules']}, which is not a privilege-action "
            f"rule; this count would then not be about this detector"
        )


def test_the_battery_file_backs_the_step_enumeration():
    """The enumeration, re-derived here from the raw file.

    Two independent enumerations that must agree — the same device
    `test_install_hints.py` uses for its package walk and `test_sdist_contents`
    for its pattern list. If `tool_call_steps()` ever grows a filter, this
    disagrees with it.
    """
    import privilege_step_report
    cases = [json.loads(l) for l in ATTACKS.read_text(
        encoding="utf-8").splitlines() if l.strip()]
    whole = sum(1 for c in cases if c["boundary"] == "tool_call")
    inside = sum(
        1 for c in cases if c["boundary"] == "sequence"
        for st in (c.get("steps") or []) if st.get("boundary") == "tool_call"
    )
    steps = privilege_step_report.tool_call_steps(cases)
    assert (whole, inside, whole + inside) == (
        sum(1 for s in steps if s["origin"] == "case"),
        sum(1 for s in steps if s["origin"] == "sequence"),
        len(steps),
    ), (
        f"an independent walk of {ATTACKS.name} finds {whole} whole tool_call "
        f"cases and {inside} tool-call steps inside sequences; "
        f"privilege_step_report.tool_call_steps() returns {len(steps)} steps"
    )
