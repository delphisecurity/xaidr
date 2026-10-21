"""The ASI battery docs must publish the figure the battery actually produces.

THE DEFECT THIS GUARDS AGAINST. A headline table such as

    | rules-only   | 21/120 (18%) | 7/120 |
    | rules + nano | 41/120 (34%) | 18/120 |

in `asi_battery/BOUNDARY_GAP.md`, stated as a present-tense fact with no
"measured at" line and no staleness marker, goes stale the moment a rule
change moves the battery. Building TWO OF THE FIVE DETECTORS THAT DOCUMENT
PROPOSES (G2 and G4) moves the rules-only figure to 43/120; without a check, the
document goes on arguing for work that has already shipped, quoting a number
from before it shipped, with nothing in the tree able to notice.

`asi_battery/RESULTS.md` is open to the identical drift. A "Measured at" line
in one file does not stop the SAME claim going stale in the file next to it:
prose in one file is not a check over both. This is the check.

WHAT IT PINS, AND WHAT IT DELIBERATELY DOES NOT. Only the rules-only catch and
false-positive counts, because those are the two figures reproducible from the
core package alone. The rules+nano figures need the `nano` extra and are
withdrawn rather than restated in both documents; a test cannot assert a number
nobody in this environment can measure, and pretending otherwise is how the
unverifiable claim survives. See `docs/nano.md`.

The assertion runs against the CURRENT figure each document publishes as
current, not against a hardcoded 43 — so it fails when a rule change moves the
battery and the docs stand still, which is the direction drift takes.
"""
from __future__ import annotations

import json
import re
import sys
import warnings
from pathlib import Path

import pytest

pytestmark = pytest.mark.asi_battery  # every test here reads asi_battery/

REPO = Path(__file__).resolve().parent.parent
BATTERY = REPO / "asi_battery"
BOUNDARY_GAP = BATTERY / "BOUNDARY_GAP.md"
RESULTS = BATTERY / "RESULTS.md"

sys.path.insert(0, str(REPO / "scripts"))


class _Null:
    def report(self, batch): pass
    def close(self): pass


@pytest.fixture(scope="module")
def rules_only():
    """The rules-only battery, measured here. 120 attacks + 120 benign, ~0.3s.

    Runs through `scripts/asi_battery_report.py`'s own scan helpers rather than
    a second implementation — a doc gate that measured the battery differently
    from the regenerator would be pinning the docs to a third number.
    """
    import asi_battery_report as rep

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sensor, err = rep._build(enable_nano=False)
    assert sensor is not None, (
        f"the rules-only sensor would not build, so the battery cannot be "
        f"measured and neither document can be checked: {err!r}"
    )

    attacks = rep._load("attacks.jsonl")
    benign = rep._load("benign.jsonl")
    ra = rep._measure(sensor, attacks)
    rb = rep._measure(sensor, benign)
    return {
        "catch": sum(v["detected"] for v in ra.values()), "attacks": len(attacks),
        "fp": sum(v["detected"] for v in rb.values()), "benign": len(benign),
    }


def test_the_battery_pools_are_the_size_the_docs_describe(rules_only):
    """120 and 120. A shrunken pool would move every ratio below silently."""
    assert (rules_only["attacks"], rules_only["benign"]) == (120, 120), (
        f"the battery is {rules_only['attacks']} attacks / "
        f"{rules_only['benign']} benign; both documents say 120/120, and every "
        f"`N/120` figure in them is read as a rate over that denominator"
    )


# `**43/120 (36%)**`, `| rules-only | 43/120 — **36%** |`, `43/120`.
_FIG = re.compile(r"(?<![\d/])(\d{1,3})/120(?![\d])")


def _current_figures(path, marker):
    """The `N/120` figures on the lines a document presents as CURRENT.

    Keyed on an explicit marker string rather than on position, because both
    documents deliberately also contain HISTORICAL `N/120` figures — the
    superseded 21/120 headline, an intermediate 35/120 — and a scan that could not tell
    them apart would either fail forever or have to ignore everything.
    """
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if marker in ln]
    return lines, [int(m.group(1)) for ln in lines for m in _FIG.finditer(ln)]


def test_boundary_gap_publishes_the_rules_only_figure_the_battery_produces(
        rules_only):
    """The banner's "measured today" row must still be true today."""
    marker = "rules-only, measured today"
    lines, figures = _current_figures(BOUNDARY_GAP, marker)
    assert lines, (
        f"{BOUNDARY_GAP.name} has no line containing {marker!r}. That row "
        f"supersedes the stale 21/120 headline; if it was removed or "
        f"reworded, this gate stops constraining the document and the figure "
        f"can go stale again unnoticed."
    )
    assert rules_only["catch"] in figures, (
        f"{BOUNDARY_GAP.name} publishes {figures} as the current rules-only "
        f"catch; the battery measures {rules_only['catch']}/120.\n"
        f"Line: {lines[0].strip()}\n"
        f"Regenerate with `python scripts/asi_battery_report.py`. Left alone, "
        f"this drift keeps a superseded figure published after the detectors "
        f"in this document's own proposal have moved it."
    )
    assert rules_only["fp"] in figures, (
        f"{BOUNDARY_GAP.name}'s current rules-only row publishes {figures}; "
        f"the battery measures {rules_only['fp']}/120 false positives"
    )


def test_results_md_publishes_the_rules_only_figure_the_battery_produces(
        rules_only):
    """The same gate on the sibling document, for the same reason.

    RESULTS.md carries a "Measured at" line; a line is not a check.
    """
    marker = "**rules-only**"
    lines, figures = _current_figures(RESULTS, marker)
    assert lines, (
        f"{RESULTS.name} has no headline row containing {marker!r}; the gate "
        f"below would pass over an empty set"
    )
    assert rules_only["catch"] in figures, (
        f"{RESULTS.name} publishes {figures} as the current rules-only catch; "
        f"the battery measures {rules_only['catch']}/120.\n"
        f"Line: {lines[0].strip()}"
    )
    assert rules_only["fp"] in figures, (
        f"{RESULTS.name}'s headline rules-only row publishes {figures}; the "
        f"battery measures {rules_only['fp']}/120 false positives"
    )


def test_boundary_gap_carries_a_staleness_marker():
    """The marker itself, asserted — without it the figure has no date.

    A figure being right today is not the whole property. If nothing says WHEN
    it was measured, nobody can tell when it has stopped being right. Both halves are required: the version it was written at, and
    the version the current figures were re-measured at.
    """
    text = BOUNDARY_GAP.read_text(encoding="utf-8")
    missing = [s for s in ("STALE", "Measured at", "measured today")
               if s not in text]
    assert not missing, (
        f"{BOUNDARY_GAP.name} is missing {missing}. Without them a figure reads "
        f"as present tense with nothing in the document naming the state it "
        f"was measured in. `asi_battery/RESULTS.md` is the format to follow."
    )


def test_the_last_run_summary_agrees_with_a_fresh_run(rules_only):
    """`asi_battery/last_run.json` is machine-readable and gitignored.

    It is written by the regenerator, so when present it must agree — a stale
    `last_run.json` beside a fresh doc is the same confusion one layer down.
    Absent is fine and common: it is gitignored precisely because it is a run
    output, so a clean clone has none.
    """
    path = BATTERY / "last_run.json"
    if not path.exists():
        pytest.skip("asi_battery/last_run.json not present (gitignored output)")
    data = json.loads(path.read_text(encoding="utf-8"))
    per_cat = data.get("per_category")
    if not per_cat:
        pytest.skip(f"no per_category block in {path.name}: {sorted(data)}")
    recorded = sum(e["rules"]["catch"] for e in per_cat.values())
    assert recorded == rules_only["catch"], (
        f"{path.name} records {recorded} rules-only catches; a fresh run "
        f"measures {rules_only['catch']}. Re-run "
        f"`python scripts/asi_battery_report.py`."
    )
