"""The OWASP Agentic Top 10 table and its probe harness must not drift apart.

WHY THIS FILE EXISTS. The previous ASI01-ASI10 mapping was written by hand
against xaidr 1.2.1 and then went stale in place. Nothing re-ran it, so by 1.10.0
it was quietly wrong in three places: the cloud-metadata rule had been rewritten
around address ranges (so the https, hex and decimal spellings that the mapping
recorded as bypasses now block), the descriptive-frame calibration had changed
(so payloads the mapping recorded as dampened to `flagged` now block), and one
intent rule had been recalibrated from block to flag in the other direction. A
published coverage claim that no longer matches what the sensor returns is worse
than no claim at all, and worse specifically for the reader it is aimed at: a
CISO reading ASI01-ASI10 as a procurement checklist.

So the table is not allowed to be prose any more. Three things are pinned:

1. **Every probe still returns what the harness records.** This is the load
   bearing one. A rule change that alters coverage fails here, naming the
   category and the probe, rather than silently making a README row untrue.
2. **The README table and the harness agree** on which categories exist and what
   verdict each one carries. Updating one without the other fails.
3. **The two uncovered categories stay visible.** The table's credibility rests
   on it saying plainly that ASI04 and ASI06 are mostly or entirely uncovered,
   and that ASI10 is out of remit. Quietly upgrading one of those to COVERED
   without the probe evidence changing is the specific failure this guards.

WHAT IS NOT PINNED, deliberately: whether a verdict is the RIGHT reading of its
evidence. That is a judgement, it is re-argued when the evidence moves, and a
test that tried to derive it would be inventing the certainty this whole table
exists to avoid.
"""

from __future__ import annotations

import os
import re
import types

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "owasp_agentic_probe.py")
README = os.path.join(REPO_ROOT, "README.md")


def _load_harness():
    """Load scripts/owasp_agentic_probe.py, from SOURCE, every time.

    It lives in scripts/ rather than in the package (it is a maintenance tool,
    not shipped in the wheel), so it is loaded by path rather than imported.

    The source is read and compiled here rather than going through
    ``spec.loader.exec_module``, and that is not stylistic. The normal loader
    writes and then trusts ``scripts/__pycache__/*.pyc``, keyed on the source's
    mtime and size. Editing this harness and running the test inside the same
    second can leave both unchanged, at which point the loader serves the
    PREVIOUS bytecode and the test reports on code that is no longer on disk.
    Observed while checking that this test can fail: a reverted edit kept
    failing because the .pyc still held it. A guard against stale claims that
    can itself read a stale file is not a guard.
    """
    with open(SCRIPT, encoding="utf-8") as fh:
        source = fh.read()
    module = types.ModuleType("owasp_agentic_probe")
    module.__file__ = SCRIPT
    exec(compile(source, SCRIPT, "exec"), module.__dict__)
    return module


@pytest.fixture(scope="module")
def harness():
    return _load_harness()


@pytest.fixture(scope="module")
def readme_rows():
    """The (id, verdict) pairs parsed out of the README's ASI table."""
    with open(README, encoding="utf-8") as fh:
        text = fh.read()
    start = text.index("## OWASP Agentic Top 10")
    end = text.index("\n## ", start + 10)
    section = text[start:end]
    rows = re.findall(
        r"^\|\s*\*\*(ASI\d\d)\*\*[^|]*\|\s*([A-Z][A-Z ]+?)\s*\|", section, re.M
    )
    return section, [(rid, verdict.strip()) for rid, verdict in rows]


# ── 1. the evidence ──────────────────────────────────────────────────────────


def test_every_probe_still_returns_what_the_table_claims(harness):
    """HARD GATE. The mechanical half of the mapping.

    A failure here means a rule change moved a coverage boundary. That is not
    necessarily a bug -- it may be an improvement -- but the verdict above it
    must be re-read by a human and the README updated in the same change.
    """
    rows, drifted = harness.run_all()
    assert rows, "the harness ran no probes at all"
    assert not drifted, (
        f"{len(drifted)} probe(s) no longer return what the mapping records:\n"
        + "\n".join(
            f"  {cid}  {label}: recorded {was!r}, got {now!r}"
            for cid, label, was, now in drifted
        )
        + "\n\nRe-read the affected verdict, then update BOTH "
        "scripts/owasp_agentic_probe.py and the README table."
    )


def test_every_category_carries_probes_and_a_legal_verdict(harness):
    ids = [c["id"] for c in harness.CATEGORIES]
    assert ids == [f"ASI{n:02d}" for n in range(1, 11)], ids
    for cat in harness.CATEGORIES:
        assert cat["probes"], f"{cat['id']} has no probes, so its verdict rests on nothing"
        assert cat["verdict"] in harness.VERDICTS, (cat["id"], cat["verdict"])


def test_a_covered_category_has_no_gap_probe_returning_allowed(harness):
    """COVERED must not be claimed over a probe the harness itself records as a gap.

    The gap probes are labelled `GAP `. A category can be COVERED and still have
    a gap probe (ASI01 has three), so this is not a ban -- it asserts the weaker,
    real property: a COVERED verdict must rest on at least as many blocking
    probes as gap probes, so it cannot be carried by a single lucky hit.
    """
    for cat in harness.CATEGORIES:
        if cat["verdict"] != "COVERED":
            continue
        gaps = [p for p in cat["probes"] if p.label.startswith("GAP ")]
        hits = [p for p in cat["probes"] if p.expect in ("blocked", "approval_required")]
        assert len(hits) > len(gaps), (
            f"{cat['id']} is marked COVERED with {len(hits)} enforcing probe(s) "
            f"and {len(gaps)} recorded gap(s); that is not a covered category"
        )


def test_an_uncovered_category_records_why_not_just_that(harness):
    """A bare NOT COVERED is a shrug. Each one must carry a reason on a probe."""
    for cat in harness.CATEGORIES:
        if cat["verdict"] not in ("NOT COVERED", "MOSTLY NOT COVERED", "OUT OF REMIT"):
            continue
        assert any(p.note for p in cat["probes"]), (
            f"{cat['id']} is {cat['verdict']} but no probe explains why"
        )


# ── 2. the table and the harness agree ───────────────────────────────────────


def test_the_readme_table_matches_the_harness(harness, readme_rows):
    _, rows = readme_rows
    assert rows, "no ASI rows parsed out of the README; the table shape changed"
    from_readme = dict(rows)
    from_harness = {c["id"]: c["verdict"] for c in harness.CATEGORIES}
    assert from_readme == from_harness, (
        "the README table and scripts/owasp_agentic_probe.py disagree.\n"
        f"  README:  {from_readme}\n"
        f"  harness: {from_harness}\n"
        "Update both in the same change."
    )


#: Ways a row is allowed to state its limit. Spelled out rather than matched
#: loosely, because "the row contains the word not" would pass on almost any
#: prose and this test would then assert nothing.
_LIMIT_MARKERS = (
    "Not covered",
    "not covered",
    "There is no",
    "there is no",
    "not a gap",
    "out of remit",
)


def test_the_readme_states_what_is_not_covered_in_every_row(readme_rows):
    """Rule (b) of the table: a row that only lists strengths is the thing this
    table exists to avoid. Every row must say what it does NOT cover."""
    section, rows = readme_rows
    seen = 0
    for line in section.splitlines():
        match = re.match(r"^\|\s*\*\*(ASI\d\d)\*\*", line)
        if not match:
            continue
        seen += 1
        assert any(marker in line for marker in _LIMIT_MARKERS), (
            f"{match.group(1)}'s row does not say what it fails to cover; "
            f"it must contain one of {_LIMIT_MARKERS}"
        )
    assert seen == 10, f"parsed {seen} ASI rows, expected 10"


def test_the_table_carries_no_percentages(readme_rows):
    """Rule (e): this is a coverage table, not a detection claim."""
    section, _ = readme_rows
    found = re.findall(r"\d+(?:\.\d+)?\s*%", section)
    assert not found, f"the ASI table quotes a percentage: {found}"


def test_the_table_uses_no_em_dashes(readme_rows):
    """Rule (f), pinned so a later edit in the surrounding house style does not
    quietly reintroduce them into this section only."""
    section, _ = readme_rows
    assert "—" not in section, "the ASI table contains an em-dash"


# ── 3. the uncovered categories stay visible ─────────────────────────────────


def test_the_two_uncovered_categories_are_still_named_as_such(harness, readme_rows):
    """The table's credibility rests on this, so it is a test and not a habit.

    If a future change genuinely closes ASI04 or ASI06, this fails, and closing
    it deliberately means editing this test with the probe evidence in hand.
    """
    verdicts = {c["id"]: c["verdict"] for c in harness.CATEGORIES}
    assert verdicts["ASI04"] == "MOSTLY NOT COVERED", (
        "ASI04 changed verdict. There is still no discovery boundary unless "
        "scan_tool_call grew a tool-definition argument; check before accepting."
    )
    assert verdicts["ASI06"] == "NOT COVERED", (
        "ASI06 changed verdict. There is still no memory or retrieval boundary "
        "unless a new scan entry point was added; check before accepting."
    )
    assert verdicts["ASI10"] == "OUT OF REMIT", (
        "ASI10 changed verdict. Drift detection still needs cross-session state "
        "that an in-process sensor does not have; check before accepting."
    )
    # Whitespace-normalised: the sentence is wrapped in the source, so a literal
    # substring match would depend on where the line break happens to fall.
    section, _ = readme_rows
    flat = " ".join(section.split())
    assert "Two categories are mostly or entirely uncovered" in flat


def test_the_opening_line_still_makes_the_rule_name_point(readme_rows):
    """The line that stops the table being read as a rule inventory."""
    section, _ = readme_rows
    assert "not coverage of it" in section
    assert "what a probe actually returns" in section


# ── the structural reasons, quoted where a reader will look for them ─────────


@pytest.mark.parametrize(
    "asi,needle",
    [
        ("ASI04", "no discovery boundary"),
        ("ASI04", "scan_tool_call(name, arguments, mcp_server)"),
        ("ASI06", "no memory boundary and no retrieval boundary"),
        ("ASI10", "cross-session state"),
        ("ASI03", "telemetry only until configured"),
        ("ASI08", "opt-in"),
    ],
)
def test_the_structural_reason_is_stated(readme_rows, asi, needle):
    """Rule (c) and (d): say why, structurally, and say where it depends on config."""
    section, _ = readme_rows
    row = next(ln for ln in section.splitlines() if ln.startswith(f"| **{asi}**"))
    assert needle in row, f"{asi}'s row no longer states: {needle!r}"
