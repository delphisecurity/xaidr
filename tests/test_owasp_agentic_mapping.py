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

WHAT F9 ADDED, and why it was not here before. The three sections above pin the
probe, the table and the verdicts. They never pinned what a CATEGORY MEANS, and
they never read `asi_battery/` at all. So when the held-out battery took its
category definitions from this repo's rule labels instead of from OWASP, and two
of those labels named the wrong risk, every test in this file stayed green: the
battery was outside its universe, and a title is not a verdict. The battery
published a 75% catch rate for "ASI04" measured entirely on resource-exhaustion
cases, while official ASI04 is Agentic Supply Chain. Section 4 closes that: the
official titles are pinned from the published source, the battery's own
definition table must quote them, every category the battery data carries must
be declared, and the case counts published in prose must equal the case counts
in the files. Section 4 still cannot check whether a CASE tests its category --
that is the same judgement the paragraph above declines to encode -- but it can
and does check that the DEFINITION a case was written against is the framework's
and not ours.
"""

from __future__ import annotations

import json
import os
import re
import types

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "owasp_agentic_probe.py")
README = os.path.join(REPO_ROOT, "README.md")
BATTERY = os.path.join(REPO_ROOT, "asi_battery")
BATTERY_README = os.path.join(BATTERY, "README.md")
BATTERY_RESULTS = os.path.join(BATTERY, "RESULTS.md")

#: The official OWASP Top 10 for Agentic Applications (2026), read from the
#: OWASP GenAI Security Project's own publication on 2026-09-15:
#:
#:   https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
#:   https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-
#:     the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
#:
#: This is the source of truth for what a category IS. It is not derived from
#: `xaidr/rules/*.json`, from the probe, or from either README -- deriving it
#: from any of those is precisely the mistake (F9) this constant exists to stop.
#: `&` is written `and` here; comparison normalises the two.
OFFICIAL_TITLES = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

#: Labels the battery is allowed to carry that are NOT OWASP categories. Each
#: one must be declared as such in `asi_battery/README.md`; the test below is
#: what makes the declaration mandatory rather than customary. An undeclared
#: label is how a category of our own invention gets read as a framework row.
NON_OWASP_BATTERY_LABELS = {"EXH"}


def _norm(title: str) -> str:
    """Compare titles on meaning, not punctuation: `&` is `and`, case is free."""
    return re.sub(r"\s+", " ", title.replace("&", "and")).strip().casefold()


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


# ── 4. the categories mean what OWASP says they mean (finding F9) ────────────


@pytest.fixture(scope="module")
def battery_cases():
    """Every attack and benign case, as (kind, list-of-dicts)."""
    out = {}
    for kind in ("attacks", "benign"):
        rows = []
        with open(os.path.join(BATTERY, f"{kind}.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        out[kind] = rows
    return out


@pytest.fixture(scope="module")
def battery_readme():
    with open(BATTERY_README, encoding="utf-8") as fh:
        return fh.read()


def _section(text, heading):
    """The text under one `##` heading, up to the next one.

    Tables are parsed per section rather than per file. `asi_battery/README.md`
    holds three tables whose first column is an ASI id -- definitions, counts,
    and the F9 case-id map -- and a file-wide regex reads whichever it reaches
    first. That is how the definition check first "passed" against the count
    table and reported ASI01 as being defined as `12`.

    A missing heading raises with the heading named. `str.index` would raise
    `ValueError: substring not found`, which tells a reader neither which file
    nor which section, and a guard whose failure message identifies nothing is
    most of the way to being no guard.
    """
    start = text.find(heading)
    if start == -1:
        raise AssertionError(
            f"asi_battery/README.md has no {heading!r} section, so the table "
            "this test reads does not exist. The battery's category "
            "definitions and its per-category case counts are published in "
            "those two sections and pinned from them; deleting one puts the "
            "labels or the denominators back to unchecked, which is the state "
            "finding F9 found them in."
        )
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end == -1 else text[start:end]


def test_the_probe_titles_are_the_official_owasp_titles(harness):
    """The probe names each category. Those names must be OWASP's.

    A shortened rendering is allowed ("Agentic Supply Chain" for "Agentic Supply
    Chain Vulnerabilities") because the table has a width budget; a DIFFERENT
    risk is not. Prefix-matching is the line between the two.
    """
    for cat in harness.CATEGORIES:
        official = OFFICIAL_TITLES[cat["id"]]
        assert _norm(official).startswith(_norm(cat["name"])), (
            f"{cat['id']} is titled {cat['name']!r} in the probe, but the "
            f"official OWASP title is {official!r}. A category titled after "
            "something else measures something else."
        )


def test_the_readme_table_titles_are_the_official_owasp_titles(readme_rows):
    section, _ = readme_rows
    seen = set()
    for line in section.splitlines():
        match = re.match(r"^\|\s*\*\*(ASI\d\d)\*\*\s*([^|]*?)\s*\|", line)
        if not match:
            continue
        asi, title = match.group(1), match.group(2)
        seen.add(asi)
        official = OFFICIAL_TITLES[asi]
        assert _norm(official).startswith(_norm(title)), (
            f"the README table titles {asi} {title!r}; OWASP calls it "
            f"{official!r}"
        )
    assert seen == set(OFFICIAL_TITLES), sorted(seen)


def test_the_battery_quotes_the_official_definitions(battery_readme):
    """THE ONE THAT WOULD HAVE CAUGHT F9.

    `asi_battery/README.md` carries the table of category definitions the cases
    were written against. Before F9 that table was derived from this repo's rule
    labels and read, for ASI04, "resource overload / denial-of-service /
    denial-of-wallet" -- a real phenomenon, but not the risk OWASP numbers
    ASI04, and twelve cases were written to it. Nothing in this file looked at
    that table, so nothing failed.

    What is checked is the DEFINITION, not the cases. Whether a case tests its
    category is a judgement (see this module's docstring). Whether the
    definition it was written against is the framework's is not.
    """
    section = _section(battery_readme, "## The category definitions are OWASP's")
    rows = dict(re.findall(r"^\|\s*(ASI\d\d)\s*\|\s*([^|]+?)\s*\|", section, re.M))
    assert set(rows) == set(OFFICIAL_TITLES), (
        "asi_battery/README.md no longer carries a definition row for every "
        f"category; parsed {sorted(rows)}"
    )
    for asi, title in sorted(rows.items()):
        official = OFFICIAL_TITLES[asi]
        assert _norm(title) == _norm(official), (
            f"the held-out battery defines {asi} as {title!r}. OWASP defines it "
            f"as {official!r}. The cases filed under {asi} were written to the "
            "definition in this table, so a wrong definition means the cases "
            "measure something other than what their label publishes."
        )


def test_every_battery_category_is_an_owasp_id_or_a_declared_exception(
    battery_cases, battery_readme
):
    """A label the framework does not have must say so where a reader will look.

    `EXH` (resource exhaustion and denial-of-wallet) is legitimate and
    deliberate: OWASP disperses those shapes across ASI02 and ASI08 rather than
    giving them a row. The danger is not the label, it is a label that LOOKS
    like a framework row. So it is allowed only while the battery README states
    in plain words that it is not one.
    """
    found = {c["category"] for rows in battery_cases.values() for c in rows}
    stray = sorted(found - set(OFFICIAL_TITLES) - NON_OWASP_BATTERY_LABELS)
    assert not stray, (
        f"the battery carries undeclared categories {stray}. Either they are "
        "OWASP ids (fix the data) or they are not (declare them in "
        "NON_OWASP_BATTERY_LABELS and in asi_battery/README.md)."
    )
    flat = " ".join(battery_readme.split())
    for label in sorted(NON_OWASP_BATTERY_LABELS & found):
        assert re.search(rf"`{label}` is not one of them|`{label}`[^.]*not an OWASP", flat), (
            f"{label} is used as a battery category but asi_battery/README.md "
            "never says it is not an OWASP Agentic Top 10 category"
        )


def test_the_published_case_counts_equal_the_files(battery_cases, battery_readme):
    """Rule (d) of F9: no quietly smaller denominator.

    The relabelling left ASI03 at 11 cases, ASI04 at 3 and ASI09 at 1. A rate
    over 3 is not the same claim as a rate over 12, and the way that goes wrong
    is not a lie -- it is a table that keeps its old shape while its rows empty
    out. So the counts are published, and this fails if the published counts
    and the files disagree in either direction.
    """
    actual = {}
    for kind, rows in battery_cases.items():
        for c in rows:
            actual.setdefault(c["category"], {"attacks": 0, "benign": 0})[kind] += 1

    section = _section(battery_readme, "## Per-category counts")
    published = {
        asi: (int(a), int(b))
        for asi, a, b in re.findall(
            r"^\|\s*\**((?:ASI\d\d|EXH))\**\s*\|\s*\**(\d+)\**\s*\|\s*\**(\d+)\**\s*\|",
            section,
            re.M,
        )
    }
    assert published, "no per-category count table parsed out of asi_battery/README.md"
    expected = {k: (v["attacks"], v["benign"]) for k, v in actual.items()}
    assert published == expected, (
        "asi_battery/README.md publishes case counts that the .jsonl files do "
        f"not have.\n  published: {published}\n  actual:    {expected}"
    )


def test_a_thin_category_is_named_as_thin(battery_cases):
    """A denominator below twelve has to be stated, not merely survivable.

    `RESULTS.md` is where the per-category rates are read, so it is where the
    warning has to be. The check is literal -- `ASI09 (1)` -- because "the file
    mentions ASI09 somewhere" would pass on any version of this document and
    would assert nothing.
    """
    counts = {}
    for c in battery_cases["attacks"]:
        counts[c["category"]] = counts.get(c["category"], 0) + 1
    thin = {k: v for k, v in counts.items() if v < 12}
    with open(BATTERY_RESULTS, encoding="utf-8") as fh:
        results = " ".join(fh.read().split())
    for cat, n in sorted(thin.items()):
        assert f"{cat} ({n})" in results, (
            f"{cat} carries only {n} of the usual 12 cases, so its rate is not "
            f"comparable with the other rows, and asi_battery/RESULTS.md does "
            f"not say so. Expected the literal '{cat} ({n})' in the text."
        )


def test_the_results_table_denominators_equal_the_files(battery_cases):
    """The `n` column of RESULTS.md's per-category table is the real count.

    This is the half that survives someone editing only the results. The count
    table in the battery README and the `n` column here are two independent
    publications of the same fact, and both are pinned to the data.
    """
    counts = {}
    for c in battery_cases["attacks"]:
        counts[c["category"]] = counts.get(c["category"], 0) + 1
    with open(BATTERY_RESULTS, encoding="utf-8") as fh:
        text = fh.read()
    start = text.index("\n## Per-category")
    end = text.index("\n## ", start + 10)
    section = text[start:end]
    published = {
        asi: int(n)
        for asi, n in re.findall(
            r"^\|\s*\**((?:ASI\d\d|EXH))\b[^|]*\|[^|]*\|\s*\**(\d+)\**\s*\|",
            section,
            re.M,
        )
    }
    assert published == counts, (
        "the RESULTS.md per-category table publishes denominators the battery "
        f"does not have.\n  published: {published}\n  actual:    {counts}"
    )
