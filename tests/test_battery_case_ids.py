"""Nothing may cite a battery case id that no longer exists, unframed.

THE DEFECT, found when this branch was rebased onto F9. F9 relabelled the
held-out battery: 28 cases moved category and their ids moved with them
(`ASI04-A01..A12` -> `EXH-A01..A12`, `ASI09-A01..A12` -> `ASI06-A13..A24`, and
four more). Nothing was rewritten — same tool, same args, label only.

Every id cited anywhere else in the tree was then a claim about a case that had
been renamed, and NOTHING NOTICED. Two survived into published prose:

  * `asi_battery/BOUNDARY_GAP.md` stated as present-tense fact that the three
    benign false positives were "unchanged and still the same case IDs:
    `ASI06-B08`, `ASI08-B10`, `ASI09-B10`". `ASI09-B10` had become `ASI06-B22`.
  * `xaidr/rules/all-l1-rules.json` — a SHIPPED asset, inside the wheel —
    justified a deliberate rule exclusion with "Two battery attacks (ASI04-A04
    delegation amplification, ASI04-A11 broadcast storm) are MISSED". Both ids
    were gone; the cases are `EXH-A04` and `EXH-A11`.

Neither is a typo. Both are a reference to a fact that silently stopped being
addressable, in documents whose whole purpose is to be checkable — and the
rebase that created them produced NO textual conflict, so review had nothing to
look at.

THE SAME SHAPE ALREADY BIT ONCE, one layer over: F9's own body records
`tests/test_f7_domain_generality.py` failing with `KeyError: 'ASI04-A02'`
because it named battery cases by id. That was caught because a dict lookup
raises. Prose does not raise.

WHAT IS AND IS NOT ALLOWED. A citation of a dead id is legitimate when it is
FRAMED AS HISTORY — "`ASI09-A01..A12` became `ASI06-A13..A24`", "`ASI06-B17`
was `ASI09-B05` before F9", the case-id map. That framing is what makes it a
record rather than a stale claim, and F9's README is largely made of it. So the
gate requires a historical marker on the citing line or its enclosing markdown
section, and fails on a BARE dead id — which is exactly what both defects were.

This gate is deliberately not "no dead ids anywhere". A tree that cannot mention
its own history loses the retraction record, and `~/.claude/CLAUDE.md` requires
the opposite: retract in place, visibly.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BATTERY = REPO / "asi_battery"
POOLS = ("attacks.jsonl", "benign.jsonl")

#: A battery case id: `ASI03-A01`, `EXH-B12`. Both LIVE on purpose — an example
#: is a citation like any other, and a dead id used decoratively here would make
#: this file fail its own gate.
_ID = re.compile(r"\b(?:ASI\d{2}|EXH)-[AB]\d{2}\b")

#: Phrases that frame a dead id as a record of a rename rather than a live
#: claim about a case.
_HISTORICAL = (
    "was", "were", "became", "become", "move", "moved", "moves", "relabel",
    "before f9", "pre-f9", "then", "no longer exists", "is now",
    "case-id map", "used to be", "formerly", "renamed", "keyerror",
)

#: Formats where each line is a self-contained record, so framing must appear
#: ON the citing line. A neighbourhood window is WRONG here and was measured to
#: be: with a +/-5 line window, `xaidr/rules/all-l1-rules.json`'s dead-id defect
#: went GREEN because an unrelated key five lines away happened to contain the
#: word "were". Adjacent JSON lines are not context, they are other records.
_LINE_SCOPED = {".json", ".yml", ".yaml", ".toml", ".cfg"}

#: Extensions worth scanning. Binary and pool files are excluded; the pools are
#: the definition of the id set and cannot disagree with themselves.
_TEXT = {".md", ".json", ".py", ".yml", ".yaml", ".toml", ".txt", ".cfg"}


def _live_ids():
    ids = set()
    for name in POOLS:
        for line in (BATTERY / name).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                ids.add(json.loads(line)["id"])
    return ids


#: Directories with nothing to cite — build output, caches, the venv.
_SKIP_DIRS = {".git", ".venv", "venv", "dist", "build", "__pycache__",
              ".pytest_cache", ".mypy_cache", ".ruff_cache", ".eggs",
              "node_modules", ".tox"}


def _walk():
    """Every text file the repo COMMITS, preferring the index, falling back.

    Tracked files are the honest scope: a gitignored regenerator output like
    `asi_battery/g4_last_run.json` legitimately holds pre-F9 ids, because it is
    a recording of a run that happened before the relabelling and is replaced
    the next time its script is run. Failing on it would be failing on a build
    artifact, and the fix would be to re-run a script rather than to correct a
    claim — so it is noise, and a gate that cries about noise gets muted.

    The fallback matters because this branch ships `tests/` inside the sdist,
    so this gate can run from an EXTRACTED SDIST with no git index and no git
    binary. There are no run outputs there either, so the plain walk has the
    same scope in that setting. Same shape, and for the same reason, as
    `tests/test_sdist_contents.py::_tracked_files`.

    Either way `scanned` asserts the result is not small, so neither path can
    degrade into a silent empty scan.
    """
    tracked = None
    try:
        p = subprocess.run(["git", "ls-files"], cwd=REPO,
                           capture_output=True, text=True, timeout=60)
        if p.returncode == 0 and p.stdout.strip():
            tracked = p.stdout.split()
    except (OSError, subprocess.SubprocessError):
        tracked = None

    if tracked is None:
        tracked = []
        for f in REPO.rglob("*"):
            if f.is_file() and not (_SKIP_DIRS & set(f.relative_to(REPO).parts)):
                tracked.append(str(f.relative_to(REPO)))

    return sorted(
        {f for f in tracked if Path(f).suffix in _TEXT}
        - {f"asi_battery/{n}" for n in POOLS}
    )


@pytest.fixture(scope="module")
def live_ids():
    ids = _live_ids()
    # The gate's own scope, asserted. A pool that failed to load would make
    # every id below "dead" and the gate would scream; an EMPTY id set with a
    # silently-empty file list would make it pass over nothing, which is the
    # failure mode this whole branch is about.
    assert len(ids) == 240, (
        f"the battery pools define {len(ids)} case ids, not 240; if the pools "
        f"genuinely changed size update this number, but check first that "
        f"both files loaded"
    )
    return ids


@pytest.fixture(scope="module")
def scanned():
    files = _walk()
    assert len(files) > 50, (
        f"the repo walk returned only {len(files)} text files to scan. This "
        f"gate would then be passing over an empty-ish set and reporting "
        f"coverage it is not performing — the exact defect this branch exists "
        f"to fix. An earlier draft of this scan used `git grep -o`, which this "
        f"git does not support, matched nothing, and reported a clean tree."
    )
    return files


def _is_break(line):
    """A paragraph boundary: blank, or a blockquote marker carrying no prose.

    `>` alone matters — the BOUNDARY_GAP banner is one long blockquote, and
    without this every line of it would share one context. The stale-id claim
    that prompted this whole gate sat in that banner five lines below an
    unrelated "is now", so a blockquote-wide context would have hidden it.
    """
    return not line.strip().lstrip(">").strip()


def _paragraph(lines, i):
    """The blank-line-delimited block containing 1-based line `i`.

    Framing is a property of the PARAGRAPH, not the line: prose wraps, and the
    sentence that says "became `EXH-A01..A12`" is routinely not the sentence
    carrying the dead id. A single-line rule for prose would be a formatting
    rule pretending to be a correctness rule.
    """
    start = i - 1
    while start > 0 and not _is_break(lines[start - 1]):
        start -= 1
    end = i - 1
    while end + 1 < len(lines) and not _is_break(lines[end + 1]):
        end += 1
    return lines[start:end + 1]


def _citations(files):
    """(path, lineno, id, line, context) for every case id cited in the tree."""
    for rel in files:
        try:
            text = (REPO / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        lines = text.splitlines()
        line_scoped = Path(rel).suffix in _LINE_SCOPED
        heading = ""
        for i, line in enumerate(lines, start=1):
            if rel.endswith(".md") and line.lstrip().startswith("#"):
                heading = line
            for m in _ID.finditer(line):
                if line_scoped:
                    context = line
                else:
                    context = "\n".join([heading, *_paragraph(lines, i)])
                yield rel, i, m.group(0), line, context


def _framed(line, context):
    return any(marker in context.lower() for marker in _HISTORICAL)


def test_the_scan_sees_the_ids_it_is_supposed_to_see(live_ids, scanned):
    """Two enumerations that must agree, before any verdict is trusted.

    The gate below reports a clean tree both when the tree is clean and when
    the scan found nothing at all. This separates those two outcomes.
    """
    cited = {c[2] for c in _citations(scanned)}
    assert cited, "no battery case id was found anywhere in the tree"
    live_cited = cited & live_ids
    assert len(live_cited) >= 20, (
        f"the scan found only {len(live_cited)} LIVE case ids cited across "
        f"{len(scanned)} files. The README, RESULTS.md and BOUNDARY_GAP.md "
        f"between them cite dozens; a number this low means the walk is not "
        f"reaching the files it claims to cover."
    )


def test_no_unframed_citation_of_a_case_id_that_no_longer_exists(
        live_ids, scanned):
    """The gate. A dead id is allowed only when framed as history."""
    bad = []
    for rel, lineno, cid, line, heading in _citations(scanned):
        if cid in live_ids or _framed(line, heading):
            continue
        bad.append(f"  {rel}:{lineno}  {cid}\n      {line.strip()[:120]}")

    assert not bad, (
        "these citations name a battery case id that no longer exists, with "
        "nothing marking them as historical — so each reads as a live claim "
        "about a case that cannot be looked up:\n"
        + "\n".join(sorted(bad))
        + "\n\nF9 relabelled 28 cases (see asi_battery/README.md 'Case-id "
          "map'). Either update the id, or frame the mention as a record of "
          "the rename the way that map does."
    )


def test_every_live_id_is_reachable_from_its_pool(live_ids):
    """The id set is well-formed: no duplicates across the two pools.

    A duplicate id would make one of the two cases unaddressable and would let
    a dead-id citation resolve to the wrong case.
    """
    seen, dupes = set(), []
    for name in POOLS:
        for line in (BATTERY / name).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            cid = json.loads(line)["id"]
            if cid in seen:
                dupes.append(cid)
            seen.add(cid)
    assert not dupes, f"duplicate battery case ids: {sorted(set(dupes))}"
    assert seen == live_ids
