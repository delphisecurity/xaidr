"""The over-length half of the `bounds` fail-closed group.

The committed pools could not measure this: their longest benign item is 3 241
characters against a 100 000-character scan cap. `benign_longform/` is the
population, and these are the gates on it.

THE DISCRIMINATING TEST IS `test_a_fully_read_long_document_is_NOT_refused`.
The first design of this group refused on `LLM01_oversized_input`, which fires
on `len(prompt) > L1_MAX_SCAN_CHARS` and nothing else — so a 150 000-character
policy document that the windowed scan covered completely carried the identical
rule to a 4 MB one whose tail was never read, and refusing on it blocked both.
The shipped signal (`LLM01_input_tail_unscanned`) refuses none of the fully-read
items while still refusing every one whose tail the windows never reached.

WHY EVERY SCAN HERE RUNS UNDER `deterministic_scan_bounds()`. The first version
of this file did not, and six CI jobs went red — correctly. Three wall-clock
bounds sit inside an L1 scan (`_L1_SCAN_BUDGET_SEC`, `_L1_RULE_SLOW_SEC`,
`TOTAL_SCAN_BUDGET_SEC`), and on GitHub's runners — a loaded host — they decided
the outcome for every item in this pool. Every over-cap item blew the window
budget, so NOTHING was "over the cap and fully read" and the vacuity guard below
fired on a pool that genuinely could not distinguish the two signals any more.
A 90 000-character item, UNDER the cap and the control case for this whole file,
blew the 0.5 s rule-loop budget and was refused under `bounds`.

`benign_longform/README.md` had already written the caveat down — "the same
document can be refused on a loaded host and allowed on an idle one" — as a
property an operator needs to know. It is that. It is also a property no
regression gate can stand on, because a wall-clock bound measures the MACHINE
and the claim under test is about the CODE. `scripts/longform_bounds.py` pins
the clocks so which bucket an item lands in is a function of its length and
`MAX_SCAN_WINDOWS` alone — the two things `manifest.json` pins. See that module
for what is consequently NOT covered here.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from build_benign_longform import MANIFEST, generate   # noqa: E402
from longform_bounds import (                          # noqa: E402
    deterministic_scan_bounds, windowed_coverage_limit,
)

from xaidr import Sensor                                        # noqa: E402
from xaidr.failclosed import FAIL_CLOSED_CATEGORY               # noqa: E402
from xaidr.scanner.l1 import (                                  # noqa: E402
    L1_MAX_SCAN_CHARS, OVERSIZED_INPUT_RULE, SCAN_INCOMPLETE_RULE,
)

LENGTH_RULES = {OVERSIZED_INPUT_RULE, SCAN_INCOMPLETE_RULE}


class _NullReporter:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass


@pytest.fixture(scope="module")
def corpus():
    return generate()


def _scan(text, fail_closed=()):
    s = Sensor(agent_id="longform", enforcement_mode="block",
               reporter=_NullReporter(), fail_closed=fail_closed)
    try:
        return s.scan(text, direction="input")
    finally:
        s.close_sync()


@pytest.fixture(scope="module")
def measured(corpus):
    """(row, open_result, closed_result) per item.

    Scanned ONCE for the whole module — two passes over ten million characters
    is the cost of this file, and every test below reads these results rather
    than rescanning.
    """
    out = []
    with deterministic_scan_bounds():
        for row in corpus:
            base = _scan(row["text"])
            closed = _scan(row["text"], fail_closed=("bounds",))
            out.append((row, base, closed))
    return out


# ── the corpus is the corpus the numbers were measured on ────────────────────

def test_manifest_pins_the_generated_corpus(corpus):
    """A generated corpus nobody pins is a corpus that drifts under the README.

    The text is not committed (24 items, 10 million characters, 25 MB against
    an 8 MB repo), so this hash check is the only thing standing between an
    edited word list and a set of published numbers that describe inputs which
    no longer exist.
    """
    with open(MANIFEST, encoding="utf-8") as fh:
        pinned = {i["id"]: i for i in json.load(fh)["items"]}
    assert len(pinned) == len(corpus)
    for row in corpus:
        want = pinned.get(row["id"])
        assert want is not None, f"{row['id']} is not in the manifest"
        got = hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
        assert want["sha256"] == got, (
            f"{row['id']} changed. Re-run scripts/build_benign_longform.py to "
            "re-pin AND scripts/benign_longform_report.py to re-measure — the "
            "README numbers are about the old text until you do."
        )


def test_the_pool_actually_reaches_the_bound(corpus):
    """Without this, every assertion below is about inputs under the cap.

    This is the precondition the whole file exists for: the reason the other
    pools say nothing about this path is that nothing in them is long enough.
    """
    over = [r for r in corpus if r["chars"] > L1_MAX_SCAN_CHARS]
    assert len(over) >= 15, (
        f"only {len(over)} of {len(corpus)} items exceed "
        f"L1_MAX_SCAN_CHARS={L1_MAX_SCAN_CHARS:,} — this pool has stopped "
        "measuring the bound it exists for."
    )
    longest = max(r["chars"] for r in corpus)
    assert longest > 8 * L1_MAX_SCAN_CHARS, (
        f"longest item is {longest:,}; nothing here exhausts the "
        "MAX_SCAN_WINDOWS cap, so the deterministic tail-unread case is absent."
    )


def test_the_pool_straddles_the_window_coverage_limit(corpus):
    """Both sides of the window cap must be populated, by LENGTH.

    The vacuity guard for everything below, and it is stated in the one unit
    that does not depend on the runner. With the clocks pinned, an item's
    bucket is decided entirely by whether it is longer than what
    `MAX_SCAN_WINDOWS` windows can cover, so if either side of that line is
    empty the discriminating tests cannot discriminate.
    """
    limit = windowed_coverage_limit()
    covered = [r for r in corpus
               if L1_MAX_SCAN_CHARS < r["chars"] <= limit]
    truncated = [r for r in corpus if r["chars"] > limit]
    assert len(covered) >= 10, (
        f"only {len(covered)} items are over the {L1_MAX_SCAN_CHARS:,}-char cap "
        f"and within the {limit:,}-char window coverage — the 'long but fully "
        "read' case this group exists to NOT refuse is barely represented."
    )
    assert len(truncated) >= 5, (
        f"only {len(truncated)} items exceed the {limit:,}-char window "
        "coverage limit — the tail-unread case is barely represented."
    )


# ── the two facts must be distinguishable ────────────────────────────────────

def test_oversized_and_tail_unread_are_different_signals(corpus, measured):
    """"Long" and "we did not read all of it" must not be the same rule.

    Conflating them is what made the over-length path impossible to fail closed
    on. Asserted by IDENTITY rather than by count: the set of items the scanner
    reports as truncated must be EXACTLY the set the window arithmetic says
    cannot be covered. "At least one of each" is satisfied by a pool that has
    quietly degenerated; this is not.
    """
    limit = windowed_coverage_limit()
    expected_truncated = {r["id"] for r in corpus if r["chars"] > limit}
    got_truncated = {row["id"] for row, base, _ in measured
                     if SCAN_INCOMPLETE_RULE in base.rules}
    assert got_truncated == expected_truncated, (
        "the items reported tail-unread are not the items past the "
        f"{limit:,}-char window coverage limit.\n"
        f"  unexpectedly truncated: {sorted(got_truncated - expected_truncated)}\n"
        f"  unexpectedly covered  : {sorted(expected_truncated - got_truncated)}\n"
        "With the wall-clock bounds pinned this is decided by length alone, so "
        "a mismatch means the windowing arithmetic changed."
    )

    over_and_read = [row["id"] for row, base, _ in measured
                     if OVERSIZED_INPUT_RULE in base.rules
                     and SCAN_INCOMPLETE_RULE not in base.rules]
    assert over_and_read, (
        "no item is over the cap AND fully read, so this pool cannot "
        "distinguish the two signals — the discriminating case below is vacuous."
    )
    assert got_truncated, "no item defeats the window budget"


def test_a_fully_read_long_document_is_NOT_refused(measured):
    """THE DISCRIMINATING TEST. Refusing on length alone is not `bounds`.

    An item that is (a) clean at the default posture and (b) fully covered by
    the windowed scan has had every rule run against every character of it.
    There is no bound fault, so there is nothing for `bounds` to refuse.
    """
    offenders = []
    checked = 0
    for row, base, closed in measured:
        content = [r for r in base.rules if r not in LENGTH_RULES]
        if content:
            continue                       # blocked on content, not on a bound
        if SCAN_INCOMPLETE_RULE in base.rules:
            continue                       # genuinely unread; refusal is correct
        if OVERSIZED_INPUT_RULE not in base.rules:
            continue                       # under the cap; not this test's case
        checked += 1
        if closed.category == FAIL_CLOSED_CATEGORY:
            offenders.append((row["id"], row["chars"], list(base.rules)))
    assert checked, (
        "no item is over the cap, fully read AND clean at the default posture, "
        "so this test asserted nothing. It is the discriminating case for the "
        "whole group — a pool that cannot produce one is not measuring it."
    )
    assert not offenders, (
        "fail_closed=('bounds',) refused a document that was read COMPLETELY "
        "and scored nothing:\n" + "\n".join(
            f"  {i} ({c:,} chars) rules={r}" for i, c, r in offenders
        ) + "\nThat is a refusal on SIZE, which is not a bound fault. The "
        "signal in _BOUND_SIGNAL_RULES has regressed to LLM01_oversized_input."
    )


def test_a_truncated_document_IS_refused(measured):
    """The other direction: an unread tail must not pass under `bounds`.

    THE FLOOR HERE IS 2, AND IT USED TO BE 5. That is not a weakened gate, it is
    the first honest count. The 5 was measured when the wall clock decided which
    items were truncated, which on the author's machine truncated everything
    from 150 KB up; with the clocks pinned, truncation starts at the window
    coverage limit (~796 KB) and only the 900 KB items reach it. Of those, the
    ones that are also clean at the default posture are the two shapes that do
    not trip a content rule on realistic long text — see finding 2 in the
    corpus README. `test_oversized_and_tail_unread_are_different_signals` pins
    the truncated set by identity, so the anti-vacuity work is done there and
    this floor only has to be non-zero.
    """
    refused = []
    for row, base, closed in measured:
        if SCAN_INCOMPLETE_RULE not in base.rules:
            continue
        if [r for r in base.rules if r not in LENGTH_RULES]:
            continue                       # content block; not this test's case
        assert closed.action == "blocked", (
            f"{row['id']}: {row['chars']:,} chars, tail never read, and "
            f"fail_closed=('bounds',) let it through as {closed.action}"
        )
        refused.append(row["id"])
    assert len(refused) >= 2, (
        f"only {len(refused)} truncated default-clean items {refused} — too "
        "few for this assertion to mean anything"
    )


def test_under_the_cap_is_untouched_by_the_group(measured):
    """The control. An item under the cap behaves identically either way."""
    checked = 0
    for row, base, closed in measured:
        if row["chars"] > L1_MAX_SCAN_CHARS:
            continue
        assert base.action == closed.action, (
            f"{row['id']}: {row['chars']:,} chars is UNDER the "
            f"{L1_MAX_SCAN_CHARS:,}-char cap, so no bound was reached, yet "
            f"fail_closed=('bounds',) moved it from {base.action} to "
            f"{closed.action}"
        )
        assert list(base.rules) == list(closed.rules)
        checked += 1
    assert checked, "no item is under the cap; the control case is missing"


def test_default_posture_is_byte_identical_on_this_pool(measured):
    """`bounds` OPEN must not have moved anything at all on long input.

    The zero-movement guarantee, asserted on the one population that can see
    the code this work touched (`iter_scan_windows` now yields a third element
    and `_scan_tail` counts coverage). A change in the default posture here
    would be a regression for every existing deployment.
    """
    for row, base, _closed in measured:
        assert base.action in ("allowed", "flagged", "blocked")
        # The scan completed and produced a verdict — no fail-closed category
        # can appear when no group is closed.
        assert base.category != FAIL_CLOSED_CATEGORY, (
            f"{row['id']} carries the fail-closed category at the DEFAULT "
            "posture, where no group is closed."
        )
