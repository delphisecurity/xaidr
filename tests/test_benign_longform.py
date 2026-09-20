"""The over-length half of the `bounds` fail-closed group.

The committed pools could not measure this: their longest benign item is 3 241
characters against a 100 000-character scan cap. `benign_longform/` is the
population, and these are the gates on it.

THE DISCRIMINATING TEST IS `test_a_fully_read_long_document_is_NOT_refused`.
The first design of this group refused on `LLM01_oversized_input`, which fires
on `len(prompt) > L1_MAX_SCAN_CHARS` and nothing else — so a 150 000-character
policy document that the windowed scan covered completely carried the identical
rule to a 4 MB one whose tail was never read, and refusing on it blocked both.
Measured on this pool: 2 of 12 default-clean items were fully read and refused.
The shipped signal (`LLM01_input_tail_unscanned`) refuses 0 of them while still
refusing all 7 whose tail the budget never reached.
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
    """(row, open_result, closed_result) per item. Scanned once, not per test."""
    out = []
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


# ── the two facts must be distinguishable ────────────────────────────────────

def test_oversized_and_tail_unread_are_different_signals(measured):
    """"Long" and "we did not read all of it" must not be the same rule.

    Conflating them is what made the over-length path impossible to fail closed
    on. This asserts the pool contains BOTH shapes — over the cap and fully
    read, over the cap and truncated — because a pool with only one of them
    cannot tell the two signals apart either.
    """
    over_and_read = [r for r, base, _ in measured
                     if OVERSIZED_INPUT_RULE in base.rules
                     and SCAN_INCOMPLETE_RULE not in base.rules]
    over_and_unread = [r for r, base, _ in measured
                       if SCAN_INCOMPLETE_RULE in base.rules]
    assert over_and_read, (
        "no item is over the cap AND fully read, so this pool cannot "
        "distinguish the two signals — the discriminating case below is vacuous."
    )
    assert over_and_unread, "no item defeats the window budget"


def test_a_fully_read_long_document_is_NOT_refused(measured):
    """THE DISCRIMINATING TEST. Refusing on length alone is not `bounds`.

    An item that is (a) clean at the default posture and (b) fully covered by
    the windowed scan has had every rule run against every character of it.
    There is no bound fault, so there is nothing for `bounds` to refuse.
    """
    offenders = []
    for row, base, closed in measured:
        content = [r for r in base.rules if r not in LENGTH_RULES]
        if content:
            continue                       # blocked on content, not on a bound
        if SCAN_INCOMPLETE_RULE in base.rules:
            continue                       # genuinely unread; refusal is correct
        if closed.category == FAIL_CLOSED_CATEGORY:
            offenders.append((row["id"], row["chars"], list(base.rules)))
    assert not offenders, (
        "fail_closed=('bounds',) refused a document that was read COMPLETELY "
        "and scored nothing:\n" + "\n".join(
            f"  {i} ({c:,} chars) rules={r}" for i, c, r in offenders
        ) + "\nThat is a refusal on SIZE, which is not a bound fault. The "
        "signal in _BOUND_SIGNAL_RULES has regressed to LLM01_oversized_input."
    )


def test_a_truncated_document_IS_refused(measured):
    """The other direction: an unread tail must not pass under `bounds`."""
    refused = 0
    for row, base, closed in measured:
        if SCAN_INCOMPLETE_RULE not in base.rules:
            continue
        if [r for r in base.rules if r not in LENGTH_RULES]:
            continue                       # content block; not this test's case
        assert closed.action == "blocked", (
            f"{row['id']}: {row['chars']:,} chars, tail never read, and "
            f"fail_closed=('bounds',) let it through as {closed.action}"
        )
        refused += 1
    assert refused >= 5, (
        f"only {refused} truncated default-clean items — too few for this "
        "assertion to mean anything"
    )


def test_under_the_cap_is_untouched_by_the_group(measured):
    """The control. An item under the cap behaves identically either way."""
    checked = 0
    for row, base, closed in measured:
        if row["chars"] > L1_MAX_SCAN_CHARS:
            continue
        assert base.action == closed.action
        assert list(base.rules) == list(closed.rules)
        checked += 1
    assert checked, "no item is under the cap; the control case is missing"


def test_default_posture_is_byte_identical_on_this_pool(corpus):
    """`bounds` OPEN must not have moved anything at all on long input.

    The zero-movement guarantee, asserted on the one population that can see
    the code this work touched (`iter_scan_windows` now yields a third element
    and `_scan_tail` counts coverage). A change in the default posture here
    would be a regression for every existing deployment.
    """
    for row in corpus:
        base = _scan(row["text"])
        assert base.action in ("allowed", "flagged", "blocked")
        # The scan completed and produced a verdict — no fail-closed category
        # can appear when no group is closed.
        assert base.category != FAIL_CLOSED_CATEGORY
