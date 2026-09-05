"""A nano-driven flag must name what flagged it.

Before this, nano could move a scan from `allowed` to `flagged` and the result
came back with ``rules == []`` and ``category is None``. The reading was carried
on ``nano_score``/``nano_raw``, but those are TUNING fields — `rules` is the
field an operator reads, and it was empty. A flagged event that names nothing is
indistinguishable from a bug, and a flag that looks like a bug gets ignored,
which costs more than the flag was ever worth.

The attribution is prefixed (``nano:injection``) rather than folded in among the
rule ids, and that is the substance of the design rather than a formatting
choice. The module docstring in nano.py is emphatic that the model's number is a
detection signal and NOT calibrated confidence; a queue that cannot tell a model
reading from a written-down pattern cannot act on that warning. The prefix makes
"filter to rules only" a one-line query.

Containment is unchanged and re-asserted here: attribution adds a STRING to a
list. It moves no score, and `blocked` stays unreachable from the nano path
(tests/test_nano_containment.py owns that argument in full).
"""
from __future__ import annotations

import pytest

nano = pytest.importorskip("xaidr.scanner.nano", reason="nano is an optional extra")

from xaidr.scanner.local import (  # noqa: E402
    NANO_FAMILY_SILENT, NANO_MIN_WORDS, LocalScanner,
)

# Rules-silent on every layer, and long enough to clear NANO_MIN_WORDS — nano
# only speaks into silence, so anything the ruleset catches would not reach it.
SILENT_TEXT = "please summarise the attached quarterly earnings memo for me"


class _FakeNano:
    """Stands in for the model only. Everything else is the shipping path."""

    def __init__(self, p_raw, family):
        self.p_raw = p_raw
        self.family = family

    def classify(self, text):
        return nano.NanoResult(p_raw=self.p_raw, family=self.family, time_ms=0.0)


class _BrokenNano:
    def classify(self, text):
        raise RuntimeError("inference kernel fault")


def _wired(fake, **kw):
    scanner = LocalScanner(**kw)
    scanner.nano_enabled = True
    scanner._nano = fake
    return scanner


def test_the_test_text_is_actually_rules_silent():
    """NON-VACUITY. If the ruleset ever catches this sentence, nano never runs
    and every assertion below would be testing the rules instead."""
    plain = LocalScanner()
    result = plain.scan(SILENT_TEXT, "agent")
    assert result.score == 0.0
    assert result.rules == []
    assert len(SILENT_TEXT.split()) >= NANO_MIN_WORDS


def test_a_nano_flag_names_nano():
    scanner = _wired(_FakeNano(0.9, "injection"))
    result = scanner.scan(SILENT_TEXT, "agent")
    assert result.action == "flagged"
    assert "nano:injection" in result.rules


def test_the_attribution_is_prefixed_so_it_sorts_apart_from_written_rules():
    scanner = _wired(_FakeNano(0.9, "injection"))
    result = scanner.scan(SILENT_TEXT, "agent")
    assert [r for r in result.rules if r.startswith("nano:")] == ["nano:injection"]


def test_no_written_rule_can_masquerade_as_a_nano_attribution():
    """The prefix only separates model from ruleset while it is UNIQUE to the
    model. A written rule id starting `nano:` would make the operator's
    "filter to rules only" query silently wrong."""
    from xaidr.scanner import l1
    for rule in list(l1.INPUT_RULES) + list(l1.OUTPUT_RULES):
        rid = rule["id"] if isinstance(rule, dict) else rule.id
        assert not rid.startswith("nano:"), rid


def test_a_silent_reading_attributes_nothing():
    """family == "none" is nano declining to speak. It must not appear as a
    detection, or every scan in the rules-silent band grows a rule id."""
    scanner = _wired(_FakeNano(1e-9, NANO_FAMILY_SILENT))
    result = scanner.scan(SILENT_TEXT, "agent")
    assert result.action == "allowed"
    assert result.rules == []


def test_an_inference_fault_attributes_nothing():
    """Fail-open returns the silent family, so a model FAULT can never be
    attributed as a model DETECTION. That collapse is deliberate — see
    NANO_FAMILY_SILENT — and this is the assertion that holds it."""
    scanner = _wired(_BrokenNano())
    result = scanner.scan(SILENT_TEXT, "agent")
    assert result.action == "allowed"
    assert result.score == 0.0
    assert not [r for r in result.rules if r.startswith("nano:")]


def test_attribution_does_not_move_the_score_or_reach_blocked():
    """Containment, re-checked at the seam this change touches. The flag lands
    on the flag-band FLOOR exactly as it did before, and the reading itself is
    still carried verbatim for tuning."""
    scanner = _wired(_FakeNano(0.999, "injection"))
    result = scanner.scan(SILENT_TEXT, "agent")
    assert result.action == "flagged"
    assert result.score == pytest.approx(scanner.flag_threshold)
    assert result.score < scanner.block_threshold
    assert result.nano_raw == pytest.approx(0.999)


def test_nano_stays_off_the_output_direction():
    """Scope guard: nano's accepted numbers were measured on inbound chat only,
    so attribution must not appear on a direction nano does not run in."""
    scanner = _wired(_FakeNano(0.9, "injection"))
    result = scanner.scan(SILENT_TEXT, "agent", direction="output")
    assert not [r for r in result.rules if r.startswith("nano:")]


def test_run_nano_returns_the_family_alongside_the_scores():
    """The seam itself. _run_nano used to drop `family` on the floor, which is
    why there was nothing to attribute with."""
    scanner = _wired(_FakeNano(0.9, "injection"))
    raw, capped, family = scanner._run_nano(SILENT_TEXT)
    assert raw == pytest.approx(0.9)
    assert 0.0 < capped < scanner.block_threshold
    assert family == "injection"


def test_run_nano_reports_the_silent_family_on_failure():
    scanner = _wired(_BrokenNano())
    assert scanner._run_nano(SILENT_TEXT) == (0.0, 0.0, NANO_FAMILY_SILENT)
