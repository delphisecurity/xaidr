"""Smoke coverage for the L2 intent/composite engine (xaidr/scanner/l2.py)."""

from __future__ import annotations

from xaidr.scanner import l2


def test_intents_composites_chains_load():
    assert len(l2.INTENTS) > 0
    assert len(l2.COMPOSITES) > 0
    assert len(l2.CHAINS) > 0


def test_dangerous_intent_triggers():
    r = l2.scan_l2("delete all files in the database")
    assert r.triggered is True
    assert r.score > 0
    # Observed intent rule for a destructive tool-misuse phrase.
    assert any(t.rule == "INTENT_destroy_resources" for t in r.threats)


def test_benign_intent_not_triggered():
    r = l2.scan_l2("what is the weather in toronto")
    assert r.triggered is False
