"""The benign SQL DML pool, held as a merge gate.

scripts/benign_sql_dml_report.py prints the table; this file is what stops a
regression landing. The two are the same measurement, and the script imports
nothing from here so the pool can be read without pytest.

WHY THE POOL IS ITS OWN FILE, in one line: `sql.unbounded_mutation` and
`sql.tautological_mutation` match only `statement` in (delete, update), and the
190-call corpus and the 50-call discriminator pool contain no DML at all. Every
SQL value in both is a SELECT, so `predicate` — the load-bearing field of the
whole SQL reader — read 0/240 for its entire life without being reached once.
"""
from __future__ import annotations

import json
import os
import warnings

import pytest

from xaidr.authz.classifier import classify
from xaidr.scanner.sql_parse import parse_sql
from xaidr.sensor import DelphiSensor

POOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "benign_toolcalls", "sql_dml.jsonl")

_DESTRUCTIVE = {"delete", "infra_destruction"}


class _Null:
    def report(self, b): pass
    def close(self): pass


def _pool():
    with open(POOL, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _statement(args):
    for key in ("query", "sql", "statement"):
        if isinstance(args.get(key), str):
            return args[key]
    return ""


@pytest.fixture(scope="module")
def sensor():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return DelphiSensor(agent_id="benign-dml", enforcement_mode="monitor",
                            reporter=_Null())


def test_the_pool_is_what_it_claims_to_be():
    """A pool of SELECTs would pass every assertion below while measuring
    nothing — which is precisely the state the other two pools were in."""
    pool = _pool()
    assert len(pool) >= 50
    verbs = set()
    for entry in pool:
        shapes = parse_sql(_statement(entry["args"]))
        assert shapes, f"{entry['id']} is not read as SQL at all"
        verbs.update(s.statement for s in shapes)
    assert {"delete", "update"} <= verbs
    assert len({e["shape"] for e in pool}) >= 40, "the shapes are not distinct"


def test_no_benign_dml_statement_is_flagged(sensor):
    flagged = [(e["id"], e["shape"], r.rules)
               for e in _pool()
               for r in [sensor.scan_tool_call(e["tool"], e["args"])]
               if r.action != "allowed"]
    assert not flagged, f"benign DML flagged: {flagged}"


def test_no_benign_dml_statement_is_given_a_destructive_impact_class():
    """The slower false positive. Nothing blocks on `delete` today — the rule is
    classify-only — but an operator with `require_approval` on
    impact_class=delete gets a human gate on every one of these."""
    named = []
    for e in _pool():
        cls = classify(e["tool"], e["args"])
        impact = cls[0] if isinstance(cls, (list, tuple)) else str(cls)
        if impact in _DESTRUCTIVE:
            named.append((e["id"], impact, e["shape"],
                          [s.predicate for s in parse_sql(_statement(e["args"]))]))
    assert not named, (
        "benign DML classified destructive — each of these asks a human to "
        "approve an ordinary write: " + "; ".join(map(str, named)))


def test_a_bounded_predicate_is_actually_being_recognised(sensor):
    """The other direction, and the one a fail-closed change can quietly break.
    If every predicate answered `unknown` the two tests above would still pass
    on `flagged` and fail only on the class — so pin the positive reading."""
    bounded = 0
    for e in _pool():
        shapes = parse_sql(_statement(e["args"]))
        if any(s.predicate == "bounded" for s in shapes):
            bounded += 1
    assert bounded >= 40, (
        f"only {bounded} of the pool's statements are read as bounded; the "
        f"predicate reader has stopped discriminating and is answering "
        f"'unknown' to routine writes")
