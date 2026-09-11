#!/usr/bin/env python3
"""Measure false positives on the benign SQL DML pool.

    python scripts/benign_sql_dml_report.py

WHY THIS EXISTS, and why it is not folded into benign_toolcall_report.py. The
SQL classifiers key on `predicate` — "none" | "bounded" | "tautology" |
"unknown" — and the two rules that consume it, `sql.unbounded_mutation` and
`sql.tautological_mutation`, match only `statement` in (delete, update).

The 190-call corpus and the 50-call discriminator pool contain **no DML at all**:
every SQL value in either is a SELECT. So the load-bearing field of the whole SQL
reader was measured against zero benign statements, and 0/240 on a rule the pool
cannot reach reads as acceptance while performing none. That is the same shape as
the blindness recorded in benign_toolcalls/README.md for the privilege detector,
on a different surface, which is why this pool is a third file rather than rows
appended to an existing one.

Two numbers, because they are different questions:

  FLAGGED     the sensor returned something other than `allowed`. This is the
              user-visible false positive.
  CLASSIFIED  the call was given a destructive impact class. Nothing blocks on
              it today — `sql.unbounded_mutation` is classify-only — but an
              operator with `require_approval` on impact_class=delete gets a
              human gate on every one of these, which is a false positive with
              a slower feedback loop, not a smaller one.

Standard library + xaidr. Monitor mode, null reporter, no network.
"""
from __future__ import annotations
import json
import os
import sys
import warnings

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL = os.path.join(REPO, "benign_toolcalls", "sql_dml.jsonl")
sys.path.insert(0, REPO)

from xaidr.authz.classifier import classify        # noqa: E402
from xaidr.scanner.sql_parse import parse_sql      # noqa: E402
from xaidr.sensor import DelphiSensor              # noqa: E402

WIDTH = 104

#: Impact classes that mean "this statement removes or rewrites data". A benign
#: DML pool entry carrying one of these is a false positive whether or not the
#: shipped rule blocks on it.
_DESTRUCTIVE = {"delete", "infra_destruction"}


class _Null:
    def report(self, b): pass
    def close(self): pass


def load():
    with open(POOL, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def statement_of(args):
    for key in ("query", "sql", "statement"):
        if isinstance(args.get(key), str):
            return args[key]
    return ""


def measure(pool, sensor):
    """-> (rows, flagged, classified). One row per entry."""
    rows, flagged, classified = [], [], []
    for e in pool:
        stmt = statement_of(e["args"])
        preds = ",".join(s.predicate for s in parse_sql(stmt)) or "-"
        cls = classify(e["tool"], e["args"])
        impact = cls[0] if isinstance(cls, (list, tuple)) else str(cls)
        tier = cls[1] if isinstance(cls, (list, tuple)) and len(cls) > 1 else ""
        result = sensor.scan_tool_call(e["tool"], e["args"])
        rows.append((e, preds, impact, tier, result))
        if result.action != "allowed":
            flagged.append(e["id"])
        if impact in _DESTRUCTIVE:
            classified.append((e["id"], f"{impact}/{tier}", e["shape"]))
    return rows, flagged, classified


def main():
    pool = load()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sensor = DelphiSensor(agent_id="benign-dml", enforcement_mode="monitor",
                              reporter=_Null())
    rows, flagged, classified = measure(pool, sensor)

    print("=" * WIDTH)
    print("BENIGN SQL DML POOL  -  false positives")
    print("=" * WIDTH)
    print(f"pool      : {len(pool)} DELETE/UPDATE statements "
          f"(benign_toolcalls/sql_dml.jsonl)")
    print("boundary  : every entry is a tool_call (scan_tool_call), mode=monitor")
    print()
    print(f"{'id':<9}{'predicate(s)':<26}{'impact':<22}{'action':<10}shape")
    print("-" * WIDTH)
    for e, preds, impact, tier, result in rows:
        print(f"{e['id']:<9}{preds:<26}{impact + '/' + str(tier):<22}"
              f"{result.action:<10}{e['shape']}")
    print("-" * WIDTH)
    print(f"flagged by the sensor        : {len(flagged)}/{len(pool)}  {flagged}")
    print(f"given a destructive class    : {len(classified)}/{len(pool)}")
    for ident, impact, shape in classified:
        print(f"    {ident}  {impact:<20} {shape}")
    print()
    ok = not flagged and not classified
    print("=" * WIDTH)
    print(f"BENIGN SQL DML GATE: {'PASS' if ok else 'FAIL'}")
    print("=" * WIDTH)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
