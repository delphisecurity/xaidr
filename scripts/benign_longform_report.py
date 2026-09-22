"""What `fail_closed=("bounds",)` costs on realistic long benign input.

This is the measurement condition 2 of the fail-closed work demanded: the
longest benign item in any other committed pool is 3 241 characters against a
100 000-character scan cap, so every number the existing pools produce about the
over-length path is an absence of test data rather than a measurement.

Run:  PYTHONPATH=. python scripts/benign_longform_report.py
      PYTHONPATH=. python scripts/benign_longform_report.py --json out.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

# Which xaidr answered? See scripts/_provenance.py. The `scripts/` entry is for
# the sibling imports below and has nothing to do with which xaidr resolves —
# that distinction is why the insert was silent and is now announced.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _provenance import bind, repo_root_of   # noqa: E402

ROOT = repo_root_of(__file__)
PROV = bind(__file__, extra_paths=(os.path.join(ROOT, "scripts"),))

from build_benign_longform import MANIFEST, generate   # noqa: E402
from longform_bounds import (                          # noqa: E402
    deterministic_scan_bounds, windowed_coverage_limit,
)


class _NullReporter:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass


def verify(rows):
    """The committed manifest still describes these exact items."""
    with open(MANIFEST, encoding="utf-8") as fh:
        pinned = {i["id"]: i for i in json.load(fh)["items"]}
    bad = []
    for row in rows:
        want = pinned.get(row["id"])
        got = hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
        if want is None or want["sha256"] != got:
            bad.append(row["id"])
    return bad


def measure(rows):
    from xaidr import Sensor
    from xaidr.scanner.l1 import (
        L1_MAX_SCAN_CHARS, OVERSIZED_INPUT_RULE, SCAN_INCOMPLETE_RULE,
    )

    # Rules that are a statement about LENGTH, not about content. An item
    # carrying only these is "clean at the default": the scanner found nothing
    # in it, and any refusal under `bounds` is attributable to the bound.
    LENGTH_RULES = {OVERSIZED_INPUT_RULE, SCAN_INCOMPLETE_RULE}

    def one(row):
        record = {"id": row["id"], "shape": row["shape"], "chars": row["chars"]}
        for label, fc in (("open", ()), ("closed", ("bounds",))):
            sensor = Sensor(agent_id="longform", enforcement_mode="block",
                            reporter=_NullReporter(), fail_closed=fc)
            t0 = time.perf_counter()
            result = sensor.scan(row["text"], direction="input")
            record[label] = {
                "action": result.action,
                "score": round(float(result.score), 4),
                "rules": list(result.rules or []),
                "ms": round((time.perf_counter() - t0) * 1000),
            }
            sensor.close_sync()
        record["oversized"] = OVERSIZED_INPUT_RULE in record["open"]["rules"]
        record["tail_unread"] = SCAN_INCOMPLETE_RULE in record["open"]["rules"]
        record["content_rules"] = [r for r in record["open"]["rules"]
                                   if r not in LENGTH_RULES]
        # ATTRIBUTION IS THE WHOLE POINT OF THIS FIELD. Some realistic long
        # operational text scores on CONTENT at the default posture — see the
        # README's second finding — and counting those as a `bounds` false
        # positive would blame this group for a refusal it did not cause. The
        # bounds cost is measured over `default_clean` items only.
        record["default_clean"] = not record["content_rules"]
        return record

    # MEASURED WITH THE WALL CLOCK PINNED, for the same reason
    # tests/test_benign_longform.py is. Without this the table below reports the
    # machine it was run on: the three wall-clock bounds inside an L1 scan
    # decided which items counted as truncated, so an idle laptop and a loaded
    # CI runner produced different numbers from identical text, and the figures
    # in benign_longform/README.md were only ever true of one box. With the
    # clocks pinned an item's bucket follows from its length and
    # MAX_SCAN_WINDOWS, which manifest.json pins. See scripts/longform_bounds.py.
    with deterministic_scan_bounds():
        out = [one(row) for row in rows]
    return out, L1_MAX_SCAN_CHARS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", metavar="PATH", help="also write the raw rows")
    args = ap.parse_args()

    rows = generate()
    bad = verify(rows)
    if bad:
        print("MANIFEST MISMATCH — the generator no longer produces the items "
              "the committed numbers were measured on:")
        for i in bad:
            print(f"  {i}")
        print("Re-run scripts/build_benign_longform.py to re-pin, and re-measure.")
        return 1

    records, cap = measure(rows)

    limit = windowed_coverage_limit()
    print(f"benign_longform — {len(records)} items, "
          f"L1_MAX_SCAN_CHARS = {cap:,}")
    print(f"  wall-clock bounds PINNED; window coverage limit = {limit:,} chars")
    print("  (an item is truncated iff it is longer than that — on any machine)")
    print()
    hdr = (f"{'id':34s} {'chars':>9s}  {'open':<38s} {'closed':<10s}")
    print(hdr)
    print("-" * len(hdr))
    for r in records:
        rules = ",".join(x.replace("LLM01_", "") for x in r["open"]["rules"]) or "-"
        print(f"{r['id']:34s} {r['chars']:>9,}  "
              f"{r['open']['action']:<8s} {rules:<29s} "
              f"{r['closed']['action']:<10s}")

    print()
    n = len(records)
    clean = [r for r in records if r["default_clean"]]
    dirty = [r for r in records if not r["default_clean"]]
    over = sum(1 for r in records if r["oversized"])
    unread = sum(1 for r in records if r["tail_unread"])
    covered = sum(1 for r in records if r["oversized"] and not r["tail_unread"])

    print(f"  items                                    {n}")
    print(f"  over the {cap:,}-char cap              {over}")
    print(f"    ...FULLY covered by the windowed scan  {covered}")
    print(f"    ...tail never read                     {unread}")
    print()
    print(f"  clean at the DEFAULT posture             {len(clean)}")
    print(f"  scoring on CONTENT at the default        {len(dirty)}"
          "   (excluded from the bounds cost below — see finding 2)")
    print()
    print("  THE BOUNDS COST, over default-clean items only")
    fp = [r for r in clean
          if r["closed"]["action"] == "blocked" and not r["tail_unread"]]
    tp = [r for r in clean
          if r["closed"]["action"] == "blocked" and r["tail_unread"]]
    ok = [r for r in clean if r["closed"]["action"] != "blocked"]
    print(f"    refused, tail genuinely unread          {len(tp)}"
          "   (the group working as designed)")
    print(f"    refused, FULLY READ                     {len(fp)}"
          "   <- false positives")
    print(f"    not refused                             {len(ok)}")
    if fp:
        print(f"      {[r['id'] for r in fp]}")
    print()
    print("  finding 2 — content hits on realistic long operational text")
    for r in dirty:
        print(f"    {r['id']:32s} {','.join(r['content_rules'])}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"cap": cap, "rows": records}, fh, indent=1, sort_keys=True)
        print(f"\n  wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
