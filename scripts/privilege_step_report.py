#!/usr/bin/env python3
"""Regenerate the README's "14 of the battery's 48 tool-call steps". Nothing else did.

    python scripts/privilege_step_report.py
    python scripts/privilege_step_report.py --json      # machine-readable

WHY THIS EXISTS. The ASI03 row of README.md's OWASP table publishes:

    it fires on **14 of the battery's 48 tool-call steps** (30 whole
    `tool_call` cases plus the 18 tool-call steps inside `sequence` cases)

Three figures — 14, 48, and the 30 + 18 that make up the 48 — and until this
script none of them had a regenerator. `scripts/asi_battery_report.py` measures
whole CASES at their own boundary and stops a sequence at its first detection,
so it cannot produce this ratio even in principle: a sequence caught at step 1
never has its later tool-call steps scanned, and a tool-call step that fires
inside a case some other rule already caught is invisible to it. The number was
therefore not recomputable from anything in the tree, which is what U-1 forbids.

It is also the LAST figure in that row without one. The same sentence's "0 of
190" and "0 of 50" come from `benign_toolcall_report.py`, the "24 of 120" from
`benign_domain_report.py`, and the "8 of 11" from `asi_battery_report.py`.

WHAT IT MEASURES, precisely. `scan_privileged_action(tool, args)` — the detector's
own entry point — is called on EVERY tool-call step in `asi_battery/attacks.jsonl`
independently, and a step counts as fired if that call returns any finding. This
is deliberately the detector in isolation rather than a full `scan_tool_call`,
because the claim in the README is about this detector's reach and not about
whether something else also caught the case.

THE DENOMINATOR IS EVERY TOOL-CALL STEP, not a count of privilege-shaped ones.
The README says so and this script prints the miss count beside the hit count to
keep that readable: the detector is not aimed at the other 34 and does not fire
on them. A denominator that quietly became "the ones we expected to fire" would
turn a 14/48 reach claim into a 14/14 tautology.

UNAFFECTED BY THE F9 RELABELLING, and this script is how that is checkable
rather than assertable. F9 moved 28 cases between categories without editing any
`tool` or `args`, so a whole-battery step count over all categories cannot move.
The per-category breakdown below shows the labels; the total does not depend on
them.

Standard library + `xaidr`. No sensor is built, no policy is bound, no network.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

# ── which xaidr answered? ────────────────────────────────────────────────────
# See scripts/_provenance.py: the repo root goes on sys.path (the default), the
# resolved path and version are printed before any table, and
# XAIDR_FROM_INSTALL=1 measures a published artifact instead and refuses a tree.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _provenance import bind, repo_root_of  # noqa: E402

REPO_ROOT = repo_root_of(__file__)
ATTACKS = os.path.join(REPO_ROOT, "asi_battery", "attacks.jsonl")
PROV = bind(__file__)

from xaidr.scanner.privilege_action import scan_privileged_action  # noqa: E402

WIDTH = 88


def _rule(c="-"):
    return c * WIDTH


def _load(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def tool_call_steps(cases):
    """Every tool-call step in the battery, from both places they occur.

    Returns dicts with `case`, `category`, `step` (None for a whole case, else
    the 1-based index within the sequence), `tool` and `args`.

    The two sources are kept distinguishable because the README's parenthetical
    publishes them separately (30 + 18) and a drift in either half that the
    total absorbed would otherwise be invisible.
    """
    out = []
    for c in cases:
        if c["boundary"] == "tool_call":
            out.append({"case": c["id"], "category": c["category"], "step": None,
                        "origin": "case", "tool": c["tool"],
                        "args": c.get("args") or {}})
        elif c["boundary"] == "sequence":
            for i, st in enumerate(c.get("steps") or [], start=1):
                if st.get("boundary") == "tool_call":
                    out.append({"case": c["id"], "category": c["category"],
                                "step": i, "origin": "sequence",
                                "tool": st["tool"], "args": st.get("args") or {}})
    return out


def measure():
    cases = _load(ATTACKS)
    steps = tool_call_steps(cases)

    fired, missed = [], []
    for s in steps:
        findings = scan_privileged_action(s["tool"], s["args"])
        rec = {**s, "rules": sorted({f["rule"] for f in findings})}
        (fired if findings else missed).append(rec)

    per_cat = defaultdict(lambda: {"steps": 0, "fired": 0})
    for s in steps:
        per_cat[s["category"]]["steps"] += 1
    for s in fired:
        per_cat[s["category"]]["fired"] += 1

    return {
        "total_steps": len(steps),
        "from_whole_cases": sum(1 for s in steps if s["origin"] == "case"),
        "from_sequences": sum(1 for s in steps if s["origin"] == "sequence"),
        "fired": len(fired),
        "missed": len(missed),
        "fired_steps": fired,
        "per_category": {k: dict(v) for k, v in sorted(per_cat.items())},
        "rule_counts": {
            r: sum(1 for s in fired if r in s["rules"])
            for r in sorted({r for s in fired for r in s["rules"]})
        },
    }


def _label(s):
    return s["case"] if s["step"] is None else f"{s['case']} step {s['step']}"


def print_report(d):
    print()
    print(_rule("="))
    print("PRIVILEGE-ACTION REACH OVER THE BATTERY'S TOOL-CALL STEPS")
    print(_rule("="))
    print(f"pool     : asi_battery/attacks.jsonl")
    print(f"detector : xaidr.scanner.privilege_action.scan_privileged_action()")
    print(f"fired    : the call returns at least one finding")
    print(_rule("="))
    print()
    print(f"  {d['from_whole_cases']} whole `tool_call` cases")
    print(f"+ {d['from_sequences']} tool-call steps inside `sequence` cases")
    print(f"= {d['total_steps']} tool-call steps in the battery")
    print()
    print(f"  the privilege-action detector fires on "
          f"{d['fired']} of {d['total_steps']}")
    print(f"  and does not fire on the other {d['missed']}, which it is not "
          f"aimed at")
    print()
    print(_rule())
    print("THE STEPS IT FIRES ON")
    print(_rule())
    for s in d["fired_steps"]:
        print(f"  {_label(s):<22} {s['tool']:<26} {', '.join(s['rules'])}")
    print()
    print(_rule())
    print("BY RULE  (a step can fire more than one)")
    print(_rule())
    for r, n in sorted(d["rule_counts"].items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {r:<34}{n:>4}")
    print()
    print(_rule())
    print("BY CATEGORY  (labels only — the total does not depend on them)")
    print(_rule())
    for cat, v in d["per_category"].items():
        print(f"  {cat:<10}{v['fired']:>4} of {v['steps']:<4} tool-call steps")
    print(_rule("="))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true",
                    help="print the measurement as JSON instead of a table")
    args = ap.parse_args(argv)

    data = measure()
    if args.json:
        data.pop("fired_steps", None)
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print_report(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
