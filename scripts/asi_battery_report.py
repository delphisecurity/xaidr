#!/usr/bin/env python3
"""Measure rules-only vs rules-plus-nano on the held-out ASI battery.

Run it from the repository root:

    python scripts/asi_battery_report.py

WHY THIS EXISTS
---------------
The existing agentic probe is 107 strings we authored; it confirms what we
already believed. This battery is authored to be held out: 120 attack cases and
120 register-matched benign cases across ASI01-ASI10, spanning the boundaries
each category actually crosses (input, tool call, output, A2A, and multi-step
sequences for the categories a single message cannot express — memory poisoning
written-then-read for ASI06, behavioural drift over calls for ASI10). Plain,
non-injection registers are used in every category, because the held-out nano
set showed that is where detection is blind. See asi_battery/README.md for
provenance and the technique breakdown.

WHAT IT REPORTS
---------------
Rules-only first, then rules-plus-nano. Per ASI category: catch rate (attacks
detected) and false-positive rate (benign detected), for each configuration,
plus the increment and every miss named. "Detected" means the scanner did not
return `allowed` (it flagged or blocked); enforcement mode is `monitor`, so a
block-worthy verdict surfaces as `flagged`. A sequence is detected if ANY of its
steps is detected; the script records which step caught it.

Nano only contributes on the INPUT boundary (it is scoped to inbound chat text
and only runs when the rules pipeline scored exactly 0.0). So on tool-call,
output, and A2A cases rules-plus-nano is identical to rules-only by construction.

NANO IS OPTIONAL. Without the `nano` extra / artifact the rules-only half still
runs and the rules-plus-nano half is reported NOT RUN, loudly.

Standard library + `xaidr` only. Monitor mode, null reporter: no telemetry, no
network, and the circuit breaker never blocks (so 240 sequential calls do not
perturb one another). Nothing is tuned to this set.
"""
from __future__ import annotations

import json
import os
import sys
import warnings
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BATTERY_DIR = os.path.join(REPO_ROOT, "asi_battery")
sys.path.insert(0, REPO_ROOT)

from xaidr.sensor import DelphiSensor  # noqa: E402

WIDTH = 92
CATEGORIES = [f"ASI{n:02d}" for n in range(1, 11)]


class _NullReporter:
    def report(self, batch): pass
    def close(self): pass


def _rule(c="-"):
    return c * WIDTH


def _load(name):
    rows = []
    with open(os.path.join(BATTERY_DIR, name), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _detected(result) -> bool:
    return result.action != "allowed"


def _scan_step(sensor, boundary, step):
    """Scan one step at its boundary; return the ScanResult."""
    if boundary == "input":
        return sensor.scan(step["text"], direction="input")
    if boundary == "output":
        return sensor.scan_output(step["text"])
    if boundary == "a2a":
        return sensor.scan_a2a(step["text"], destination="peer-agent")
    if boundary == "tool_call":
        return sensor.scan_tool_call(step["tool"], step.get("args") or {})
    raise ValueError(f"unknown boundary {boundary!r}")


def _scan_case(sensor, case):
    """Return (detected: bool, detail: dict) for one case.

    For a sequence, detected iff any step is; detail records the catching step.
    """
    if case["boundary"] == "sequence":
        caught_at = None
        best = None
        for i, step in enumerate(case["steps"], start=1):
            r = _scan_step(sensor, step["boundary"], step)
            if best is None or r.score > best[0]:
                best = (r.score, r)
            if _detected(r):
                caught_at = (i, step["boundary"], r)
                break
        if caught_at:
            i, b, r = caught_at
            return True, {"score": r.score, "rules": list(r.rules or []),
                          "nano_raw": r.nano_raw, "caught_step": i, "caught_boundary": b}
        r = best[1]
        return False, {"score": r.score, "rules": list(r.rules or []),
                       "nano_raw": r.nano_raw, "caught_step": None, "caught_boundary": None}
    # single-boundary case
    step = case if case["boundary"] != "tool_call" else case
    r = _scan_step(sensor, case["boundary"], case)
    return _detected(r), {"score": r.score, "rules": list(r.rules or []),
                          "nano_raw": r.nano_raw, "caught_step": None,
                          "caught_boundary": case["boundary"]}


def _measure(sensor, cases):
    out = {}
    for c in cases:
        det, detail = _scan_case(sensor, c)
        out[c["id"]] = {**detail, "detected": det, "category": c["category"],
                        "boundary": c["boundary"], "tests": c.get("tests"),
                        "mirrors": c.get("mirrors")}
    return out


def _rate(hit, total):
    pct = 100.0 * hit / total if total else 0.0
    return f"{hit}/{total} ({pct:.0f}%)"


def _nano_provenance():
    info = {}
    try:
        from xaidr.scanner import nano as nano_mod
        status, applies, _dev = nano_mod.figure_applies()
        env = nano_mod.live_environment()
        info["onnxruntime"] = env.get("onnxruntime")
        info["status"] = status
    except Exception as exc:
        info["error"] = repr(exc)
    return info


def _build(enable_nano):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return DelphiSensor(agent_id="asi-battery", enforcement_mode="monitor",
                                enable_nano=enable_nano, reporter=_NullReporter()), None
    except Exception as exc:
        return None, exc


def main():
    attacks = _load("attacks.jsonl")
    benign = _load("benign.jsonl")

    rules_sensor, _ = _build(enable_nano=False)
    ra = _measure(rules_sensor, attacks)
    rb = _measure(rules_sensor, benign)

    nano_sensor, nano_err = _build(enable_nano=True)
    nano_on = nano_sensor is not None
    if nano_on:
        na = _measure(nano_sensor, attacks)
        nb = _measure(nano_sensor, benign)

    print(_rule("="))
    print("HELD-OUT ASI BATTERY  -  rules-only vs rules-plus-nano")
    print(_rule("="))
    print(f"dataset      : {len(attacks)} attacks, {len(benign)} benign "
          f"(asi_battery/attacks.jsonl, benign.jsonl)")
    print("detection    : action != 'allowed'; sequence = any step detected; mode=monitor")
    if nano_on:
        prov = _nano_provenance()
        print(f"nano runtime : onnxruntime {prov.get('onnxruntime')} "
              f"(figure status={prov.get('status')})")
    else:
        print("nano runtime : NOT AVAILABLE - rules-plus-nano NOT RUN")
        print(f"               reason: {nano_err!r}")
    print()

    # ---- per-category table ----
    print(_rule("="))
    print("PER-CATEGORY CATCH / FALSE-POSITIVE")
    print(_rule("="))
    hdr = (f"{'cat':<7}{'rules catch':>14}{'rules FP':>12}"
           f"{'  |':>4}{'+nano catch':>14}{'+nano FP':>12}{'  nano adds':>12}")
    print(hdr)
    print(_rule())
    tot = defaultdict(int)
    for cat in CATEGORIES:
        a_ids = [c["id"] for c in attacks if c["category"] == cat]
        b_ids = [c["id"] for c in benign if c["category"] == cat]
        rc = sum(ra[i]["detected"] for i in a_ids)
        rf = sum(rb[i]["detected"] for i in b_ids)
        tot["rc"] += rc; tot["rf"] += rf; tot["na"] += len(a_ids); tot["nb"] += len(b_ids)
        row = f"{cat:<7}{_rate(rc,len(a_ids)):>14}{_rate(rf,len(b_ids)):>12}{'  |':>4}"
        if nano_on:
            nc = sum(na[i]["detected"] for i in a_ids)
            nf = sum(nb[i]["detected"] for i in b_ids)
            added = sum(1 for i in a_ids if na[i]["detected"] and not ra[i]["detected"])
            tot["nc"] += nc; tot["nf"] += nf; tot["added"] += added
            row += f"{_rate(nc,len(a_ids)):>14}{_rate(nf,len(b_ids)):>12}{('+'+str(added)):>12}"
        print(row)
    print(_rule())
    trow = (f"{'ALL':<7}{_rate(tot['rc'],tot['na']):>14}{_rate(tot['rf'],tot['nb']):>12}{'  |':>4}")
    if nano_on:
        trow += (f"{_rate(tot['nc'],tot['na']):>14}{_rate(tot['nf'],tot['nb']):>12}"
                 f"{('+'+str(tot['added'])):>12}")
    print(trow)
    print()

    # ---- the increment ----
    if nano_on:
        added = [i for i in ra if na[i]["detected"] and not ra[i]["detected"]]
        added_fp = [i for i in rb if nb[i]["detected"] and not rb[i]["detected"]]
        print(_rule("="))
        print("THE INCREMENT (nano over rules alone)")
        print(_rule("="))
        print(f"attacks nano newly catches : {len(added)}")
        print(f"benign nano newly flags    : {len(added_fp)}  (new false positives)")
        for i in added:
            print(f"  +catch [{i}] {na[i]['category']}/{na[i]['boundary']}  "
                  f"nano_raw={na[i]['nano_raw']}")
        for i in added_fp:
            print(f"  +FP    [{i}] mirrors {nb[i]['mirrors']}  nano_raw={nb[i]['nano_raw']}")
        print()

    # ---- name every miss ----
    final = na if nano_on else ra
    label = "rules+nano" if nano_on else "rules-only"
    print(_rule("="))
    print(f"MISSES - attacks NOT detected by {label}, by category")
    print(_rule("="))
    total_miss = 0
    for cat in CATEGORIES:
        misses = [c for c in attacks if c["category"] == cat and not final[c["id"]]["detected"]]
        total_miss += len(misses)
        print(f"\n{cat}  ({len(misses)} missed)")
        for c in misses:
            d = final[c["id"]]
            print(f"  [{c['id']}] {c['boundary']:<9} score={d['score']:.2f} "
                  f"nano_raw={d['nano_raw']}")
            print(f"        {c['tests']}")
    print()
    print(f"TOTAL missed by {label}: {total_miss}/{len(attacks)}")
    print()

    # ---- false positives listed ----
    print(_rule("="))
    print("FALSE POSITIVES")
    print(_rule("="))
    print("rules-only:")
    for c in benign:
        if rb[c["id"]]["detected"]:
            print(f"  [{c['id']}] {c['category']}/{c['boundary']} score={rb[c['id']]['score']:.2f} "
                  f"rules={rb[c['id']]['rules'][:3]}")
    if nano_on:
        print("rules+nano (additional beyond rules-only):")
        for c in benign:
            if nb[c["id"]]["detected"] and not rb[c["id"]]["detected"]:
                print(f"  [{c['id']}] {c['category']}/{c['boundary']} "
                      f"nano_raw={nb[c['id']]['nano_raw']} rules={nb[c['id']]['rules'][:3]}")
    print()

    # ---- machine-readable ----
    summary = {"counts": {"attacks": len(attacks), "benign": len(benign)},
               "nano_available": nano_on, "per_category": {}}
    for cat in CATEGORIES:
        a_ids = [c["id"] for c in attacks if c["category"] == cat]
        b_ids = [c["id"] for c in benign if c["category"] == cat]
        entry = {"rules": {"catch": sum(ra[i]["detected"] for i in a_ids),
                           "fp": sum(rb[i]["detected"] for i in b_ids),
                           "n_attacks": len(a_ids), "n_benign": len(b_ids)}}
        if nano_on:
            entry["nano"] = {"catch": sum(na[i]["detected"] for i in a_ids),
                             "fp": sum(nb[i]["detected"] for i in b_ids)}
        entry["misses"] = [i for i in a_ids if not final[i]["detected"]]
        summary["per_category"][cat] = entry
    if nano_on:
        summary["nano_runtime"] = _nano_provenance()
    out_path = os.path.join(BATTERY_DIR, "last_run.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    print(_rule("="))
    print(f"machine-readable summary -> {out_path}")
    print(_rule("="))
    return 0


if __name__ == "__main__":
    sys.exit(main())
