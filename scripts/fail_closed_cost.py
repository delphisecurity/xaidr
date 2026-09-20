#!/usr/bin/env python3
"""What each ``fail_closed`` group costs on the committed BENIGN pools.

    python scripts/fail_closed_cost.py                    # from a checkout
    cd / && /path/to/venv/bin/python -I \
        /path/to/scripts/fail_closed_cost.py --pools /path/to/clone

This is the regenerator U-1 (``docs/releasing.md``) requires for the 814-row
table in ``docs/fail-closed-design.md`` §e. Those numbers were measured by a
harness that was described in prose and never committed, which is the same
state the seven unreproducible corpus digests were in: a figure that reads as
rigour and cannot be recomputed. This script is that harness, committed.

WHAT IS COUNTED. A **refusal** is a verdict whose ``category`` is
``fail_closed`` — not any block. ``asi.benign``, ``heldout.benign`` and
``shell.prose`` each contain one row that the content layer blocks today at the
default posture, with no group closed; counting those as a fail-closed cost
would blame the option for verdicts it did not produce. The per-config
``blocked`` column is printed beside ``refused`` so the two stay distinguishable.

WHICH GROUPS. ``artifact`` is absent by construction and that is not an
oversight: it refuses to CONSTRUCT the sensor and never produces a verdict on
traffic, so it has no per-row cost to measure. See §f1 and
``failclosed.resolve()``, which rejects ``{'artifact': 'approval_required'}``
for the same reason. Its cost is measured by emptying rule assets one at a time
(§e, "What fail-open costs today"), not here.

THE POOLS: the benign half of the ``scripts/corpus_diff.py`` pool list, plus
``benign_a2a/nested.jsonl``, which ``corpus_diff`` does not carry. 814 rows over
725 distinct items — ``shell.prose`` is scanned on both the input and the tool
surface and counted once per surface.

THE ``controls`` AND ``internal`` ZEROS ARE BLIND AND ARE NOT A COST. This
harness installs no extensions, no escalators and no breaker, so no control
fault can occur and nothing in those groups can fire. The zeros here are a
**no-movement gate on the default**, not a measurement of those groups; they are
measured by fault injection in ``tests/test_fail_closed_sabotage.py``. Printed
with that label so the table cannot be read as coverage it does not have.

Standard library and ``xaidr`` only. No network. Null reporter throughout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


class _NullReporter:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass


#: Configs swept, in the order an operator would consider them. ``artifact`` is
#: deliberately absent — see the module docstring.
CONFIGS = (
    (),
    ("controls",),
    ("bounds",),
    ("internal",),
    ("bounds", "controls", "internal"),
)

#: Groups whose zero on this harness is structural, not measured.
BLIND = ("controls", "internal")

#: Rows this harness must find, per pool. A gate whose population can silently
#: shrink to nothing reports "refused 0 of 0" as a PASS — the passes-vacuously
#: failure, which reads as coverage while performing none. A moved or renamed
#: pool file must make this script LOUD, not green, so the counts are pinned
#: here and checked before any verdict is computed. Update deliberately when a
#: pool genuinely changes size, and say so in the commit.
EXPECTED = {
    "asi.benign": 146, "benign_a2a": 60, "benign_disc": 50, "benign_dml": 50,
    "benign_tc": 190, "heldout.benign": 50, "shell.benign": 78,
    "shell.prose": 89, "shell.prose.tool": 89, "shell.template": 12,
}
EXPECTED_TOTAL = sum(EXPECTED.values())   # 814


def check_population(rows):
    """Raise unless every pool contributed exactly the rows it is supposed to."""
    seen = {}
    for rid, _ in rows:
        seen[_pool_of(rid)] = seen.get(_pool_of(rid), 0) + 1
    problems = []
    for pool in sorted(set(EXPECTED) | set(seen)):
        want, got = EXPECTED.get(pool), seen.get(pool, 0)
        if want is None:
            problems.append(f"  {pool}: {got} rows from a pool this gate does not know about")
        elif want != got:
            problems.append(f"  {pool}: expected {want} rows, found {got}")
    if len(rows) != EXPECTED_TOTAL:
        problems.append(f"  TOTAL: expected {EXPECTED_TOTAL} rows, found {len(rows)}")
    if problems:
        raise SystemExit(
            "POPULATION CHECK FAILED — this gate is measuring a different corpus "
            "than it was written against, so its verdict means nothing:\n"
            + "\n".join(problems)
            + "\n\nA missing or renamed pool file makes every config report "
              "'refused 0', which is a PASS this script must never give."
        )


def _load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def benign_rows(pools):
    """Every committed BENIGN row as (row_id, callable(sensor) -> ScanResult).

    Mirrors ``corpus_diff.dump_rows`` boundary for boundary, minus the attack
    pools and plus ``benign_a2a``. Kept as thunks rather than results so the
    same row set can be replayed under each config without re-reading the files.
    """
    rows = []

    with open(os.path.join(pools, "tests", "fixtures", "shell_corpus.json"),
              encoding="utf-8") as fh:
        shell = json.load(fh)

    for i, e in enumerate(shell["benign"]):
        args = {"command": e["command"]}
        rows.append((f"shell.benign/{i:03d}",
                     lambda s, a=args: s.scan_tool_call("run_command", a)))
    for e in shell["benign_prose"]:
        t = e["text"]
        rows.append((f"shell.prose/{e['id']}",
                     lambda s, t=t: s.scan(t, direction="input")))
        rows.append((f"shell.prose.tool/{e['id']}",
                     lambda s, t=t: s.scan_tool_call("send_message", {"body": t})))
    for e in shell["benign_templates"]:
        t = e["template"]
        rows.append((f"shell.template/{e['id']}",
                     lambda s, t=t: s.scan(t, direction="input")))

    for e in _load_jsonl(os.path.join(pools, "asi_battery", "benign.jsonl")):
        steps = e["steps"] if e["boundary"] == "sequence" else [e]
        for i, step in enumerate(steps):
            rid = f"asi.benign/{e['id']}#{i}" if e["boundary"] == "sequence" \
                else f"asi.benign/{e['id']}"
            rows.append((rid, lambda s, st=step: _scan_step(s, st["boundary"], st)))

    for pool, name in (("benign_tc", "corpus.jsonl"),
                       ("benign_disc", "discriminator.jsonl"),
                       ("benign_dml", "sql_dml.jsonl")):
        for e in _load_jsonl(os.path.join(pools, "benign_toolcalls", name)):
            rows.append((f"{pool}/{e['id']}",
                         lambda s, e=e: s.scan_tool_call(e["tool"], e["args"])))

    for e in _load_jsonl(os.path.join(pools, "heldout", "benign.jsonl")):
        rows.append((f"heldout.benign/{e['id']}",
                     lambda s, e=e: s.scan(e["prompt"], direction="input")))

    for e in _load_jsonl(os.path.join(pools, "benign_a2a", "nested.jsonl")):
        body = json.dumps(e["body"])
        rows.append((f"benign_a2a/{e['id']}",
                     lambda s, b=body: s.scan_a2a(b, destination="peer-agent")))

    return rows


def _scan_step(sensor, boundary, step):
    if boundary == "input":
        return sensor.scan(step["text"], direction="input")
    if boundary == "output":
        return sensor.scan_output(step["text"])
    if boundary == "a2a":
        return sensor.scan_a2a(step["text"], destination="peer-agent")
    if boundary == "tool_call":
        return sensor.scan_tool_call(step["tool"], step.get("args") or {})
    raise ValueError(f"unknown boundary {boundary!r}")


def _pool_of(rid):
    return rid.split("/", 1)[0]


def sweep(pools):
    from xaidr import Sensor
    from xaidr.failclosed import FAIL_CLOSED_CATEGORY

    rows = benign_rows(pools)
    check_population(rows)
    results = []

    for cfg in CONFIGS:
        sensor = Sensor(agent_id="fail-closed-cost", enforcement_mode="block",
                        reporter=_NullReporter(), fail_closed=cfg)
        refused, blocked = [], 0
        for rid, thunk in rows:
            r = thunk(sensor)
            if r.category == FAIL_CLOSED_CATEGORY:
                refused.append((rid, list(r.rules or [])))
            elif r.action == "blocked":
                blocked += 1
        results.append((cfg, len(rows), refused, blocked))

    return rows, results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pools", default=os.getcwd(),
                    help="directory holding the committed pools (default: cwd)")
    ap.add_argument("--allow-source-tree", action="store_true",
                    help="permit importing xaidr from a checkout instead of a wheel")
    a = ap.parse_args()

    import xaidr
    if not a.allow_source_tree and "site-packages" not in xaidr.__file__:
        sys.exit(f"refusing to measure a source tree: {xaidr.__file__}\n"
                 f"install the wheel and run at a neutral cwd, or pass "
                 f"--allow-source-tree")

    rows, results = sweep(a.pools)

    pools_seen = {}
    for rid, _ in rows:
        pools_seen[_pool_of(rid)] = pools_seen.get(_pool_of(rid), 0) + 1

    print("=" * 78)
    print(f"FAIL-CLOSED COST ON THE COMMITTED BENIGN POOLS   xaidr {xaidr.__version__}")
    print("=" * 78)
    print(f"xaidr     : {xaidr.__file__}")
    print(f"pools     : {a.pools}")
    print()
    print("POOL SIZES (benign only)")
    for pool in sorted(pools_seen):
        print(f"  {pool:<22} n={pools_seen[pool]:>4}")
    print(f"  {'TOTAL':<22} n={len(rows):>4}")
    print()
    print(f"  {'fail_closed':<44} {'n':>5} {'refused':>8} {'blocked':>8}")
    print("  " + "-" * 68)
    for cfg, n, refused, blocked in results:
        label = f"fail_closed={cfg!r}"
        note = ""
        if cfg and all(g in BLIND for g in cfg):
            note = "  <- BLIND on this harness"
        print(f"  {label:<44} {n:>5} {len(refused):>8} {blocked:>8}{note}")
        for rid, rules in refused:
            print(f"      refused: {rid}  {rules}")
    print("  " + "-" * 68)
    print()
    print("  'refused' counts category == 'fail_closed' ONLY. 'blocked' is the")
    print("  content layer and is expected to be non-zero and constant: it is the")
    print("  same 3 rows at every config, and they are not a cost of this option.")
    print()
    print("  The controls/internal zeros are STRUCTURAL: this harness installs no")
    print("  extensions, no escalators and no breaker, so no control fault can")
    print("  occur. Those groups are measured in tests/test_fail_closed_sabotage.py,")
    print("  by injecting the faults. Read the zeros as a no-movement gate on the")
    print("  DEFAULT, never as a false-positive rate for those groups.")

    default_refused = results[0][2]
    if default_refused:
        print()
        print(f"GATE FAIL: the DEFAULT posture refused {len(default_refused)} row(s); "
              f"it must refuse none.")
        return 1
    print()
    print(f"GATE PASS: fail_closed=() refused 0 of {len(rows)} benign rows.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
