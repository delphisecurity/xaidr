#!/usr/bin/env python3
"""Measure false positives on the benign NESTED A2A corpus.

    python scripts/benign_a2a_report.py

WHY THIS EXISTS. The A2A structural validator used to read only the top-level
message, so a forged role or an id traversal inside `result.status.message` or
`result.history[]` passed unexamined. Reaching those containers means walking
attacker-controlled structure and scanning strictly more values — which is
strictly more chances to misfire.

The existing pools cannot measure that. Instrumenting
`A2AStructuralValidator.validate` across `asi_battery/`, `heldout/` and
`benign_toolcalls/` shows it is called ZERO times: the 42 items those pools
route through `scan_a2a` are PLAIN TEXT, so the body never parses to a dict and
the structural layer never runs. A false-positive delta of zero on a population
the code does not touch measures nothing. That is the blind population this
corpus closes.

`benign_a2a/nested.jsonl` is 60 real A2A JSON-RPC bodies, every one benign, that
between them populate every container the spec says can hold a Message, a Part
or an Artifact: params.message, result (bare Message), result.status.message,
result.history[], result.artifacts[], result.artifact, result.tasks[], and the
bare Task / bare Message in-process shapes. It deliberately contains the shapes
the walk could plausibly fire on — namespaced ids with slashes, filesystem paths
in prose, long artifact text, deeply nested metadata, 24-turn histories, parts
without a `kind` discriminator — because a benign corpus that avoids them
measures nothing.

THE GATE: zero structural signals on all 60. Not "few". A benign body has no
structural anomaly by construction, so any signal here is a false positive.

Standard library + xaidr. Monitor mode, null reporter, no network.
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict

# ── which xaidr answered? ────────────────────────────────────────────────────
# This is the script the defect was caught on: run under the published 1.17.0
# wheel it printed the same `A2A nodes walked: 274` as under 1.18.0, from a
# wheel whose a2a_structural.py has no `_walk_a2a_nodes` at all — because the
# bare `sys.path.insert(0, REPO)` it used to do made both runs measure the tree.
# `bind` prints which copy answered before anything else. See _provenance.py.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _provenance import bind, repo_root_of  # noqa: E402

REPO = repo_root_of(__file__)
CORPUS = os.path.join(REPO, "benign_a2a", "nested.jsonl")
PROV = bind(__file__)

from xaidr.scanner.a2a_structural import (  # noqa: E402
    A2AStructuralValidator,
    _walk_a2a_nodes,
)

WIDTH = 82


def _rule(c="-"):
    return c * WIDTH


def load():
    rows = []
    with open(CORPUS, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> int:
    rows = load()
    validator = A2AStructuralValidator()

    fps = []
    by_persona = defaultdict(lambda: [0, 0])
    containers = defaultdict(int)
    nodes_total = 0
    depth_max = 0

    for row in rows:
        body = row["body"]
        out = validator.validate(body, "a2a")
        nodes, bounds = _walk_a2a_nodes(body)
        nodes_total += len(nodes)
        for kind, _ in nodes:
            containers[kind] += 1
        persona = row.get("persona", "?")
        by_persona[persona][0] += 1
        if out["signals"] or bounds:
            by_persona[persona][1] += 1
            fps.append((row["id"], row.get("container", "?"), out["signals"], sorted(bounds)))

    print(_rule("="))
    print(f"BENIGN NESTED A2A CORPUS  -  structural false positives   (n={len(rows)})")
    print(_rule("="))
    print(f"corpus            : {os.path.relpath(CORPUS, REPO)}")
    print(f"A2A nodes walked  : {nodes_total}  (mean {nodes_total / len(rows):.1f} per body)")
    print("node kinds        : " + ", ".join(
        f"{k}={v}" for k, v in sorted(containers.items())))
    print()

    print("persona          n    structural FP")
    print(_rule())
    for persona in sorted(by_persona):
        n, fp = by_persona[persona]
        print(f"{persona:<15} {n:>3}    {fp:>3}")
    print(_rule())
    total_fp = sum(v[1] for v in by_persona.values())
    print(f"{'TOTAL':<15} {len(rows):>3}    {total_fp:>3}")
    print()

    if fps:
        print("FALSE POSITIVES")
        print(_rule())
        for rid, container, signals, bounds in fps:
            print(f"  [{rid}] {container}")
            if signals:
                print(f"      signals: {signals}")
            if bounds:
                print(f"      bounds exceeded: {bounds}")
        print()

    print(_rule("="))
    ok = total_fp == 0
    print(f"BENIGN NESTED A2A GATE: {'PASS' if ok else 'FAIL'}"
          f"   gate: structural FP must be 0, got {total_fp}")
    print(_rule("="))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
