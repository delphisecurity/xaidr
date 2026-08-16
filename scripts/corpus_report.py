#!/usr/bin/env python3
"""Measure the shell corpus against the installed sensor and print one table.

Run it from the repository root:

    python scripts/corpus_report.py

What it is for: every detection change is supposed to be measured against
tests/fixtures/shell_corpus.json rather than eyeballed in a diff. A rule that
misses and a rule that over-blocks both look the same in a patch; they look
completely different here. Run this before and after a rule change and put the
two tables in the pull request.

WHAT THIS SCRIPT IS NOT: it does not own any threshold. The attack numbers below
are reported, never asserted — no floor, no target, no "coverage must be N%".
The regression floors live in the test suite (tests/test_benign_prose.py's
ATTACK_BASELINE_* and the per-class tests in tests/test_shell_classes_stage3.py)
and that is deliberate: one place to argue about, and it is the place that gates
the merge. Reading the numbers is a human job; holding the line is pytest's.

The ONE thing this script does enforce is the benign side, because a false
positive is the failure mode that gets a security tool switched off:

  * benign COMMANDS (the false-positive gate) must not score and must not block
  * benign PROSE must not block, except for the entries the suite already
    documents as accepted blockers

Those are read from the test suite rather than restated here, so the exception
list cannot drift between the two. Exit status is 0 when the benign gates hold
and 1 when any of them is violated.

Standard library and the `xaidr` package only — no third-party imports, no
network, no telemetry (the sensor is constructed with a null reporter).

Definitions used in the table, matching the test suite exactly so the numbers
are comparable:

  classified  `classify("run_command", {"command": cmd})` returned something
              other than "unknown" — the sensor understood what the command
              does, whether or not any rule fired
  detected    `scan_tool_call("run_command", …).score > 0`
  blocked     `scan_tool_call("run_command", …).action == "blocked"`
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "shell_corpus.json")
PROSE_TEST = os.path.join(REPO_ROOT, "tests", "test_benign_prose.py")

WIDTH = 78


# ── helpers ──────────────────────────────────────────────────────────────────

def _quiet(fn, *args, **kwargs):
    """Run a sensor call with its stdout swallowed.

    The sensor prints its own detection lines; in a report they would bury the
    table under several hundred lines of noise.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def _pct(hit: int, total: int) -> str:
    return f"{100.0 * hit / total:.0f}%" if total else "—"


def _cell(hit: int, total: int) -> str:
    return f"{hit:>4} ({_pct(hit, total):>4})"


def _rule(char: str = "─") -> str:
    return char * WIDTH


def _documented_blocking_prose() -> tuple[dict, str]:
    """Read KNOWN_BLOCKING_PROSE out of the prose test, without importing it.

    Parsed with `ast` rather than imported because importing the test module
    would drag in pytest, and this script is meant to run against a bare install
    with nothing but the package present.

    Returns (mapping, note). On any failure the mapping is empty, which makes
    the gate strictly stricter — every blocking prose entry then counts as a
    violation — and the note says why.
    """
    try:
        with open(PROSE_TEST, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=PROSE_TEST)
    except OSError as exc:
        return {}, f"could not read {os.path.relpath(PROSE_TEST, REPO_ROOT)}: {exc}"

    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "KNOWN_BLOCKING_PROSE" not in names:
            continue
        try:
            value = ast.literal_eval(node.value)
        except ValueError as exc:
            return {}, f"KNOWN_BLOCKING_PROSE is not a literal: {exc}"
        if isinstance(value, dict):
            return value, ""

    return {}, "KNOWN_BLOCKING_PROSE not found in the prose test"


# ── measurement ──────────────────────────────────────────────────────────────

def measure(corpus, sensor, classify):
    """Run the whole corpus through the sensor. Returns a results dict."""
    by_class = defaultdict(lambda: {"n": 0, "classified": 0, "detected": 0, "blocked": 0})

    for entry in corpus["attacks"]:
        command = entry["command"]
        row = by_class[entry["class"]]
        row["n"] += 1
        if classify("run_command", {"command": command})[0] != "unknown":
            row["classified"] += 1
        result = _quiet(sensor.scan_tool_call, "run_command", {"command": command})
        if result.score > 0:
            row["detected"] += 1
        if result.action == "blocked":
            row["blocked"] += 1

    benign_scored, benign_blocked = [], []
    for entry in corpus["benign"]:
        command = entry["command"]
        result = _quiet(sensor.scan_tool_call, "run_command", {"command": command})
        if result.score > 0:
            benign_scored.append((command, result.score, result.rules))
        if result.action == "blocked":
            benign_blocked.append((command, result.score, result.rules))

    prose_input, prose_tool = [], []
    for entry in corpus["benign_prose"]:
        if _quiet(sensor.scan, entry["text"], direction="input").action == "blocked":
            prose_input.append(entry["id"])
        if _quiet(sensor.scan_tool_call, "send_message", {"body": entry["text"]}).action == "blocked":
            prose_tool.append(entry["id"])

    return {
        "by_class": dict(by_class),
        "benign_scored": benign_scored,
        "benign_blocked": benign_blocked,
        "benign_n": len(corpus["benign"]),
        "prose_input": prose_input,
        "prose_tool": prose_tool,
        "prose_n": len(corpus["benign_prose"]),
    }


# ── report ───────────────────────────────────────────────────────────────────

def print_report(results, documented, doc_note) -> bool:
    """Print the table. Returns True when every benign gate holds."""
    by_class = results["by_class"]

    print(_rule("="))
    print("xaidr corpus report")
    print(f"fixture: {os.path.relpath(FIXTURE, REPO_ROOT)}")
    print(_rule("="))
    print()

    # ── attacks, per class ──
    total_n = sum(r["n"] for r in by_class.values())
    print(f"ATTACKS BY CLASS  (n={total_n})")
    print(f"{'class':<24}{'n':>5}{'classified':>14}{'detected':>14}{'blocked':>14}")
    print(_rule())
    for name in sorted(by_class):
        row = by_class[name]
        print(
            f"{name:<24}{row['n']:>5}"
            f"{_cell(row['classified'], row['n']):>14}"
            f"{_cell(row['detected'], row['n']):>14}"
            f"{_cell(row['blocked'], row['n']):>14}"
        )
    print(_rule())
    totals = {k: sum(r[k] for r in by_class.values()) for k in ("classified", "detected", "blocked")}
    print(
        f"{'TOTAL':<24}{total_n:>5}"
        f"{_cell(totals['classified'], total_n):>14}"
        f"{_cell(totals['detected'], total_n):>14}"
        f"{_cell(totals['blocked'], total_n):>14}"
    )
    print()
    print("  Reported, not asserted. The regression floors live in the test suite.")
    print()

    ok = True

    # ── benign commands ──
    benign_n = results["benign_n"]
    scored, blocked = results["benign_scored"], results["benign_blocked"]
    print(f"BENIGN COMMANDS  (n={benign_n})   the false-positive gate")
    print(_rule())
    print(f"  scored (score > 0) : {len(scored):>4}    gate: must be 0    "
          f"{'PASS' if not scored else 'FAIL'}")
    print(f"  blocked            : {len(blocked):>4}    gate: must be 0    "
          f"{'PASS' if not blocked else 'FAIL'}")
    for command, score, rules in scored:
        print(f"    SCORED  {command!r} -> {score} via {rules}")
    for command, score, rules in blocked:
        print(f"    BLOCKED {command!r} -> {score} via {rules}")
    if scored or blocked:
        ok = False
    print()

    # ── benign prose ──
    prose_n = results["prose_n"]
    prose_input, prose_tool = results["prose_input"], results["prose_tool"]
    expected_input = sorted(k for k, v in documented.items() if v[0] == "input")
    expected_tool = sorted(k for k, v in documented.items() if v[0] == "tool")
    unexpected_input = sorted(set(prose_input) - set(expected_input))
    unexpected_tool = sorted(set(prose_tool) - set(expected_tool))

    print(f"BENIGN PROSE  (n={prose_n})   text ABOUT dangerous commands must not block")
    print(_rule())
    if doc_note:
        print(f"  NOTE: {doc_note}")
        print("        every blocking entry is therefore treated as a violation.")
    print(f"  blocked, content path  : {len(prose_input):>4}"
          f"{'    ' + ', '.join(prose_input) if prose_input else ''}")
    print(f"  blocked, tool-arg path : {len(prose_tool):>4}"
          f"{'    ' + ', '.join(prose_tool) if prose_tool else ''}")
    if expected_input or expected_tool:
        documented_ids = sorted(set(expected_input) | set(expected_tool))
        print(f"  documented as accepted : {', '.join(documented_ids)}"
              "   (tests/test_benign_prose.py)")
    print(f"  gate: no UNDOCUMENTED prose blocks    "
          f"{'PASS' if not (unexpected_input or unexpected_tool) else 'FAIL'}")
    for pid in unexpected_input:
        print(f"    BLOCKED (content path, undocumented) {pid}")
    for pid in unexpected_tool:
        print(f"    BLOCKED (tool-arg path, undocumented) {pid}")
    if unexpected_input or unexpected_tool:
        ok = False

    # A documented blocker that stopped blocking is not a benign-gate violation
    # — it is the gate getting cleaner — but the suite asserts on it, so say so
    # rather than letting the report and pytest disagree silently.
    stale = sorted((set(expected_input) - set(prose_input))
                   | (set(expected_tool) - set(prose_tool)))
    if stale:
        print(f"  note: {', '.join(stale)} no longer blocks — the suite expects it to; "
              "drop it from KNOWN_BLOCKING_PROSE")
    print()

    print(_rule("="))
    print(f"BENIGN GATES: {'PASS' if ok else 'VIOLATED'}")
    print(_rule("="))
    return ok


def main() -> int:
    try:
        with open(FIXTURE, encoding="utf-8") as fh:
            corpus = json.load(fh)
    except OSError as exc:
        print(f"error: cannot read the corpus fixture: {exc}", file=sys.stderr)
        print("       run this from the repository root: python scripts/corpus_report.py",
              file=sys.stderr)
        return 2

    try:
        from xaidr import Sensor
        from xaidr.authz.classifier import classify
    except ImportError as exc:
        print(f"error: the xaidr package is not importable: {exc}", file=sys.stderr)
        print("       install it first: pip install .", file=sys.stderr)
        return 2

    class _NullReporter:
        """No telemetry, no network — the report only needs the verdicts."""

        def report(self, batch): pass

        def close(self): pass

    sensor = Sensor(agent_id="corpus-report", enforcement_mode="block",
                    reporter=_NullReporter())
    try:
        results = measure(corpus, sensor, classify)
    finally:
        # close_sync, not close — close() is a coroutine and calling it from
        # sync code silently drops it (and warns).
        with contextlib.suppress(Exception):
            sensor.close_sync()

    documented, doc_note = _documented_blocking_prose()
    return 0 if print_report(results, documented, doc_note) else 1


if __name__ == "__main__":
    sys.exit(main())
