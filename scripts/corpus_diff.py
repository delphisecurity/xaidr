#!/usr/bin/env python3
"""Compare two installed xaidr versions, verdict for verdict, over every committed pool.

This is the regenerator `docs/releasing.md` step 4 asks for and that U-1 says
must exist before any figure derived from it ships. Six release bodies — v1.9.0
through v1.14.0 — cite seven hex digests as the proof that detection did not
move, and not one of those digests has ever appeared in a committed file on any
branch. This script exists so that the 1.17.0 body does not add an eighth.

    # dump under each interpreter, at a neutral cwd, with -I
    cd / && /tmp/prevvenv/bin/python -I  /path/to/corpus_diff.py --dump /tmp/old.json --pools /path/to/clone
    cd / && /tmp/relvenv/bin/python  -I  /path/to/corpus_diff.py --dump /tmp/new.json --pools /path/to/clone

    # then diff, under any interpreter
    python3 corpus_diff.py --compare /tmp/old.json /tmp/new.json

TWO INTERPRETERS, ONE POOL DIRECTORY. The pools are read from `--pools` (a
clone of the tag) and the CODE comes from whichever interpreter runs the dump.
That separation is the point: the alternative — checking out each version and
running its own pools — compares two pools as well as two sensors, and a row
that exists on one side only then reads as a moved verdict.

`--dump` asserts `xaidr.__file__` is inside site-packages and refuses to run
otherwise, for the same reason step 3 does: run from a source tree, Python
imports `./xaidr/` in preference to the installed wheel and every number below
becomes a claim about the tree you were just editing.

WHAT IS COMPARED, per row: `action`, `score`, `category`, the ORDERED rule list,
and the impact class/tier from `classify()` for tool-call rows. Ordered, because
a rule moving position is a real change in what an operator reading the rule
list sees, and the 1.16.0 cut had exactly one such row (ASI03-A06) and nothing
else.

NO DIGEST IS PRINTED AS THE HEADLINE. The row count and the changed rows are
the evidence; a digest is a summary of evidence you can no longer check. A
digest IS printed at the end of `--compare`, over the dump files that are still
on disk beside it, so it can be recomputed by re-running the dumps.

Standard library and `xaidr` only. No network. Null reporter throughout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys


# ── pools ────────────────────────────────────────────────────────────────────

class _NullReporter:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass


def _load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _fields(result, impact=None):
    rules = list(result.rules or [])
    row = {
        "action": result.action,
        "score": round(float(result.score), 4),
        "category": result.category,
        "rules": rules,
    }
    if impact is not None:
        row["impact"] = list(impact)
    return row


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


def dump_rows(pools):
    """Every committed pool, through the installed sensor. Returns {row_id: fields}."""
    from xaidr import Sensor
    from xaidr.authz.classifier import classify

    sensor = Sensor(agent_id="corpus-diff", enforcement_mode="block",
                    reporter=_NullReporter())
    rows = {}

    # 1-4. the shell corpus: 277 attacks, 78 benign, 89 prose, 12 templates
    with open(os.path.join(pools, "tests", "fixtures", "shell_corpus.json"),
              encoding="utf-8") as fh:
        shell = json.load(fh)

    for i, e in enumerate(shell["attacks"]):
        args = {"command": e["command"]}
        rows[f"shell.attack/{i:03d}"] = _fields(
            sensor.scan_tool_call("run_command", args), classify("run_command", args))
    for i, e in enumerate(shell["benign"]):
        args = {"command": e["command"]}
        rows[f"shell.benign/{i:03d}"] = _fields(
            sensor.scan_tool_call("run_command", args), classify("run_command", args))
    for e in shell["benign_prose"]:
        # Prose is scanned on BOTH surfaces the corpus report gates, in one row.
        r_in = sensor.scan(e["text"], direction="input")
        r_tool = sensor.scan_tool_call("send_message", {"body": e["text"]})
        row = _fields(r_in)
        row["tool"] = _fields(r_tool)
        rows[f"shell.prose/{e['id']}"] = row
    for e in shell["benign_templates"]:
        rows[f"shell.template/{e['id']}"] = _fields(
            sensor.scan(e["template"], direction="input"))

    # 5-6. the ASI battery: sequences expand to one row per step (147 / 146)
    for pool, name in (("asi.attacks", "attacks.jsonl"), ("asi.benign", "benign.jsonl")):
        for e in _load_jsonl(os.path.join(pools, "asi_battery", name)):
            if e["boundary"] == "sequence":
                for i, step in enumerate(e["steps"]):
                    rows[f"{pool}/{e['id']}#{i}"] = _fields(
                        _scan_step(sensor, step["boundary"], step))
            else:
                rows[f"{pool}/{e['id']}"] = _fields(
                    _scan_step(sensor, e["boundary"], e))

    # 7-9. the benign tool-call pools: 190 + 50 + 50, every entry a tool call
    for pool, name in (("benign_tc", "corpus.jsonl"),
                       ("benign_disc", "discriminator.jsonl"),
                       ("benign_dml", "sql_dml.jsonl")):
        for e in _load_jsonl(os.path.join(pools, "benign_toolcalls", name)):
            rows[f"{pool}/{e['id']}"] = _fields(
                sensor.scan_tool_call(e["tool"], e["args"]),
                classify(e["tool"], e["args"]))

    # 10-11. the held-out pools: 50 + 50, input boundary
    for pool, name in (("heldout.attacks", "attacks.jsonl"),
                       ("heldout.benign", "benign.jsonl")):
        for e in _load_jsonl(os.path.join(pools, "heldout", name)):
            rows[f"{pool}/{e['id']}"] = _fields(
                sensor.scan(e["prompt"], direction="input"))

    return rows


# ── compare ──────────────────────────────────────────────────────────────────

def _flat(row, prefix=""):
    """Flatten one row to comparable field -> value pairs."""
    out = {}
    for k, v in row.items():
        if isinstance(v, dict):
            out.update(_flat(v, prefix=f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def compare(old, new):
    old_rows, new_rows = old["rows"], new["rows"]
    only_old = sorted(set(old_rows) - set(new_rows))
    only_new = sorted(set(new_rows) - set(old_rows))
    shared = sorted(set(old_rows) & set(new_rows))

    changes = []
    for rid in shared:
        a, b = _flat(old_rows[rid]), _flat(new_rows[rid])
        moved = {k: (a.get(k), b.get(k)) for k in sorted(set(a) | set(b))
                 if a.get(k) != b.get(k)}
        if moved:
            changes.append((rid, moved))
    return only_old, only_new, shared, changes


def _pool_of(rid):
    return rid.split("/", 1)[0]


def _gates(rows):
    """blocked / scored counts per pool — the numbers the release body reports."""
    out = {}
    for rid, row in rows.items():
        pool = _pool_of(rid)
        g = out.setdefault(pool, {"n": 0, "blocked": 0, "scored": 0})
        g["n"] += 1
        if row["action"] == "blocked":
            g["blocked"] += 1
        if row["score"] > 0:
            g["scored"] += 1
        if "tool" in row:  # prose: the tool surface has its own gate
            g.setdefault("tool_blocked", 0)
            if row["tool"]["action"] == "blocked":
                g["tool_blocked"] += 1
    return out


def print_compare(old, new):
    only_old, only_new, shared, changes = compare(old, new)
    v_old, v_new = old["version"], new["version"]

    print(f"xaidr corpus diff   {v_old} -> {v_new}")
    print(f"  old  {old['package']}")
    print(f"  new  {new['package']}")
    print(f"  pools {new['pools']}")
    print()
    print(f"compared={len(shared)}  only-in-old={len(only_old)}  only-in-new={len(only_new)}")
    for rid in only_old:
        print(f"  ONLY IN OLD  {rid}")
    for rid in only_new:
        print(f"  ONLY IN NEW  {rid}")
    print()

    print(f"CHANGED VERDICTS: {len(changes)} of {len(shared)}")
    for rid, moved in changes:
        print(f"  {rid}")
        for field, (a, b) in moved.items():
            print(f"      {field}: {a!r} -> {b!r}")
    if not changes:
        print("  (none — every compared row is identical field for field)")
    print()

    print("PER-POOL GATES   n   blocked  scored      (old -> new)")
    g_old, g_new = _gates(old["rows"]), _gates(new["rows"])
    for pool in sorted(set(g_old) | set(g_new)):
        a = g_old.get(pool, {"n": 0, "blocked": 0, "scored": 0})
        b = g_new.get(pool, {"n": 0, "blocked": 0, "scored": 0})
        flag = "" if (a["blocked"], a["scored"]) == (b["blocked"], b["scored"]) else "   <<< MOVED"
        print(f"  {pool:<18} {b['n']:>4}   {a['blocked']:>3} -> {b['blocked']:<3}  "
              f"{a['scored']:>3} -> {b['scored']:<3}{flag}")
        if "tool_blocked" in a or "tool_blocked" in b:
            print(f"  {'  (tool surface)':<18} {b['n']:>4}   "
                  f"{a.get('tool_blocked', 0):>3} -> {b.get('tool_blocked', 0):<3}")
    print()

    # The digest is a SUMMARY of the rows above, printed last and never alone.
    for label, dump in (("old", old), ("new", new)):
        body = json.dumps(dump["rows"], sort_keys=True, separators=(",", ":"))
        print(f"  {label} rows sha256  {hashlib.sha256(body.encode()).hexdigest()}")
    print("  regenerate: python scripts/corpus_diff.py --dump ... (both), then --compare")

    return 0 if not (only_old or only_new) else 1


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dump", metavar="FILE",
                    help="run every pool through the INSTALLED xaidr and write JSON")
    ap.add_argument("--pools", metavar="DIR", default=os.getcwd(),
                    help="directory holding the committed pools (a clone of the tag)")
    ap.add_argument("--compare", nargs=2, metavar=("OLD", "NEW"),
                    help="diff two dump files")
    ap.add_argument("--allow-source-tree", action="store_true",
                    help="skip the site-packages assertion (for a source-tree smoke run)")
    args = ap.parse_args()

    if args.compare:
        with open(args.compare[0], encoding="utf-8") as fh:
            old = json.load(fh)
        with open(args.compare[1], encoding="utf-8") as fh:
            new = json.load(fh)
        return print_compare(old, new)

    if not args.dump:
        ap.error("one of --dump or --compare is required")

    import xaidr
    if "site-packages" not in xaidr.__file__ and not args.allow_source_tree:
        print(f"refusing to dump from a source tree: {xaidr.__file__}\n"
              "  build the wheel, install it, and run this at a neutral cwd with -I.\n"
              "  (--allow-source-tree overrides, for smoke runs only.)", file=sys.stderr)
        return 2

    pools = os.path.abspath(args.pools)
    rows = dump_rows(pools)
    with open(args.dump, "w", encoding="utf-8") as fh:
        json.dump({"version": xaidr.__version__, "package": xaidr.__file__,
                   "pools": pools, "rows": rows}, fh, sort_keys=True)
    print(f"{len(rows)} rows   xaidr {xaidr.__version__}   {xaidr.__file__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
