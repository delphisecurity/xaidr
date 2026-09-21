#!/usr/bin/env python3
"""Regenerate the README's policy-width table. Nothing else produced it.

    python scripts/policy_width_report.py
    python scripts/policy_width_report.py --json      # machine-readable

WHY THIS EXISTS. README.md publishes this:

    | policy                      | attacks gated | ordinary DevOps gated |
    | none (shipped default)      | 165 of 277    | 0 of 38               |
    | impact_tier: [critical]     | 188 of 277    | 0 of 38               |
    | impact_tier: [critical,high]| 253 of 277    | 4 of 38               |
    | impact_class: all ten       | 265 of 277    | 5 of 38               |

Eight figures. Until this script, **not one of them had a regenerator.** They
entered the tree in `ab09cb3` ("docs: correct every published corpus figure and
add the policy ceiling"), a commit that touched four markdown files and no code,
no test and no fixture. Its body says "Measured", and that word was the entire
provenance. `scripts/corpus_report.py` — credited in the same commit for the
other figures — contains the string "policy" zero times. U-1 forbids exactly
this: a figure that reads as rigour and cannot be recomputed.

The denominator then drifted from 281 to 277 in a later edit with nothing
re-deriving the DevOps column, so the two halves of each row have not been
measured in the same run since the row was written.

WHAT "GATED" MEANS, precisely, because the README's phrase is "the action does
not execute": `scan_tool_call(...).action` is `blocked` OR `approval_required`.
A `flagged` verdict is NOT gated — it emits an event and the call proceeds.
That is why the "none" row is the block count and not the catch rate, and it is
why this table's denominator is all 277 rather than the 186 the headline uses:
this table is about how much of the corpus a POLICY stops, dual-use commands
included.

WHAT IS SWEPT

  pool              source                                            n
  attacks           tests/fixtures/shell_corpus.json  ["attacks"]     277
  benign commands   tests/fixtures/shell_corpus.json  ["benign"]       78
  ordinary DevOps   tests/test_shell_classes_stage3.py ORDINARY_DEVOPS 38

The DevOps pool is a Python literal inside a test, read with `ast` rather than
imported (importing would drag in pytest). That it lives there and not in a
fixture is not this script's choice to make, but it IS the reason the column was
never regenerated alongside the others — it is in the one place a corpus script
does not look. `scripts/intent_metrics.py` reads it the same way.

THE TEN CLASSES, AND THE THREE THAT CANNOT MATCH. "impact_class: all ten" means
the ten classes the CORPUS labels its families with. The sensor's classifier
emits a different set, and three of the corpus's ten — `exfiltration`,
`obfuscation`, `discovery` — are not in it, so a policy naming them binds to
something `classify()` never returns. The report prints that overlap explicitly
instead of leaving the reader to discover that a third of the widest policy is
inert.

Standard library and `xaidr` only. Null reporter, no network, nothing executed:
every "command" is a string handed to the scanner.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import os
import sys
import warnings

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _provenance import bind, repo_root_of  # noqa: E402

REPO_ROOT = repo_root_of(__file__)
FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "shell_corpus.json")
DEVOPS_TEST = os.path.join(REPO_ROOT, "tests", "test_shell_classes_stage3.py")
PROV = bind(__file__)

WIDTH = 88

# The ten classes the corpus labels its families with, in the fixture's own
# order. Read from the fixture at runtime — this literal is the fallback for a
# fixture whose `_schema.classes` key has moved, and a mismatch is reported.
_CORPUS_TEN = (
    "execute", "credential_access", "escalate", "persist", "evade",
    "destructive_filesystem", "infra_destruction", "exfiltration",
    "obfuscation", "discovery",
)

# The four rows of the README table, in its order. `match` is None for the
# shipped default — no policy at all, which is not the same as a policy that
# matches nothing.
WIDTHS = [
    ("none (shipped default)", None),
    ("impact_tier: [critical]", {"impact_tier": ["critical"]}),
    ("impact_tier: [critical, high]", {"impact_tier": ["critical", "high"]}),
    ("impact_class: all ten", "ALL_TEN"),  # resolved once the fixture is read
]

# `blocked` and `approval_required` are the two verdicts under which the action
# does not execute. `flagged` is not one of them and this is the whole point of
# the table; see the module docstring.
GATED = ("blocked", "approval_required")


class _Null:
    def report(self, batch): pass
    def close(self): pass


def _rule(char="-"):
    return char * WIDTH


def _quiet(fn, *args, **kwargs):
    """The sensor prints its own detection lines; a table would drown in them."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def _literal_from_test(path, name):
    """Read a module-level literal out of a test file without importing pytest.

    Same device as `scripts/intent_metrics.py::_literal_from_test` and
    `scripts/corpus_report.py::_documented_blocking_prose`. Returns None on any
    failure, which the caller turns into a loud refusal rather than an empty
    column — a zero-length pool would make every DevOps cell read `0 of 0` and
    look like a clean bill of health.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
    except OSError:
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            try:
                return ast.literal_eval(node.value)
            except ValueError:
                return None
    return None


def _policy(match):
    """A one-rule `require_approval` policy bound to `match`.

    `defaults.effect = allow` and `unclassified = allow` so the only thing the
    policy adds is the gate under test. Detection is unaffected either way:
    policy composition in xaidr is stricter-wins, so a policy can never turn a
    block into an allow — which is why the "attacks gated" column is a union of
    what detection blocks and what the policy holds, not policy alone.
    """
    return {
        "version": "1",
        "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": "width", "effect": "require_approval", "match": match}],
    }


def _sensor(match):
    from xaidr import Sensor
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = Sensor(agent_id="policy-width", enforcement_mode="block",
                   reporter=_Null())
    if match is not None:
        applied = s.set_policy(_policy(match))
        if not applied:
            sys.exit(f"policy rejected by set_policy(): {match!r}")
    return s


def _gated(sensor, commands):
    """How many of `commands` the sensor stops. Returns (count, [(cmd, action)])."""
    hits = []
    for cmd in commands:
        res = _quiet(sensor.scan_tool_call, "run_command", {"command": cmd})
        if res.action in GATED:
            hits.append((cmd, res.action))
    return len(hits), hits


def _emittable(ten):
    """Which of the corpus's ten classes `classify()` can actually return."""
    from xaidr.authz.classifier import IMPACT_CLASSES
    emit = set(IMPACT_CLASSES)
    return [c for c in ten if c in emit], [c for c in ten if c not in emit]


def measure():
    with open(FIXTURE, encoding="utf-8") as fh:
        corpus = json.load(fh)

    attacks = [a["command"] for a in corpus["attacks"]]
    benign = [b["command"] for b in corpus["benign"]]

    devops = _literal_from_test(DEVOPS_TEST, "ORDINARY_DEVOPS")
    if not devops:
        sys.exit(
            f"could not read ORDINARY_DEVOPS from "
            f"{os.path.relpath(DEVOPS_TEST, REPO_ROOT)}. Refusing to print the "
            f"table: an empty DevOps pool makes every cost cell read `0 of 0`, "
            f"which is indistinguishable from a policy that costs nothing."
        )

    declared_ten = list((corpus.get("_schema", {}).get("classes") or {}).keys())
    ten = declared_ten or list(_CORPUS_TEN)

    rows = []
    for label, match in WIDTHS:
        if match == "ALL_TEN":
            match = {"impact_class": list(ten)}
        sensor = _sensor(match)
        a_n, a_hits = _gated(sensor, attacks)
        d_n, d_hits = _gated(sensor, devops)
        b_n, b_hits = _gated(sensor, benign)
        rows.append({
            "policy": label,
            "match": match,
            "attacks_gated": a_n, "attacks_n": len(attacks),
            "devops_gated": d_n, "devops_n": len(devops),
            "devops_hits": [c for c, _ in d_hits],
            "benign_gated": b_n, "benign_n": len(benign),
            "benign_hits": [c for c, _ in b_hits],
        })

    emittable, inert = _emittable(ten)
    return {
        "corpus_ten": ten,
        "declared_in_fixture": bool(declared_ten),
        "emittable": emittable,
        "inert": inert,
        "rows": rows,
    }


def print_report(data):
    rows = data["rows"]
    print(_rule("="))
    print("POLICY WIDTH — what a deployer who writes the policy actually gets")
    print(_rule("="))
    print(f"fixture : {os.path.relpath(FIXTURE, REPO_ROOT)}")
    print(f"devops  : {os.path.relpath(DEVOPS_TEST, REPO_ROOT)}  (ORDINARY_DEVOPS)")
    print("gated   : scan_tool_call(...).action in " + repr(GATED)
          + " — `flagged` is NOT gated")
    print(_rule("="))
    print()

    print(f"{'policy':<32}{'attacks gated':>18}{'DevOps gated':>16}"
          f"{'benign gated':>16}")
    print(_rule())
    for r in rows:
        # Built as three plain strings and then padded, rather than as an
        # f-string nested inside an f-string's format spec. The nested spelling
        # reused the enclosing `'` inside the replacement expression
        # (`f'{r['attacks_gated']}'`), which PEP 701 legalised in 3.12 and 3.10
        # and 3.11 reject at PARSE time — so the whole file failed to import on
        # two of the three jobs the matrix runs. Same output, one quote level.
        attacks = f"{r['attacks_gated']} of {r['attacks_n']}"
        devops = f"{r['devops_gated']} of {r['devops_n']}"
        benign = f"{r['benign_gated']} of {r['benign_n']}"
        print(f"{r['policy']:<32}{attacks:>18}{devops:>16}{benign:>16}")
    print(_rule())
    print()

    print("THE TEN CLASSES THE WIDEST POLICY BINDS")
    src = ("the fixture's _schema.classes" if data["declared_in_fixture"]
           else "this script's fallback literal (fixture key missing!)")
    print(f"  read from : {src}")
    print(f"  classify() can return : {', '.join(data['emittable'])}")
    if data["inert"]:
        print(f"  classify() NEVER returns: {', '.join(data['inert'])}")
        print(f"  -> {len(data['inert'])} of the {len(data['corpus_ten'])} "
              f"clauses in the widest policy match nothing. Attacks in those "
              f"corpus families are gated only if another clause, or detection "
              f"itself, reaches them.")
    print()

    print("WHAT THE POLICY COSTS — every ordinary DevOps command it gates")
    for r in rows:
        if not r["devops_hits"]:
            print(f"  {r['policy']}: none")
            continue
        print(f"  {r['policy']}:")
        for cmd in r["devops_hits"]:
            print(f"      {cmd}")
    print()

    worst = max(r["benign_gated"] for r in rows)
    print(f"benign shell commands gated under EVERY width above: max {worst} "
          f"of {rows[0]['benign_n']}")
    for r in rows:
        for cmd in r["benign_hits"]:
            print(f"      [{r['policy']}] {cmd}")
    print()
    print(_rule("="))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true",
                    help="print the measurement as JSON instead of a table")
    args = ap.parse_args(argv)

    data = measure()
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print_report(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
