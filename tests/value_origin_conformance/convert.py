"""Author the conformance inputs from the corpus LABELS — run once, output committed.

    python tests/value_origin_conformance/convert.py --sentinel ~/delphi-sentinel \
        [--rev origin/main] [--adopt]

Reads, from delphi-sentinel at ``--rev`` (git objects, never the working tree):
``bench/action-path-corpus/corpus.jsonl``, ``classes.py`` (for DESIGNATIONS) and
``reference_ledger.py`` (the oracle). Writes, beside this file:

    flows.jsonl      one flow script per corpus case (§5.1)
    expected.jsonl   the expected outcome of every corpus case under configs A,
                     B and C, and of every supplementary case (config "S")
    oracle.jsonl     the ORACLE's wire for every case, configs A and B,
                     unsabotaged and under each of its five sabotages
    SOURCE.json      the sentinel commit and the sha256 of every input read

WHY THE EXPECTED FILE IS WRITTEN HERE AND NOT BY THE CORE (§5.2). It is written
from the corpus labels by the mapping table below, so it cannot be a recording of
what the code happened to do. This module does NOT import ``xaidr``. Where the
mapping and the core disagree, the presumption is that the core is wrong, and
changing an expected row must name the rule that justifies it (and obliges paid
to bump EVALUATOR_GENERATION on re-vendor — P4).

WHY THE ORACLE RUNS OVER THERE. ``reference_ledger.py`` says "Nothing may import
this outside bench/action-path-corpus". It is run as a subprocess whose working
directory is an extract of that directory; its answers are committed to
oracle.jsonl, and test_probes.py compares the REAL core to them. Oracle-versus-
core disagreement is a red (§5.4, ruling 2026-09-24).

A CHANGED CORPUS IS A VISIBLE RE-AUTHORING. The converter refuses a corpus whose
sha256 differs from SOURCE.json unless ``--adopt`` is passed, and the diff of
SOURCE.json then says so.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS_DIR = "bench/action-path-corpus"

# ── §5.2, the mapping table: destination_origin -> config-A wire ─────────────
A_WIRE = {
    "tool_result": "trusted_source",
    "principal_span": "principal",
    "agent_constructed": "unresolved",
    "quoted_span": "untrusted_source",
    "unattributed": "unresolved",
    "untrusted_read": "untrusted_source",
    "attacker_keyed_read": "untrusted_source",
    "flagged_input_span": "untrusted_source",
}
# The origin behind an authorizing wire, by label: principal-derived or read-derived.
PRINCIPAL_DERIVED = {"principal_span", "quoted_span"}
READ_DERIVED = {"tool_result", "attacker_keyed_read"}

VERDICT = {                       # §1.4 verdict_of, transcribed (not imported)
    "argument_bound": "unresolved", "result_truncated": "not_evaluated",  # RULING 1+2 after M8
    "principal": "authorized", "principal_undeclared_span": "authorized",
    "trusted_source": "authorized", "untrusted_source": "unauthorized",
    "unresolved": "unresolved", "no_destination": "not_evaluated",
    "no_flow": "not_evaluated", "ledger_absent": "not_evaluated",
    "ledger_saturated": "not_evaluated",
}
ORIGIN_OF_WIRE = {"principal": "principal", "trusted_source": "trusted_source",
                  "untrusted_source": "untrusted_source", "unresolved": "unresolved"}

# §5.1 config A designations, as data. Asserted equal to classes.DESIGNATIONS.
CONFIG_A = [
    {"tool": "directory_lookup", "match": "exact", "source_arg": "directory",
     "pattern": "corporate_directory", "key_args": ["query"]},
    {"tool": "order_lookup", "match": "any", "source_arg": None, "pattern": None,
     "key_args": ["order_id"]},
    {"tool": "group_expand", "match": "any", "source_arg": None, "pattern": None,
     "key_args": ["group"]},
    {"tool": "vendor_lookup", "match": "exact", "source_arg": "system",
     "pattern": "vendor_master", "key_args": ["vendor_id"]},
    {"tool": "service_registry", "match": "exact", "source_arg": "registry",
     "pattern": "internal_services", "key_args": ["service"]},
]


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _git_show(repo: Path, rev: str, path: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), "show", f"{rev}:{path}"],
                          check=True, capture_output=True).stdout


def _label_destination(case) -> str:
    """The expected authority KEY of the labelled destination, by a label-side
    rule that handles only the shapes the corpus uses — and refuses others, so
    a new shape is a visible authoring decision, not a silent guess. This is
    deliberately NOT the core's normaliser."""
    v = case["arguments"][case["destination_key"]]
    if re.fullmatch(r"[a-z0-9._+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)+", v):
        return "mailto:" + v
    m = re.fullmatch(r"https?://([a-z0-9\-]+(?:\.[a-z0-9\-]+)*)(?:[/?].*)?", v)
    if m:
        host = m.group(1)
        if not host.endswith(".example"):
            raise SystemExit(f"{case['case_id']}: host {host!r} is not under .example; "
                             "the label-side rule only knows the PSL default for it")
        return "dns:" + ".".join(host.split(".")[-2:])
    if re.fullmatch(r"\+[0-9]{8,15}", v):
        return "tel:" + v
    raise SystemExit(f"{case['case_id']}: destination {v!r} has a shape this "
                     "converter does not author; add a rule deliberately")


def _names_registrable(case) -> bool:
    """subdomain_path_drift: does a PRINCIPAL span name the destination's
    registrable domain as a bare host? (§5.2's 20 exceptions)"""
    reg = _label_destination(case).split(":", 1)[1]
    pat = r"(?<![\w.@/\-])" + re.escape(reg) + r"(?![\w@\-])"
    return any(s["writer"] == "principal" and re.search(pat, s["text"])
               for s in case["request_spans"])


def _writes_national_phone(case) -> bool:
    """format_variance: the destination is E.164 but the request wrote no '+'
    (§5.2's 23 exceptions)."""
    return case["destination_value"].startswith("+") and "+" not in case["request_text"]


def expected_for(case, config):
    lab = case["destination_origin"]
    wire = A_WIRE[lab]
    cls = case["class"]
    if cls == "format_variance" and _writes_national_phone(case):
        wire = "unresolved"
    derived_principal = lab in PRINCIPAL_DERIVED
    if cls == "subdomain_path_drift" and _names_registrable(case):
        wire, derived_principal = "principal", True
    origin = ORIGIN_OF_WIRE[wire]
    if config == "B":
        # §5.2 as amended (ruling 2026-09-24, C-3a): no span is declared, so
        # every principal-derived destination and every designated-read
        # authorization reports principal_undeclared_span.
        if derived_principal and wire in ("principal", "untrusted_source") \
                and lab != "flagged_input_span":
            wire, origin = "principal_undeclared_span", "principal"
        elif lab in READ_DERIVED and wire in ("trusted_source", "untrusted_source"):
            wire, origin = "principal_undeclared_span", "trusted_source"
    elif config == "C":
        if lab == "tool_result":
            wire, origin = "untrusted_source", "untrusted_source"
    return wire, origin


def _row_state(wire):
    rows = json.loads((HERE / "row_text.json").read_text(encoding="utf-8"))
    for r in rows:
        if r["scan_mode"] == "tool_call" and r["wire"] == wire:
            return r["row_state"]
    raise SystemExit(f"row_text.json has no tool_call row for {wire!r}")


def build_flow(case):
    events = []
    for ev in case["event_order"]:
        if ev == "input":
            events.append({"kind": "input"})
        else:
            rd = case["destination_reads"][int(ev.split(":", 1)[1])]
            events.append({"kind": "read", "tool": rd["tool_name"],
                           "arguments": rd["arguments"], "result": rd["result"]})
    return {
        "case_id": case["case_id"], "class": case["class"],
        "label_basis": case["label_basis"], "expected_verdict": case["expected_verdict"],
        "destination_origin": case["destination_origin"],
        "request_text": case["request_text"],
        "request_spans": [[s["writer"], s["text"]] for s in case["request_spans"]],
        "input_clean": case["input_scan"] == "clean",
        "events": events,
        "call": {"tool": case["tool_name"], "arguments": case["arguments"]},
    }


_ORACLE_SCRIPT = r"""
import json, sys
sys.path.insert(0, '.')
import reference_ledger as RL
from classes import DESIGNATIONS
out = []
for line in open('corpus.jsonl'):
    c = json.loads(line)
    for cfg, sc in (('A', 'declared'), ('B', 'undeclared')):
        for sab in (None,) + RL.SABOTAGES:
            out.append({'case_id': c['case_id'], 'config': cfg, 'sabotage': sab,
                        'wire': RL.evaluate(c, DESIGNATIONS, sab, span_config=sc)})
print(json.dumps(out))
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sentinel", type=Path, required=True)
    ap.add_argument("--rev", default="origin/main")
    ap.add_argument("--adopt", action="store_true",
                    help="accept a corpus whose sha256 differs from SOURCE.json")
    a = ap.parse_args(argv)

    commit = subprocess.run(["git", "-C", str(a.sentinel), "rev-parse", a.rev],
                            check=True, capture_output=True, text=True).stdout.strip()
    files = {n: _git_show(a.sentinel, commit, f"{CORPUS_DIR}/{n}")
             for n in ("corpus.jsonl", "classes.py", "reference_ledger.py")}
    shas = {n: _sha(b) for n, b in files.items()}

    src = HERE / "SOURCE.json"
    if src.exists() and not a.adopt:
        pinned = json.loads(src.read_text(encoding="utf-8"))["inputs"]
        for n, s in shas.items():
            if pinned.get(n, {}).get("sha256") != s:
                raise SystemExit(f"{n} sha256 {s} differs from SOURCE.json "
                                 f"({pinned.get(n, {}).get('sha256')}). A changed "
                                 "corpus is a re-authoring: re-run with --adopt and "
                                 "say so in the PR.")

    # Label and config cannot part silently: classes.DESIGNATIONS == config A.
    tree = ast.parse(files["classes.py"])
    desig = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "DESIGNATIONS" for t in node.targets):
            desig = ast.literal_eval(node.value)
    got = [dict(d, key_args=list(d["key_args"])) for d in desig]
    if got != CONFIG_A:
        raise SystemExit(f"classes.DESIGNATIONS differs from §5.1 config A:\n{got}")

    cases = [json.loads(line) for line in files["corpus.jsonl"].decode().splitlines()]
    flows = [build_flow(c) for c in cases]
    expected = []
    counts = {"national": 0, "drift": 0}
    for c in cases:
        if c["class"] == "format_variance" and _writes_national_phone(c):
            counts["national"] += 1
        if c["class"] == "subdomain_path_drift" and _names_registrable(c):
            counts["drift"] += 1
        dest = _label_destination(c)
        for cfg in ("A", "B", "C"):
            wire, origin = expected_for(c, cfg)
            expected.append({
                "case_id": c["case_id"], "config": cfg, "wire": wire,
                "verdict": VERDICT[wire], "row_state": _row_state(wire),
                "truncated": False,
                "findings": [{"path": [c["destination_key"]], "destination": dest,
                              "origin": origin}],
            })
    if counts != {"national": 23, "drift": 20}:
        raise SystemExit(f"§5.2 enumerates 23 national-phone and 20 drift "
                         f"exceptions; the label rules found {counts}")

    for line in (HERE / "supplementary.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        s = json.loads(line)
        e = dict(s["expect"])
        e = {"case_id": s["id"], "config": "S", **e}
        if "verdict" not in e:
            e["verdict"] = VERDICT[e["wire"]]
        if "row_state" not in e:
            e["row_state"] = _row_state(e["wire"])
        expected.append(e)

    with tempfile.TemporaryDirectory() as td:
        for n, b in files.items():
            (Path(td) / n).write_bytes(b)
        res = subprocess.run([sys.executable, "-c", _ORACLE_SCRIPT], cwd=td,
                             check=True, capture_output=True, text=True)
        oracle = json.loads(res.stdout)

    def dump(name, rows):
        (HERE / name).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                                 encoding="utf-8")

    dump("flows.jsonl", flows)
    dump("expected.jsonl", expected)
    dump("oracle.jsonl", oracle)
    src.write_text(json.dumps({
        "repo": "github.com/delphisecurity/delphi-sentinel",
        "commit": commit,
        "inputs": {n: {"path": f"{CORPUS_DIR}/{n}", "sha256": s} for n, s in shas.items()},
        "cases": len(cases),
        "expected_sha256": _sha((HERE / "expected.jsonl").read_bytes()),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(cases)} cases from {commit[:12]}; {len(expected)} expected rows; "
          f"{len(oracle)} oracle rows; exceptions {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
