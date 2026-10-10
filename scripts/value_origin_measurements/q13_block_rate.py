"""Q13: what ENFORCE would block on this repo's corpora, with NO designations.

Run from the repo root of the tree under test, with that tree first on the path:
    PYTHONPATH=$PWD:$PWD/tests python scripts/value_origin_measurements/q13_block_rate.py

A call counts as blocked iff the TREE'S OWN ``should_block`` says so for its wire.
Until the RULING 1+2 review this script counted ``wires.count("untrusted_source")``,
which is blind to every bound state (argument_bound, result_truncated,
input_truncated, ledger_saturated): a before/after comparison with it was
identical by construction, and was reported as a measurement.

benign_a2a and benign_longform are measured here too (they were measured once by a
script that was never committed; this reproduces its output on 255a4b3 exactly:
benign_a2a P-flow-I 0/64 [no_destination 58, principal_undeclared_span 4,
unresolved 2], P-flow-R 4/64; benign_longform 0/24 [unresolved 24]).
"""
import collections
import importlib.util
import json
import logging
import os
import sys
import types

logging.disable(logging.CRITICAL)
import xaidr  # noqa: E402
from xaidr import value_origin as vo  # noqa: E402

print("xaidr from:", os.path.dirname(xaidr.__file__))
spec = importlib.util.spec_from_file_location("c11", "tests/outside/drivers/c11_oracle.py")
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
sys.path.insert(0, "scripts")
import benign_a2a_report as ba  # noqa: E402
import build_benign_longform as bl  # noqa: E402

PASSES = ("P-flow-I", "P-flow-R", "P-seam")


def blocks(w):
    if w is None:
        return False
    try:
        wv = vo.WireValue(w)
    except ValueError:
        return False
    return vo.should_block(types.SimpleNamespace(wire=wv, verdict=vo.verdict_of(wv)),
                           mode=vo.Mode.ENFORCE)


def frac(ws):
    return f"{sum(map(blocks, ws))}/{len(ws)}"


def line(name, wires, extra=""):
    n = len(wires)
    b = sum(map(blocks, wires))
    print(f"  {name:28} calls={n:5d}  would block={b:4d}  rate={(b / n if n else 0):6.2%} {extra}")


def by_bucket(texts, title, show_wires=False):
    print(title)
    out = o.run_passes(xaidr, "enforce", "block", texts, include=PASSES)
    for p in PASSES:
        wires = out[p][2]
        per = collections.defaultdict(list)
        k = 0
        for bucket, _, text in texts:
            n = len(o.calls_for(text))
            per[bucket] += wires[k:k + n]
            k += n
        assert k == len(wires), (p, k, len(wires))
        extra = "| " + " | ".join(f"{b}: {frac(w)}" for b, w in sorted(per.items()))
        if show_wires:
            extra += " " + str(sorted(collections.Counter(wires).items()))
        line(p, wires, extra)


by_bucket(o.corpus_texts(), "456-row shell corpus, ENFORCE, block mode:")
by_bucket([("benign_a2a", i, json.dumps(r["body"])) for i, r in enumerate(ba.load())],
          "benign_a2a (60 A2A JSON-RPC bodies), ENFORCE, block mode:", show_wires=True)
by_bucket([("benign_longform", i, r["text"]) for i, r in enumerate(bl.generate())],
          "benign_longform (24 generated documents, 90k..1.4M chars), ENFORCE, block mode:",
          show_wires=True)
adv = o.run_adversarial(xaidr, "enforce", "block")
print("adversarial / benign corpora, ENFORCE:")
for p, v in sorted(adv.items()):
    wires = [x for x in (v[2] if isinstance(v, (list, tuple)) and len(v) > 2 else []) if x is not None]
    line(p, wires, str(sorted(collections.Counter(wires).items())))
rows = [json.loads(ln) for ln in open("tests/value_origin_conformance/expected.jsonl")]
print("conformance flows (expected wire per config; designed cases, not traffic):")
for cfg in ("A", "B", "C"):
    line(f"config {cfg}", [r["wire"] for r in rows if r.get("config") == cfg])
