"""What atom extraction past the bounds costs (owner, 2026-10-05: "Measure, do
not assume"). Value origin's OWN cost, called on the core, best of 3; then the
5 MB case end to end through the sensor. Run from the repo root of the tree under
test: PYTHONPATH=$PWD:$PWD/tests python scripts/value_origin_measurements/atom_cost.py
(milestone review: the first figures were mislabelled and left out the worst case)."""
import contextvars
import logging
import os
import sys
import time
import warnings

logging.disable(logging.CRITICAL)
sys.path.insert(0, "scripts")
import build_benign_longform as bl  # noqa: E402
import xaidr  # noqa: E402
from xaidr import value_origin as vo  # noqa: E402

print("xaidr from:", os.path.dirname(xaidr.__file__).replace(os.getcwd(), "."))
N = 5_000_000
docs = [r["text"] for r in bl.generate()]
SHAPES = {
    "test_truncation_bypass's own input ('(a|a)' x n/5)": ("(a|a)" * (N // 5))[:N],
    "real prose (benign_longform's largest doc, repeated)": (max(docs, key=len) * 4)[:N],
    "ADDRESS-DENSE ('x.co ' repeated): the worst case": ("x.co " * (N // 5))[:N],
}


def ctx(fn):
    return contextvars.Context().run(fn)


def best(fn, n=3):
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t0)
    return min(out)


def path(kind, text):
    def run():
        vo.bind_fresh_ledger()
        if kind == "input":
            vo.record_principal_input(text, None, input_clean=True)
        elif kind == "result":
            vo.record_tool_result("web_fetch", {}, text, designations=(), result_blocked=False)
        else:
            vo.evaluate_call("run_command", {"command": text}, flow_active=True)
    return lambda: ctx(run)


print(f"5 MB ({N:,} chars), core value-origin cost per path:")
for label, text in SHAPES.items():
    cells = []
    for kind in ("input", "result", "argument"):
        sec = best(path(kind, text), n=1 if "DENSE" in label else 3)
        cells.append(f"{kind} {sec * 1000:7.0f} ms ({sec / N * 1e9:6.0f} ns/char)")
    print(f"  {label:54s} " + " | ".join(cells))
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    null = type("N", (), {"report": lambda *a, **k: None})()
    sensors = {m: xaidr.Sensor(agent_id="cost", value_origin=m, reporter=null) for m in ("off", "record")}


def end_to_end(s, text):
    def run():
        from xaidr import provenance_chain as pc
        pc.begin_flow(principal="p")
        try:
            s.scan(text, direction="input")
        finally:
            pc.clear_flow()
    return lambda: ctx(run)


text = SHAPES["test_truncation_bypass's own input ('(a|a)' x n/5)"]
off, rec = best(end_to_end(sensors["off"], text), 2), best(end_to_end(sensors["record"], text), 2)
print(f"END TO END sensor.scan(test_truncation_bypass's 5 MB input): off {off * 1000:.0f} ms, "
      f"record {rec * 1000:.0f} ms, delta {(rec - off) * 1000:+.0f} ms")
tot = {k: sum(best(path(k, d), 1) for d in docs) for k in ("input", "result", "argument")}
print(f"benign_longform ({len(docs)} docs, {sum(map(len, docs)):,} chars): " + " | ".join(
    f"{k} {v * 1000:.0f} ms total, {v / len(docs) * 1000:.0f} ms/doc" for k, v in tot.items()))
