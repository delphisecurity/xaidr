import importlib.util, json, collections, warnings, logging
logging.disable(logging.CRITICAL)
import xaidr
spec = importlib.util.spec_from_file_location("c11", "tests/outside/drivers/c11_oracle.py"); o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)
texts = o.corpus_texts()
def line(name, wires, extra=""):
    n = len(wires); b = wires.count("untrusted_source")
    print(f"  {name:28} calls={n:5d}  would block={b:4d}  rate={(b/n if n else 0):6.2%} {extra}")
print("456-row shell corpus (buckets:", sorted({b for b, _, _ in texts}), "), ENFORCE, block mode:")
out = o.run_passes(xaidr, "enforce", "block", texts, include=("P-flow-I", "P-flow-R", "P-seam"))
for p in ("P-flow-I", "P-flow-R", "P-seam"):
    wires = out[p][2]; per = collections.defaultdict(list); k = 0
    for bucket, i, text in texts:
        n = len(o.calls_for(text)); per[bucket] += wires[k:k + n]; k += n
    assert k == len(wires), (p, k, len(wires))
    line(p, wires, "| " + " | ".join(f"{b}: {w.count('untrusted_source')}/{len(w)}" for b, w in sorted(per.items())))
adv = o.run_adversarial(xaidr, "enforce", "block")
print("adversarial / benign corpora, ENFORCE:")
for p, v in sorted(adv.items()):
    wires = [x for x in (v[2] if isinstance(v, (list, tuple)) and len(v) > 2 else []) if x is not None]
    line(p, wires, f"(pass result parts: {len(v) if isinstance(v, (list, tuple)) else type(v).__name__})")
rows = [json.loads(l) for l in open("tests/value_origin_conformance/expected.jsonl")]
print("conformance flows (expected wire per config; designed cases, not traffic):")
for cfg in ("A", "B", "C"):
    ws = [r["wire"] for r in rows if r.get("config") == cfg]; line(f"config {cfg}", ws)
