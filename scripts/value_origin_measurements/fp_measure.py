import json, sys, collections, warnings, logging
logging.disable(logging.CRITICAL)
import xaidr
import xaidr.value_origin._authority as A
from xaidr.value_origin import extract_destinations
from xaidr.scanner.url_parse import parse_url
corpus = json.load(open(sys.argv[1]))
class N:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass
with warnings.catch_warnings():
    warnings.simplefilter("ignore"); s = xaidr.Sensor(agent_id="fp", value_origin="off", reporter=N())
real = A._macos_readings
def observe(value):
    keys = sorted(f.destination.key() for f in extract_destinations({"v": value})[0] if f.destination)
    shape = parse_url(value); addr = shape.address if shape else None
    r = s.scan_tool_call("http_get", {"url": value}); act = f"{r.action} {','.join(sorted(r.rules or []))}"
    return keys, addr, act
def both(value):
    A._macos_readings = lambda raw: []
    try: before = observe(value)
    finally: A._macos_readings = real
    return before, observe(value)
cases = []
for host, p in corpus["url_hosts"]:
    cases.append(("real URL host", f"http://{host}/", p))
for tok, kind, p in corpus["tokens"]:
    cases.append((f"{kind} as found (whole value)", tok, p))
    cases.append((f"{kind} as a URL host", f"http://{tok.strip('[]') if kind != 'embedded_v4' else '[' + tok.strip('[]') + ']'}/", p))
seen, changed = set(), collections.defaultdict(list); totals = collections.Counter()
for kind, value, p in cases:
    if (kind, value) in seen: continue
    seen.add((kind, value)); totals[kind] += 1
    before, after = both(value)
    if before != after:
        changed[kind].append({"value": value, "source": p, "before": before, "after": after})
print(json.dumps({"distinct_cases": {k: totals[k] for k in totals},
                  "changed": {k: len(v) for k, v in changed.items()}}, indent=1))
for k, rows in changed.items():
    for r in rows:
        d = [x for x, (b, a) in zip(("readings", "url_parse", "action"), zip(r["before"], r["after"])) if b != a]
        print(f"  [{k}] {r['value']!r}  ({r['source']})  changed: {d}\n     before={r['before']}\n     after ={r['after']}")
json.dump(changed, open(sys.argv[2], "w"), indent=1)
