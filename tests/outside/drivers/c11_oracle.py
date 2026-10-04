"""C-11: RECORD never changes an action. The passes, as one module.

Used two ways, so the in-process gate and the out-of-process check cannot drift
apart:

* imported by ``tests/test_value_origin_c11.py`` (fast, in-tree);
* run as a driver by ``tests/outside/harness.py`` inside a fresh venv holding a
  BUILT wheel. There it refuses unless ``xaidr`` comes from that venv's
  site-packages, and it prints one JSON line of digests. Building a wheel from
  ``git archive 25dc9de`` and one from HEAD and comparing the two lines is the
  cross-commit check (ARCHITECTURE.md §3.2 item 3).

THE PASSES (ARCHITECTURE.md §3.1). The 456 texts of
tests/fixtures/shell_corpus.json are driven through:

  P-input   byte-for-byte the existing oracle (tests/test_seam_zero_movement.py):
            a fresh sensor and ``scan(T, direction="input")``.
  P-flow-I  a flow; T as the principal input; then the calls built from T.
  P-flow-R  a flow; a NEUTRAL principal input; T returned as a tool result; then
            the calls. Neutral because principal entries persist under C-18, so
            with T as the input the result seam could never be what produced an
            ``untrusted_source``.
  P-seam    as P-flow-R, but T is the return value of a ``protect_tools``-
            wrapped tool. AT M1 THIS COVERS NO RESULT SEAM: protect_tools has
            no result position (ARCHITECTURE.md §1.2), so T never reaches value
            origin and the digest is the same whatever the tool returns. M7
            gives protect_tools its result position and adds the langchain_core
            and MCP after-hooks here (ARCHITECTURE.md §5, M7).
  P-fault   one call per row through each NON-normal exit: circuit open, a
            gating extension, the bounds fail-closed group, a scan error, a
            non-str tool name. Each path's own marker is counted, so a fault
            that never reached its path shows up as a vacuous pass.

Calls are built from T with the STDLIB only (``urlsplit(tok).netloc``, a plain
mailbox regex), never the core, so the oracle does not reuse the extractor it
tests. A digest line holds ``action score category rules``. It holds neither
``ScanResult.value_origin`` nor any telemetry key: those are RECORD's intended
output, and C-11 is about actions.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import sys
from urllib.parse import urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(_HERE, "..", "..", "fixtures", "shell_corpus.json")
BUCKETS = ("attacks", "benign", "benign_prose", "benign_templates")
NEUTRAL = "Please summarise the attached document for me."
MODES = ("off", "record", "enforce")
ENFORCEMENT = ("block", "monitor")
FAULT_PATHS = ("circuit", "gate", "bounds", "scan_error", "not_scannable")
_MAILBOX = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+")


class _Null:
    def report(self, *a, **k):
        pass

    def close(self, *a, **k):
        pass


def corpus_texts(fixture=FIXTURE):
    with open(fixture, encoding="utf-8") as fh:
        corpus = json.load(fh)
    out = []
    for bucket in BUCKETS:
        for i, entry in enumerate(corpus[bucket]):
            for key in ("command", "text", "template"):
                if key in entry:
                    out.append((bucket, i, entry[key]))
                    break
            else:
                raise KeyError(f"{bucket}[{i}] has no text field: {list(entry)}")
    return out


def calls_for(text):
    """Tool calls built from ``text`` with the stdlib only."""
    out = [("run_command", {"command": text})]
    for tok in text.split():
        tok = tok.strip("'\"`;,()<>[]{}")
        try:
            if urlsplit(tok).netloc:
                out.append(("http_post", {"url": tok, "body": "report"}))
                continue
        except ValueError:
            pass
        if _MAILBOX.fullmatch(tok):
            out.append(("send_email", {"to": tok, "body": "report"}))
    return out


def line(r):
    rules = ",".join(sorted(r.rules or []))
    return f"{r.action} {float(r.score):.4f} {r.category or '-'} {rules or '-'}"


def wire(r):
    v = getattr(r, "value_origin", None)
    return getattr(getattr(v, "wire", None), "value", None)


def supports_value_origin(xaidr):
    return "value_origin" in inspect.signature(xaidr.Sensor).parameters


def _sensor(xaidr, mode, enforcement, **kw):
    if mode is not None:
        kw["value_origin"] = mode
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return xaidr.Sensor(agent_id="c11-oracle", enforcement_mode=enforcement,
                            reporter=_Null(), **kw)


def run_passes(xaidr, mode, enforcement, texts,
               include=("P-input", "P-flow-I", "P-flow-R", "P-seam", "P-fault")):
    """{pass: (digest, lines, wires)} for one (mode, enforcement). ``mode`` None
    runs the sensor's default (for a wheel that predates ``value_origin=``)."""
    from xaidr import begin_flow, clear_flow
    out = {}

    if "P-input" in include:
        s = _sensor(xaidr, mode, enforcement)
        lines = []
        for bucket, i, text in texts:
            lines.append(f"{bucket}[{i:03d}] {line(s.scan(text, direction='input'))}")
        out["P-input"] = (lines, [])

    def flow(tag, prepare):
        s = _sensor(xaidr, mode, enforcement)
        lines, wires = [], []
        for bucket, i, text in texts:
            clear_flow()
            begin_flow(principal="c11-principal")
            prepare(s, text)
            for k, (tool, args) in enumerate(calls_for(text)):
                r = s.scan_tool_call(tool, args)
                lines.append(f"{bucket}[{i:03d}] {tag}{k} {tool} {line(r)}")
                wires.append(wire(r))
        clear_flow()
        return lines, wires

    if "P-flow-I" in include:
        out["P-flow-I"] = flow("I", lambda s, t: s.scan(t, direction="input"))

    def via_result(s, t):
        s.scan(NEUTRAL, direction="input")
        s.scan(t, direction="tool_result")
    if "P-flow-R" in include:
        out["P-flow-R"] = flow("R", via_result)

    def via_seam(s, t):
        s.scan(NEUTRAL, direction="input")

        def fetch(url):
            return t
        (wrapped,) = s.protect_tools([fetch])
        wrapped(url="https://news.example/c11")
    if "P-seam" in include:
        out["P-seam"] = flow("S", via_seam)

    if "P-fault" in include:
        out["P-fault"] = _fault_pass(xaidr, mode, enforcement, texts)
    return {k: (digest(v[0]), v[0], v[1]) for k, v in out.items()}


def _fault_pass(xaidr, mode, enforcement, texts):
    from xaidr import CircuitBreaker, ScanResult, SensorExtension

    class _Gate(SensorExtension):
        name = "c11-gate"

        def gate(self, req):
            if req.direction == "tool_call":
                return ScanResult(action="blocked", score=1.0, category="c11_gate",
                                  rules=["C11_GATE"])
            return None

    lines = []
    breaker = _sensor(xaidr, mode, enforcement,
                      circuit_breaker=CircuitBreaker(rate_threshold=1, cooldown_sec=None))
    breaker.scan_tool_call("warm_up", {"command": "ls"})          # trips the breaker
    gate = _sensor(xaidr, mode, enforcement, extensions=[_Gate()])
    bounds = _sensor(xaidr, mode, enforcement, fail_closed=("bounds",))
    plain = _sensor(xaidr, mode, enforcement)
    import xaidr.sensor as sensor_module
    real_classify = sensor_module.classify

    def boom(*a, **k):
        raise RuntimeError("c11 injected classify fault")

    for bucket, i, text in texts:
        wide = {f"k{n}": ("v" if n else text) for n in range(80)}   # > 64 leaves: a bound
        rows = [("circuit", breaker.scan_tool_call("run_command", {"command": text})),
                ("gate", gate.scan_tool_call("run_command", {"command": text})),
                ("bounds", bounds.scan_tool_call("run_command", wide))]
        sensor_module.classify = boom
        try:
            rows.append(("scan_error", plain.scan_tool_call("run_command", {"command": text})))
        finally:
            sensor_module.classify = real_classify
        rows.append(("not_scannable", plain.scan_tool_call(12345, {"command": text})))
        for path, r in rows:
            lines.append(f"{bucket}[{i:03d}] F-{path} {line(r)}")
    return lines, []


ADVERSARIAL_TEXTS = (("heldout/attacks.jsonl", "prompt"), ("heldout/benign.jsonl", "prompt"),
                     ("asi_battery/attacks.jsonl", "text"), ("asi_battery/benign.jsonl", "text"))
ADVERSARIAL_CALLS = ("benign_toolcalls/corpus.jsonl", "benign_toolcalls/discriminator.jsonl",
                     "benign_toolcalls/domains.jsonl", "benign_toolcalls/sql_dml.jsonl",
                     "asi_battery/attacks.jsonl", "asi_battery/benign.jsonl")
_REPO = os.path.join(_HERE, "..", "..", "..")


def adversarial_texts():
    """The corpora C-11 was NOT built on (§3.3): heldout/ prompts and the TEXT
    rows of asi_battery/ (its other rows are tool calls; see adversarial_calls)."""
    out = []
    for rel, key in ADVERSARIAL_TEXTS:
        with open(os.path.join(_REPO, rel), encoding="utf-8") as fh:
            for i, ln in enumerate(l for l in fh if l.strip()):
                row = json.loads(ln)
                if key in row:
                    out.append((rel.split(".")[0], i, row[key]))
    return out


def adversarial_calls():
    """Real tool calls, arguments used verbatim (§3.3): benign_toolcalls/ and the
    TOOL-CALL rows of asi_battery/ (attacks and their benign mirrors)."""
    out = []
    for rel in ADVERSARIAL_CALLS:
        with open(os.path.join(_REPO, rel), encoding="utf-8") as fh:
            for i, ln in enumerate(l for l in fh if l.strip()):
                row = json.loads(ln)
                if "tool" in row:
                    out.append((rel.split(".")[0], i, row["tool"], row["args"]))
    return out


def adversarial_steps():
    """The MULTI-TURN rows of asi_battery/ (26 per file): input turns and tool
    calls, replayed in order inside one flow, so a later milestone's ledger is
    exercised across turns, not one call at a time."""
    out = []
    for rel in ("asi_battery/attacks.jsonl", "asi_battery/benign.jsonl"):
        with open(os.path.join(_REPO, rel), encoding="utf-8") as fh:
            for i, ln in enumerate(l for l in fh if l.strip()):
                row = json.loads(ln)
                if "steps" in row:
                    out.append((rel.split(".")[0], i, row["steps"]))
    return out


def run_adversarial(xaidr, mode, enforcement):
    """{pass: (digest, lines, wires)} over the adversarial corpora."""
    from xaidr import begin_flow, clear_flow
    texts = adversarial_texts()
    full = run_passes(xaidr, mode, enforcement, texts, include=("P-flow-I", "P-flow-R"))
    s = _sensor(xaidr, mode, enforcement)
    lines, wires = [], []
    for bucket, i, tool, args in adversarial_calls():
        clear_flow()
        begin_flow(principal="c11-principal")
        s.scan(NEUTRAL, direction="input")
        s.scan(json.dumps(args, sort_keys=True), direction="tool_result")
        r = s.scan_tool_call(tool, args)
        lines.append(f"{bucket}[{i:03d}] {tool} {line(r)}")
        wires.append(wire(r))
    clear_flow()
    out = {f"A-{k[2:]}": v for k, v in full.items()}
    out["A-calls"] = (digest(lines), lines, wires)
    lines, wires = [], []
    for bucket, i, steps in adversarial_steps():
        clear_flow()
        begin_flow(principal="c11-principal")
        for k, step in enumerate(steps):
            if "tool" in step:
                r = s.scan_tool_call(step["tool"], step["args"])
                wires.append(wire(r))
            else:
                r = s.scan(step["text"], direction="input")
            lines.append(f"{bucket}[{i:03d}] T{k} {line(r)}")
    clear_flow()
    out["A-steps"] = (digest(lines), lines, wires)
    return out


def construction_checks(xaidr):
    """What a user sees at construction: the validation message, and how many
    value_origin warnings each configuration logs."""
    import logging
    from xaidr.value_origin import MatchKind, SourceDesignation

    class _Count(logging.Handler):
        def __init__(self):
            super().__init__()
            self.msgs = []

        def emit(self, record):
            if "value_origin" in record.getMessage():
                self.msgs.append(record.getMessage())

    try:
        xaidr.Sensor(agent_id="c11", value_origin="enforec", reporter=_Null())
        rejected = None
    except ValueError as exc:
        rejected = str(exc)
    designation = SourceDesignation(tool="order_lookup", match=MatchKind.ANY, label="orders")
    counts = {}
    for name, kw in (("default", {}), ("off", {"value_origin": "off"}),
                     ("record", {"value_origin": "record"}),
                     ("enforce", {"value_origin": "enforce"}),
                     ("enforce+designation", {"value_origin": "enforce",
                                              "value_origin_sources": [designation]})):
        h = _Count()
        logger = logging.getLogger("xaidr.sensor")
        logger.addHandler(h)
        try:
            xaidr.Sensor(agent_id="c11", reporter=_Null(), **kw)
        finally:
            logger.removeHandler(h)
        counts[name] = h.msgs
    return {"enforec_rejected": rejected, "warnings": counts}


def compare(base_json, head_json):
    """The cross-commit comparison: every pass and mode in ``base_json`` (a
    wheel built with --base) against HEAD's off, record and enforce."""
    b, h = json.load(open(base_json)), json.load(open(head_json))
    print("base xaidr:", b["xaidr_file"], "| py", b["python"])
    print("head xaidr:", h["xaidr_file"], "| py", h["python"])
    bad = 0
    for e in ENFORCEMENT:
        base = b["digests"][f"default/{e}"]
        for p in sorted(base):
            row = {m: h["digests"][f"{m}/{e}"][p] for m in MODES}
            same = base[p] == row["off"] == row["record"] == row["enforce"]
            bad += not same
            print(f"  {e:7} {p:10} base={base[p][:12]} off={row['off'][:12]} "
                  f"record={row['record'][:12]} enforce={row['enforce'][:12]}  "
                  f"{'IDENTICAL' if same else 'DIFFERS'}")
    print("cross-commit:", "all identical" if not bad else f"{bad} differ")
    return bad


def digest(lines):
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def markers(lines):
    """How many P-fault rows actually reached each path's own marker."""
    want = {"circuit": "CIRCUIT_BREAKER_OPEN", "gate": "C11_GATE", "bounds": "fail_closed",
            "scan_error": "SCAN_ERROR", "not_scannable": "NOT_SCANNABLE"}
    got = {p: 0 for p in want}
    for ln in lines:
        for p, mark in want.items():
            if f" F-{p} " in ln and mark.lower() in ln.lower():
                got[p] += 1
    return got


if __name__ == "__main__":
    if "--compare" in sys.argv:
        i = sys.argv.index("--compare")
        sys.exit(1 if compare(sys.argv[i + 1], sys.argv[i + 2]) else 0)
    import sysconfig

    import xaidr
    site = sysconfig.get_paths()["purelib"]
    if not xaidr.__file__.startswith(site):
        sys.exit(f"REFUSING: xaidr imported from {xaidr.__file__}, not this venv's "
                 f"site-packages {site}; the source tree is shadowing the wheel")
    base = "--base" in sys.argv
    if not supports_value_origin(xaidr) and not base:
        sys.exit("REFUSING: this wheel has no Sensor(value_origin=...); a HEAD wheel "
                 "that lost it would otherwise be compared as 'default' against default")
    texts = corpus_texts(os.environ.get("C11_FIXTURE", FIXTURE))
    modes = MODES if supports_value_origin(xaidr) else (None,)
    result = {"xaidr_file": xaidr.__file__, "python": sys.version.split()[0], "digests": {}}
    for m in modes:
        for e in ENFORCEMENT:
            passes = run_passes(xaidr, m, e, texts)
            passes.update(run_adversarial(xaidr, m, e))
            result["digests"][f"{m or 'default'}/{e}"] = {k: v[0] for k, v in passes.items()}
    if supports_value_origin(xaidr):
        result["construction"] = construction_checks(xaidr)
    print(json.dumps(result, sort_keys=True))
