"""Level-1 flow runner: replays flow scripts through ``xaidr.value_origin``'s
PUBLIC interface only (§5.3). Vendored with the suite, so it imports nothing
from ``xaidr`` except ``xaidr.value_origin``'s ``__all__``.
"""
from __future__ import annotations

import json
from pathlib import Path

from xaidr.value_origin import (
    MatchKind,
    SourceDesignation,
    Span,
    Writer,
    bind_fresh_ledger,
    bind_ledger,
    evaluate_call,
    record_principal_input,
    record_tool_result,
    unbind_ledger,
    validate_designations,
)

HERE = Path(__file__).resolve().parent

WRITERS = {"principal": Writer.PRINCIPAL, "quoted_untrusted": Writer.UNTRUSTED,
           "untrusted": Writer.UNTRUSTED}


def load_jsonl(name):
    return [json.loads(line) for line in (HERE / name).read_text(encoding="utf-8").splitlines()
            if line.strip()]


def designations_from(data):
    return validate_designations(
        SourceDesignation(tool=d["tool"], match=MatchKind(d["match"]),
                          source_arg=d.get("source_arg"), pattern=d.get("pattern"),
                          key_args=tuple(d.get("key_args", ())),
                          label=d.get("label", d["tool"]))
        for d in data)


def _config_a():
    from .convert import CONFIG_A
    return designations_from(CONFIG_A)


CONFIG_A = _config_a()
CONFIGS = {"A": (True, CONFIG_A), "B": (False, CONFIG_A), "C": (True, ())}


def run_corpus_flow(flow, config):
    """§5.1's flow script, events replayed in ``event_order``."""
    declare_spans, designations = CONFIGS[config]
    bind_fresh_ledger()
    outcomes = []
    for ev in flow["events"]:
        if ev["kind"] == "input":
            spans = ([Span(text=t, writer=WRITERS[w]) for w, t in flow["request_spans"]]
                     if declare_spans else None)
            outcomes.append(record_principal_input(flow["request_text"], spans,
                                                   input_clean=flow["input_clean"]))
        else:
            outcomes.append(record_tool_result(ev["tool"], ev["arguments"], ev["result"],
                                               designations=designations,
                                               result_blocked=False))
    v = evaluate_call(flow["call"]["tool"], flow["call"]["arguments"], flow_active=True)
    return v, outcomes


def run_supplementary(case):
    """Ops: bind_fresh | bind | unbind | input | read | call. The LAST op must
    be a call; it is the case's verdict. Every record op's outcome is kept."""
    d = case.get("designations", "A")
    designations = (CONFIG_A if d == "A" else () if d == "none" else designations_from(d))
    outcomes = []
    verdict = None
    unbind_ledger()
    for op in case["steps"]:
        kind = op["op"]
        if kind == "bind_fresh":
            bind_fresh_ledger()
        elif kind == "bind":
            bind_ledger()
        elif kind == "unbind":
            unbind_ledger()
        elif kind == "input":
            spans = (None if op.get("spans") is None
                     else [Span(text=t, writer=WRITERS[w]) for w, t in op["spans"]])
            outcomes.append(record_principal_input(
                op["text"], spans, input_clean=op.get("input_clean", True)).value)
        elif kind == "read":
            outcomes.append(record_tool_result(
                op["tool"], op.get("arguments"), op.get("result"),
                designations=designations,
                result_blocked=op.get("result_blocked", False)).value)
        elif kind == "call":
            verdict = evaluate_call(op["tool"], op.get("arguments"),
                                    flow_active=op.get("flow_active", True))
        else:
            raise ValueError(f"unknown op {kind!r}")
    assert case["steps"][-1]["op"] == "call", f"{case['id']}: last op must be a call"
    return verdict, outcomes


def observed(v, outcomes=None):
    """A CallVerdict as the comparable dict expected.jsonl rows use."""
    if v is None:
        return {"fault": True}
    fs = []
    for f in v.findings:
        d = {"path": list(f.path), "origin": f.origin.value,
             "span_declared": f.span_declared, "source_label": f.source_label}
        if f.destination is not None:
            d["destination"] = f.destination.key()
        else:
            d["reason"] = f.reason.value
        fs.append(d)
    out = {"wire": v.wire.value, "verdict": v.verdict.value,
           "row_state": v.row_state.value, "truncated": v.truncated, "findings": fs}
    if outcomes is not None:
        out["record_outcomes"] = outcomes
    return out


def diff(expected, got):
    """Field-by-field differences. A finding's ``span_declared`` and
    ``source_label`` are compared only when the expected row states them; every
    other field is compared exactly."""
    problems = []
    for k in ("wire", "verdict", "row_state", "truncated"):
        if expected.get(k) != got.get(k):
            problems.append(f"{k}: expected {expected.get(k)!r}, core gave {got.get(k)!r}")
    if "record_outcomes" in expected and expected["record_outcomes"] != got.get("record_outcomes"):
        problems.append(f"record_outcomes: expected {expected['record_outcomes']}, "
                        f"core gave {got.get('record_outcomes')}")
    ef, gf = expected.get("findings", []), got.get("findings", [])
    if len(ef) != len(gf):
        problems.append(f"findings: expected {len(ef)}, core gave {len(gf)}: {gf}")
    else:
        for i, (e, g) in enumerate(zip(ef, gf)):
            for k in e:
                if e[k] != g.get(k):
                    problems.append(f"findings[{i}].{k}: expected {e[k]!r}, core gave {g.get(k)!r}")
            for k in ("destination", "reason"):
                if k in g and k not in e:
                    problems.append(f"findings[{i}].{k}: core gave {g[k]!r}, expected none")
    return problems
