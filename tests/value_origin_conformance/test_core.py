"""Level 1 — the core against expected.jsonl (§5.3). Vendored: byte-identical in paid.

Every corpus case under configs A, B and C, and every supplementary case, is
replayed through ``xaidr.value_origin``'s public interface and compared with
the row written from the LABELS (convert.py), field by field: wire, verdict,
row_state, truncated, and every finding's destination (or reason) and origin.

Per-class reporting only. A pooled rate is never printed (corpus README: "PER
CLASS OR NOT AT ALL").
"""
from __future__ import annotations

import collections
import hashlib
import json

import pytest

from xaidr.value_origin import (
    Mode,
    WireValue,
    bind_fresh_ledger,
    evaluate_call,
    record_tool_result,
    row_text,
    should_block,
    unbind_ledger,
)

from .harness import (
    HERE,
    diff,
    load_jsonl,
    observed,
    run_corpus_flow,
    run_supplementary,
)

FLOWS = load_jsonl("flows.jsonl")
EXPECTED = {(r["case_id"], r["config"]): r for r in load_jsonl("expected.jsonl")}
SUPPLEMENTARY = load_jsonl("supplementary.jsonl")
AUTHORIZING = {"principal", "principal_undeclared_span", "trusted_source"}


@pytest.fixture(autouse=True)
def _fresh_context():
    unbind_ledger()
    yield
    unbind_ledger()


def _run_config(config):
    out = {}
    for flow in FLOWS:
        v, outcomes = run_corpus_flow(flow, config)
        out[flow["case_id"]] = (flow, observed(v), [o.value for o in outcomes])
    return out


@pytest.fixture(scope="module")
def results():
    return {cfg: _run_config(cfg) for cfg in ("A", "B", "C")}


def test_source_pins_what_was_converted():
    """expected.jsonl is the file SOURCE.json says was authored (a hand edit of
    expected.jsonl that skips the converter is a red here)."""
    src = json.loads((HERE / "SOURCE.json").read_text(encoding="utf-8"))
    got = hashlib.sha256((HERE / "expected.jsonl").read_bytes()).hexdigest()
    assert got == src["expected_sha256"], (
        "expected.jsonl differs from the file convert.py wrote (SOURCE.json "
        "expected_sha256). An expected row is changed only by re-running the "
        "converter, and the PR names the rule that justifies it.")
    assert src["cases"] == len(FLOWS) == 620


@pytest.mark.parametrize("config", ["A", "B", "C"])
def test_every_corpus_case_matches_expected(results, config):
    bad = []
    for cid, (flow, got, outcomes) in results[config].items():
        if any(o != "recorded" for o in outcomes):
            bad.append(f"{cid} [{flow['class']}]: a record call returned {outcomes}")
        problems = diff(EXPECTED[(cid, config)], got)
        if problems:
            bad.append(f"{cid} [{flow['class']}]: " + "; ".join(problems))
    by_class = collections.defaultdict(collections.Counter)
    for cid, (flow, got, _) in results[config].items():
        by_class[flow["class"]][got["wire"]] += 1
    print(f"\nconfig {config}, per class:")
    for cls in sorted(by_class):
        print(f"  {cls:28s} {dict(by_class[cls])}")
    assert not bad, (f"config {config}: {len(bad)} of {len(FLOWS)} cases differ from "
                     "expected.jsonl (authored from the labels — the presumption is "
                     "that the core is wrong):\n  " + "\n  ".join(bad[:25]))


def test_no_false_authorization_in_config_a(results):
    bad = [f"{cid} is labelled unauthorized and resolved to {got['wire']} — value "
           "origin AUTHORIZED an attack destination; the rule is only safe if this "
           "set is empty."
           for cid, (flow, got, _) in results["A"].items()
           if flow["expected_verdict"] == "unauthorized" and got["wire"] in AUTHORIZING]
    assert not bad, "\n".join(bad)


def test_every_config_b_false_authorization_is_labelled(results):
    """Ruling 2026-09-24 / C-3a: in B, an authorized attack must carry
    principal_undeclared_span — including all 30 attacker_keyed_lookup."""
    bad, n = [], 0
    for cid, (flow, got, _) in results["B"].items():
        if flow["expected_verdict"] == "unauthorized" and got["wire"] in AUTHORIZING:
            n += 1
            if got["wire"] != "principal_undeclared_span":
                bad.append(f"{cid} [{flow['class']}] is labelled unauthorized and "
                           f"resolved to {got['wire']} — an UNLABELLED false "
                           "authorization, the failure the config-B ruling forbids")
    assert not bad, "\n".join(bad)
    assert n == 63, f"config B false authorizations: {n}, §5.2 as amended says 63 (33 + 30 D1)"


def test_tripwire(results):
    want = {"A": "principal", "B": "principal_undeclared_span", "C": "principal"}
    for cfg, w in want.items():
        got = {cid: g["wire"] for cid, (f, g, _) in results[cfg].items()
               if f["class"] == "trivial_control"}
        assert len(got) == 20
        bad = {c: v for c, v in got.items() if v != w}
        assert not bad, (f"TRIPWIRE ({cfg}): a destination written verbatim by the "
                         f"principal did not resolve to {w} — the comparator is broken "
                         f"and every other number in this run is invalid: {bad}")


@pytest.mark.parametrize("case", SUPPLEMENTARY, ids=[c["id"] for c in SUPPLEMENTARY])
def test_supplementary_case(case):
    v, outcomes = run_supplementary(case)
    exp = EXPECTED[(case["id"], "S")]
    got = observed(v, outcomes if "record_outcomes" in exp else None)
    problems = diff(exp, got)
    assert not problems, f"{case['id']} ({case['rule']}):\n  " + "\n  ".join(problems)


# R1 (2026-10-03) is a ruling about BLOCKING, so it is pinned at should_block
# under ENFORCE, not only at the wire: an untrusted part beside junk blocks, and
# a trusted or principal part beside junk does not newly block.
R1_BLOCKS = {
    "R32-untrusted-plus-bad-part": True, "R32-untrusted-junk-before": True,
    "R32-untrusted-junk-semicolon": True, "R32-two-untrusted-parts": True,
    "R32-untrusted-unbalanced-quote": True,
    "R32-trusted-plus-junk": False, "R32-one-bad-part": False,
}
SUPPLEMENTARY_BY_ID = {c["id"]: c for c in SUPPLEMENTARY}


@pytest.mark.parametrize("cid", sorted(R1_BLOCKS))
def test_r1_an_untrusted_part_beside_junk_blocks_and_a_trusted_one_does_not(cid):
    v, _ = run_supplementary(SUPPLEMENTARY_BY_ID[cid])
    got = should_block(v, mode=Mode.ENFORCE)
    assert got is R1_BLOCKS[cid], (
        f"{cid}: should_block under ENFORCE is {got}, R1 says {R1_BLOCKS[cid]} — "
        + ("an untrusted mailbox walked through behind a junk part" if R1_BLOCKS[cid]
           else "a trusted mailbox beside junk now BLOCKS, which R1 forbids"))


@pytest.mark.xfail(strict=True, reason=(
    "found, not fixed (2026-10-03): junk in the SAME part as the address. R1 works "
    "on the parts of a ','/';' split; `evil@x.example <` has one part, and it fails. "
    "email.utils.getaddresses reads [('', 'evil@x.example'), ('', '')] out of it."))
def test_r1_residual_junk_inside_the_part_still_hides_an_untrusted_mailbox():
    bind_fresh_ledger()
    record_tool_result("web_fetch", {"url": "https://news.example/"}, "evil@x.example",
                       designations=(), result_blocked=False)
    v = evaluate_call("send_email", {"to": "evil@x.example <"}, flow_active=True)
    assert should_block(v, mode=Mode.ENFORCE), (
        f"wire {v.wire.value}: an untrusted mailbox walked through behind '<'")


def test_row_text_matches_the_committed_export():
    """§5.3: row_text() over WireValue x {tool_call, input, None}, None, and the
    V-29 unrecognised samples equals row_text.json — the same JSON the Brain's
    and the waterfall's TypeScript tables are checked against."""
    rows = json.loads((HERE / "row_text.json").read_text(encoding="utf-8"))
    assert {r["wire"] for r in rows if r["scan_mode"] == "tool_call"} >= (
        {w.value for w in WireValue} | {None})
    bad = []
    for r in rows:
        state, text = row_text(r["wire"], r["scan_mode"])
        if (state.value, text) != (r["row_state"], r["text"]):
            bad.append(f"{r['wire']!r}/{r['scan_mode']!r}: got ({state.value}, {text!r})")
    assert not bad, "\n".join(bad)
