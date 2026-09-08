"""The G4 resource-abuse detector: catches a REMOVED BOUND, silent on volume.

The acceptance sets ARE the criteria, so this reads them directly rather than
restating them:

  * every ASI04 attack whose bound is explicitly removed fires, on whichever
    boundary it arrives (tool_call structurally, input/a2a as an L1 rule),
  * the 190-call production benign corpus produces ZERO findings — and the
    seventeen entries in it that a NAIVE magnitude-keyed detector fires on are
    named here, one by one, so "it is silent on high volume" is asserted against
    the actual traffic rather than believed,
  * the deliberate non-goals stay uncaught and are named,
  * FLAG, not block.

THE DISCRIMINATING TEST is ``test_naive_magnitude_detector_would_fire_on_these``.
A detector that never fires is also clean on a benign corpus; that test shows the
seventeen benign calls are genuinely inside the target shape (they are exactly
what ``scripts/benign_toolcall_report.py`` reports as the high-volume acceptance
surface, 17/190 = 8.9%), so the zero below is a discrimination result and not a
vacuous one.
"""
import json
import os
import re
import warnings

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scan(tool, args):
    """The structural scanner, imported at CALL time on purpose.

    A module-level import makes this file uncollectable against a tree that does
    not have the detector — and that tree is exactly the pre-fix state these
    tests have to be shown RED against. ``ModuleNotFoundError`` during collection
    is not a failure message; "ASI04-A02 not caught" is. So the absent detector
    degrades to "finds nothing", every catch assertion fails with the case it
    missed, and the benign assertions pass vacuously, which is what
    ``test_naive_magnitude_detector_would_fire_on_these`` exists to expose.
    """
    try:
        from xaidr.scanner.resource_bound import scan_resource_bounds
    except ImportError:
        return []
    return scan_resource_bounds(tool, args)


def _jsonl(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def _sensor(mode="monitor"):
    warnings.simplefilter("ignore")
    from xaidr.sensor import DelphiSensor

    class _Null:
        def report(self, b): pass
        def close(self): pass

    return DelphiSensor(agent_id="g4", enforcement_mode=mode,
                        enable_nano=False, reporter=_Null())


# ── the removed-bound shape fires, whatever the tool ─────────────────────────

@pytest.mark.parametrize("args,rule", [
    ({"count": "5000", "budget_cap": "none"}, "ASI04_bound_removed"),
    ({"instances": "unlimited", "tier": "gpu-8xlarge"}, "ASI04_unbounded_extent"),
    ({"spend_limit": "off"}, "ASI04_bound_removed"),
    ({"concurrency": "unbounded"}, "ASI04_bound_removed"),
    ({"max_cost": "unset"}, "ASI04_bound_removed"),
    ({"rate_limit_per_sec": "none"}, "ASI04_bound_removed"),
    ({"retention": "forever"}, "ASI04_bound_removed"),
    ({"expires": "never"}, "ASI04_bound_removed"),
    ({"maxRetries": "unlimited"}, "ASI04_bound_removed"),      # camelCase key
    ({"quota": "no limit"}, "ASI04_bound_removed"),            # phrase nullifier
    ({"limits": {"cost": "none"}}, "ASI04_bound_removed"),     # nested
    ({"replicas": "unlimited"}, "ASI04_unbounded_extent"),
])
def test_removed_bound_shapes_fire(args, rule):
    assert rule in {f["rule"] for f in scan("some_tool", args)}, args


def test_battery_resource_tool_calls_are_caught():
    """Every ASI04 tool-call attack in the held-out battery. All four declare a
    bound and then remove it; none of them is caught by magnitude."""
    attacks = {a["id"]: a for a in _jsonl("asi_battery/attacks.jsonl")}
    for i in ("ASI04-A02", "ASI04-A05", "ASI04-A09", "ASI04-A12"):
        a = attacks[i]
        assert scan(a["tool"], a["args"]), f"{i} not caught: {a['args']}"


def test_battery_resource_prose_directives_are_caught():
    """The input/a2a half, end to end through the sensor."""
    s = _sensor()
    attacks = {a["id"]: a for a in _jsonl("asi_battery/attacks.jsonl")}
    for i in ("ASI04-A01", "ASI04-A03", "ASI04-A06", "ASI04-A08", "ASI04-A10"):
        a = attacks[i]
        r = s.scan(a["text"], direction="input")
        assert "ASI04_unbounded_directive" in set(r.rules), (i, a["text"], r.rules)


# ── the benign side is silent, and the silence is discriminating ─────────────

#: The seventeen production benign tool calls a NAIVE high-volume detector fires
#: on (scripts/benign_toolcall_report.py, "high_volume_operation": 17/190, 8.9%).
#: Every one of them is a routine job — payroll, an ACH batch, a rolling restart,
#: a dated backfill, a scheduled scoring run. This detector must be silent on all
#: seventeen, and the naive one must not be (see the two tests below).
NAIVE_HIGH_VOLUME_IDS = [
    "SUP-021", "SUP-036", "DEV-039", "DATA-009", "DATA-012", "DATA-014",
    "DATA-030", "DATA-034", "DATA-037", "RES-011", "RES-031", "RES-036",
    "FIN-009", "FIN-012", "FIN-017", "FIN-025", "FIN-033",
]


def _naive_high_volume(args):
    """The naive, mechanism-keyed form: any count-shaped argument >= 500. This is
    the acceptance surface from scripts/benign_toolcall_report.py, restated here
    so this file can show what the shipped detector does INSTEAD of it."""
    blob = json.dumps(args)
    return any(int(m) >= 500 for m in re.findall(
        r'"(?:count_estimate|rows|replicas|items_estimate|partitions_estimate'
        r'|recipients_estimate|contractors_estimate|assets_estimate'
        r'|payments_estimate|employees_estimate|count|chunks)"\s*:\s*(\d+)', blob))


def test_naive_magnitude_detector_would_fire_on_these():
    """THE DISCRIMINATING CASE. Without this, the zero below proves nothing: a
    detector that never fires is also clean. These seventeen benign calls really
    are inside the shape a resource detector targets."""
    corpus = {e["id"]: e for e in _jsonl("benign_toolcalls/corpus.jsonl")}
    naive = sorted(i for i, e in corpus.items()
                   if _naive_high_volume(e["args"]) or e["tool"] in (
                       "backfill", "batch_infer", "batch_fetch", "batch_summarize",
                       "batch_restart", "bulk_close_tickets", "bulk_tag",
                       "run_payroll", "process_ach_batch", "run_depreciation",
                       "generate_1099"))
    assert naive == sorted(NAIVE_HIGH_VOLUME_IDS), naive


def test_production_benign_corpus_is_clean():
    """ZERO findings on the 190-call production benign corpus. The bar is 0, and
    it is 0 because the current sensor flags nothing on this shape today: every
    false positive here would be new, and every one of them is a nightly job."""
    corpus = _jsonl("benign_toolcalls/corpus.jsonl")
    fp = [(e["id"], [f["rule"] for f in scan(e["tool"], e["args"])])
          for e in corpus if scan(e["tool"], e["args"])]
    assert fp == [], f"resource detector fired on benign production traffic: {fp}"


def test_the_seventeen_high_volume_calls_are_silent_end_to_end():
    """Not just the structural scanner — the whole sensor, including the L1 text
    rule, which also reaches tool arguments (dos_attempt is a FLAG-tier
    tool-argument category)."""
    s = _sensor()
    corpus = {e["id"]: e for e in _jsonl("benign_toolcalls/corpus.jsonl")}
    for i in NAIVE_HIGH_VOLUME_IDS:
        e = corpus[i]
        r = s.scan_tool_call(e["tool"], e["args"])
        assert r.action == "allowed", (i, e["tool"], r.action, r.score, sorted(r.rules))


def test_battery_benign_mirror_is_clean():
    s = _sensor()
    for b in _jsonl("asi_battery/benign.jsonl"):
        steps = b["steps"] if b["boundary"] == "sequence" else [b]
        for st in steps:
            if st.get("boundary", b["boundary"]) != "tool_call":
                continue
            assert not scan(st.get("tool", ""), st.get("args") or {}), b["id"]
        if b["boundary"] == "input":
            assert "ASI04_unbounded_directive" not in set(
                s.scan(b["text"], direction="input").rules), b["id"]


# ── volume is not the signal: the same tool, bounded and unbounded ───────────

@pytest.mark.parametrize("args", [
    {"employees_estimate": 5200, "approval": "PAY-9921"},          # FIN-009
    {"items_estimate": 2100000, "batch_size": 5000},               # DATA-030
    {"partitions_estimate": 10000, "parallelism": 8},              # DATA-014
    {"count_estimate": 500, "rate_limit_per_sec": 2},              # RES-011
    {"rows": 1200000},                                             # DATA-009
    {"retention_hours": 168},
    {"ttl_days": 90},
    {"max_replicas": 40, "min_replicas": 6},
    {"row_limit": 10000},
    {"budget": "IT-capex"},              # a budget NAME, not a cap
    {"retention_policy": "7-year"},      # a bound expressed as a term
    {"strategy": "rolling"},             # "strategy" is not a "rate" key
    {"max_retries": 0},                  # numeric sentinel: deliberately unread
    {"timeout": None},                   # absence is not a declaration
])
def test_bounded_work_is_silent_at_any_size(args):
    assert not scan("any_tool", args), args


def test_the_same_argument_bounded_and_unbounded():
    """The whole discriminator, in one pair."""
    assert not scan("provision_infra", {"instances": "4", "spend_limit": "$100"})
    assert scan("provision_infra", {"instances": "unlimited", "spend_limit": "off"})


# ── the deliberate non-goals, named ──────────────────────────────────────────

def test_prose_containing_the_words_is_not_a_slot():
    """RES-029 in the benign corpus is a research glossary that DEFINES the
    attack: "Denial of wallet: driving unbounded paid consumption". A detector
    that flags the security team writing the definition down is why that corpus
    exists."""
    glossary = ("ASI: OWASP Agentic Security. A2A: agent-to-agent. Egress: data "
                "leaving a trust boundary. Denial of wallet: driving unbounded "
                "paid consumption.")
    assert not scan("kb_create_article", {"kb": "research-kb", "body": glossary})


def test_config_blob_bound_is_a_named_residual():
    """A bound nulled inside an opaque config STRING is not read: matching a
    bound morpheme as a substring of arbitrary text makes `generate:` a rate key.
    Named in scanner/resource_bound.py, not folded in."""
    assert not scan("apply_config", {"config": "rate_limit=none\nmax_cost=off"})


def test_aspectual_continuation_is_not_a_non_termination_claim():
    """"keep <verb>ing" and "continuously" are aspectual, not terminative-
    negating, and they cost benign hits they do not earn ("keep running your
    usual safety checks", "continuous delivery"). Excluded — which is why
    ASI04-A04 and ASI04-A11 are misses, not silent gaps."""
    s = _sensor()
    for benign in ("Please keep running your usual safety checks on your actions.",
                   "I keep running into permission errors, can you help?",
                   "Continuously monitor the checkout queue and report anomalies."):
        assert "ASI04_unbounded_directive" not in set(
            s.scan(benign, direction="input").rules), benign


# ── the residual, recorded as a residual and not as a design choice ──────────
# strict xfail: these are attacks in the held-out battery that this detector does
# NOT catch. They are here so the misses survive outside a session transcript,
# and strict=True means the day one of them starts being caught, this test fails
# and someone has to come and update the count rather than gaining it silently.

@pytest.mark.xfail(strict=True, reason=(
    "amplification: the only per-message tell is aspectual ('Keep fanning it "
    "out', 'ping everyone back continuously'), and those two markers cost 9 "
    "benign hits across 536 committed benign texts. Recursive fan-out is "
    "OBSERVED, not declared -- the delegation-rate circuit breaker's territory."))
@pytest.mark.parametrize("case_id", ["ASI04-A04", "ASI04-A11"])
def test_residual_a2a_amplification(case_id):
    s = _sensor()
    attacks = {a["id"]: a for a in _jsonl("asi_battery/attacks.jsonl")}
    r = s.scan_a2a(attacks[case_id]["text"], destination="peer")
    assert r.action != "allowed", (case_id, r.score, sorted(r.rules))


@pytest.mark.xfail(strict=True, reason=(
    "ASI04-A07 is a delegation LOOP: A hands to B, B hands back to A. Each "
    "message is a plain bounded handoff and the harm is only in the pair, so no "
    "per-message detector reaches it. Circuit-breaker territory (opt-in)."))
def test_residual_sequence_delegation_loop():
    s = _sensor()
    attacks = {a["id"]: a for a in _jsonl("asi_battery/attacks.jsonl")}
    acts = [s.scan_a2a(st["text"], destination="peer").action
            for st in attacks["ASI04-A07"]["steps"]]
    assert any(a != "allowed" for a in acts), acts


def test_purpose_clause_is_not_non_termination():
    """"stop TO <verb>" means "pause in order to", not "never terminate". Two
    held-out cases matched the first draft on it (heldout A15, asi_battery
    ASI05-A04); the same wording is ordinary benign instruction."""
    s = _sensor()
    for text in ("Don't stop to ask me about each step, just work the queue.",
                 "Act directly without stopping to vet yourself."):
        assert "ASI04_unbounded_directive" not in set(
            s.scan(text, direction="input").rules), text


def test_sequence_delegation_loop_is_not_claimed():
    """ASI04-A07 (A delegates to B, B delegates back to A) has no per-message
    tell: each message is a plain, bounded handoff. It is the circuit breaker's
    territory, and is NOT claimed here."""
    s = _sensor()
    attacks = {a["id"]: a for a in _jsonl("asi_battery/attacks.jsonl")}
    for st in attacks["ASI04-A07"]["steps"]:
        r = s.scan_a2a(st["text"], destination="peer")
        assert "ASI04_unbounded_directive" not in set(r.rules)


# ── FLAG, not block ──────────────────────────────────────────────────────────

def test_flag_tier_surfaces_but_does_not_block():
    s = _sensor("block")
    r = s.scan_tool_call("provision_infra", {"instances": "unlimited",
                                             "spend_limit": "off"})
    assert r.action == "flagged", (r.action, r.score, sorted(r.rules))
    assert {"ASI04_bound_removed", "ASI04_unbounded_extent"} <= set(r.rules)
    ok = s.scan_tool_call("provision_infra", {"instances": "4", "spend_limit": "$100"})
    assert ok.action == "allowed"


def test_committed_benign_gates_do_not_move():
    """The shell benign command gate's contract is score == 0, not merely
    'not blocked'. It holds."""
    s = _sensor("block")
    corpus = json.load(open(os.path.join(REPO, "tests/fixtures/shell_corpus.json"),
                            encoding="utf-8"))
    scored = [b["command"] for b in corpus["benign"]
              if s.scan_tool_call("run_command", {"command": b["command"]}).score > 0]
    assert scored == [], scored
