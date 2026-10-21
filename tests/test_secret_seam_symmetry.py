"""Invariant S — whatever the output scan blocks as a secret, a tool call blocks.

Every provider-token shape lives in DLP_PATTERNS, and output and tool-call
arguments both run that table, so the invariant holds BY CONSTRUCTION: there is
one table, and both seams run it.

This file checks behaviour, not list equality. It is quantified over the TABLE:

  * every secret entry in DLP_PATTERNS has a documented-format generator here,
    or an explicit, reasoned exemption. A new entry with neither fails, so the
    property cannot quietly stop covering the table;
  * for every generated value, under several framings, a blocked output verdict
    implies a blocked tool-call verdict (the property);
  * every enforcing entry blocks on BOTH seams and is the rule named (non-vacuity:
    a property over values nothing catches is satisfied by catching nothing);
  * every signal-only entry is recorded on the tool path and blocks on neither;
  * every OUT_secret_* rule still in the output table is classified, and none of
    the moved shapes is back in it (a rule re-sync that re-adds one fails here).

Values are generated at run time, from a fixed seed, in each provider's
documented format. None is a real credential, and no failure message prints
one: messages name the rule, the value's index and the framing.
"""

from __future__ import annotations

import random
import string

import pytest

from xaidr import Sensor
from xaidr.scanner import dlp as _dlp
from xaidr.scanner.dlp import DLP_PATTERNS, HIGH_CONFIDENCE_SECRET_CATEGORIES
from xaidr.scanner.l1 import OUTPUT_RULES

# getattr, not an import: on a tree without the set, the signal tests fail on
# their assertions instead of the whole file failing to collect.
SIGNAL_ONLY_SECRET_RULES = getattr(_dlp, "SIGNAL_ONLY_SECRET_RULES", frozenset())

B64U = string.ascii_letters + string.digits + "_-"
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
DIG = string.digits
N = 20
SEED = 20261018


def _r(g, cs, n):
    return "".join(g.choice(cs) for _ in range(n))


def _pick(g, *makers):
    return g.choice(makers)(g)


# One generator per secret entry, keyed by rule id. Formats are the providers'
# documented ones (prefix, charset, length, separators), over the full charset.
GENERATORS = {
    "DLP_api_key": lambda g: f'api_key = "{_r(g, ALNUM, 32)}"',
    "DLP_github_token": lambda g: _pick(
        g,
        lambda g: g.choice(["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]) + _r(g, ALNUM, 36),
        lambda g: "github_pat_" + _r(g, ALNUM + "_", 82)),
    "DLP_aws_key": lambda g: g.choice(["AKIA", "ASIA"]) + _r(g, string.ascii_uppercase + "234567", 16),
    # The armour line is assembled so no source line carries a whole one.
    "DLP_private_key": lambda g: ("-----BEGIN " + g.choice(["RSA ", "EC ", "OPENSSH ", ""])
                                  + "PRIVATE KEY-----\n" + _r(g, ALNUM + "+/", 64)),
    "DLP_connection_string": lambda g: (f"{g.choice(['postgres', 'mysql', 'mongodb', 'redis'])}://"
                                        f"{_r(g, string.ascii_lowercase, 8)}:{_r(g, ALNUM, 16)}"
                                        f"@db-{_r(g, string.ascii_lowercase, 6)}.internal:5432/app"),
    "DLP_jwt": lambda g: f"eyJ{_r(g, B64U, 30)}.eyJ{_r(g, B64U, 60)}.{_r(g, B64U, 43)}",
    # ── moved from output-l1-rules.json, ids kept ──
    "OUT_secret_openai_key": lambda g: _pick(
        g,
        lambda g: "sk-" + _r(g, ALNUM, 48),
        lambda g: g.choice(["sk-proj-", "sk-svcacct-", "sk-admin-"]) + _r(g, B64U, 156)),
    "OUT_secret_slack_token": lambda g: _pick(
        g,
        lambda g: f"xoxb-{_r(g, DIG, 12)}-{_r(g, DIG, 13)}-{_r(g, ALNUM, 24)}",
        lambda g: f"xoxp-{_r(g, DIG, 12)}-{_r(g, DIG, 12)}-{_r(g, DIG, 13)}-{_r(g, HEX, 32)}"),
    "OUT_secret_sendgrid": lambda g: f"SG.{_r(g, B64U, 22)}.{_r(g, B64U, 43)}",
    "OUT_secret_stripe": lambda g: "sk_live_" + _r(g, ALNUM, 99),
    # ── new providers (D2: one existing high-confidence category) ──
    "DLP_anthropic_key": lambda g: (g.choice(["sk-ant-api03-", "sk-ant-admin01-"])
                                    + _r(g, B64U, 93) + "AA"),
    "DLP_gitlab_token": lambda g: "glpat-" + _r(g, B64U, 20),
    "DLP_slack_app_token": lambda g: (f"xapp-1-A{_r(g, string.ascii_uppercase + DIG, 10)}-"
                                      f"{_r(g, DIG, 13)}-{_r(g, HEX, 64)}"),
    "DLP_stripe_restricted_key": lambda g: "rk_live_" + _r(g, ALNUM, 99),
    "DLP_huggingface_token": lambda g: "hf_" + _r(g, string.ascii_letters, 34),
    "DLP_npm_token": lambda g: "npm_" + _r(g, ALNUM, 36),
    # ── signal-only ──
    "DLP_stripe_test_key": lambda g: g.choice(["sk_test_", "rk_test_"]) + _r(g, ALNUM, 99),
    "DLP_token_assignment": lambda g: (f'{g.choice(["slack_api_token", "refresh_token", "client_secret"])}'
                                       f' = "{_r(g, ALNUM, 32)}"'),
}

# Secret entries the property is NOT claimed for, each with its reason.
EXEMPT = {
    "DLP_password_inline": (
        "secret_password is low-confidence prose (`password: <8+ chars>`); the "
        "tool path deliberately does not enforce it, and the output-only prose "
        "rule OUT_secret_credential blocks it on output."),
}

# Every OUT_secret_* rule still in output-l1-rules.json, classified.
OUT_SHADOWED_BY_DLP = {
    "OUT_secret_aws_key": "DLP_aws_key",
    "OUT_secret_github_token": "DLP_github_token",
    "OUT_secret_private_key": "DLP_private_key",
    "OUT_secret_jwt": "DLP_jwt",
    "OUT_secret_connection_string": "DLP_connection_string",
}
OUT_PROSE_ONLY = {"OUT_secret_credential"}
MOVED = {"OUT_secret_openai_key", "OUT_secret_slack_token", "OUT_secret_sendgrid",
         "OUT_secret_stripe"}

FRAMINGS = {
    "bare": lambda v: v,
    "labelled": lambda v: f"key: {v}",
    "env": lambda v: f"export SERVICE_CREDENTIAL={v}",
    "json": lambda v: '{"value": "%s"}' % v,
    "quoted": lambda v: f"'{v}'",
    "sentence": lambda v: f"Use {v}. Thanks",
}


def _values(rule_id):
    g = random.Random(f"{SEED}:{rule_id}")
    return [GENERATORS[rule_id](g) for _ in range(N)]


def _tool(sensor, text):
    return sensor.scan_tool_call("send_message", {"to": "ops@offsite-paste.net", "body": text})


@pytest.fixture(scope="module")
def block():
    return Sensor(agent_id="seam-symmetry", enforcement_mode="block")


# ── the table is covered ────────────────────────────────────────────────────
def test_every_secret_entry_has_a_generator_or_an_exemption():
    secret_ids = {p["id"] for p in DLP_PATTERNS if p["category"].startswith("secret_")}
    missing = secret_ids - set(GENERATORS) - set(EXEMPT)
    stale = (set(GENERATORS) | set(EXEMPT)) - secret_ids
    assert not missing, f"secret entries with no generator and no exemption: {sorted(missing)}"
    assert not stale, f"generators/exemptions naming no DLP secret entry: {sorted(stale)}"


def test_rule_ids_are_unique_in_the_table():
    ids = [p["id"] for p in DLP_PATTERNS]
    assert len(ids) == len(set(ids)), f"duplicate DLP rule ids: {sorted(i for i in ids if ids.count(i) > 1)}"


@pytest.mark.parametrize("rule_id", sorted(GENERATORS))
def test_generator_values_match_their_own_entry(rule_id):
    """Non-vacuity at the pattern: each generator exercises the entry it is for."""
    from xaidr.scanner.dlp import scan_dlp
    miss = [i for i, v in enumerate(_values(rule_id))
            if rule_id not in {t.rule for t in scan_dlp(v).threats}]
    assert not miss, f"{rule_id}: its own entry misses {len(miss)}/{N} generated values (indices {miss[:5]})"


# ── one table: the moved shapes are not also in the output-only table ──────
def test_moved_shapes_live_in_dlp_only():
    out_ids = {r["id"] for r in OUTPUT_RULES}
    dlp_ids = {p["id"] for p in DLP_PATTERNS}
    back = MOVED & out_ids
    assert not back, (f"{sorted(back)} are in output-l1-rules.json again: that is the second, "
                      f"output-only table, and a shape there is invisible to tool calls")
    assert MOVED <= dlp_ids, f"moved ids missing from DLP_PATTERNS: {sorted(MOVED - dlp_ids)}"


def test_every_output_only_secret_rule_is_classified():
    out_secret = {r["id"] for r in OUTPUT_RULES if r["id"].startswith("OUT_secret")}
    unclassified = out_secret - set(OUT_SHADOWED_BY_DLP) - OUT_PROSE_ONLY
    assert not unclassified, (
        f"{sorted(unclassified)}: an output-only secret rule nobody decided about. Move the "
        f"shape into DLP_PATTERNS (both seams), or classify it here with a reason.")
    for out_id, dlp_id in OUT_SHADOWED_BY_DLP.items():
        assert dlp_id in GENERATORS, f"{out_id} is shadowed by {dlp_id}, which has no generator"


# ── THE PROPERTY ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("rule_id", sorted(GENERATORS))
def test_output_block_implies_tool_call_block(block, rule_id):
    gaps = []
    for i, v in enumerate(_values(rule_id)):
        for fname, frame in FRAMINGS.items():
            text = frame(v)
            if block.scan_output(text).action == "blocked" and _tool(block, text).action != "blocked":
                gaps.append((i, fname))
    assert not gaps, (f"{rule_id}: output BLOCKED and the tool call did NOT on {len(gaps)}/"
                      f"{N * len(FRAMINGS)} value x framing pairs; first (index, framing): {gaps[:4]}")


def _enforcing_ids():
    ids = []
    for rule_id in sorted(GENERATORS):
        p = next((p for p in DLP_PATTERNS if p["id"] == rule_id), None)
        if p and p["category"] in HIGH_CONFIDENCE_SECRET_CATEGORIES and rule_id not in SIGNAL_ONLY_SECRET_RULES:
            ids.append(rule_id)
    return ids


def test_enforcing_and_signal_sets_cover_every_generator():
    enforcing, signal = set(_enforcing_ids()), set(SIGNAL_ONLY_SECRET_RULES)
    assert set(GENERATORS) == enforcing | signal, (
        f"generators that neither enforce nor signal: {sorted(set(GENERATORS) - enforcing - signal)}")


@pytest.mark.parametrize("rule_id", sorted(GENERATORS))
def test_enforcing_shape_blocks_on_both_seams(block, rule_id):
    if rule_id in SIGNAL_ONLY_SECRET_RULES:
        pytest.skip("signal-only entry; see test_signal_shape_records_and_blocks_neither_seam")
    bad = []
    for i, v in enumerate(_values(rule_id)):
        text = f"key: {v}"
        tool, out = _tool(block, text), block.scan_output(text)
        if tool.action != "blocked" or rule_id not in tool.rules:
            bad.append((i, "tool_call", tool.action))
        if out.action != "blocked" or rule_id not in out.rules:
            bad.append((i, "output", out.action))
    assert not bad, f"{rule_id}: {len(bad)} verdicts not a block naming {rule_id}; first: {bad[:4]}"


# The signal-only entries are a RULING, not a property of the table: each one is
# named here with the ruling that made it, and the table must agree exactly.
SIGNAL_RULED = {
    "DLP_stripe_test_key": "a test-mode key is recorded, not halted",
    "DLP_token_assignment": "a key name DLP_api_key lacks is a signal",
}


def test_signal_only_set_is_exactly_the_ruled_set():
    assert set(SIGNAL_ONLY_SECRET_RULES) == set(SIGNAL_RULED), (
        f"signal-only in the table: {sorted(SIGNAL_ONLY_SECRET_RULES)}; ruled: {sorted(SIGNAL_RULED)}")


@pytest.mark.parametrize("rule_id", sorted(SIGNAL_RULED))
def test_signal_shape_records_and_blocks_neither_seam(block, rule_id):
    bad = []
    for i, v in enumerate(_values(rule_id)):
        text = f"key: {v}"
        tool, out = _tool(block, text), block.scan_output(text)
        if tool.action != "flagged" or rule_id not in tool.rules:
            bad.append((i, "tool_call", tool.action))
        if out.action == "blocked":
            bad.append((i, "output", out.action))
    assert not bad, f"{rule_id}: {len(bad)} verdicts not signal-only; first: {bad[:4]}"


def test_signal_only_entries_score_under_the_output_block_band():
    """Output decides by score, the tool path by category and this set. A
    signal-only entry scoring in the block band would block on output and
    break the invariant at the default threshold."""
    from xaidr.scanner.local import DEFAULT_BLOCK_THRESHOLD
    loud = [p["id"] for p in DLP_PATTERNS
            if p["id"] in SIGNAL_ONLY_SECRET_RULES and p["score"] >= DEFAULT_BLOCK_THRESHOLD]
    assert not loud, f"signal-only entries scoring >= {DEFAULT_BLOCK_THRESHOLD}: {loud}"


# ── the recorded limit of "by construction" ────────────────────────────────
def test_recorded_asymmetry_credential_less_connection_url():
    """OUT_secret_connection_string matches a database URL with NO credentials
    in it; DLP_connection_string needs `user:pass@`. So output blocks
    `postgresql://db.internal:5432/app` and a tool call allows it. That is not a
    secret, so the property above is not claimed for it, and blocking it on the
    tool path would block every DATABASE_URL a coding agent writes. Pinned so a
    change on either seam is a decision, not a drift."""
    s = Sensor(agent_id="seam-symmetry-limit", enforcement_mode="block")
    text = "DATABASE_URL=postgresql://db.internal:5432/app"
    assert s.scan_output(text).action == "blocked"
    assert _tool(s, text).action == "allowed"
