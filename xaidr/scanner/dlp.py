"""DLP Scanner — PII and secret pattern detection.

Matches the npm sensor's dlp-scanner.ts patterns.
"""

import re
import time
from dataclasses import dataclass
from typing import List

# RFC 2606 reserved example/test/invalid domains + RFC 6761 localhost. Email at
# these is a documentation PLACEHOLDER — the domains route nowhere by definition,
# so they cannot be exfiltration targets and flagging them as PII leaks is pure
# noise. This is a principled, published reserved set — NOT context-guessing: we
# never suppress real-looking domains, and a real email always still triggers.
_RESERVED_EMAIL_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_RESERVED_EMAIL_TLDS = (".test", ".example", ".invalid", ".localhost")


def _is_reserved_email(email: str) -> bool:
    """True if an email's domain is an RFC-reserved documentation domain."""
    if not isinstance(email, str):
        return False
    at = email.rfind("@")
    if at == -1:
        return False
    domain = email[at + 1:].strip().lower().rstrip(".")
    if domain in _RESERVED_EMAIL_DOMAINS:
        return True
    return domain.endswith(_RESERVED_EMAIL_TLDS)


def _luhn_valid(text: str) -> bool:
    """True if the digits in ``text`` (separators stripped) satisfy the Luhn
    checksum and form a plausible 13-19 digit card. Used to gate DLP_credit_card
    so a non-Luhn 13-19 digit number (an order ID, tracking number) is NOT a
    payment card. Pure integer arithmetic — no regex, no ReDoS surface."""
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_VALIDATORS = {"luhn": _luhn_valid}


@dataclass
class ThreatDetail:
    rule: str
    category: str
    score: float
    matched: str = ""


@dataclass
class DLPResult:
    score: float
    threats: List[ThreatDetail]
    time_ms: float
    triggered: bool


DLP_PATTERNS = [
    {
        "id": "DLP_ssn",
        "pattern": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
        "category": "pii_ssn",
        "score": 0.85,
    },
    {
        # Payment-card numbers (Visa/MC/Amex/Discover), tolerant of space/dash
        # grouping ("4242 4242 4242 4242"). Prefix-anchored to card BINs so an
        # arbitrary long digit run is not a candidate, and gated by ``validate:
        # luhn`` below — a match only counts if the stripped digits pass the Luhn
        # checksum, which cuts the FP rate on non-card 13-19 digit numbers (order
        # IDs, tracking numbers) dramatically. Bounded {9,15} repeat → no ReDoS.
        "id": "DLP_credit_card",
        "pattern": re.compile(
            r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))"
            r"(?:[ -]?[0-9]){9,15}\b"
        ),
        "category": "pii_credit_card",
        "score": 0.85,
        "validate": "luhn",
    },
    {
        # Bulk-email exfiltration. The old pattern repeated an email-shaped group
        # `(?:…@…){3,}` with UNBOUNDED inner `+` quantifiers — O(n^2) on long
        # word-char runs (a ReDoS; ~37s at a 100k cap). Replaced with a single,
        # provably-linear email regex (bounded quantifiers) matched via findall +
        # a count threshold: 3+ distinct email matches => bulk. Same intent, no
        # catastrophic backtracking.
        "id": "DLP_email_bulk",
        "pattern": re.compile(
            r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b",
            re.IGNORECASE,
        ),
        "category": "pii_email_bulk",
        "score": 0.70,
        "min_count": 3,
        # Drop RFC-reserved documentation domains before applying the bulk
        # threshold, so a list of example.com/.test/.invalid placeholders is not
        # flagged as a PII leak. Only the email finding carries this flag.
        "filter_reserved_email": True,
    },
    {
        "id": "DLP_phone",
        "pattern": re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
        ),
        "category": "pii_phone",
        "score": 0.40,
    },
    {
        # `secret[_-]?access[_-]?key` is listed separately from `secret[_-]?key`
        # because AWS's own spelling puts a word between the two halves
        # (`aws_secret_access_key = …`), so the shorter alternative does not
        # reach it. The value shape (20+ key chars after an explicit `=`/`:`)
        # is what keeps this from firing on prose.
        "id": "DLP_api_key",
        "pattern": re.compile(
            r"(?:api[_-]?key|apikey|secret[_-]?key|secret[_-]?access[_-]?key|"
            r"access[_-]?token|auth[_-]?token|bearer)"
            r"\s*[:=]\s*[\"']?([a-zA-Z0-9_\-/+]{20,})[\"']?",
            re.IGNORECASE,
        ),
        "category": "secret_api_key",
        "score": 0.85,
    },
    {
        # GitHub tokens carry their own prefix, so no surrounding key name is
        # needed and there is no prose that looks like one: `ghp_`/`gho_`/`ghu_`/
        # `ghs_`/`ghr_` (classic + OAuth/app tokens) and `github_pat_`
        # (fine-grained). Bounded repeats over a negated-free character class —
        # linear, no ReDoS surface.
        "id": "DLP_github_token",
        "pattern": re.compile(
            r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"
            r"|\bgithub_pat_[A-Za-z0-9_]{40,255}\b"
        ),
        "category": "secret_github_token",
        "score": 0.90,
    },
    {
        "id": "DLP_aws_key",
        "pattern": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
        "category": "secret_aws_key",
        "score": 0.90,
    },
    {
        "id": "DLP_private_key",
        "pattern": re.compile(
            r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"
        ),
        "category": "secret_private_key",
        "score": 0.90,
    },
    {
        "id": "DLP_connection_string",
        "pattern": re.compile(
            r"(?:mongodb|postgres|mysql|redis|amqp)://"
            r"[^\s\"']+:[^\s\"']+@[^\s\"']+",
            re.IGNORECASE,
        ),
        "category": "secret_connection_string",
        "score": 0.85,
    },
    {
        "id": "DLP_jwt",
        "pattern": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        "category": "secret_jwt",
        "score": 0.85,
    },
    {
        "id": "DLP_password_inline",
        "pattern": re.compile(
            r"(?:password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?",
            re.IGNORECASE,
        ),
        "category": "secret_password",
        "score": 0.80,
    },
]


# ── Secret categories by CONFIDENCE (used by the tool-argument scan) ──────────
# The tool-argument path enforces on SECRETS and never on PII — see
# DelphiSensor._scan_tool_call_impl for why. The split lives here, next to the
# patterns, so adding a pattern forces a conscious decision about its confidence
# instead of silently inheriting one.
#
# HIGH CONFIDENCE: the match shape is self-identifying — a token prefix (AKIA,
# ghp_), a PEM armour line, a URL scheme with inline credentials, a JWT's three
# base64 segments, or an explicit `api_key = <20+ key chars>`. None of these
# shapes occur in ordinary English, so a hit is a secret, not a sentence.
HIGH_CONFIDENCE_SECRET_CATEGORIES = frozenset({
    "secret_api_key",
    "secret_aws_key",
    "secret_github_token",
    "secret_private_key",
    "secret_connection_string",
    "secret_jwt",
})

# LOWER CONFIDENCE, deliberately excluded from enforcement: `secret_password`
# matches `password:` followed by any 8+ non-space characters, which ordinary
# prose produces constantly ("please reset your password: instructions are at
# …"). It stays a SIGNAL — it still scores and still surfaces — but it does not
# block a tool call on its own. Tightening the pattern instead would weaken the
# content path, where a low-confidence signal is fused with others rather than
# acted on alone.
LOW_CONFIDENCE_SECRET_CATEGORIES = frozenset({"secret_password"})


def scan_dlp(text: str) -> DLPResult:
    """Run DLP pattern scan."""
    start = time.perf_counter()
    threats: List[ThreatDetail] = []
    max_score = 0.0

    for p in DLP_PATTERNS:
        min_count = p.get("min_count")
        if min_count:
            # Count-threshold rule (e.g. bulk email): a single linear regex is
            # matched with findall and flagged only when it occurs >= min_count
            # times. findall is linear, avoiding the repeated-group ReDoS.
            matches = p["pattern"].findall(text)
            if p.get("filter_reserved_email"):
                # RFC-reserved placeholder domains are not exfiltration targets;
                # drop them, then apply the bulk threshold to the real remainder.
                # Linear: a list comprehension over already-found matches.
                matches = [m for m in matches if not _is_reserved_email(m)]
            if len(matches) >= min_count:
                first = matches[0]
                if isinstance(first, tuple):  # if the regex ever has groups
                    first = next((g for g in first if g), "")
                threats.append(ThreatDetail(
                    rule=p["id"],
                    category=p["category"],
                    score=p["score"],
                    matched=f"{len(matches)} matches: {str(first)[:40]}",
                ))
                if p["score"] > max_score:
                    max_score = p["score"]
            continue

        match = p["pattern"].search(text)
        if match:
            # Optional value-level validation (e.g. Luhn for cards): a regex match
            # only counts if the validator on the matched span passes. Keeps the
            # FP guard (non-Luhn digit runs) in code, not the pattern.
            validator = _VALIDATORS.get(p.get("validate"))
            if validator and not validator(match.group()):
                continue
            threats.append(ThreatDetail(
                rule=p["id"],
                category=p["category"],
                score=p["score"],
                matched=match.group()[:50],
            ))
            if p["score"] > max_score:
                max_score = p["score"]

    time_ms = (time.perf_counter() - start) * 1000
    return DLPResult(
        score=max_score,
        threats=threats,
        time_ms=round(time_ms, 2),
        triggered=len(threats) > 0,
    )
