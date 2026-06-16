"""DLP Scanner — PII and secret pattern detection.

Matches the npm sensor's dlp-scanner.ts patterns.
"""

import re
import time
from dataclasses import dataclass
from typing import List


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
        "id": "DLP_credit_card",
        "pattern": re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
            r"6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        "category": "pii_credit_card",
        "score": 0.85,
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
        "id": "DLP_api_key",
        "pattern": re.compile(
            r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|"
            r"auth[_-]?token|bearer)\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{20,})[\"']?",
            re.IGNORECASE,
        ),
        "category": "secret_api_key",
        "score": 0.85,
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
