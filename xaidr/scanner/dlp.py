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
        "id": "DLP_email_bulk",
        "pattern": re.compile(
            r"(?:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}[\s,;]+){3,}",
            re.IGNORECASE,
        ),
        "category": "pii_email_bulk",
        "score": 0.70,
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
