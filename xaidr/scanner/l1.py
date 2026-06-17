"""L1 Scanner — regex pattern matching against rule JSON files.

Loads rules from JSON at import time, compiles regex patterns once.
Matches the npm sensor's l1-scanner.ts architecture.
"""

import json
import os
import re
import time
from dataclasses import dataclass
from typing import List

from .dlp import _is_reserved_email

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")

# Maximum number of characters L1 will regex-scan. A megabyte-class input fed to
# every compiled pattern causes catastrophic regex backtracking (an exploitable
# ReDoS / denial-of-service). We scan only the first L1_MAX_SCAN_CHARS characters
# — large enough that no real attack payload is missed (attacks lead with their
# injection, not after 100k chars of filler), small enough to bound worst-case
# work to well under a second. Truncation applies to the SCANNED view only; the
# caller's original data is never mutated. The shared call site (local.py) caps
# the same way so L2/DLP/compositional are bounded too.
L1_MAX_SCAN_CHARS = 100_000

# Defense-in-depth wall-clock budget for one L1 scan. If the cumulative time
# spent in the rule loop exceeds this, remaining rules are skipped with a warning
# so a single pathological pattern can never hang the whole scan. Thread-safe
# (no signals): checked between rules.
_L1_SCAN_BUDGET_SEC = 0.5


@dataclass
class ThreatDetail:
    rule: str
    category: str
    score: float
    matched: str = ""


@dataclass
class L1Result:
    score: float
    threats: List[ThreatDetail]
    time_ms: float
    triggered: bool


def _load_and_compile(filename: str) -> list:
    """Load rules from JSON and compile regex patterns."""
    path = os.path.join(_RULES_DIR, filename)
    try:
        with open(path) as f:
            raw = json.load(f)
    except FileNotFoundError:
        print(f"[xaidr] Warning: {filename} not found, using empty ruleset")
        return []

    compiled = []
    for r in raw:
        try:
            compiled.append({
                "id": r["id"],
                "pattern": re.compile(r["pattern"], re.IGNORECASE),
                "score": r["score"],
                "category": r["category"],
                # Email PII rules set this so RFC-reserved documentation domains
                # (example.com/.test/.invalid/...) don't fire as a PII leak.
                "filter_reserved_email": bool(r.get("filter_reserved_email", False)),
            })
        except re.error as e:
            print(f"[xaidr] Warning: rule {r.get('id')} regex failed: {e}")
    return compiled


INPUT_RULES = _load_and_compile("all-l1-rules.json")
OUTPUT_RULES = _load_and_compile("output-l1-rules.json")


def scan_l1(text: str, output: bool = False) -> L1Result:
    """Run L1 regex scan. Returns score, threats, timing."""
    start = time.perf_counter()
    rules = OUTPUT_RULES if output else INPUT_RULES
    threats: List[ThreatDetail] = []
    max_score = 0.0

    # Size cap: bound the text every regex sees. Truncates the scanned view only.
    if len(text) > L1_MAX_SCAN_CHARS:
        text = text[:L1_MAX_SCAN_CHARS]

    for rule in rules:
        # Wall-clock guard (defense in depth): never let one bad pattern hang the
        # scan. With the size cap + linear patterns this should never trip.
        if time.perf_counter() - start > _L1_SCAN_BUDGET_SEC:
            print(
                f"[xaidr] Warning: L1 scan budget exceeded "
                f"({_L1_SCAN_BUDGET_SEC}s); skipping remaining rules"
            )
            break
        if rule.get("filter_reserved_email"):
            # Email PII rule: drop RFC-reserved documentation-domain matches and
            # fire only if a real (non-reserved) email remains. Linear: findall +
            # a list filter over already-found matches (no new backtracking regex).
            emails = rule["pattern"].findall(text)
            real = [e for e in emails if not _is_reserved_email(e)]
            if real:
                threats.append(ThreatDetail(
                    rule=rule["id"],
                    category=rule["category"],
                    score=rule["score"],
                    matched=str(real[0])[:100],
                ))
                if rule["score"] > max_score:
                    max_score = rule["score"]
            continue

        match = rule["pattern"].search(text)
        if match:
            threats.append(ThreatDetail(
                rule=rule["id"],
                category=rule["category"],
                score=rule["score"],
                matched=match.group()[:100],
            ))
            if rule["score"] > max_score:
                max_score = rule["score"]

    categories = set(t.category for t in threats)
    if len(categories) >= 2:
        max_score = min(1.0, max_score * 1.3)

    time_ms = (time.perf_counter() - start) * 1000
    return L1Result(
        score=max_score,
        threats=threats,
        time_ms=round(time_ms, 2),
        triggered=len(threats) > 0,
    )
