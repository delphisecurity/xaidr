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

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


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

    for rule in rules:
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
