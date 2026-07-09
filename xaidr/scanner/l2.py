"""L2 Scanner — intent decomposition, composite rules, attack chains.

Mirrors the npm sensor's l2-scanner.ts architecture.
"""

import json
import os
import re
import time
from dataclasses import dataclass
from typing import List, Optional

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


@dataclass
class ThreatDetail:
    rule: str
    category: str
    score: float
    matched: str = ""


@dataclass
class L2Result:
    score: float
    threats: List[ThreatDetail]
    time_ms: float
    triggered: bool


def _load_json(filename: str) -> list:
    path = os.path.join(_RULES_DIR, filename)
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    except Exception as e:
        # Corrupt/unreadable asset must not crash `import xaidr` — degrade empty.
        print(f"[xaidr] Warning: {filename} failed to load ({e}); using empty ruleset")
        return []
    return data if isinstance(data, list) else []


def _compile_intents():
    raw = _load_json("dangerous-intents.json")
    compiled = []
    for r in raw:
        try:
            compiled.append({
                "name": r["name"],
                "actions": re.compile(r["actions"], re.IGNORECASE),
                "targets": re.compile(r["targets"], re.IGNORECASE),
                "modifiers": re.compile(
                    r.get("modifiers", "(?!)"), re.IGNORECASE
                ),
                "category": r["category"],
                "baseScore": r.get("baseScore", 0.50),
                "modifiedScore": r.get("modifiedScore", 0.75),
            })
        except re.error as e:
            print(f"[xaidr] Warning: intent {r.get('name')} regex failed: {e}")
    return compiled


INTENTS = _compile_intents()
COMPOSITES = _load_json("composite-rules.json")
CHAINS = _load_json("attack-chains.json")


SELF_REF_PATTERN = re.compile(
    r"\b(?:what|how|tell|describe|explain|share|give|show|reveal|list)\b"
    r".{0,30}"
    r"\b(?:your|you|yourself)\b"
    r".{0,30}"
    r"\b(?:setup|configuration|config|role|purpose|instruction|prompt|rule|"
    r"guideline|directive|how\s+you|inner|foundation|blueprint|framework|"
    r"parameters?|settings?|init(?:ial)?|origin(?:al)?|train(?:ing|ed)|"
    r"built|made|programmed|configured|core\s+(?:function|behavior|logic))\b",
    re.IGNORECASE | re.DOTALL,
)

SELF_REF_SCORE = 0.15


def _check_self_referential(text: str) -> Optional[ThreatDetail]:
    if SELF_REF_PATTERN.search(text):
        return ThreatDetail(
            rule="L2_self_referential_probe",
            category="system_prompt_leak",
            score=SELF_REF_SCORE,
            matched="self-referential probe",
        )
    return None


def _check_intents(text: str) -> List[ThreatDetail]:
    threats = []
    for intent in INTENTS:
        action_match = intent["actions"].search(text)
        target_match = intent["targets"].search(text)
        if action_match and target_match:
            modifier_match = intent["modifiers"].search(text)
            score = (
                intent["modifiedScore"] if modifier_match else intent["baseScore"]
            )
            threats.append(ThreatDetail(
                rule=intent["name"],
                category=intent["category"],
                score=score,
                matched=(
                    f"action={action_match.group()[:30]} "
                    f"target={target_match.group()[:30]}"
                ),
            ))
    return threats


def _check_composites(detected_categories: set) -> List[ThreatDetail]:
    threats = []
    for comp in COMPOSITES:
        conditions = comp.get("conditions", {})
        require_all = conditions.get("requireAll", [])

        all_met = True
        for group in require_all:
            if not any(cat in detected_categories for cat in group):
                all_met = False
                break

        if all_met and require_all:
            threats.append(ThreatDetail(
                rule=comp["name"],
                category=comp["category"],
                score=comp["confidence"],
                matched=f"composite: {', '.join(detected_categories)}",
            ))
    return threats


def scan_l2(text: str, l1_categories: set = None) -> L2Result:
    """Run L2 scan: intents + composites + self-referential probe."""
    start = time.perf_counter()
    threats: List[ThreatDetail] = []
    max_score = 0.0

    self_ref = _check_self_referential(text)
    if self_ref:
        threats.append(self_ref)
        max_score = max(max_score, self_ref.score)

    intent_threats = _check_intents(text)
    threats.extend(intent_threats)
    for t in intent_threats:
        max_score = max(max_score, t.score)

    all_categories = set(l1_categories or set())
    all_categories.update(t.category for t in threats)
    composite_threats = _check_composites(all_categories)
    threats.extend(composite_threats)
    for t in composite_threats:
        max_score = max(max_score, t.score)

    time_ms = (time.perf_counter() - start) * 1000
    return L2Result(
        score=max_score,
        threats=threats,
        time_ms=round(time_ms, 2),
        triggered=len(threats) > 0,
    )
