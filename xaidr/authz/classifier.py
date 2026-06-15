"""Action Impact Classifier — maps tool calls to (impact_class, impact_tier).

Loads the bundled impact-classes.json ruleset at import time (same packaging
pattern as the L1 scanner's all-l1-rules.json; structured so a server-pushed
ruleset can replace it later). Rules are evaluated in order; first match wins.
Argument escalations can only raise the tier, never lower it.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from typing import Optional

_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "rules", "impact-classes.json"
)

IMPACT_CLASSES = {
    "send", "delete", "transfer", "deploy", "publish",
    "share", "authenticate", "read", "unknown",
}

_TIER_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_FALLBACK_DEFAULT = {"impact_class": "unknown", "impact_tier": "medium"}


def _load_ruleset() -> dict:
    try:
        with open(_RULES_PATH) as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[xaidr] Warning: impact-classes.json failed to load ({exc}), using defaults only")
        return {"version": 0, "default": dict(_FALLBACK_DEFAULT), "rules": [], "argument_escalations": []}

    # Pre-compile value patterns; drop escalation entries with bad regexes.
    escalations = []
    for esc in raw.get("argument_escalations") or []:
        pattern = esc.get("value_pattern")
        if pattern is not None:
            try:
                esc = {**esc, "value_pattern": re.compile(pattern)}
            except re.error as exc:
                print(f"[xaidr] Warning: escalation {esc.get('id')} regex failed: {exc}")
                continue
        escalations.append(esc)
    raw["argument_escalations"] = escalations
    return raw


_RULESET = _load_ruleset()


def _glob_any(value: Optional[str], patterns: list) -> bool:
    if not value:
        return False
    lowered = value.lower()
    return any(fnmatch.fnmatchcase(lowered, str(p).lower()) for p in patterns)


def _rule_matches(rule: dict, tool_name: str, mcp_server: Optional[str]) -> bool:
    tool_patterns = rule.get("tool_name")
    mcp_patterns = rule.get("mcp_server")
    if not tool_patterns and not mcp_patterns:
        return False
    if tool_patterns and not _glob_any(tool_name, tool_patterns):
        return False
    if mcp_patterns and not _glob_any(mcp_server, mcp_patterns):
        return False
    return True


def _raise_tier(current: str, minimum: str) -> str:
    if _TIER_ORDER.get(minimum, -1) > _TIER_ORDER.get(current, -1):
        return minimum
    return current


def _apply_escalations(tier: str, arguments: dict) -> str:
    for esc in _RULESET.get("argument_escalations") or []:
        keys = esc.get("keys") or []
        min_tier = esc.get("min_tier")
        if min_tier not in _TIER_ORDER:
            continue
        pattern = esc.get("value_pattern")
        for key, value in arguments.items():
            if not _glob_any(str(key), keys):
                continue
            if pattern is not None and not pattern.search(str(value)):
                continue
            tier = _raise_tier(tier, min_tier)
            break
    return tier


def classify(
    tool_name: str,
    arguments: Optional[dict] = None,
    mcp_server: Optional[str] = None,
) -> tuple[str, str]:
    """Classify a tool call. Returns (impact_class, impact_tier).

    Never raises — any internal error falls back to ("unknown", "medium").
    """
    try:
        default = _RULESET.get("default") or _FALLBACK_DEFAULT
        impact_class = default.get("impact_class", "unknown")
        tier = default.get("impact_tier", "medium")

        for rule in _RULESET.get("rules") or []:
            if _rule_matches(rule, tool_name or "", mcp_server):
                impact_class = rule.get("impact_class", "unknown")
                tier = rule.get("impact_tier", "medium")
                break

        if isinstance(arguments, dict) and arguments:
            tier = _apply_escalations(tier, arguments)

        if impact_class not in IMPACT_CLASSES:
            impact_class = "unknown"
        if tier not in _TIER_ORDER:
            tier = "medium"
        return (impact_class, tier)
    except Exception:
        return ("unknown", "medium")
