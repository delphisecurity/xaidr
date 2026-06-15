"""Local action-policy evaluator.

The policy arrives via the agent-config refresh payload under the optional
"action_policy" key (versioned YAML-equivalent JSON). parse_action_policy()
validates it; evaluate() runs an AuthZEN-shaped request through the rules in
order, first match wins. Both are pure functions and never raise — a malformed
policy or evaluation error degrades to the monitor-only default.

AuthZEN-shaped request::

    {
        "subject":  {"agent_id": str, "trust": float | None},
        "action":   {"tool_name": str, "impact_class": str, "impact_tier": str},
        "resource": {"destination_type": str, "destination_identifier": str},
        "context":  {...},
    }
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger("xaidr.authz")

SUPPORTED_VERSIONS = {"1", "1.0", 1}

EFFECTS = {"allow", "block", "monitor", "require_approval"}

_EFFECT_TO_DECISION = {
    "allow": "allowed",
    "block": "blocked",
    "monitor": "monitor",
    "require_approval": "approval_required",
}

# Rule match fields -> (request section, request key). Unknown fields are ignored.
_MATCH_FIELDS = {
    "tools": ("action", "tool_name"),
    "agents": ("subject", "agent_id"),
    "impact_class": ("action", "impact_class"),
    "impact_tier": ("action", "impact_tier"),
    "destination_type": ("resource", "destination_type"),
    "destination_identifier": ("resource", "destination_identifier"),
    "mcp_server": ("context", "mcp_server"),
}


@dataclass
class AuthzDecision:
    decision: str  # allowed | blocked | monitor | approval_required
    policy_id: Optional[str] = None
    reason: Optional[str] = None


MONITOR_DECISION = AuthzDecision(decision="monitor")


def parse_action_policy(raw: Any) -> Optional[dict]:
    """Validate and normalize an action_policy payload.

    Returns the normalized policy dict, or None for anything malformed —
    callers treat None as monitor-only defaults (never raise).
    Unknown fields at any level are ignored.
    """
    try:
        if not isinstance(raw, dict):
            return None
        if raw.get("version") not in SUPPORTED_VERSIONS:
            logger.warning(f"[xaidr] action_policy version {raw.get('version')!r} unsupported")
            return None

        raw_rules = raw.get("rules", [])
        if not isinstance(raw_rules, list):
            return None

        rules = []
        for r in raw_rules:
            if not isinstance(r, dict) or r.get("effect") not in EFFECTS:
                logger.warning(f"[xaidr] action_policy has a malformed rule: {r!r}")
                return None
            match = r.get("match") if isinstance(r.get("match"), dict) else {}
            conditions = r.get("conditions") if isinstance(r.get("conditions"), dict) else {}
            rules.append({
                "id": str(r.get("id")) if r.get("id") is not None else None,
                "effect": r["effect"],
                "match": match,
                "conditions": conditions,
                "message": r.get("message"),
            })

        raw_defaults = raw.get("defaults") if isinstance(raw.get("defaults"), dict) else {}
        defaults = {
            "effect": raw_defaults.get("effect", "allow"),
            "unclassified": raw_defaults.get("unclassified", "monitor"),
        }
        if defaults["effect"] not in EFFECTS or defaults["unclassified"] not in EFFECTS:
            return None

        return {"version": str(raw["version"]), "defaults": defaults, "rules": rules}
    except Exception as exc:
        logger.warning(f"[xaidr] action_policy parse failed: {exc}")
        return None


def build_request(
    agent_id: str,
    trust: Optional[float],
    tool_name: str,
    impact_class: str,
    impact_tier: str,
    destination_type: str,
    destination_identifier: str,
    context: Optional[dict] = None,
) -> dict:
    """Build the AuthZEN-shaped evaluation request."""
    return {
        "subject": {"agent_id": agent_id, "trust": trust},
        "action": {
            "tool_name": tool_name,
            "impact_class": impact_class,
            "impact_tier": impact_tier,
        },
        "resource": {
            "destination_type": destination_type,
            "destination_identifier": destination_identifier,
        },
        "context": context or {},
    }


def _glob_any(value: Any, patterns: Any) -> bool:
    if not isinstance(patterns, list) or value is None:
        return False
    lowered = str(value).lower()
    return any(fnmatch.fnmatchcase(lowered, str(p).lower()) for p in patterns)


def _rule_matches(rule: dict, request: dict) -> bool:
    matched_anything = False
    for field, (section, key) in _MATCH_FIELDS.items():
        patterns = rule["match"].get(field)
        if patterns is None:
            continue
        matched_anything = True
        value = (request.get(section) or {}).get(key)
        if not _glob_any(value, patterns):
            return False

    trust_below = rule["conditions"].get("trust_below")
    if trust_below is not None:
        matched_anything = True
        trust = (request.get("subject") or {}).get("trust")
        if trust is None or not float(trust) < float(trust_below):
            return False

    # A rule with no recognized matchers or conditions matches nothing —
    # an empty rule must not silently become a catch-all.
    return matched_anything


def evaluate(policy: Optional[dict], request: dict) -> AuthzDecision:
    """Evaluate the request against a parsed policy. Never raises.

    - No policy (None): monitor-only default.
    - Rules in order, first match wins.
    - No rule matched: defaults.unclassified for impact_class=unknown,
      defaults.effect (allow) otherwise.
    """
    try:
        if policy is None:
            return MONITOR_DECISION

        for rule in policy["rules"]:
            if _rule_matches(rule, request):
                return AuthzDecision(
                    decision=_EFFECT_TO_DECISION[rule["effect"]],
                    policy_id=rule["id"],
                    reason=rule.get("message"),
                )

        defaults = policy["defaults"]
        impact_class = (request.get("action") or {}).get("impact_class")
        if impact_class == "unknown":
            return AuthzDecision(decision=_EFFECT_TO_DECISION[defaults["unclassified"]])
        return AuthzDecision(decision=_EFFECT_TO_DECISION[defaults["effect"]])
    except Exception as exc:
        logger.warning(f"[xaidr] action_policy evaluation error: {exc}")
        return MONITOR_DECISION
