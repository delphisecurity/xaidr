"""local_policy.py — Local YAML policy loading + composition (phase 4).

Lets a developer enforce their own authorization policy with NO backend: write a
YAML file, drop it next to the agent, and the sensor enforces it in-process. The
decision engine (authz/policy.py) already exists; this module adds the missing
local policy *source* and composes the policy verdict with the detection verdict.

Resolution of the policy source (first match wins):
  1. an explicit path:        Sensor(policy_file="my-policy.yaml")
  2. a programmatic dict:      sensor.set_policy({...})
  3. a conventional default:   ./xaidr-policy.yaml  (auto-loaded, logged)
  4. none -> detection-only

Composition (policy-as-overlay, STRICTER WINS):
  The final action is the stricter of {detection verdict, policy verdict}, so a
  policy can ADD restrictions (deny a tool detection allowed) but can NEVER
  weaken detection (a policy `allow` does not switch off a detected attack).
  This makes a misconfigured policy fail safe: over-restrictive just blocks more;
  over-permissive cannot disable the detector.

Fail-safe: a malformed policy file logs a warning and falls through to
detection-only. A policy error never crashes the agent and never blocks-all.

Policy YAML format (mirrors the engine's action_policy structure)::

    version: "1"
    defaults:
      effect: allow            # allow | block | monitor | require_approval
      unclassified: monitor
    rules:
      - id: no-destructive-deletes
        effect: block
        message: "destructive deletes are not permitted"
        match:
          tools: ["delete_*", "drop_*"]
          impact_tier: ["destructive"]
      - id: untrusted-external
        effect: require_approval
        match:
          destination_type: ["external_api"]
        conditions:
          trust_below: 0.5
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from .authz.policy import (
    AuthzDecision,
    build_request,
    evaluate,
    parse_action_policy,
)

logger = logging.getLogger("xaidr.local_policy")

DEFAULT_POLICY_FILENAME = "xaidr-policy.yaml"

# Severity ranking for stricter-wins composition. Higher = stricter.
_SEVERITY = {
    "allow": 0,
    "allowed": 0,
    "monitor": 1,
    "flag": 1,
    "flagged": 1,
    "approval_required": 2,
    "require_approval": 2,
    "block": 3,
    "blocked": 3,
}


def load_policy(
    policy_file: Optional[str] = None,
    *,
    auto_default: bool = True,
) -> Optional[dict]:
    """Load and parse a policy from a file (or the conventional default).

    Returns a parsed policy dict, or None if there is no policy / it was
    malformed (fail-safe: never raises). Logs what it loaded.
    """
    path = policy_file
    if path is None and auto_default:
        if os.path.isfile(DEFAULT_POLICY_FILENAME):
            path = DEFAULT_POLICY_FILENAME
    if not path:
        return None

    try:
        import yaml  # lazy — only needed if a policy file is used
    except Exception:
        logger.warning(
            "[xaidr] a policy file was given but PyYAML is not installed; "
            "policy not loaded (detection-only). Install with: pip install xaidr[policy]"
        )
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        logger.warning("[xaidr] policy file not found: %s (detection-only)", path)
        return None
    except Exception as exc:
        logger.warning("[xaidr] could not read policy file %s: %s (detection-only)", path, exc)
        return None

    policy = parse_action_policy(raw)
    if policy is None:
        logger.warning(
            "[xaidr] policy file %s is malformed or unsupported; "
            "falling through to detection-only", path,
        )
        return None

    logger.info("[xaidr] loaded local policy from %s (%d rules)", path, len(policy.get("rules", [])))
    return policy


def set_policy_dict(raw: Any) -> Optional[dict]:
    """Parse a policy supplied programmatically as a dict. Fail-safe (None on bad)."""
    policy = parse_action_policy(raw)
    if policy is None:
        logger.warning("[xaidr] set_policy: malformed policy ignored (detection-only)")
    return policy


def evaluate_policy(
    policy: Optional[dict],
    *,
    agent_id: str,
    trust: Optional[float],
    tool_name: str,
    impact_class: str,
    impact_tier: str,
    destination_type: str,
    destination_identifier: str,
) -> AuthzDecision:
    """Evaluate the local policy for one action. Never raises (engine is fail-safe).

    Returns AuthzDecision (decision in: allowed|blocked|monitor|approval_required).
    With no policy, returns the engine's monitor-only default.
    """
    request = build_request(
        agent_id=agent_id,
        trust=trust,
        tool_name=tool_name,
        impact_class=impact_class,
        impact_tier=impact_tier,
        destination_type=destination_type,
        destination_identifier=destination_identifier,
    )
    return evaluate(policy, request)


def compose(detection_action: str, policy_decision: Optional[str]) -> str:
    """Combine the detection action with the policy decision — STRICTER WINS.

    detection_action: allowed | flagged | blocked  (the sensor's verdict)
    policy_decision:  allowed | blocked | monitor | approval_required | None

    Returns the stricter normalized action: allowed | flagged | blocked |
    approval_required. Policy can only tighten; it can never downgrade a
    detection block/flag to allow.
    """
    det = _SEVERITY.get(detection_action, 0)
    pol = _SEVERITY.get(policy_decision or "allow", 0)
    winner = max(det, pol)
    # normalize back to an action label
    if winner >= 3:
        return "blocked"
    if winner == 2:
        return "approval_required"
    if winner == 1:
        return "flagged"
    return "allowed"
