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
A malformed policy passed to ``set_policy()`` is refused and the policy already
in force keeps enforcing (keep-last-good, see ``adopt_policy``). A policy file
with a duplicate YAML key is refused rather than keeping the last value.

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

Supported match fields: ``tools``, ``agents``, ``impact_class``,
``impact_tier``, ``destination_type``, ``destination_identifier``,
``mcp_server``, ``category``. The ``trust_below`` condition
is NOT supported in this open distribution — it needs a per-agent trust score
that only the platform tier computes, so a policy using it is REJECTED at load
(with a clear error) rather than silently never firing.

Every match value is a LIST of glob patterns. ``tools: deploy`` (a scalar) is a
type error, not a shorthand, and is rejected at load with the correction in the
message — it would otherwise load cleanly and match nothing, which is the one
outcome a policy loader must never produce. The same applies to a non-mapping
``match:``/``conditions:``/``defaults:`` block and to a rule with nothing to
match on. See ``docs/policies.md`` for the full table and for why these are
rejected rather than coerced.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Mapping, Optional

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


def _unique_key_loader(yaml):
    """A SafeLoader that refuses a mapping with two equal keys.

    Every key written in the file is then the one the policy is built from.
    Keys introduced by a YAML merge (`<<: *anchor`) are not counted, since
    overriding a merged key is what a merge is for.
    """
    class _UniqueKeySafeLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            seen = set()
            for key_node, _ in getattr(node, "value", ()):
                if key_node.tag == "tag:yaml.org,2002:merge":
                    continue
                key = self.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in seen
                except TypeError:
                    continue  # unhashable; the base constructor reports it
                if duplicate:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping", node.start_mark,
                        f"found duplicate key {key!r}; each key may appear "
                        "once per mapping", key_node.start_mark,
                    )
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

    return _UniqueKeySafeLoader


def load_policy(
    policy_file: Optional[str] = None,
    *,
    auto_default: bool = True,
    extra_conditions: Optional[Mapping[str, Any]] = None,
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
            "policy not loaded (detection-only). Install with: pip install 'xaidr[policy]'"
        )
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.load(fh, Loader=_unique_key_loader(yaml))  # noqa: S506 - SafeLoader subclass
    except FileNotFoundError:
        logger.warning("[xaidr] policy file not found: %s (detection-only)", path)
        return None
    except Exception as exc:
        logger.warning("[xaidr] could not read policy file %s: %s (detection-only)", path, exc)
        return None

    policy = parse_action_policy(raw, extra_conditions=extra_conditions)
    if policy is None:
        logger.warning(
            "[xaidr] policy file %s is malformed or unsupported; "
            "falling through to detection-only", path,
        )
        return None

    logger.info("[xaidr] loaded local policy from %s (%d rules)", path, len(policy.get("rules", [])))
    return policy


def set_policy_dict(
    raw: Any,
    *,
    extra_conditions: Optional[Mapping[str, Any]] = None,
) -> Optional[dict]:
    """Parse a policy supplied programmatically as a dict. Fail-safe (None on bad).

    Takes `extra_conditions` for the same reason `load_policy` does: a policy
    set at RUNTIME must accept the same extension-supplied condition names a
    policy FILE would. `Sensor.set_policy()` goes through `adopt_policy`, which
    forwards them the same way; this function has no caller in the sensor.
    """
    policy = parse_action_policy(raw, extra_conditions=extra_conditions)
    if policy is None:
        logger.warning("[xaidr] set_policy: malformed policy refused")
    return policy


def adopt_policy(
    raw: Any,
    *,
    in_force: Callable[[], Optional[dict]],
    extra_conditions: Optional[Mapping[str, Any]] = None,
) -> Optional[dict]:
    """Parse `raw` and return the policy to install, or None to install nothing.

    KEEP-LAST-GOOD. The candidate is parsed in full before anything changes.
    An accepted candidate is installed by the caller with a single assignment,
    which is the atomic swap. A refused one returns None and the caller writes
    nothing, so whatever is in force when the refusal lands, including a
    policy set or cleared by another thread during the parse, stays in force.
    ``in_force`` is read only to report what stayed in force.
    """
    parsed = parse_action_policy(raw, extra_conditions=extra_conditions)
    if parsed is not None:
        return parsed
    current = in_force()
    if current is not None:
        logger.error(
            "[xaidr] set_policy: policy REFUSED; the previous policy remains in "
            "force (%d rules). The error above names the field.",
            len(current.get("rules", [])),
        )
    else:
        logger.error(
            "[xaidr] set_policy: policy REFUSED; no policy was in force, so the "
            "sensor stays detection-only. The error above names the field.",
        )
    return None


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
    context: Optional[dict] = None,
    category: Optional[str] = None,
) -> AuthzDecision:
    """Evaluate the local policy for one action. Never raises (engine is fail-safe).

    Returns AuthzDecision (decision in: allowed|blocked|monitor|approval_required).
    With no policy, returns the engine's monitor-only default.

    ``context`` is forwarded verbatim to ``build_request`` and is where the
    context-keyed match fields are read from. Today that is ``mcp_server``:
    without it, a ``match: {mcp_server: [...]}`` rule reads an absent value and
    can never fire — an advertised control that silently does nothing. Callers
    with an MCP server in hand MUST pass it.

    ``category`` is the same contract for the ``category:`` match field: the
    caller must pass the detection category it has already resolved, or a rule
    keyed on a category reads None and never fires.
    """
    request = build_request(
        agent_id=agent_id,
        trust=trust,
        tool_name=tool_name,
        impact_class=impact_class,
        impact_tier=impact_tier,
        destination_type=destination_type,
        destination_identifier=destination_identifier,
        context=context,
        category=category,
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
