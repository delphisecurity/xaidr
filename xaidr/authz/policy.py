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

import difflib
import fnmatch
import logging
from dataclasses import dataclass
from typing import Any, Mapping, Optional

logger = logging.getLogger("xaidr.authz")

SUPPORTED_VERSIONS = {"1", "1.0", 1}

EFFECTS = {"allow", "block", "monitor", "require_approval"}

_EFFECT_TO_DECISION = {
    "allow": "allowed",
    "block": "blocked",
    "monitor": "monitor",
    "require_approval": "approval_required",
}

# Rule match fields -> (request section, request key). This dict is the SINGLE
# source of truth for which match keys exist: the evaluator reads it, and the
# loader validates against it (see _reject_unknown_keys), so a field added here
# is automatically accepted and one removed is automatically rejected. Do not
# duplicate this list anywhere — a second copy is how a validator drifts out of
# sync with the evaluator and starts rejecting keys that actually work.
_MATCH_FIELDS = {
    "tools": ("action", "tool_name"),
    "agents": ("subject", "agent_id"),
    "impact_class": ("action", "impact_class"),
    "impact_tier": ("action", "impact_tier"),
    "destination_type": ("resource", "destination_type"),
    "destination_identifier": ("resource", "destination_identifier"),
    "mcp_server": ("context", "mcp_server"),
    # The DETECTION category the scan resolved for this action (`jailbreak`,
    # `system_prompt_leak`, `prompt_injection`, …), not a property of the tool.
    # It exists so a deployer can decide the enforcement level for a family the
    # shipped default only FLAGS: the tool-argument scan surfaces the ambiguous
    # model-directed categories rather than blocking them, and without this field
    # "we flag it, you decide" is advice with no mechanism behind it.
    #
    # Absent (None) on any path that has not run a detection when the policy is
    # consulted — the inert direction, matching `mcp_server` on a plain tool call.
    "category": ("action", "category"),
}

# The keys `_rule_matches` reads out of a rule's `conditions:` block. Same
# single-source-of-truth discipline as _MATCH_FIELDS above. (`trust_below` is
# additionally rejected on its own, with a more specific message, because it
# parses fine but can never fire in this distribution.)
#
# `min_chain_tier_above` is a NUMERIC comparison and belongs here rather than in
# _MATCH_FIELDS: every match field is resolved through `_glob_any`, which is
# fnmatch over strings. A tier put there would be compared as a glob pattern —
# `"4"` would match the string `"4"` and nothing else, so `> 1` semantics would
# be quietly unavailable while the rule still loaded and appeared to work.
# Living under `conditions:` also means it inherits the ADV-2 unknown-key
# validator, so `min_chain_tier_abov` is rejected at load instead of disarming
# the rule in silence.
_CONDITION_FIELDS = frozenset({"trust_below", "min_chain_tier_above"})


def _reject_unknown_keys(rule_id: Any, block_name: str, block: dict, known) -> bool:
    """Log and reject the first unrecognized key in a rule's match/conditions.

    An unknown key is NOT a harmless typo: `match: {tool: [...]}` (singular)
    parses, loads, reports success, and then matches nothing — the rule is
    silently disarmed while the operator believes it is enforcing. That is the
    same failure class as `trust_below`, so it gets the same loud treatment
    rather than being quietly ignored.

    Returns True when an unknown key was found (caller must reject the policy).
    """
    for key in sorted(block, key=str):
        if key in known:
            continue
        near = difflib.get_close_matches(str(key), sorted(known), n=1, cutoff=0.6)
        did_you_mean = f" Did you mean {near[0]!r}?" if near else ""
        logger.error(
            "[xaidr] action_policy rule %r has an unknown key %r under '%s:'."
            "%s A rule with an unrecognized key matches NOTHING — it would load "
            "cleanly and silently never fire. Policy REJECTED (detection-only). "
            "Valid '%s:' keys: %s.",
            rule_id, key, block_name, did_you_mean, block_name,
            ", ".join(sorted(known)),
        )
        return True
    return False


@dataclass
class AuthzDecision:
    decision: str  # allowed | blocked | monitor | approval_required
    policy_id: Optional[str] = None
    reason: Optional[str] = None


MONITOR_DECISION = AuthzDecision(decision="monitor")


def parse_action_policy(
    raw: Any,
    *,
    extra_conditions: Optional[Mapping[str, Any]] = None,
) -> Optional[dict]:
    """Validate and normalize an action_policy payload.

    Returns the normalized policy dict, or None for anything malformed —
    callers treat None as monitor-only defaults (never raise).

    Unknown keys INSIDE a rule's ``match:`` or ``conditions:`` block are
    REJECTED, not ignored: such a rule loads cleanly and then matches nothing,
    which is a security control that silently does not run. Unknown fields
    elsewhere (top level, rule level) remain ignored — those do not disarm
    anything.
    """
    # S2 · extension-supplied condition names. Resolved ONCE, here, so the two
    # places below that consult it cannot drift apart. Empty for every caller
    # that does not pass it, which is what makes this seam a no-op in open:
    # `_condition_fields` is then `_CONDITION_FIELDS` and the trust_below guard
    # is unconditional, exactly as before.
    _extra: Mapping[str, Any] = extra_conditions or {}
    _condition_fields = _CONDITION_FIELDS | set(_extra)
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
            # trust_below requires a per-agent trust score, which is a platform-
            # tier signal this open distribution does not compute (the subject's
            # trust is always None here). Rather than let such a rule SILENTLY
            # never fire — a policy that looks enforced but does nothing — reject
            # the whole policy loudly so the operator sees it and removes the
            # unsupported condition. (Paid/platform tiers, which do compute trust,
            # accept it.)
            # Rejected in EITHER placement — under `conditions:` or under `match:`.
            # Only `conditions.trust_below` is ever read at evaluation time, so a
            # rule that puts it under `match:` (the placement the README shows) is
            # exactly the silent no-op this guard exists to prevent.
            # S2: an extension that REGISTERED `trust_below` has supplied the
            # per-agent trust score this rejection exists to protect against, so
            # the rule can fire and the guard does not apply. With no extension
            # registered `_extra` is empty and this reads exactly as it did
            # before the seam: the rejection below is unchanged for open.
            if "trust_below" not in _extra and (
                "trust_below" in conditions or "trust_below" in match
            ):
                logger.error(
                    "[xaidr] action_policy rule %r uses 'trust_below' (under "
                    "'conditions:' or 'match:' — both are rejected), which "
                    "requires a per-agent trust score not available in the open "
                    "distribution — it would never fire. Policy REJECTED "
                    "(detection-only). Remove the trust_below condition, or use "
                    "the platform tier which computes trust.",
                    r.get("id"),
                )
                return None
            # An unrecognized key under match:/conditions: disarms the rule just
            # as silently as trust_below would, so it is rejected the same way.
            # Checked AFTER trust_below so that key keeps its specific message.
            if _reject_unknown_keys(r.get("id"), "match", match, _MATCH_FIELDS.keys()):
                return None
            if _reject_unknown_keys(
                r.get("id"), "conditions", conditions, _condition_fields
            ):
                return None
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

        # The registered evaluators ride WITH the parsed policy. `evaluate()`
        # takes (policy, request) and is called from one place; threading a
        # third argument through every caller would leave the two halves of this
        # seam able to drift apart — a policy parsed with one condition set and
        # evaluated against another. Carrying them here makes that impossible by
        # construction. Absent (not empty) when nobody registered any, so a
        # policy parsed by open is byte-identical to what it was before S2.
        parsed = {"version": str(raw["version"]), "defaults": defaults,
                  "rules": rules}
        if _extra:
            parsed["condition_evaluators"] = dict(_extra)
        return parsed
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
    category: Optional[str] = None,
) -> dict:
    """Build the AuthZEN-shaped evaluation request.

    ``category`` is the detection category the scan resolved (None when the
    caller has no detection verdict at this point). It feeds the ``category:``
    match field; left unpassed, that field can never fire.
    """
    return {
        "subject": {"agent_id": agent_id, "trust": trust},
        "action": {
            "tool_name": tool_name,
            "impact_class": impact_class,
            "impact_tier": impact_tier,
            "category": category,
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


def _rule_matches(rule: dict, request: dict, evaluators: Optional[Mapping[str, Any]] = None) -> bool:
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

    # PRIVILEGE TIERS (OWASP ASI03). Matches when the LEAST PRIVILEGED tier
    # anywhere in the delegation chain — including this sensor's own configured
    # tier — is numerically GREATER than the given value. Numerically greater
    # means LESS privileged (1 = highest, 4 = lowest), so
    # `min_chain_tier_above: 1` reads as "something below tier 1 is involved in
    # this action".
    #
    # A missing value means the sensor did not compute one, which happens only
    # when this code path is reached without the tier context — the rule then
    # does NOT match. That is the inert direction, and it is deliberate: an
    # un-upgraded caller must not start halting traffic because a policy
    # mentions a condition it never populates.
    min_chain_tier_above = rule["conditions"].get("min_chain_tier_above")
    if min_chain_tier_above is not None:
        matched_anything = True
        least_privileged = (request.get("context") or {}).get("least_privileged_tier")
        if least_privileged is None:
            return False
        try:
            if not int(least_privileged) > int(min_chain_tier_above):
                return False
        except (TypeError, ValueError):
            return False

    # S2 · extension-supplied conditions. The parser ACCEPTED these keys, so
    # they must be EVALUATED here — a condition that parses and is then ignored
    # does not merely fail to fire, it WIDENS the rule: `geo_outside: EU` is
    # written to narrow a `tools:` match, and dropping it makes that rule fire
    # on every tool call instead of the non-EU ones. That is the same silent
    # disarming the unknown-key validator exists to prevent, inverted.
    #
    # An unknown key here (registered at parse time, no evaluator at eval time)
    # fails CLOSED — the rule does not match — because the alternative is the
    # widening above.
    # BUILT-IN condition names keep built-in semantics even when an extension
    # also registers them. `trust_below` is the case that matters: an extension
    # registers the name to lift A-11's parse-time rejection and supplies the
    # SCORE through S9's subject_trust; the comparison stays here. Registration
    # means "I provide the input", not "I replace the comparison".
    handled = ("trust_below", "min_chain_tier_above")
    extra_keys = [k for k in rule["conditions"] if k not in handled]
    if extra_keys:
        matched_anything = True
        evaluators = evaluators or {}
        for key in extra_keys:
            evaluator = evaluators.get(key)
            if evaluator is None:
                logger.error(
                    "[xaidr] action_policy rule %r uses condition %r but no "
                    "evaluator is registered for it — the rule does NOT match. "
                    "This happens when a policy parsed with an extension "
                    "attached is evaluated without it.",
                    rule.get("id"), key,
                )
                return False
            try:
                if not evaluator(request, rule["conditions"][key]):
                    return False
            except Exception as exc:
                logger.error(
                    "[xaidr] condition evaluator %r raised (%s: %s) — rule %r "
                    "does NOT match. A condition that cannot answer must not "
                    "widen the rule it was written to narrow.",
                    key, type(exc).__name__, exc, rule.get("id"),
                )
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
            if _rule_matches(rule, request,
                             policy.get("condition_evaluators")):
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
