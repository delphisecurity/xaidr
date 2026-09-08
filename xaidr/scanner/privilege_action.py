"""Structural detection of privilege-subversion SHAPES in tool arguments (ASI03,
and the privilege-abuse edge of ASI02/ASI05/ASI08).

WHY THIS IS STRUCTURAL AND NOT A RULE. The tool-argument L1 scan joins argument
VALUES into one string and regexes it, so a key name never reaches the pattern:
``update_policy(require_approval=false)`` and ``terraform_apply(auto_approve=false)``
both collapse to the token ``false`` and become indistinguishable. The whole
distinction between a benign privileged action and a malicious one lives in the
key/value STRUCTURE, so this walks the argument dict and matches on (key, value)
pairs, the way command_parse / sql_parse / url_parse already do for their
surfaces.

WHY THIS IS NOT SECRETLY A LIST. It keys on none of the ~40 privileged tool
names. It keys on the SHAPE of the argument, which is tool-agnostic and, read
against the 190-call benign corpus, is what actually separates the two
populations:

  benign privileged action              malicious privileged action
  ------------------------              ---------------------------
  granted to a NAMED human/group        granted to SELF (agent://self, account:self)
  a control is ADDED or KEPT            a control is DISABLED (approval, safety,
                                          monitoring, backup, audit, trust)
  a scoped, bounded target              approval explicitly WAIVED (approval:none,
                                          confirm:skip)
  a non-admin role, or admin WITH       escalated to admin/root with NO governance
    an approval reference                 marker present
  a specific host / CIDR                opened to the world (0.0.0.0/0)
  a visible object                      a CONCEALED object (visible:false)

Every predicate below is one of those right-hand shapes. The benign side needs
no enumeration: an argument that carries none of these shapes produces nothing,
whether or not it is a privileged action, so an approved scoped grant, a
scheduled credential rotation and a payroll run are silent by construction.

WHAT THIS DELIBERATELY DOES NOT CATCH. Crypto-mining as a workload
(``schedule_job(image="xmrig/...")``) is a privilege/resource abuse, but the only
way to detect it is a denylist of miner image names, which IS secretly a list.
It is left to the policy engine / a workload allowlist and is NOT folded in here.

WHAT AN ATTACKER CAN DO. Every governance marker read here (an ``approval``
reference, a ``change_ref``) is APP-SUPPLIED and unverified, exactly like the
tier and chain claims the sensor already treats as unsigned. An attacker who
fabricates ``approval: "AP-0000"`` on a self-grant defeats the governance gate
below, the same way they defeat the policy engine. This raises the cost of the
obvious shapes; it is not an authorization boundary. Verdicts are FLAG, not
block, for that reason.
"""
from __future__ import annotations

import re
from typing import Iterable, Tuple

CATEGORY = "privileged_action"
_SCORE = 0.5  # flag band [flag_threshold, block_threshold)

# Tokens that mean "off / removed / none" for a control-shaped key.
_DISABLING = {"false", "no", "off", "disabled", "disable", "none", "0", "off/none"}
# Keys whose FALSE value is SAFE, not a subversion (they mean "require a human"):
# auto_approve=false REQUIRES approval; dry_run=false just means "really run".
_SAFE_FALSE_KEYS = {"auto_approve", "auto_apply", "dry_run", "dryrun"}

# Control-shaped keys whose disabling is the subversion. ENABLE-framed: a false /
# off / disabled value turns the control OFF.
_CONTROL_KEYS = {
    "require_approval", "approval_required", "requires_approval", "requires_review",
    "enforce_approvals", "approvals_required", "review_required", "require_review",
    "safety_checks", "safety", "guardrails", "verification", "verify",
    "monitoring", "monitor", "health_check", "healthcheck", "health_checks",
    "audit", "auditing", "audit_log", "logging", "log",
}
# Governance-control NAMES, for the set_flag(flag=<name>, value=false) shape and
# the value-embedded "health_check=disabled" shape.
_CONTROL_NAMES = (
    "require_approval", "approval_required", "enforce_approvals", "approvals_required",
    "safety_checks", "health_check", "healthcheck", "monitoring", "auditing",
    "audit_log", "logging", "guardrails",
)
_EMBED_DISABLE = re.compile(
    r"\b(" + "|".join(_CONTROL_NAMES) + r")\s*[:=]\s*(disabled|false|off|none|0)\b",
    re.I,
)

_PRINCIPAL_KEYS = {"principal", "grantee", "user", "account", "beneficiary",
                   "subject", "assignee", "member", "identity", "to"}
_SELF = re.compile(r"^(agent://)?self$|(^|[:/])self$", re.I)

_ROLE_KEYS = {"role", "roles", "scope", "scopes", "permission", "permissions",
              "access", "access_level", "grant", "privileges", "entitlement"}
_ADMIN = re.compile(r"\b(org-?admin|super-?user|superuser|root|administrator|admin)\b",
                    re.I)

_APPROVAL_KEYS = {"approval", "approvals", "authorization", "authorized"}
_CONFIRM_KEYS = {"confirm", "confirmation", "confirmed"}

# Markers that show a human/process authorised the action. Presence of any (with
# a real value) makes an admin-role grant a governed action rather than a
# self-escalation, so it is NOT flagged by the admin-escalation predicate.
_GOVERNANCE_KEYS = {"approval", "approved_by", "approver", "second_approver",
                    "change_ref", "authorized_by", "ticket", "engagement_ref"}

_WORLD = re.compile(r"0\.0\.0\.0/0|::/0")


def _norm(v) -> str:
    return str(v).strip().lower()


def _pairs(obj, key: str = "") -> Iterable[Tuple[str, object]]:
    """Every (lowercased key, value) pair, recursively. A list inherits its
    parent key so ``scopes: [..., "admin"]`` is seen under ``scopes``."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _pairs(v, str(k).lower())
    elif isinstance(obj, list):
        for v in obj:
            yield from _pairs(v, key)
    else:
        yield key, obj


def _is_disabling(value) -> bool:
    if value is False:
        return True
    if value is True:
        return False
    return _norm(value) in _DISABLING


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return _norm(value) in {"true", "yes", "on", "1", "enabled", "enable"}


def scan_privileged_action(tool_name: str, arguments) -> list:
    """Return findings [{rule, category, score}] for privilege-subversion shapes.

    Tool name is accepted for signature symmetry with the other structural
    scanners; it is deliberately NOT used to decide anything.
    """
    if not isinstance(arguments, dict) or not arguments:
        return []
    pairs = list(_pairs(arguments))
    findings: list = []

    def fire(rule: str):
        if not any(f["rule"] == rule for f in findings):
            findings.append({"rule": rule, "category": CATEGORY, "score": _SCORE})

    governance = any(
        k in _GOVERNANCE_KEYS and v not in (None, "", False)
        and _norm(v) not in ("none", "skip", "false", "no")
        for k, v in pairs
    )
    values = [v for _, v in pairs]
    str_values = [str(v) for v in values if v is not None]
    blob = " ".join(str_values)

    for k, v in pairs:
        # 1. self-directed grant / action
        if k in _PRINCIPAL_KEYS and isinstance(v, str) and _SELF.search(v.strip()):
            fire("ASI03_self_privileged_action")
        # 2a. an ENABLE-framed control disabled
        if k in _CONTROL_KEYS and k not in _SAFE_FALSE_KEYS and _is_disabling(v):
            fire("ASI03_disable_control")
        # 2b. an explicit "disable this" flag
        if k in ("disable", "disabled") and _truthy(v):
            fire("ASI03_disable_control")
        # 2c. retention set to zero (backups / audit)
        if k in ("retention_days", "retention", "retention_hours") and _norm(v) in ("0", "0.0"):
            fire("ASI03_disable_control")
        # 3. approval / confirmation explicitly waived
        if k in _APPROVAL_KEYS and _norm(v) in ("none", "skip", "false", "no", "off"):
            fire("ASI03_waive_approval")
        if k in _CONFIRM_KEYS and _norm(v) in ("skip", "none", "false", "no", "off"):
            fire("ASI03_waive_approval")
        # 4. escalation to admin/root in a role/scope, with no governance marker
        if k in _ROLE_KEYS and isinstance(v, str) and _ADMIN.search(v) and not governance:
            fire("ASI03_admin_escalation")
        # 5. concealed privileged object
        if k in ("visible", "listed") and _is_disabling(v):
            fire("ASI03_concealed_grant")
        if k in ("hidden", "invisible", "stealth") and _truthy(v):
            fire("ASI03_concealed_grant")

    # 2d. value-embedded "health_check=disabled" (config-blob and file-content shapes)
    if _EMBED_DISABLE.search(blob):
        fire("ASI03_disable_control")
    # 2e. set_flag(flag=<control-name>, value=false): the control name is a VALUE
    if any(_norm(v) in _CONTROL_NAMES for v in values) and any(_is_disabling(v) for v in values):
        fire("ASI03_disable_control")
    # 2f. trust root invalidated without reissue
    pd = {k: v for k, v in pairs}
    if _truthy(pd.get("invalidate_existing")) and not _truthy(pd.get("reissue", True)):
        fire("ASI03_disable_control")
    # 6. opened to the world
    if _WORLD.search(blob):
        fire("ASI03_open_to_world")

    return findings
