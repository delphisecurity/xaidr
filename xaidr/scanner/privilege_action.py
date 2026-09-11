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

WHERE A FACT IS ALLOWED TO BE READ FROM, because every carve-out here is a
relation between two keys and the scope of that relation IS the control:

    a fact that turns detection ON     may be read anywhere in the call
    a fact that turns detection OFF    must be a SIBLING of what it excuses

Both directions are the fail-closed one. Widening an enabling fact costs a false
positive; widening a SUPPRESSING fact costs the detection outright, and it hands
the caller a switch they can flip from any nesting depth — `{"role": "admin",
"metadata": {"type": "grant"}}` was silent because `type` is a filter key
somewhere in the tree. 1.14.1 made three predicates relational and applied the
sibling requirement to two of them; this is the third.

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

# THERE IS NO _SAFE_FALSE_KEYS, DELIBERATELY, AND THIS IS WHERE THE REASON LIVES.
# There used to be: {auto_approve, auto_apply, dry_run, dryrun}, subtracted from
# _CONTROL_KEYS in predicate 2a, on the argument that auto_approve=false REQUIRES
# a human and dry_run=false just means "really run". The argument is correct and
# the guard was dead: none of those four keys was ever IN _CONTROL_KEYS, so the
# subtraction removed nothing, and the test that claimed to pin it stayed green
# with the whole set deleted. A guard that guards nothing is worse than no guard,
# because it reads as a handled case.
#
# The keys are silent for the real reason instead — they are not control keys —
# and test_disable_framed_keys_are_not_control_keys pins that directly, so
# adding one to _CONTROL_KEYS fails a test rather than quietly changing verdicts.

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
# An admin-shaped value that is explicitly READ-ONLY is not an escalation.
# `admin.directory.user.readonly` is an ordinary OAuth scope request; the admin
# morpheme is naming the API surface, not the power being taken. Matched on the
# SAME value, never on the call. Deliberately NOT a bare `read`: the battery's
# ASI03-A03 widens a token to "read,write,admin,billing" and must keep firing.
_READ_ONLY = re.compile(r"read[-_.]?only|\breadonly\b|\bviewer\b|\breader\b", re.I)

# Keys that make a call a QUERY rather than a mutation. `role=admin` next to one
# of these is a filter ("repos where I am an admin"), which is a read, not a
# grant. This is a relation between keys, not a list of tools: the same
# `role=admin` with no filter key present still fires.
#
# "NEXT TO" MEANS IN THE SAME RECORD, and it did not. Read from the flattened
# argument tree, any of these fourteen names — `state`, `type`, `query`, `page`,
# `sort` — anywhere in the call at any depth turned the predicate off. See the
# per-record loop in `scan_privileged_action`, which is where that is enforced.
_FILTER_KEYS = {"visibility", "filter", "filters", "query", "q", "search",
                "sort", "order", "order_by", "page", "per_page", "page_size",
                "cursor", "offset", "state", "since", "until", "type"}

# ── the name/value SETTING relation (predicate 2e) ───────────────────────────
# `set_flag(flag="enforce_approvals", value=false)` puts the control's NAME in
# one slot and its new value in another. Reading that shape needs both halves to
# belong to the SAME setting record. Testing "a control name appears somewhere in
# this call AND something disabling appears somewhere in this call" is a
# cross-product with no relation between the two facts, and it fires on
# `{"panel": "monitoring", "offset": 0}` — a dashboard query with pagination.
_FLAG_NAME_KEYS = {"flag", "flag_name", "setting", "setting_name", "control",
                   "feature", "toggle", "option", "parameter", "param",
                   "property", "field", "name", "key"}
_FLAG_VALUE_KEYS = {"value", "val", "new_value", "newvalue", "enabled", "enable",
                    "state", "status", "setting_value", "to"}

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


# Key components: split on `_ - . space` AND camelCase, then rejoin with `_`.
# `accessLevel` and `access_level` are the SAME key and were not the same key
# here: `_ROLE_KEYS` lists `access_level`, `str(k).lower()` produced
# `accesslevel`, and `grant_role(accessLevel="admin")` — the spelling every
# JavaScript and Java SDK emits — reached no predicate at all. The identical
# split already exists in scanner.resource_bound (`_KEY_PARTS`); it simply never
# reached this module.
_KEY_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def _key(k) -> str:
    """Canonical snake_case form of a key. ``accessLevel`` -> ``access_level``."""
    return "_".join(p.lower() for p in _KEY_SPLIT.split(str(k)) if p)


def _pairs(obj, key: str = "") -> Iterable[Tuple[str, object]]:
    """Every (canonical key, value) pair, recursively. A list inherits its
    parent key so ``scopes: [..., "admin"]`` is seen under ``scopes``."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _pairs(v, _key(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _pairs(v, key)
    else:
        yield key, obj


def _dicts(obj) -> Iterable[dict]:
    """Every dict in the argument tree, so a predicate can require two facts to
    be SIBLINGS rather than merely both present somewhere in the call."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _dicts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _dicts(v)


def _own_pairs(d: dict) -> Iterable[Tuple[str, object]]:
    """The (canonical key, leaf value) pairs of ONE record.

    Lists are flattened — ``{"scopes": ["read", "admin"]}`` is one record with
    two values under ``scopes`` — and nested dicts are NOT, because a nested
    dict is its own record and ``_dicts`` will visit it in turn. That is the
    whole difference between this and ``_pairs``, and it is what makes
    "sibling" mean something.
    """
    for k, v in d.items():
        ck = _key(k)
        if isinstance(v, dict):
            continue
        if isinstance(v, (list, tuple)):
            stack = list(v)
            while stack:
                item = stack.pop()
                if isinstance(item, (list, tuple)):
                    stack.extend(item)
                elif not isinstance(item, dict):
                    yield ck, item
        else:
            yield ck, v


def _scopes(value: str) -> list:
    """A role/scope value split into the scopes it actually grants.

    ``"admin,readonly"`` is TWO scopes and one of them is admin. Reading the
    read-only carve-out against the whole string let a comma excuse the
    escalation sitting next to it: `role="admin,readonly"`, `scopes="read-only,
    root"` and `permissions="viewer, superuser"` were all silent. Split on the
    separators every SDK uses for a scope list — comma, semicolon, whitespace —
    and judge each scope on its own. A single scope with an internal dot
    (`admin.directory.user.readonly`) is untouched by the split, which is why
    that carve-out keeps working.
    """
    return [s for s in re.split(r"[,;\s]+", value) if s]


def _setting_disable(obj) -> bool:
    """True for the ``{name-slot: <control name>, value-slot: <disabling>}``
    record, with both halves in ONE dict. ``{"flag": "enforce_approvals",
    "value": "false"}`` yes; ``{"panel": "monitoring", "offset": 0}`` no,
    because ``offset`` is not a value slot for the thing ``panel`` names."""
    for d in _dicts(obj):
        # The control NAME is a value here, and it is a key-shaped value, so it
        # gets the same camelCase/separator normalisation a key does:
        # `{"flag": "requireApproval", "value": false}` names the same control
        # as `require_approval`.
        named = any(
            _key(k) in _FLAG_NAME_KEYS and _key(v) in _CONTROL_NAMES
            for k, v in d.items()
        )
        if not named:
            continue
        if any(_key(k) in _FLAG_VALUE_KEYS and _is_disabling(v)
               for k, v in d.items()):
            return True
    return False


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

    values = [v for _, v in pairs]
    str_values = [str(v) for v in values if v is not None]
    blob = " ".join(str_values)

    # A self-directed PRINCIPAL is only a self-GRANT when the call also names
    # what is being granted. `get_profile(user="self")` and `whoami(account=
    # "self")` are reads: `self` is the subject of an ordinary query, and on the
    # 190-call benign corpus that is the only way `self` appears. Requiring a
    # role/permission/scope key in the same call is the grant relation, and it is
    # the one the battery's ASI03-A02 (`principal=agent://self, role=org-admin`)
    # satisfies. COST, NAMED: a self-directed action with no role key —
    # `transfer(to="self", amount=…)` — is no longer reached by this predicate.
    # That is a value-movement shape, not a privilege shape, and it belongs to
    # the policy engine's impact classes rather than here.
    granting = any(k in _ROLE_KEYS for k, _ in pairs)

    for k, v in pairs:
        # 1. self-directed grant / action
        if (granting and k in _PRINCIPAL_KEYS and isinstance(v, str)
                and _SELF.search(v.strip())):
            fire("ASI03_self_privileged_action")
        # 2a. an ENABLE-framed control disabled
        if k in _CONTROL_KEYS and _is_disabling(v):
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
        # 4. escalation to admin/root in a role/scope -> handled per RECORD
        #    below, because its two carve-outs are SUPPRESSORS and a suppressor
        #    read from the whole tree is a switch anyone can flip.
        # 5. concealed privileged object
        if k in ("visible", "listed") and _is_disabling(v):
            fire("ASI03_concealed_grant")
        if k in ("hidden", "invisible", "stealth") and _truthy(v):
            fire("ASI03_concealed_grant")

    # 4. ESCALATION TO ADMIN/ROOT IN A ROLE OR SCOPE, read one RECORD at a time.
    #
    # THE RULE THIS PREDICATE NOW FOLLOWS, and the one the cross-product fix in
    # 1.14.1 reached for two of its three predicates: a fact that turns
    # detection ON may be read anywhere in the call, because missing it is the
    # fail-open direction. A fact that turns detection OFF must be a SIBLING of
    # the thing it excuses, because a suppressor read from the flattened tree is
    # a switch the caller can flip from anywhere.
    #
    # Both carve-outs here suppress:
    #
    #   the FILTER marker.  `list_repos(visibility="all", role="admin")` is a
    #       query, and that reading depends on `visibility` and `role` being
    #       arguments of the same call. Read from the flattened tree it was not
    #       a relation at all: a `sort` key three levels down in an unrelated
    #       `context` object, or a `type` key inside a `metadata` blob, silenced
    #       the admin grant beside it. `_FILTER_KEYS` holds fourteen of the
    #       commonest key names in any API — `state`, `type`, `query`, `page` —
    #       so an attacker needing one of them somewhere in a nested argument is
    #       not being asked for anything.
    #   the GOVERNANCE marker.  Same shape, same fix: an `approval` or
    #       `change_ref` in a sibling record excuses the grant in this one.
    #       Named in the module docstring as app-supplied and forgeable, which
    #       is an argument for keeping its reach SHORT, not long.
    #
    # `granting` (predicate 1) is deliberately still read call-wide. It ENABLES,
    # and narrowing it would lose catches rather than add them.
    for record in _dicts(arguments):
        own = list(_own_pairs(record))
        querying = any(k in _FILTER_KEYS for k, _ in own)
        governed = any(
            k in _GOVERNANCE_KEYS and v not in (None, "", False)
            and _norm(v) not in ("none", "skip", "false", "no")
            for k, v in own
        )
        if querying or governed:
            continue
        for k, v in own:
            if k not in _ROLE_KEYS or not isinstance(v, str):
                continue
            # Judge each SCOPE, not the string that carries them: a read-only
            # word in one scope does not excuse an admin scope beside it.
            if any(_ADMIN.search(s) and not _READ_ONLY.search(s)
                   for s in _scopes(v)):
                fire("ASI03_admin_escalation")

    # 2d. value-embedded "health_check=disabled" (config-blob and file-content shapes)
    if _EMBED_DISABLE.search(blob):
        fire("ASI03_disable_control")
    # 2e. set_flag(flag=<control-name>, value=false): the control name is a VALUE.
    #     Both halves must be siblings in ONE dict — see _setting_disable.
    if _setting_disable(arguments):
        fire("ASI03_disable_control")
    # 2f. trust root invalidated without reissue
    pd = {k: v for k, v in pairs}
    if _truthy(pd.get("invalidate_existing")) and not _truthy(pd.get("reissue", True)):
        fire("ASI03_disable_control")
    # 6. opened to the world
    if _WORLD.search(blob):
        fire("ASI03_open_to_world")

    return findings
