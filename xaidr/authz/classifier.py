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
    # Stage 2: derived from the PARSED STRUCTURE of a shell command rather than
    # from the tool name, so `run_command` stops being a blind spot.
    "execute", "credential_access",
}

_TIER_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_FALLBACK_DEFAULT = {"impact_class": "unknown", "impact_tier": "medium"}

# Argument keys whose VALUE is a shell command line. Deliberately a short,
# explicit list: a wider net (every string arg) would parse prose as commands and
# manufacture classifications out of nothing.
SHELL_ARG_KEYS = ("command", "cmd", "script", "args", "shell", "code")

# Tie-break when two segments classify at the SAME tier. A named sensitive
# object beats a generic capability: `cat ~/.ssh/id_rsa | bash` is a credential
# read that also runs code, and the credential read is the sharper fact.
_CLASS_PRECEDENCE = ("credential_access", "execute", "read", "unknown")

# A parse_degraded segment may contribute a class but may not be the SOLE basis
# for a critical tier — see command_classifiers.aggregation.degraded_rule.
_DEGRADED_TIER_CAP = "high"


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

    # Pre-compile the command-classifier regexes once. A bad pattern drops that
    # one rule with a warning rather than disabling command classification.
    cc = raw.get("command_classifiers") or {}
    for bucket in ("rules", "combinations"):
        compiled = []
        for entry in cc.get(bucket) or []:
            try:
                compiled.append(_compile_command_entry(entry))
            except re.error as exc:
                print(f"[xaidr] Warning: command classifier {entry.get('id')} regex failed: {exc}")
        cc[bucket] = compiled
    raw["command_classifiers"] = cc
    return raw


_REGEX_MATCH_FIELDS = ("args_pattern", "redirect_target_pattern", "raw_pattern")


def _compile_command_entry(entry: dict) -> dict:
    """Compile the regex fields of one command-classifier entry (or combination)."""
    out = dict(entry)
    for key in ("match", "when_any", "and_any"):
        block = out.get(key)
        if not isinstance(block, dict):
            continue
        block = dict(block)
        for field in _REGEX_MATCH_FIELDS:
            if block.get(field):
                block[field] = re.compile(block[field])
        out[key] = block
    return out


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


def _segment_matches(block: dict, seg) -> bool:
    """Does one match block describe this parsed segment?

    All present conditions must hold (AND). An empty block matches nothing — an
    empty rule must not become a catch-all that classifies every command.
    """
    matched_anything = False

    names = block.get("name")
    if names:
        matched_anything = True
        if not _glob_any(seg.name, names):
            return False

    wrappers = block.get("wrappers_any")
    if wrappers:
        matched_anything = True
        if not any(_glob_any(w, wrappers) for w in seg.wrappers):
            return False

    max_args = block.get("max_args")
    if max_args is not None:
        matched_anything = True
        if len(seg.args) > int(max_args):
            return False

    args_pattern = block.get("args_pattern")
    if args_pattern is not None:
        matched_anything = True
        if not args_pattern.search(" ".join(seg.args)):
            return False

    args_any = block.get("args_any")
    if args_any:
        matched_anything = True
        if not any(_glob_any(a, args_any) for a in seg.args):
            return False

    rt = block.get("redirect_target_pattern")
    if rt is not None:
        matched_anything = True
        if not any(rt.search(str(r.get("target") or "")) for r in seg.redirects):
            return False

    ops = block.get("redirect_op")
    if ops:
        matched_anything = True
        if not any(r.get("op") in ops for r in seg.redirects):
            return False

    env_keys = block.get("env_prefix_keys")
    if env_keys:
        matched_anything = True
        if not any(_glob_any(k, env_keys) for k in seg.env_prefix):
            return False

    expands = block.get("expands")
    if expands is not None:
        matched_anything = True
        if bool(seg.expands) is not bool(expands):
            return False

    raw_pattern = block.get("raw_pattern")
    if raw_pattern is not None:
        matched_anything = True
        if not raw_pattern.search(seg.raw or ""):
            return False

    return matched_anything


def _classify_segment(seg) -> Optional[tuple]:
    """First matching command rule for one segment -> (class, tier, rule_id)."""
    for rule in (_RULESET.get("command_classifiers") or {}).get("rules") or []:
        block = rule.get("match")
        if isinstance(block, dict) and _segment_matches(block, seg):
            return (
                rule.get("impact_class", "unknown"),
                rule.get("impact_tier", "medium"),
                rule.get("id"),
            )
    return None


def _better(a: Optional[tuple], b: Optional[tuple]) -> Optional[tuple]:
    """Pick the stronger of two (class, tier, id) findings. See tie_break docs."""
    if a is None:
        return b
    if b is None:
        return a
    ta, tb = _TIER_ORDER.get(a[1], -1), _TIER_ORDER.get(b[1], -1)
    if tb > ta:
        return b
    if ta > tb:
        return a
    pa = _CLASS_PRECEDENCE.index(a[0]) if a[0] in _CLASS_PRECEDENCE else 99
    pb = _CLASS_PRECEDENCE.index(b[0]) if b[0] in _CLASS_PRECEDENCE else 99
    return b if pb < pa else a          # equal tier+class -> earliest (a) wins


def classify_command(command: str) -> Optional[tuple]:
    """Classify a shell command line by its parsed structure.

    Returns ``(impact_class, impact_tier)`` or ``None`` when no command rule
    matched. Every segment is classified — including nested segments expanded
    from ``-c`` payloads — and the strongest finding wins.

    Never raises: a parse or rule fault returns None, leaving the caller exactly
    where it was before command classification existed.
    """
    try:
        from ..scanner.command_parse import parse_command

        segments = parse_command(command)
        if not segments:
            return None

        best_clean: Optional[tuple] = None      # from non-degraded segments
        best_any: Optional[tuple] = None
        for seg in segments:
            found = _classify_segment(seg)
            if found is None:
                continue
            best_any = _better(best_any, found)
            if not seg.parse_degraded:
                best_clean = _better(best_clean, found)

        # Cross-segment combinations (curl|bash, env|grep token): neither half
        # alone carries the finding, the relationship between them does.
        for combo in (_RULESET.get("command_classifiers") or {}).get("combinations") or []:
            when, and_ = combo.get("when_any"), combo.get("and_any")
            if not isinstance(when, dict) or not isinstance(and_, dict):
                continue
            if any(_segment_matches(when, s) for s in segments) and \
               any(_segment_matches(and_, s) for s in segments):
                found = (combo.get("impact_class", "unknown"),
                         combo.get("impact_tier", "medium"), combo.get("id"))
                best_any = _better(best_any, found)
                if any(not s.parse_degraded for s in segments):
                    best_clean = _better(best_clean, found)

        if best_any is None:
            return None

        # A degraded segment may name a class but may not alone justify critical.
        if best_any[1] == "critical" and (
            best_clean is None or _TIER_ORDER.get(best_clean[1], -1) < 3
        ):
            return (best_any[0], _DEGRADED_TIER_CAP)
        return (best_any[0], best_any[1])
    except Exception:
        return None


def _extract_command(arguments: dict) -> Optional[str]:
    """Pull a shell command line out of tool arguments, or None.

    Only the keys in ``SHELL_ARG_KEYS`` are considered. A list value is joined,
    which is how `args: ["-c", "cat /etc/shadow"]` style calls arrive.
    """
    for key, value in arguments.items():
        if str(key).lower() not in SHELL_ARG_KEYS:
            continue
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, (list, tuple)) and value:
            parts = [str(v) for v in value if isinstance(v, (str, int, float))]
            if parts:
                return " ".join(parts)
    return None


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

        matched_by_tool_name = False
        for rule in _RULESET.get("rules") or []:
            if _rule_matches(rule, tool_name or "", mcp_server):
                impact_class = rule.get("impact_class", "unknown")
                tier = rule.get("impact_tier", "medium")
                matched_by_tool_name = True
                break

        # Command classification runs ONLY when the tool name told us nothing.
        # A tool that already classifies as transfer/delete/deploy keeps that
        # answer, so no existing classification can regress.
        if not matched_by_tool_name and isinstance(arguments, dict) and arguments:
            command = _extract_command(arguments)
            if command:
                found = classify_command(command)
                if found is not None:
                    impact_class, cmd_tier = found
                    tier = _raise_tier(tier, cmd_tier) if _TIER_ORDER.get(cmd_tier, -1) > \
                        _TIER_ORDER.get(tier, -1) else cmd_tier

        if isinstance(arguments, dict) and arguments:
            tier = _apply_escalations(tier, arguments)

        if impact_class not in IMPACT_CLASSES:
            impact_class = "unknown"
        if tier not in _TIER_ORDER:
            tier = "medium"
        return (impact_class, tier)
    except Exception:
        return ("unknown", "medium")
