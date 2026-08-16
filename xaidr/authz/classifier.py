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
    # Stage 3: the remaining shell classes. Most of these rules CLASSIFY without
    # blocking — `terraform destroy`, `systemctl enable` and `sudo` are real
    # operations someone's deploy agent performs — so naming the class is the
    # deliverable: it is what a require_approval policy binds to.
    "escalate", "persist", "evade", "infra_destruction", "destructive_filesystem",
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

    # Same treatment for the SQL classifiers. Separate section, separate reader,
    # identical failure policy: one bad pattern costs that rule, not the feature.
    sc = raw.get("sql_classifiers") or {}
    compiled = []
    for entry in sc.get("rules") or []:
        try:
            compiled.append(_compile_command_entry(entry))
        except re.error as exc:
            print(f"[xaidr] Warning: sql classifier {entry.get('id')} regex failed: {exc}")
    sc["rules"] = compiled
    raw["sql_classifiers"] = sc
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


def _operand_text(seg) -> str:
    """The text a rule's ``args_pattern`` matches against.

    argv operands, plus the body of any heredoc this segment receives AS A
    PROGRAM. Both are the same fact wearing different syntax: `python -c '<code>'`
    puts the payload in argv, where args_pattern has always seen it, while
    `python - <<PY … PY` puts the identical payload in a heredoc body. Without
    this the two forms classify differently — the `-c` form as
    credential_access, the heredoc form as `unknown` — and a policy written
    against the class would gate one and miss the other.

    A DATA heredoc (`cat <<EOF > config.yaml`, a database client reading a
    query) is deliberately EXCLUDED. Its body is content being written, not an
    operand describing what the command acts on, so folding it in here would let
    a YAML document that merely mentions a credential path classify as a
    credential read. ``is_program`` is decided once at parse time; see
    ``command_parse._heredoc_is_program``.

    Length is bounded by the parser's own input and heredoc-line caps, so this
    adds no unbounded work.
    """
    parts = list(seg.args)
    for hd in getattr(seg, "heredocs", None) or ():
        if hd.get("is_program") and hd.get("body"):
            parts.append(hd["body"])
    return " ".join(parts)


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
        if not args_pattern.search(_operand_text(seg)):
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


def classify_command_findings(command: str) -> list:
    """Structural DETECTION findings for a shell command line.

    Returns ``[{"rule", "impact_class", "impact_tier", "score"}, …]`` for every
    matched classifier rule that carries a ``detect`` block — the subset of the
    ruleset judged unambiguous enough to ENFORCE on, not merely to classify.

    Detection and classification read the SAME rules deliberately. The
    alternative — a parallel list of raw-string regexes in all-l1-rules.json —
    is what produced the gap this workstream exists to close: the classifier
    understood ``rm`` + a sensitive object while the detector only knew the
    literal ``rm -rf /``. One ruleset cannot drift from itself.

    Two guards, both inherited from classification:

    * first-match-wins PER SEGMENT, so the ordering that decides a segment's
      class also decides whether it enforces. Specific enforcing rules are
      therefore ordered ahead of the general classify-only ones they sit inside
      (``escalate.setuid_bit`` before ``escalate.privileged_wrapper``).
    * a ``parse_degraded`` segment never produces a finding. Non-shell payloads
      (Python/Perl source shell-tokenized into pseudo-names) are approximations;
      they may contribute a CLASS but must not, on their own, block a call.

    Never raises: any fault returns ``[]``, leaving the caller where it was.
    """
    try:
        from ..scanner.command_parse import parse_command

        segments = parse_command(command)
        if not segments:
            return []

        cc = _RULESET.get("command_classifiers") or {}
        findings = []
        seen = set()

        def _emit(entry):
            detect = entry.get("detect")
            if not isinstance(detect, dict):
                return
            rule_id = entry.get("id")
            if rule_id in seen:
                return
            seen.add(rule_id)
            findings.append({
                "rule": rule_id,
                "impact_class": entry.get("impact_class", "unknown"),
                "impact_tier": entry.get("impact_tier", "medium"),
                "score": float(detect.get("score", 0.0)),
            })

        for seg in segments:
            if seg.parse_degraded:
                continue
            for rule in cc.get("rules") or []:
                block = rule.get("match")
                if isinstance(block, dict) and _segment_matches(block, seg):
                    _emit(rule)
                    break               # first match wins, as in classification

        clean = [s for s in segments if not s.parse_degraded]
        for combo in cc.get("combinations") or []:
            when, and_ = combo.get("when_any"), combo.get("and_any")
            if not isinstance(when, dict) or not isinstance(and_, dict):
                continue
            if any(_segment_matches(when, s) for s in clean) and \
               any(_segment_matches(and_, s) for s in clean):
                _emit(combo)
        return findings
    except Exception:
        return []


# ── SQL carried in a tool argument ───────────────────────────────────────────
# The shell reader above answers "what binary is this", which is the right
# question for `psql -c "DROP TABLE users"` and meaningless for the way agents
# actually run SQL: `run_sql(query="DROP TABLE users")`, where the statement is
# just an argument value. These functions are the SQL peer of _classify_segment /
# classify_command / classify_command_findings and share their contract exactly:
# first match wins, only rules carrying a `detect` block enforce, nothing raises.


def _sql_matches(block: dict, shape) -> bool:
    """Does one sql_classifiers `match` block describe this statement?"""
    if not isinstance(block, dict) or not block:
        return False
    statement = block.get("statement")
    if statement and not _glob_any(shape.statement, statement):
        return False
    object_kind = block.get("object_kind")
    if object_kind and not _glob_any(shape.object_kind, object_kind):
        return False
    obj = block.get("object")
    if obj and not _glob_any(shape.object, obj):
        return False
    predicate = block.get("predicate")
    if predicate and shape.predicate not in predicate:
        return False
    raw_pattern = block.get("raw_pattern")
    if raw_pattern is not None and not raw_pattern.search(shape.raw or ""):
        return False
    return True


def _classify_sql_statement(shape) -> Optional[tuple]:
    """First matching SQL rule for one statement -> (class, tier, rule_id)."""
    for rule in (_RULESET.get("sql_classifiers") or {}).get("rules") or []:
        block = rule.get("match")
        if isinstance(block, dict) and _sql_matches(block, shape):
            return (
                rule.get("impact_class", "unknown"),
                rule.get("impact_tier", "medium"),
                rule.get("id"),
            )
    return None


def classify_sql(text: str) -> Optional[tuple]:
    """Classify a SQL statement (or a semicolon-separated batch) by its shape.

    Returns ``(impact_class, impact_tier)`` or ``None`` when the value is not SQL
    or no rule matched. The strongest statement in a batch wins, so a migration
    that ends in a table drop is classified by the drop.

    Never raises.
    """
    try:
        from ..scanner.sql_parse import parse_sql

        best: Optional[tuple] = None
        for shape in parse_sql(text):
            found = _classify_sql_statement(shape)
            if found is not None:
                best = _better(best, found)
        return (best[0], best[1]) if best else None
    except Exception:
        return None


def classify_sql_findings(text: str) -> list:
    """Structural DETECTION findings for SQL in a tool argument.

    Same contract as ``classify_command_findings``: only rules carrying a
    ``detect`` block appear here, so the classify-only majority (a migration's
    ``DROP TABLE``, an unbounded-but-deliberate ``DELETE FROM sessions``) names
    its class for a policy and never blocks on its own.

    Never raises.
    """
    try:
        from ..scanner.sql_parse import parse_sql

        rules = (_RULESET.get("sql_classifiers") or {}).get("rules") or []
        findings, seen = [], set()
        for shape in parse_sql(text):
            for rule in rules:
                block = rule.get("match")
                if not isinstance(block, dict) or not _sql_matches(block, shape):
                    continue
                # First match wins per statement, exactly as classification does,
                # so rule ORDER decides enforcement and not just the class.
                detect = rule.get("detect")
                if isinstance(detect, dict) and rule.get("id") not in seen:
                    seen.add(rule.get("id"))
                    findings.append({
                        "rule": rule.get("id"),
                        "impact_class": rule.get("impact_class", "unknown"),
                        "impact_tier": rule.get("impact_tier", "medium"),
                        "score": float(detect.get("score", 0.0)),
                    })
                break
        return findings
    except Exception:
        return []


def extract_sql(arguments: dict) -> Optional[str]:
    """Pull a SQL statement out of tool arguments, or None.

    UNLIKE ``_extract_command`` this looks at EVERY key, because there is no
    conventional name for the one that carries SQL. ``query``, ``sql``,
    ``statement`` and ``q`` are all ordinary, a custom tool may use anything, and
    the reviewer's reproducer, ``run_sql(query=...)``, is how real agents are
    written. A key allowlist here would be a gate the attacker chooses the
    combination to.

    The gate is the VALUE, not the key: ``sql_parse.looks_like_sql`` requires the
    value to BEGIN with a SQL statement keyword. That is what keeps prose out
    ("we had to DROP TABLE users last night" starts with "we") and keeps the
    shell path separate (`psql -c "..."` starts with a binary name), without
    caring what the argument is called.
    """
    try:
        from ..scanner.sql_parse import looks_like_sql

        for value in arguments.values():
            if isinstance(value, str) and value.strip() and looks_like_sql(value):
                return value
        return None
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


# Public alias. The sensor's tool-argument scan needs the same answer to "is this
# argument a shell command line?" that classification uses, and the two must not
# drift: a key the classifier parses but the scanner does not (or vice versa) is a
# silent coverage hole.
extract_shell_command = _extract_command


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

        # SQL in an argument value. Unlike the shell reader above, this runs even
        # when the TOOL NAME already matched, and only ever RAISES.
        #
        # The shell reader defers to the tool name so an existing classification
        # cannot regress. That is the right rule for it, and the wrong rule here:
        # a tool called `query_tool` matches the read.* family by name, and
        # `query_tool(query="DROP TABLE users")` would keep `read`/medium: the
        # tool's usual purpose overriding what this particular call actually
        # does. So SQL is allowed to override, under a strict condition that
        # preserves the no-regression guarantee: it applies only when the
        # statement's tier is HIGHER than the one already assigned. A call can
        # therefore get more severe from reading its SQL and never less.
        if isinstance(arguments, dict) and arguments:
            statement = extract_sql(arguments)
            if statement:
                found = classify_sql(statement)
                if found is not None:
                    sql_class, sql_tier = found
                    if _TIER_ORDER.get(sql_tier, -1) > _TIER_ORDER.get(tier, -1):
                        impact_class, tier = sql_class, sql_tier

        if isinstance(arguments, dict) and arguments:
            tier = _apply_escalations(tier, arguments)

        if impact_class not in IMPACT_CLASSES:
            impact_class = "unknown"
        if tier not in _TIER_ORDER:
            tier = "medium"
        return (impact_class, tier)
    except Exception:
        return ("unknown", "medium")
