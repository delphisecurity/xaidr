"""Normalize an action string to a canonical form, then let the classifier judge
the canonical form.

WHY THIS EXISTS. A tool-call argument is a string the model produced; the
runtime that executes it rewrites that string first. A classifier that reads the
pre-rewrite string and the runtime that reads the post-rewrite string are
looking at two different commands. This stage closes that distance for the
deterministic, non-executing rewrites, so the classifier that already exists
judges the form the runtime would actually run.

KEYED BY LANGUAGE. The public entry is ``canonicalize(text, language)``.
Two are implemented: ``shell``, for a command the classifier judges, and
``string``, for an argument value the DLP secret scan reads. SQL and URL plug in
the same way, by registering a normalizer in ``_NORMALIZERS`` — the sensor seam
and the ``Canonical`` contract do not change when they do.

WHAT IT MUST NEVER DO. It never executes anything. A command substitution
or a backtick is DETECTED and left in place; it is never run to discover what it
expands to. A value that cannot be resolved statically is reported as
unresolved, with a verdict from the unresolved-construct verdict table, never a
guess at the value.

Guarantees, because this sits on a scan path:

* **Never raises.** Any input returns a :class:`Canonical`; a fault returns the
  input unchanged with no findings.
* **Bounded.** Input is capped; every rewrite is linear in the capped length.
* **Pure.** No I/O, no global mutable state.
* **Additive to the verdict.** The normalized text is handed to the SAME
  classifier the raw string goes through, and the findings here only ADD to the
  sensor's ``danger`` list, so this stage can raise a verdict, never lower one.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .command_parse import parse_command, _normalize_name

# Input cap. Far above any real command; past it the tail is dropped rather than
# the parse hung. Matches command_parse's own ceiling in spirit.
_MAX_INPUT_CHARS = 16_384

# A finding category that is FLAG-tier in the sensor (never blocks on its own).
# Used for the unresolvable constructs the verdict table says to flag, not block.
_FLAG_CATEGORY = "shell_unresolved"
# A finding category that is BLOCK-tier in the sensor.
_BLOCK_CATEGORY = "code_execution"


@dataclass
class Canonical:
    """The normalized form of an action string plus the verdicts for anything
    that could not be resolved.

    Attributes:
        text: The normalized string. Deterministic, non-executing rewrites are
            applied (see the shell normalizer); substitutions and unresolved
            variables are left exactly as written.
        language: The language key the normalizer was selected by.
        applied: The rewrite kinds applied, for telemetry — e.g.
            ``"ifs_to_space"``, ``"literal_var_substituted"``. Empty when the
            text was returned unchanged.
        findings: Verdicts for unresolvable constructs, as
            ``[{"rule", "category", "score"}, …]``. ``category`` is flag-tier
            (surface) or block-tier (enforce) per the verdict table. Empty when
            nothing was unresolvable.
    """

    text: str
    language: str
    applied: List[str] = field(default_factory=list)
    findings: List[Dict[str, object]] = field(default_factory=list)


def canonicalize(text: str, language: str = "shell") -> Canonical:
    """Normalize ``text`` for ``language`` and return its canonical form.

    Never raises. An unknown language, or any fault, returns the input unchanged
    with no findings — the same position the caller was in without this stage.
    """
    if not isinstance(text, str) or not text.strip():
        return Canonical(text if isinstance(text, str) else "", language)
    normalizer = _NORMALIZERS.get(language)
    if normalizer is None:
        return Canonical(text, language)
    try:
        if len(text) > _MAX_INPUT_CHARS:
            text = text[:_MAX_INPUT_CHARS]
        return normalizer(text)
    except Exception:
        return Canonical(text, language)


# ── shell ─────────────────────────────────────────────────────────────────────

# `$IFS` and `${IFS}` as a reference (not followed by more name characters).
_IFS_TOKEN = re.compile(r"\$\{IFS\}|\$IFS(?![A-Za-z0-9_])")

# `IFS=` as a statement-leading or env-prefix assignment (reassignment). Anchored
# to a statement boundary or whitespace so `$IFS` and a path like `a/IFS=x` do
# not match.
_IFS_REASSIGN = re.compile(r"(?:^|(?<=[;&|\n ]))IFS=")

# A statement-leading literal assignment: `name=<literal>` where the literal has
# no whitespace, separator, quote, `$`, backtick or backslash — i.e. a value we
# can substitute with certainty, never an expansion we would have to resolve.
_LITERAL_ASSIGN = re.compile(
    r"(?:^|[;&|\n])\s*([A-Za-z_][A-Za-z0-9_]*)=([^\s;&|'\"$`\\]+)"
)

# A variable reference that was NOT resolved here (no in-line literal binding):
# `$NAME` or `${NAME}`. A substitution (`$(`) is deliberately excluded — it is a
# different construct with a different verdict.
_UNRESOLVED_VAR = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")

# Destructive verbs whose presence makes an unresolved TARGET the developer
# `rm -rf "$VAR"` pattern (flag, never block) rather than an opaque command.
_DESTRUCTIVE_VERBS = frozenset({
    "rm", "rmdir", "unlink", "shred", "srm", "gio", "dd", "mkfs", "wipefs",
    "blkdiscard", "truncate", "chmod", "chown", "chgrp",
})


def _shell(text: str) -> Canonical:
    applied: List[str] = []

    # 1. $IFS / ${IFS} word-separators. Expanded to a single space ONLY when IFS
    #    is not reassigned in-line — a reassigned IFS changes what the split
    #    produces, which is out of v1 scope and handled as unresolvable below.
    ifs_reassigned = bool(_IFS_REASSIGN.search(text))
    out = text
    if not ifs_reassigned and _IFS_TOKEN.search(out):
        out = _IFS_TOKEN.sub(" ", out)
        applied.append("ifs_to_space")

    # 2. In-line literal variable assignment then use. The binding is certain
    #    (the value is a bare literal), so the use is substituted and the result
    #    classified normally. A value that is itself an expansion is NOT a
    #    literal and is left for the unresolved-variable path.
    out, did = _substitute_literal_vars(out)
    if did:
        applied.append("literal_var_substituted")

    findings: List[Dict[str, object]] = []
    if ifs_reassigned:
        applied.append("ifs_reassigned")
        findings.extend(_ifs_reassigned_verdict(out))
    findings.extend(_unresolved_construct_verdict(out))

    return Canonical(text=out, language="shell", applied=applied, findings=findings)


def _substitute_literal_vars(text: str) -> tuple[str, bool]:
    """Substitute `$name`/`${name}` where `name` has an in-line literal binding.

    Bindings are collected in source order from statement-leading `name=literal`
    assignments. A use is substituted only OUTSIDE single quotes (which suppress
    expansion) so a quoted `'$x'` is left as written. Returns (text, changed).
    """
    bindings: Dict[str, str] = {}
    for m in _LITERAL_ASSIGN.finditer(text):
        bindings[m.group(1)] = m.group(2)
    if not bindings:
        return text, False

    changed = False
    for name, literal in bindings.items():
        pattern = re.compile(r"\$\{" + re.escape(name) + r"\}|\$" + re.escape(name)
                             + r"(?![A-Za-z0-9_])")
        new = _sub_outside_single_quotes(pattern, literal, text)
        if new != text:
            changed = True
            text = new
    return text, changed


def _sub_outside_single_quotes(pattern: re.Pattern, repl: str, text: str) -> str:
    """Apply ``pattern`` → ``repl`` only in spans that are not single-quoted."""
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        q = text.find("'", i)
        if q == -1:
            out.append(pattern.sub(repl, text[i:]))
            break
        out.append(pattern.sub(repl, text[i:q]))
        end = text.find("'", q + 1)
        if end == -1:
            out.append(text[q:])          # unbalanced quote: keep the rest verbatim
            break
        out.append(text[q:end + 1])
        i = end + 1
    return "".join(out)


def _ifs_reassigned_verdict(text: str) -> List[Dict[str, object]]:
    """IFS reassigned to a non-default value (out of v1 scope): block in a
    destructive context, otherwise flag — never resolve the split."""
    if _has_resolved_destructive_segment(text):
        return [_finding("canon.ifs_reassigned_destructive", _BLOCK_CATEGORY, 0.9)]
    return [_finding("canon.ifs_reassigned_unresolved", _FLAG_CATEGORY, 0.4)]


def _unresolved_construct_verdict(text: str) -> List[Dict[str, object]]:
    """Verdicts for command substitution / backticks and unresolved variables,
    following the verdict table. Reads the parse; never executes anything."""
    findings: List[Dict[str, object]] = []
    try:
        segments = parse_command(text)
    except Exception:
        return findings
    for seg in segments:
        if getattr(seg, "depth", 0):
            continue                      # top-level commands only
        argv = seg.argv
        if not argv:
            continue
        verb, operands = argv[0], argv[1:]
        nonflag = [t for t in operands if not t.startswith("-")]

        if _is_substitution(verb):
            # Substitution in the verb position. Block only when the surrounding
            # command is itself destructive — destructive flags AND a non-safe
            # target — i.e. the substitution sits in the dangerous slot. Any
            # other substitution (an argument value, a non-destructive command)
            # passes untouched.
            if _has_rf_flag(operands) and any(_is_nonsafe_target(t) for t in nonflag):
                findings.append(_finding(
                    "canon.substitution_in_destructive_position", _BLOCK_CATEGORY, 0.9))
            continue

        if _is_unresolved_var(verb):
            # Unresolved verb: ambiguous, flag, never block on the verb alone.
            findings.append(_finding("canon.unresolved_verb", _FLAG_CATEGORY, 0.3))
            continue

        if _normalize_name(verb) in _DESTRUCTIVE_VERBS and any(
                _is_unresolved_var(t) for t in nonflag):
            # The `rm -rf "$VAR"` developer pattern: destructive verb established,
            # the unresolved token is the target. Flag, not block.
            findings.append(_finding(
                "canon.unresolved_destructive_target", _FLAG_CATEGORY, 0.4))
    return findings


def _has_resolved_destructive_segment(text: str) -> bool:
    """True when some top-level segment is a resolvable destructive command —
    a destructive verb with destructive flags and a non-safe target."""
    try:
        segments = parse_command(text)
    except Exception:
        return False
    for seg in segments:
        if getattr(seg, "depth", 0) or not seg.argv:
            continue
        if _normalize_name(seg.argv[0]) not in _DESTRUCTIVE_VERBS:
            continue
        operands = seg.argv[1:]
        nonflag = [t for t in operands if not t.startswith("-")]
        if _has_rf_flag(operands) and any(_is_nonsafe_target(t) for t in nonflag):
            return True
    return False


# ── token predicates ────────────────────────────────────────────────────────

def _is_substitution(tok: str) -> bool:
    return "$(" in tok or "`" in tok


def _is_unresolved_var(tok: str) -> bool:
    return bool(_UNRESOLVED_VAR.match(tok))


def _has_rf_flag(operands: List[str]) -> bool:
    """A recursive/force flag among the operands, short or long, any order."""
    for t in operands:
        if not t.startswith("-"):
            continue
        if t.startswith("--"):
            if t.lower() in ("--recursive", "--force"):
                return True
        elif re.fullmatch(r"-[a-zA-Z]*[rRfF][a-zA-Z]*", t):
            return True
    return False


def _is_nonsafe_target(tok: str) -> bool:
    """A target operand that is NOT safe in-project cleanup.

    Safe (returns False): a relative path with no leading `/`, `~`, `$`, `*` and
    no parent-escape — `build`, `./build`, `build/`, `node_modules`, `src/x`.
    Non-safe (returns True): absolute, home, `$HOME`/env, glob-root, or `../`.
    An unresolved `$VAR` target is handled on its own path and is NOT treated as
    non-safe here, so it cannot turn into a block.
    """
    if not tok or _is_unresolved_var(tok) or _is_substitution(tok):
        return False
    first = tok[0]
    if first in "/~*":
        return True
    if tok.startswith("../") or tok == "..":
        return True
    return False


def _finding(rule: str, category: str, score: float) -> Dict[str, object]:
    return {"rule": rule, "category": category, "score": score}


# ── string values ─────────────────────────────────────────────────────────────
# The "string" language is a tool-argument VALUE as the code it will be pasted
# into would read it: adjacent quoted literals joined across `+`, `.`, `..` or
# `||` (or plain juxtaposition), and base64 runs decoded to the text they
# encode. The canonical text is handed to the DLP secret scan, so a credential
# is matched on its value however the argument spells it. Pure string handling:
# nothing is evaluated, imported or run.

# A single- or double-quoted literal on one line, no escapes. The body is
# bounded so one long line cannot make the chain walk quadratic.
_QUOTED = re.compile(r"""(?P<q>["'])(?P<s>(?:(?!(?P=q))[^\\\n]){0,4096})(?P=q)""")
# What may sit between two literals of one concatenation.
_JOIN_OP = re.compile(r"[ \t]*(?:\+|\|\||\.\.?)?[ \t]*")

# A base64 / base64url run. 16 characters encode 12 bytes, below which a run is
# far more often an identifier than an encoding. Bounded above for the same
# reason as _QUOTED.
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,8192}={0,2}")
# Decoding is attempted on at most this many runs per value.
_MAX_B64_RUNS = 64
# Decoded text is kept only when it reads as text: printable, at least this long.
_MIN_DECODED_CHARS = 8


def _string(text: str) -> Canonical:
    applied: List[str] = []
    out = _join_literals(text)
    if out != text:
        applied.append("literals_joined")
    decoded = _decode_base64_runs(out)
    if decoded != out:
        applied.append("base64_decoded")
    return Canonical(text=decoded, language="string", applied=applied)


def _join_literals(text: str) -> str:
    """Join each chain of two or more quoted literals into one literal."""
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        m = _QUOTED.search(text, i)
        if m is None:
            break
        parts, end = [m.group("s")], m.end()
        while end < n:
            op = _JOIN_OP.match(text, end)
            nxt = _QUOTED.match(text, op.end())
            if nxt is None:
                break
            parts.append(nxt.group("s"))
            end = nxt.end()
        out.append(text[i:m.start()])
        if len(parts) > 1:
            q = m.group("q")
            out.append(q + "".join(parts) + q)
        else:
            out.append(m.group())
        i = end
    out.append(text[i:])
    return "".join(out)


def _decode_base64_runs(text: str) -> str:
    """Replace each base64 run that decodes to printable text with that text."""
    budget = [_MAX_B64_RUNS]

    def repl(m: re.Match) -> str:
        if budget[0] <= 0:
            return m.group()
        budget[0] -= 1
        run = m.group().rstrip("=")
        if len(run) % 4 == 1:
            return m.group()
        run = run.replace("-", "+").replace("_", "/")
        try:
            raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError):
            return m.group()
        if len(decoded) < _MIN_DECODED_CHARS or not all(
                c.isprintable() or c in "\t\n\r" for c in decoded):
            return m.group()
        return decoded

    return _B64_RUN.sub(repl, text)


_NORMALIZERS: Dict[str, Callable[[str], Canonical]] = {"shell": _shell, "string": _string}
