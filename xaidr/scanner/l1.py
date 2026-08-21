"""L1 Scanner — regex pattern matching against rule JSON files.

Loads rules from JSON at import time, compiles regex patterns once.
Matches the npm sensor's l1-scanner.ts architecture.
"""

import difflib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import List

from .dlp import _is_reserved_email
from .repetition import find_phrase_repeat

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")

# Non-regex rule bodies, addressed by name from the rule JSON's "detector" field.
# A rule belongs here when the thing it asks is not a pattern-matching question —
# see repetition.py for why phrase repetition is a counting problem and what the
# regex formulation of it cost.
_DETECTORS = {
    "phrase_repeat": find_phrase_repeat,
}

# The CANONICAL set of category strings an L1 rule is allowed to emit. This is
# the authority the rest of the engine keys on: sensor.scan_tool_call filters
# tool-argument threats BY CATEGORY, so a rule whose `category` is misspelled
# ("jailbrake", "sytem_prompt_leak") loads cleanly, fires on the content path,
# and is then SILENTLY DISCARDED on the tool path — a rule half-disabled by a
# typo, exactly the failure class the ADV-2 policy-key validator exists to stop.
# So an unrecognized category is rejected LOUDLY at load, not defaulted quietly.
#
# Deliberately an EXPLICIT allowlist, not `{r["category"] for r in rules}`: a set
# derived from the file would happily contain the typo and validate it against
# itself. Adding a genuinely new category is a one-line, reviewed edit here — the
# same friction the tool-path keep/flag sets in sensor.py carry, on purpose.
# Covers BOTH rule files: input (all-l1-rules.json) and output (output-l1-rules).
_KNOWN_L1_CATEGORIES = frozenset({
    # input categories (all-l1-rules.json)
    "code_execution", "credential_access", "data_exfiltration", "dos_attempt",
    "encoding_evasion", "eva003", "excessive_agency", "forged_trust",
    "jailbreak", "llm02", "llm09", "pii_detected", "prompt_injection",
    "supply_chain", "system_prompt_leak",
    # output categories (output-l1-rules.json)
    "out", "social_engineering",
})


class UnknownRuleDetector(ValueError):
    """An L1 rule names a detector callable no code path provides.

    Same posture as ``UnknownRuleCategory``: fail at LOAD. A rule pointing at a
    missing detector would compile fine and simply never fire, which is the
    failure mode that is invisible in production and obvious in CI.
    """


class UnknownRuleCategory(ValueError):
    """An L1 rule declares a category no code path recognizes.

    Raised at LOAD (import) rather than defaulting quietly, because the effect of
    a bad category is invisible at runtime: the rule still fires on the content
    path but is dropped by the tool-path category filter, so the operator sees a
    working rule that is in fact disarmed on one surface. Fail loudly at ship
    time (CI imports the package) instead. Mirrors the ADV-2 precedent for
    unknown policy keys (authz/policy.py) and unknown enforcement modes (sensor).
    """

# Maximum number of characters L1 will regex-scan. A megabyte-class input fed to
# every compiled pattern causes catastrophic regex backtracking (an exploitable
# ReDoS / denial-of-service). We scan only the first L1_MAX_SCAN_CHARS characters
# — large enough that no real attack payload is missed (attacks lead with their
# injection, not after 100k chars of filler), small enough to bound worst-case
# work to well under a second. Truncation applies to the SCANNED view only; the
# caller's original data is never mutated. The shared call site (local.py) caps
# the same way so L2/DLP/compositional are bounded too.
L1_MAX_SCAN_CHARS = 100_000

# Defense-in-depth wall-clock budget for one L1 scan. Checked BETWEEN rules, and
# that limitation is fundamental rather than a shortcut: in CPython a running
# ``re.search`` is a single C call, so no signal handler and no thread can
# interrupt it. A budget can therefore only ever observe that a pattern WAS
# pathological — it cannot stop one. That is why the real fix for a backtracker
# is always a linear pattern (see repetition.py) and never a timeout.
_L1_SCAN_BUDGET_SEC = 0.5

# Per-rule wall-clock above which ONE pattern is treated as having behaved
# pathologically on this input. Calibrated from the audit, not guessed: with every
# pattern now linear, the slowest single rule on a full-size 100k adversarial
# input measures 376ms, so 1.0s leaves ~2.7x headroom for a loaded machine. The
# separation from a real backtracker is not close — the one this finding exists
# for did not finish in 60 seconds on 105 characters — so a wide margin costs
# nothing in detection and removes any chance of firing on honest work.
_L1_RULE_SLOW_SEC = 1.0

# WHAT HAPPENS WHEN A BOUND IS BLOWN — AND WHY NEITHER IS A TIMEOUT.
#
# Both used to be a bare `print`: rules were skipped, nothing was recorded, and
# the scan returned whatever the rules before the slow one had found. That is a
# DETECTION-LOSS path an attacker controls, and this scanner also fails OPEN on an
# unexpected exception (sensor._emit_scan_error returns `allowed` with
# SCAN_FAILED_OPEN), so "make the scanner slow" and "make the scanner throw" would
# both reduce a verdict. Neither may stay silent.
#
# They are DIFFERENT FAILURES and get different verdicts, which is the whole of
# the calibration:
#
#   PATHOLOGICAL PATTERN — one rule alone exceeded _L1_RULE_SLOW_SEC. With every
#   pattern audited linear, no honest rule can do this at any input size; it means
#   a pattern has re-entered super-linear behaviour on attacker-chosen structure.
#   BLOCK BAND. This is what makes slowness unusable as a bypass: an input crafted
#   to make the scanner grind now blocks BECAUSE it made the scanner grind, so the
#   attacker's lever raises the verdict instead of lowering it.
#
#   SCAN BUDGET — the rule LOOP ran long without any single rule misbehaving.
#   After the audit this means one thing only: the input is very large and 160
#   linear rules over it add up. That is ordinary work on a big document, not an
#   attack, and this engine has a standing decision that large input is SURFACED
#   and never hard-blocked (LLM01_oversized_input, and
#   test_truncation_bypass.test_benign_large_input_flagged_not_blocked, which is
#   what caught an earlier version of this change blocking a 150k benign
#   document). FLAG BAND — visible, attributable, and not a new false positive.
#   The detection loss it admits is the pre-existing, deliberate windowing
#   trade-off; what is new is that it is now reported instead of printed.
SCAN_DEGRADED_CATEGORY = "dos_attempt"

PATHOLOGICAL_PATTERN_RULE = "LLM04_pathological_pattern"
PATHOLOGICAL_PATTERN_SCORE = 0.65

SCAN_DEGRADED_RULE = "LLM04_scan_budget_exceeded"
SCAN_DEGRADED_SCORE = 0.25

# --- Over-length windowing (truncation-bypass fix) ---------------------------
# Truncating to the first L1_MAX_SCAN_CHARS silently dropped everything past the
# cap — an attacker padded >100k of benign filler to push a payload past it and
# the whole engine never saw the payload (a clean total bypass). Instead of
# dropping the tail we scan the FULL input in successive OVERLAPPING windows, but
# under a HARD TOTAL wall-clock budget so a megabyte-class input cannot impose
# unbounded latency (the very DoS the cap existed to prevent).
#
# The overlap ensures a payload straddling a window boundary appears whole in at
# least one window. The total budget (checked BETWEEN windows — a single regex
# can't be interrupted) bounds the worst case to a FIXED ceiling regardless of
# input size: a 100k input is one window (unchanged); a 10MB input scans as many
# windows as the budget allows, then stops. Over-length is ALSO surfaced as a
# flag by the caller, so even a payload past the budget is never a silent pass.
# The total budget must keep the WHOLE scan (head + tail windows) inside the
# engine's hard per-scan latency bound (the ReDoS invariant, ~2s). Since a single
# window can't be interrupted mid-regex, the true worst case is budget + one
# window, so this is set well below the 2s bound. Over-length is ALWAYS flagged
# regardless of how far the windowed scan reaches, so a tail the budget can't
# reach is still surfaced — never a silent pass.
SCAN_WINDOW_OVERLAP = 512
MAX_SCAN_WINDOWS = 8
TOTAL_SCAN_BUDGET_SEC = 1.0

# Signal attached by callers when the input exceeds L1_MAX_SCAN_CHARS. Flag-band
# (monitor-surfaced), not a hard block: legitimate inputs are rarely this large,
# but some are, so the operator SEES every over-length input without benign large
# documents being broken.
OVERSIZED_INPUT_RULE = "LLM01_oversized_input"
OVERSIZED_INPUT_CATEGORY = "oversized_input"


def iter_scan_windows(
    text: str,
    start_time: float,
    *,
    window: int = L1_MAX_SCAN_CHARS,
    overlap: int = SCAN_WINDOW_OVERLAP,
    max_windows: int = MAX_SCAN_WINDOWS,
    budget_sec: float = TOTAL_SCAN_BUDGET_SEC,
):
    """Yield successive overlapping windows of ``text`` under a total budget.

    Yields ``(index, window_text)``. The FIRST window is always yielded (so a
    ``<= window`` input behaves exactly as an un-windowed scan). Subsequent
    windows are yielded only while BOTH the window count is under ``max_windows``
    AND the cumulative wall-clock since ``start_time`` is under ``budget_sec``
    (checked between windows — a running regex cannot be interrupted, so the true
    ceiling is budget + one window). Consecutive windows overlap by ``overlap``
    so a payload spanning a boundary appears whole in at least one window.
    """
    n = len(text)
    step = max(1, window - overlap)
    pos = 0
    idx = 0
    while True:
        if idx > 0:
            if idx >= max_windows:
                break
            if (time.perf_counter() - start_time) > budget_sec:
                break
        yield idx, text[pos:pos + window]
        if pos + window >= n:
            break
        pos += step
        idx += 1


@dataclass
class ThreatDetail:
    rule: str
    category: str
    score: float
    matched: str = ""


@dataclass
class L1Result:
    score: float
    threats: List[ThreatDetail]
    time_ms: float
    triggered: bool


def _load_and_compile(filename: str) -> list:
    """Load rules from JSON and compile regex patterns."""
    path = os.path.join(_RULES_DIR, filename)
    try:
        with open(path) as f:
            raw = json.load(f)
    except FileNotFoundError:
        print(f"[xaidr] Warning: {filename} not found, using empty ruleset")
        return []
    except Exception as e:
        # A corrupt/unreadable rule asset must NOT make `import xaidr` crash the
        # host — degrade to an empty ruleset (same posture as a missing file).
        print(f"[xaidr] Warning: {filename} failed to load ({e}); using empty ruleset")
        return []

    if not isinstance(raw, list):
        print(f"[xaidr] Warning: {filename} is not a rule list; using empty ruleset")
        return []

    compiled = []
    for r in raw:
        # Category validation runs BEFORE the re.compile try/except and is NOT
        # caught by it: a misspelled category is an authoring bug in a vendored
        # rule that must fail the build, not a corrupt-asset condition to degrade
        # around. A did-you-mean names the offending rule and category, matching
        # the ADV-2 unknown-key message shape in authz/policy.py.
        category = r.get("category")
        if category not in _KNOWN_L1_CATEGORIES:
            near = difflib.get_close_matches(
                str(category), sorted(_KNOWN_L1_CATEGORIES), n=1, cutoff=0.6
            )
            did_you_mean = f" Did you mean {near[0]!r}?" if near else ""
            raise UnknownRuleCategory(
                f"[xaidr] rule {r.get('id')!r} in {filename} declares unknown "
                f"category {category!r}.{did_you_mean} A rule with an "
                f"unrecognized category fires on the content path but is SILENTLY "
                f"DROPPED by the tool-path category filter — a rule half-disabled "
                f"by a typo. Add the category to _KNOWN_L1_CATEGORIES (and the "
                f"tool-path keep/flag sets in sensor.py) or fix the spelling. "
                f"Valid categories: {', '.join(sorted(_KNOWN_L1_CATEGORIES))}."
            )
        # A rule may name a DETECTOR instead of carrying a regex. Some questions
        # are not regex questions: "is a 5-50 character unit repeated 21 times"
        # is a counting problem, and the regex that expressed it
        # (`(.{5,50})\s*(?:\1\s*){20,}`) was a catastrophic backtracker — 104
        # spaces did not finish in 60 seconds. See scanner/repetition.py. An
        # unknown detector name fails at LOAD for the same reason an unknown
        # category does: a rule that silently does nothing is worse than a build
        # error.
        detector_name = r.get("detector")
        if detector_name is not None:
            fn = _DETECTORS.get(detector_name)
            if fn is None:
                raise UnknownRuleDetector(
                    f"[xaidr] rule {r.get('id')!r} in {filename} names unknown "
                    f"detector {detector_name!r}. A rule with an unrecognized "
                    f"detector would load and never fire. Valid detectors: "
                    f"{', '.join(sorted(_DETECTORS))}."
                )
            params = r.get("detector_params") or {}
            if not isinstance(params, dict):
                raise UnknownRuleDetector(
                    f"[xaidr] rule {r.get('id')!r} in {filename} has a non-object "
                    f"detector_params."
                )
            compiled.append({
                "id": r["id"],
                "pattern": None,
                "detector": (lambda f, kw: lambda text: f(text, **kw))(fn, params),
                "score": r["score"],
                "category": category,
                "filter_reserved_email": False,
            })
            continue
        try:
            compiled.append({
                "id": r["id"],
                "pattern": re.compile(r["pattern"], re.IGNORECASE),
                "detector": None,
                "score": r["score"],
                "category": category,
                # Email PII rules set this so RFC-reserved documentation domains
                # (example.com/.test/.invalid/...) don't fire as a PII leak.
                "filter_reserved_email": bool(r.get("filter_reserved_email", False)),
            })
        except re.error as e:
            print(f"[xaidr] Warning: rule {r.get('id')} regex failed: {e}")
    return compiled


def _detectors_first(rules: list) -> list:
    """Stable partition putting the non-regex DETECTOR rules at the front.

    The rule loop abandons remaining rules when it blows its budget, and on a
    huge input that is exactly the family you least want to skip: the detectors
    ARE the flood rules, and a flood is what exhausts a budget. Measured on 100k
    of "curl " repeated — a repetition flood — the expensive destination rules ran
    first, the budget went, and the LLM04 family (positions 42-89 in file order)
    never ran: the input came back flagged/0.25 on the degradation signal alone
    instead of blocked on the repetition it plainly was.

    Detectors are the cheapest rules in the set and their cost is bounded by
    input length alone, so running them first costs the common path nothing and
    guarantees the flood family always gets its say. Stable within each group, so
    file order still decides everything else.
    """
    return ([r for r in rules if r["detector"] is not None]
            + [r for r in rules if r["detector"] is None])


INPUT_RULES = _detectors_first(_load_and_compile("all-l1-rules.json"))
OUTPUT_RULES = _detectors_first(_load_and_compile("output-l1-rules.json"))


def scan_l1(text: str, output: bool = False) -> L1Result:
    """Run L1 regex scan. Returns score, threats, timing."""
    start = time.perf_counter()
    rules = OUTPUT_RULES if output else INPUT_RULES
    threats: List[ThreatDetail] = []
    max_score = 0.0

    # Size cap: bound the text every regex sees. Truncates the scanned view only.
    if len(text) > L1_MAX_SCAN_CHARS:
        text = text[:L1_MAX_SCAN_CHARS]

    # Two distinct degradations, deliberately not merged (see the comment on
    # PATHOLOGICAL_PATTERN_RULE): `pathological` is one rule misbehaving and
    # blocks; `budget_blown` is the loop running long on a large input and flags.
    pathological = None
    budget_blown = False

    for rule in rules:
        # Wall-clock guard (defense in depth): never let one bad pattern hang the
        # scan. With the size cap + linear patterns this should never trip — and
        # if it does, it produces a FINDING rather than silence (see
        # SCAN_DEGRADED_RULE above).
        if time.perf_counter() - start > _L1_SCAN_BUDGET_SEC:
            print(
                f"[xaidr] Warning: L1 scan budget exceeded "
                f"({_L1_SCAN_BUDGET_SEC}s); skipping remaining rules"
            )
            budget_blown = True
            break

        if rule["detector"] is not None:
            rule_start = time.perf_counter()
            span = rule["detector"](text)
            if time.perf_counter() - rule_start > _L1_RULE_SLOW_SEC:
                pathological = pathological or rule["id"]
            if span:
                threats.append(ThreatDetail(
                    rule=rule["id"],
                    category=rule["category"],
                    score=rule["score"],
                    matched=str(span)[:100],
                ))
                if rule["score"] > max_score:
                    max_score = rule["score"]
            continue

        if rule.get("filter_reserved_email"):
            # Email PII rule: drop RFC-reserved documentation-domain matches and
            # fire only if a real (non-reserved) email remains. Linear: findall +
            # a list filter over already-found matches (no new backtracking regex).
            emails = rule["pattern"].findall(text)
            real = [e for e in emails if not _is_reserved_email(e)]
            if real:
                threats.append(ThreatDetail(
                    rule=rule["id"],
                    category=rule["category"],
                    score=rule["score"],
                    matched=str(real[0])[:100],
                ))
                if rule["score"] > max_score:
                    max_score = rule["score"]
            continue

        rule_start = time.perf_counter()
        match = rule["pattern"].search(text)
        if time.perf_counter() - rule_start > _L1_RULE_SLOW_SEC:
            # This pattern took pathologically long ON THIS INPUT. It cannot be
            # interrupted (a C-level re.search is uninterruptible in CPython), so
            # this is observed after the fact — but it is still recorded, because
            # the alternative is a scanner that gets slower and quieter at the
            # same time.
            pathological = pathological or rule["id"]
        if match:
            threats.append(ThreatDetail(
                rule=rule["id"],
                category=rule["category"],
                score=rule["score"],
                matched=match.group()[:100],
            ))
            if rule["score"] > max_score:
                max_score = rule["score"]

    if pathological is not None:
        threats.append(ThreatDetail(
            rule=PATHOLOGICAL_PATTERN_RULE,
            category=SCAN_DEGRADED_CATEGORY,
            score=PATHOLOGICAL_PATTERN_SCORE,
            matched=f"rule={pathological}",
        ))
        max_score = max(max_score, PATHOLOGICAL_PATTERN_SCORE)
    if budget_blown:
        threats.append(ThreatDetail(
            rule=SCAN_DEGRADED_RULE,
            category=SCAN_DEGRADED_CATEGORY,
            score=SCAN_DEGRADED_SCORE,
            matched="rule loop exceeded its budget; remaining rules skipped",
        ))
        max_score = max(max_score, SCAN_DEGRADED_SCORE)

    categories = set(t.category for t in threats)
    if len(categories) >= 2:
        max_score = min(1.0, max_score * 1.3)

    time_ms = (time.perf_counter() - start) * 1000
    return L1Result(
        score=max_score,
        threats=threats,
        time_ms=round(time_ms, 2),
        triggered=len(threats) > 0,
    )
