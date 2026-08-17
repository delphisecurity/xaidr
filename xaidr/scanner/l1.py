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

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")

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

# Defense-in-depth wall-clock budget for one L1 scan. If the cumulative time
# spent in the rule loop exceeds this, remaining rules are skipped with a warning
# so a single pathological pattern can never hang the whole scan. Thread-safe
# (no signals): checked between rules.
_L1_SCAN_BUDGET_SEC = 0.5

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
        try:
            compiled.append({
                "id": r["id"],
                "pattern": re.compile(r["pattern"], re.IGNORECASE),
                "score": r["score"],
                "category": category,
                # Email PII rules set this so RFC-reserved documentation domains
                # (example.com/.test/.invalid/...) don't fire as a PII leak.
                "filter_reserved_email": bool(r.get("filter_reserved_email", False)),
            })
        except re.error as e:
            print(f"[xaidr] Warning: rule {r.get('id')} regex failed: {e}")
    return compiled


INPUT_RULES = _load_and_compile("all-l1-rules.json")
OUTPUT_RULES = _load_and_compile("output-l1-rules.json")


def scan_l1(text: str, output: bool = False) -> L1Result:
    """Run L1 regex scan. Returns score, threats, timing."""
    start = time.perf_counter()
    rules = OUTPUT_RULES if output else INPUT_RULES
    threats: List[ThreatDetail] = []
    max_score = 0.0

    # Size cap: bound the text every regex sees. Truncates the scanned view only.
    if len(text) > L1_MAX_SCAN_CHARS:
        text = text[:L1_MAX_SCAN_CHARS]

    for rule in rules:
        # Wall-clock guard (defense in depth): never let one bad pattern hang the
        # scan. With the size cap + linear patterns this should never trip.
        if time.perf_counter() - start > _L1_SCAN_BUDGET_SEC:
            print(
                f"[xaidr] Warning: L1 scan budget exceeded "
                f"({_L1_SCAN_BUDGET_SEC}s); skipping remaining rules"
            )
            break
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

        match = rule["pattern"].search(text)
        if match:
            threats.append(ThreatDetail(
                rule=rule["id"],
                category=rule["category"],
                score=rule["score"],
                matched=match.group()[:100],
            ))
            if rule["score"] > max_score:
                max_score = rule["score"]

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
