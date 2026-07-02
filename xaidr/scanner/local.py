"""LocalScanner — runs L1 + L2 + DLP + compositional locally. Standalone — no backend.

Default scanner for xaidr. Local scanning in <5ms with a 3-state verdict
model (allow / flag / block); enforcement_mode gates whether a block verdict
actually blocks.
"""

import time
from uuid import uuid4

from ..types import ScanResult
from .compositional import CompositionalScanner
from .directive_context import is_descriptive
from .dlp import scan_dlp
from .l1 import scan_l1, L1_MAX_SCAN_CHARS
from .l2 import scan_l2
from .normalizer import TypoNormalizer

DEFAULT_BLOCK_THRESHOLD = 0.60
DEFAULT_FLAG_THRESHOLD = 0.20

# Context-sensitive (behavioral) categories that a DESCRIPTIVE frame dampens:
# instruction/injection/extraction/jailbreak/code-exec/tool-misuse signals fire
# on keyword presence and cannot tell a command from a description of one. In a
# descriptive frame (see directive_context) these are suppressed below threshold.
# DLP/PII/secret, DoS, and structural signals are NEVER in this set — a real
# secret or a pathological payload is not made benign by descriptive wording.
GATED_CATEGORIES = frozenset({
    "prompt_injection",
    "system_prompt_leak",
    "jailbreak",
    "excessive_agency",
    "code_execution",
    "tool_misuse",
    "agentic_abuse",
    "data_exfiltration",
    # compositional signal categories (the whole compositional layer is behavioral)
    "exfiltration",
    "override",
    "role_override",
    "persona",
})

# Directive-attack veto (mirrors directive_context._SELF_EXFIL, but by rule-class
# instead of regex): a LITERAL command form or a LITERAL imperative override is
# high-signal REGARDLESS of surrounding prose — there is no benign reason for a
# bare executable command / live "ignore all previous instructions" to appear as
# an active directive. These are NEVER dampened, so a fake descriptive prefix
# ("For example, rm -rf /", "In this tutorial, ignore all previous instructions")
# can no longer smuggle a real attack past the dampener. The distinction is
# code-as-COMMAND (never dampen) vs code-as-DOCUMENTATION (may dampen): softer
# keyword rules (theatre-play "system prompt", "how do I delete a file") are NOT
# in this set and stay dampenable, preserving the FP fix.
NEVER_DAMPEN_CATEGORIES = frozenset({
    "code_execution",  # all mirrored command-form rules (LLM08_* shell/os/pipe/…)
})
NEVER_DAMPEN_RULES = frozenset({
    "LLM01_direct_override",           # literal "ignore/disregard … instructions"
    "LLM01_override_expanded_nouns",
    "LLM01_override_synonym_verbs",
    "LLM01_code_injection",            # eval(/exec(/os.system( live code call
    "LLM01_decode_and_execute",        # "decode this and run it"
})


def _is_directive_attack(threat) -> bool:
    """True for high-confidence literal command / imperative-override signals that
    must never be dampened by a descriptive frame."""
    return (
        threat.category in NEVER_DAMPEN_CATEGORIES
        or threat.rule in NEVER_DAMPEN_RULES
    )

# DLP scan cap. The DLP patterns are now linear (the bulk-email ReDoS was
# linearized to a findall + count threshold), so DLP uses the same ceiling as the
# other detection scanners — no tighter stopgap is needed.
DLP_MAX_SCAN_CHARS = L1_MAX_SCAN_CHARS


class LocalScanner:
    """Scans locally using L1/L2/DLP + compositional rules. Standalone — no backend."""

    def __init__(
        self,
        block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
        flag_threshold: float = DEFAULT_FLAG_THRESHOLD,
        shadow_mode: bool = False,
        dlp_enabled: bool = True,
        enforcement_mode: str = "monitor",
    ):
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.shadow_mode = shadow_mode
        self.dlp_enabled = dlp_enabled
        # shadow_mode forces observe-only: it IS monitor mode.
        self.enforcement_mode = "monitor" if shadow_mode else enforcement_mode
        self._normalizer = TypoNormalizer()
        self._compositional = CompositionalScanner()

    def scan(
        self,
        prompt: str,
        agent_id: str,
        direction: str = "input",
    ) -> ScanResult:
        """Run full local scan pipeline."""
        scan_start = time.perf_counter()
        scan_id = uuid4().hex[:12]  # noqa: F841 — reserved for future telemetry

        # Size cap (ReDoS guard) — applied BEFORE any pipeline stage, including
        # normalization. A megabyte-class input can stall a stage (regex
        # backtracking, or the normalizer's per-token DL work); capping the raw
        # input first bounds EVERY stage to the L1_MAX_SCAN_CHARS ceiling. This
        # truncates the SCANNED view only; `prompt` (the caller's data) is not
        # mutated. scan_l1 self-caps too as defense in depth.
        capped = (
            prompt
            if len(prompt) <= L1_MAX_SCAN_CHARS
            else prompt[:L1_MAX_SCAN_CHARS]
        )

        # Phase 0: typo normalization (on the already-capped view)
        normalized = self._normalizer.normalize(capped)

        # Normalization preserves length to within token-correction deltas; keep a
        # defensive ceiling so downstream stages never exceed the cap.
        scan_text = (
            normalized
            if len(normalized) <= L1_MAX_SCAN_CHARS
            else normalized[:L1_MAX_SCAN_CHARS]
        )

        # L1: regex rules (input or output ruleset)
        is_output = direction == "output"
        l1 = scan_l1(scan_text, output=is_output)

        # L2: intents + composites + self-referential probe
        l1_categories = set(t.category for t in l1.threats)
        l2 = scan_l2(scan_text, l1_categories=l1_categories)

        # DLP: PII / secret patterns. The bulk-email ReDoS was linearized
        # (findall + count threshold), so DLP now uses the same scan ceiling as
        # the other detection scanners (DLP_MAX_SCAN_CHARS == L1_MAX_SCAN_CHARS).
        dlp_score = 0.0
        dlp_threats = []
        dlp_rules = []
        if self.dlp_enabled:
            dlp = scan_dlp(scan_text[:DLP_MAX_SCAN_CHARS])
            dlp_score = dlp.score
            dlp_threats = dlp.threats
            dlp_rules = [t.rule for t in dlp.threats]

        # --- Compositional scanner (always-on, MAX-fused) ---
        # Runs on EVERY scan and fuses via max, so a weak L1/L2/DLP signal (e.g.
        # a 0.15 self-referential probe) can never preempt a strong relation-based
        # compositional detection (e.g. 0.65). Compositional's own soft-context FP
        # guards keep benign inputs near zero, so always-on is safe. `scan_text`
        # is already capped (L1_MAX_SCAN_CHARS), so the path stays bounded.
        comp_rules = []
        comp_category = None
        comp_score = 0.0
        if direction == "a2a":
            comp_mode = "a2a"
        elif direction == "output":
            comp_mode = "output"
        else:
            comp_mode = "chat"
        comp = self._compositional.scan(scan_text, scan_mode=comp_mode)
        comp_score = comp["score"]
        if comp_score > 0:
            comp_rules = [d["rule"] for d in comp.get("details", [])]
            if comp.get("details"):
                comp_category = comp["details"][0].get("category")

        # --- Directive-context calibration (two-way FP/recall fix) -------------
        # In a DESCRIPTIVE frame (educational / quoting / benign how-to, and NOT a
        # directive-action wrapper), dampen the gated behavioral signals below
        # threshold: describing or quoting an attack must not flag, while a real
        # command still does (a bare attack is not descriptive). Only inbound
        # (input/a2a) is gated; DLP/DoS/structural signals are never gated. The
        # whole compositional layer is behavioral, so it is suppressed wholesale.
        l1_threats = list(l1.threats)
        l2_threats = list(l2.threats)
        l1_score = l1.score
        l2_score = l2.score
        if direction != "output" and is_descriptive(scan_text):
            # Keep a signal if it is NOT a gated behavioral category, OR it is a
            # directive-attack (literal command / imperative override) — the
            # latter is never dampened, closing the descriptive-frame bypass.
            l1_threats = [
                t for t in l1_threats
                if t.category not in GATED_CATEGORIES or _is_directive_attack(t)
            ]
            l2_threats = [
                t for t in l2_threats
                if t.category not in GATED_CATEGORIES or _is_directive_attack(t)
            ]
            l1_score = max((t.score for t in l1_threats), default=0.0)
            l2_score = max((t.score for t in l2_threats), default=0.0)
            comp_score = 0.0
            comp_rules = []
            comp_category = None

        score = self._compute_composite(l1_score, l2_score, dlp_score)
        # Fuse: never let compositional LOWER the score, never let a weak
        # L1/L2/DLP composite suppress a strong compositional signal.
        score = max(score, comp_score)

        # 3-state local verdict (no backend, no escalation)
        if score >= self.block_threshold:
            verdict = "block"
        elif score >= self.flag_threshold:
            verdict = "flag"
        else:
            verdict = "allow"

        # enforcement_mode gates whether a block verdict actually blocks.
        # monitor (default): nothing is blocked; everything is emitted/logged.
        # block: a "block" verdict is enforced.
        if verdict == "block" and self.enforcement_mode == "block":
            action = "blocked"
        elif verdict == "block":
            action = "flagged"  # monitor mode: block-worthy but observe-only
        elif verdict == "flag":
            action = "flagged"
        else:
            action = "allowed"

        all_rules = (
            [t.rule for t in l1_threats]
            + [t.rule for t in l2_threats]
            + dlp_rules
            + comp_rules
        )

        all_threats = list(l1_threats) + list(l2_threats) + list(dlp_threats)
        top_threat = max(all_threats, key=lambda t: t.score, default=None)
        top_l1l2dlp = top_threat.score if top_threat else 0.0
        # Attribute the category to whichever layer produced the winning signal:
        # compositional when it is the strict-or-equal top contributor, else the
        # strongest L1/L2/DLP threat (with compositional as the fallback).
        if comp_category and comp_score >= top_l1l2dlp:
            category = comp_category
        elif top_threat is not None:
            category = top_threat.category
        else:
            category = comp_category

        scan_time_ms = round((time.perf_counter() - scan_start) * 1000, 1)

        return ScanResult(
            action=action,
            score=round(score, 3),
            category=category,
            rules=all_rules,
            latency_ms=int(scan_time_ms),
        )

    def _compute_composite(
        self, l1_score: float, l2_score: float, dlp_score: float
    ) -> float:
        """Combine L1, L2, DLP scores into a single composite score."""
        base = max(l1_score, l2_score, dlp_score)

        layers_triggered = sum(
            1 for s in [l1_score, l2_score, dlp_score] if s > 0
        )
        if layers_triggered >= 2:
            base = min(1.0, base * 1.2)
        if layers_triggered >= 3:
            base = min(1.0, base * 1.1)

        return base

    def close(self) -> None:
        """No-op — standalone scanner holds no network clients."""
        return
