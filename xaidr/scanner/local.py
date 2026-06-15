"""LocalScanner — runs L1 + L2 + DLP + compositional locally. Standalone — no backend.

Default scanner for xaidr. Local scanning in <5ms with a 3-state verdict
model (allow / flag / block); enforcement_mode gates whether a block verdict
actually blocks.
"""

import time
from uuid import uuid4

from ..types import ScanResult
from .compositional import CompositionalScanner
from .dlp import scan_dlp
from .l1 import scan_l1
from .l2 import scan_l2
from .normalizer import TypoNormalizer

DEFAULT_BLOCK_THRESHOLD = 0.60
DEFAULT_FLAG_THRESHOLD = 0.20


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

        # Phase 0: typo normalization
        normalized = self._normalizer.normalize(prompt)

        # L1: regex rules (input or output ruleset)
        is_output = direction == "output"
        l1 = scan_l1(normalized, output=is_output)

        # L2: intents + composites + self-referential probe
        l1_categories = set(t.category for t in l1.threats)
        l2 = scan_l2(normalized, l1_categories=l1_categories)

        # DLP: PII / secret patterns
        dlp_score = 0.0
        dlp_threats = []
        dlp_rules = []
        if self.dlp_enabled:
            dlp = scan_dlp(normalized)
            dlp_score = dlp.score
            dlp_threats = dlp.threats
            dlp_rules = [t.rule for t in dlp.threats]

        score = self._compute_composite(l1.score, l2.score, dlp_score)

        # --- Compositional scanner (L1-zero gate) ---
        # Runs ONLY when L1/L2/DLP all found nothing (score == 0). Catches
        # relation-based paraphrase attacks the regex/category layers miss.
        comp_rules = []
        comp_category = None
        if score == 0:
            if direction == "a2a":
                comp_mode = "a2a"
            elif direction == "output":
                comp_mode = "output"
            else:
                comp_mode = "chat"
            comp = self._compositional.scan(normalized, scan_mode=comp_mode)
            if comp["score"] > 0:
                score = comp["score"]
                comp_rules = [d["rule"] for d in comp.get("details", [])]
                if comp.get("details"):
                    comp_category = comp["details"][0].get("category")

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
            [t.rule for t in l1.threats]
            + [t.rule for t in l2.threats]
            + dlp_rules
            + comp_rules
        )

        all_threats = list(l1.threats) + list(l2.threats) + list(dlp_threats)
        top_threat = max(all_threats, key=lambda t: t.score, default=None)
        category = top_threat.category if top_threat else None
        if category is None and comp_category:
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
