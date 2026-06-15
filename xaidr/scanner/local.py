"""LocalScanner — runs L1 + L2 + DLP locally, escalates ambiguous cases to Brain.

Default scanner for xaidr v0.2. Matches the npm sensor architecture:
local scanning in <5ms, Brain only for L4 escalation.
"""

import json
import time
from typing import Optional
from uuid import uuid4

import httpx

from ..types import ScanResult
from .dlp import scan_dlp
from .l1 import scan_l1
from .l2 import scan_l2
from .normalizer import TypoNormalizer

DEFAULT_BLOCK_THRESHOLD = 0.65
DEFAULT_ESCALATE_THRESHOLD = 0.30


class LocalScanner:
    """Scans locally using L1/L2/DLP rules. Escalates to Brain L4 when ambiguous."""

    def __init__(
        self,
        api_key: str,
        sentinel_url: str,
        block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
        escalate_threshold: float = DEFAULT_ESCALATE_THRESHOLD,
        shadow_mode: bool = False,
        dlp_enabled: bool = True,
        escalation_client: Optional[httpx.Client] = None,
    ):
        self._api_key = api_key
        self._sentinel_url = sentinel_url.rstrip("/")
        self.block_threshold = block_threshold
        self.escalate_threshold = escalate_threshold
        self.shadow_mode = shadow_mode
        self.dlp_enabled = dlp_enabled
        self._normalizer = TypoNormalizer()
        self._escalation_client = escalation_client or httpx.Client(
            timeout=10.0,
            headers={"x-delphi-api-key": api_key},
        )

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

        action = "allowed"
        if score >= self.block_threshold:
            action = "flagged" if self.shadow_mode else "blocked"
        elif score >= self.escalate_threshold:
            action = "escalated"
        elif score > 0:
            action = "flagged"

        all_rules = (
            [t.rule for t in l1.threats]
            + [t.rule for t in l2.threats]
            + dlp_rules
        )

        all_threats = list(l1.threats) + list(l2.threats) + list(dlp_threats)
        top_threat = max(all_threats, key=lambda t: t.score, default=None)
        category = top_threat.category if top_threat else None

        if action == "escalated":
            l4_result = self._escalate_to_l4(prompt, agent_id, score, category)
            if l4_result:
                if l4_result.get("action") == "blocked":
                    action = "blocked"
                    score = max(score, l4_result.get("score", 0.85))
                    category = l4_result.get("category") or category
                    all_rules.append("L4_aprielguard")
                else:
                    action = "allowed"

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

    def _escalate_to_l4(
        self,
        prompt: str,
        agent_id: str,
        pre_score: float,
        category: Optional[str],
    ) -> Optional[dict]:
        """Escalate to Brain for L4 AprielGuard classification."""
        try:
            body_dict = {
                "prompt": prompt[:2000],
                "agentId": agent_id,
                "direction": "input",
                "escalation": True,
                "preScore": pre_score,
                "preCategory": category,
            }

            body_bytes = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")

            headers = {"x-delphi-api-key": self._api_key}

            resp = self._escalation_client.post(
                f"{self._sentinel_url}/v1/scan",
                content=body_bytes,
                headers={**headers, "Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    def close(self) -> None:
        if self._escalation_client:
            self._escalation_client.close()
