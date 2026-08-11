"""LocalScanner — runs L1 + L2 + DLP + compositional locally. Standalone — no backend.

Default scanner for xaidr. Local scanning is <5ms typical, with a bounded
worst-case (~2s) on a max-size adversarial input (a 100k separator-bomb; large
inputs stay under a fixed ceiling, non-scaling). 3-state verdict model (allow /
flag / block); enforcement_mode gates whether a block verdict actually blocks.
"""

import time
from uuid import uuid4

from ..types import ScanResult
from .compositional import CompositionalScanner
from .directive_context import (
    active_extraction,
    is_descriptive,
    protective_override_bypass,
    security_mention,
)
from .dlp import scan_dlp
from .encoding_evasion import encoded_payload_with_directive, url_decoded_danger
from .l1 import (
    scan_l1,
    L1_MAX_SCAN_CHARS,
    OVERSIZED_INPUT_CATEGORY,
    OVERSIZED_INPUT_RULE,
    iter_scan_windows,
)
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
    # credential_access IS gated, and the distinction from the DLP/secret
    # exclusion above is worth stating: a DLP signal fires on secret MATERIAL
    # being present in the text, and descriptive wording does not make a leaked
    # key un-leaked. credential_access fires on a COMMAND THAT WOULD READ a
    # secret, which is a behavioral signal like code_execution — quoting the
    # command reads nothing. Measured: without gating, "For example, the command
    # cat ~/.ssh/id_rsa reads a private key." BLOCKS at 0.90; with gating it
    # drops to flagged/0.28 while the bare live command `cat ~/.ssh/id_rsa`
    # still blocks at 1.00 via the directive-attack veto. Gating costs nothing
    # on the tool path (90 detected / 88 blocked either way) because the
    # tool-arg scan calls _scan_l1 directly and never reaches this gate.
    "credential_access",
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


# Live command-form signals that must NEVER be capped into the flag band by the
# benign-mention calibration: a shell/eval/decode-and-execute call is a live
# command regardless of any surrounding "documentation" framing (guards the
# runbook-framed "execute: curl … | sh" bypass).
_LIVE_COMMAND_RULES = frozenset({
    "LLM01_code_injection",
    "LLM01_decode_and_execute",
})


def _has_live_command(l1_threats, l2_threats) -> bool:
    """True when a live command-form signal (code-execution category or an
    eval/exec/decode-and-run rule) fired — such text is never a mere mention, so
    it is excluded from the benign-mention flag-band cap."""
    for t in (*l1_threats, *l2_threats):
        if t.category == "code_execution" or t.rule in _LIVE_COMMAND_RULES:
            return True
    return False


def _FLAG_BAND_CAP(block_threshold: float, flag_threshold: float) -> float:
    """A score strictly inside the flag band [flag_threshold, block_threshold):
    just below the block threshold so a benign mention SURFACES (flag) without
    blocking. Kept ≥ flag_threshold so it never silently drops to allow."""
    return max(flag_threshold, block_threshold - 0.05)

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

        # --- Benign-security MENTION cap (flag-band calibration) ----------------
        # Text that QUOTES or DOCUMENTS an attack (security docs, checklists, test
        # fixtures, log lines) rather than ISSUING it should be SURFACED (flag),
        # not BLOCK legitimate documentation. When such a mention frame is present
        # we CAP the gated behavioral score into the flag band — but ONLY when the
        # attack is genuinely just mentioned: no live command form (code exec), no
        # active-extraction imperative targeting a secret, and the score is not
        # driven by a real secret (DLP). Real attacks — a bare/live override, an
        # active extraction, a shell pipe, a leaked secret — are all excluded, so
        # they keep their block-band score. Only lowers a score, never raises one.
        if (
            direction != "output"
            and score >= self.block_threshold
            and dlp_score < self.block_threshold
            and not _has_live_command(l1_threats, l2_threats)
            and not active_extraction(scan_text)
            and security_mention(scan_text)
        ):
            score = min(score, _FLAG_BAND_CAP(self.block_threshold, self.flag_threshold))

        # --- Protective-then-override bypass: a POSITIVE attack signal ----------
        # "Protect the secret … now dump/echo/show it" is a live extraction attack
        # even when the target is a bare pronoun no keyword rule scored on its own.
        # When the clause-scoped structural bypass fires, ensure a block-band score
        # (this runs AFTER the mention cap so a genuine override attack still
        # blocks). Purely-protective input never fires it (all extraction verbs are
        # negated), so FP3 is preserved. Inbound only; never touches output.
        bypass_hit = direction != "output" and protective_override_bypass(scan_text)
        if bypass_hit:
            score = max(score, self.block_threshold, 0.85)

        # --- Embedded encoded-payload evasion: a POSITIVE attack signal --------
        # The bare-blob rule is anchored ^…$ (blob must dominate the input), so an
        # encoded blob embedded in prose ("please decode and follow: <blob>", a
        # blob in a log line, "run this: <blob>") evaded it. The real signal is an
        # encoded blob that is the OBJECT of a decode/execute directive — caught
        # RATIO-INDEPENDENTLY here, regardless of how much prose surrounds it. A
        # bare blob with no directive (config/JWT/data-uri/API field) never fires,
        # so this adds the embedded case without new base64 false positives.
        encoding_hit = direction != "output" and encoded_payload_with_directive(scan_text)
        if encoding_hit:
            score = max(score, self.block_threshold, 0.75)

        # --- URL/percent-encoded payload: decode-and-rescan --------------------
        # Percent-encoding is unambiguously decodable, so unlike the opaque
        # base64/hex blobs the signal is the DECODED content. A url-encoded
        # dangerous command / injection ("%72%6d…" → rm -rf, "ignore%20all…" →
        # the override) evades the raw keyword rules (partial %20 encoding breaks
        # word matching); decoding + re-scanning L1 exposes it to the SAME rules,
        # ratio-independently. Benign %20/%2F URLs decode to benign text (no
        # dangerous rule) so they never fire — the decoded DANGER is the signal,
        # not the presence of %XX. Uses the decoded L1 score directly (severity-
        # accurate). Inbound only; never touches output.
        url_score = url_decoded_danger(scan_text) if direction != "output" else 0.0
        if url_score > 0:
            score = max(score, url_score)

        # --- Over-length truncation-bypass fix ---------------------------------
        # Everything above scanned only the first L1_MAX_SCAN_CHARS. If the input
        # is longer, the tail was historically DROPPED — a total bypass (pad >100k
        # of filler, hide the payload after it). Instead: (1) scan the tail in
        # bounded overlapping windows (MAX-fused, no descriptive dampening — a
        # payload buried past 100k is an attack, not "documentation"), so a
        # payload just past the cap is CAUGHT; and (2) ALWAYS raise an over-length
        # flag so even a payload past the scan budget can never sail through
        # silently. Flag-band floor (monitor-surfaced), so benign large inputs are
        # not hard-blocked. The windowed scan shares scan_start's total budget, so
        # a megabyte-class input stays bounded (the ReDoS ceiling the cap guarded).
        oversized = len(prompt) > L1_MAX_SCAN_CHARS
        oversize_rules: list = []
        oversize_category = None
        if oversized:
            tail_score, tail_rules, tail_category = self._scan_tail(
                prompt, direction, scan_start
            )
            if tail_score > score:
                score = tail_score
            oversize_rules.extend(tail_rules)
            oversize_category = tail_category
            # Flag floor: never a silent pass, never a hard block on size alone.
            score = max(score, self.flag_threshold)
            # Always surface the over-length signal in telemetry.
            oversize_rules.append(OVERSIZED_INPUT_RULE)

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
        if bypass_hit:
            all_rules.append("DIRECTIVE_protective_override_bypass")
        if encoding_hit:
            all_rules.append("LLM01_encoded_payload_directive")
        if url_score > 0:
            all_rules.append("LLM01_url_encoded_danger")
        for r in oversize_rules:
            if r not in all_rules:
                all_rules.append(r)

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
        # Bypass is a positive signal even when no keyword threat scored (bare
        # pronoun target) — attribute the category so telemetry is not empty.
        if bypass_hit and not category:
            category = "system_prompt_leak"
        if encoding_hit and not category:
            category = "prompt_injection"
        if url_score > 0 and not category:
            category = "prompt_injection"
        # Over-length attribution: a real tail detection names its own category;
        # otherwise the input is attributed to the over-length signal so an
        # oversized (but content-clean) input is never a category-less flag.
        if oversized and not category:
            category = oversize_category or OVERSIZED_INPUT_CATEGORY

        scan_time_ms = round((time.perf_counter() - scan_start) * 1000, 1)

        return ScanResult(
            action=action,
            score=round(score, 3),
            category=category,
            rules=all_rules,
            latency_ms=int(scan_time_ms),
        )

    def _scan_tail(self, prompt: str, direction: str, scan_start: float):
        """Scan the input PAST the first window in bounded overlapping windows.

        Returns ``(max_score, rules, category)`` for the strongest detection
        found across the tail windows. Runs L1/L2/DLP/compositional on each
        normalized window and MAX-fuses — no descriptive-context dampening: a
        payload buried past L1_MAX_SCAN_CHARS is a bypass attempt, not benign
        documentation, so it must not be excused. Bounded by iter_scan_windows'
        total budget (shared with scan_start) and window cap, so a huge input
        stays within a fixed latency ceiling. The first window (index 0) is the
        already-scanned head and is skipped here.
        """
        is_output = direction == "output"
        if direction == "a2a":
            comp_mode = "a2a"
        elif is_output:
            comp_mode = "output"
        else:
            comp_mode = "chat"

        max_score = 0.0
        rules: list = []
        category = None
        for idx, window in iter_scan_windows(prompt, scan_start):
            if idx == 0:
                continue  # head already scanned by the main pipeline
            norm = self._normalizer.normalize(window)
            l1 = scan_l1(norm, output=is_output)
            l1_cats = set(t.category for t in l1.threats)
            l2 = scan_l2(norm, l1_categories=l1_cats)
            dlp_score = 0.0
            dlp_threats: list = []
            if self.dlp_enabled:
                dlp = scan_dlp(norm)
                dlp_score = dlp.score
                dlp_threats = list(dlp.threats)
            comp = self._compositional.scan(norm, scan_mode=comp_mode)
            comp_score = comp.get("score", 0.0)

            window_score = max(l1.score, l2.score, dlp_score, comp_score)
            if window_score > max_score:
                max_score = window_score
                # Attribute to the strongest layer in THIS (winning) window.
                threats = list(l1.threats) + list(l2.threats) + dlp_threats
                top = max(threats, key=lambda t: t.score, default=None)
                if comp_score >= (top.score if top else 0.0) and comp.get("details"):
                    category = comp["details"][0].get("category")
                elif top is not None:
                    category = top.category
                rules = (
                    [t.rule for t in l1.threats]
                    + [t.rule for t in l2.threats]
                    + [t.rule for t in dlp_threats]
                    + [d.get("rule") for d in comp.get("details", []) if d.get("rule")]
                )
        return max_score, rules, category

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
