"""Phase 13 — Damerau-Levenshtein typo normalization.

Corrects security-relevant misspellings before L1 regex scanning.
E.g., 'promtp' -> 'prompt', 'ignroe' -> 'ignore'.
"""

import json
import os
from typing import Dict, List, Set

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")

# Leetspeak digit/symbol substitutions. A single leet char (e.g. "ign0re") is
# already within Damerau-Levenshtein distance 1 of its keyword, but MULTI-char
# leet ("1gn0r3" -> distance 3) is not — DL alone can't bridge it. Folding the
# common substitutions before keyword matching lets the same keyword set catch
# multi-char leet evasion. Folding is applied ONLY to tokens that contain a leet
# char, so pure-letter tokens (all normal prose) are completely unaffected.
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s",
})
_LEET_CHARS = frozenset("013456789@$")


def _load_typo_config() -> dict:
    path = os.path.join(_RULES_DIR, "typo-keywords.json")
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"all_keywords": [], "denylist": []}


def _damerau_levenshtein(s1: str, s2: str) -> int:
    """Damerau-Levenshtein distance (transpositions count as 1 edit)."""
    len1, len2 = len(s1), len(s2)
    d: Dict[tuple, int] = {}
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,
                d[(i, j - 1)] + 1,
                d[(i - 1, j - 1)] + cost,
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost)
    return d[(len1 - 1, len2 - 1)]


class TypoNormalizer:
    """Corrects typos of security-relevant keywords before scanning."""

    def __init__(self):
        config = _load_typo_config()
        self.keywords: List[str] = config.get("all_keywords", [])
        self.denylist: Set[str] = set(
            w.lower() for w in config.get("denylist", [])
        )
        self.min_length = config.get("min_token_length", 4)
        self.max_distance = config.get("max_edit_distance", 1)
        self.corrections: List[dict] = []
        self._match_cache: Dict[str, tuple] = {}

    def _best_keyword_match(self, clean: str):
        """Return (best_match, best_dist) for a cleaned token, or (None, _).

        This is the expensive per-token Damerau-Levenshtein scan against the
        keyword list (also tried against a leetspeak-folded form). It depends
        ONLY on `clean`, so results are memoized per unique token: a token
        repeated N times (e.g. "a@b.com" x125k in a bulk payload) costs ONE scan,
        not N — collapsing the O(tokens x keywords) ReDoS-class blowup."""
        cached = self._match_cache.get(clean)
        if cached is not None:
            return cached

        # Candidate forms: the token as-is, plus a leetspeak-folded form when the
        # token contains a leet char (so normal letter-only tokens add no work).
        candidates = [clean]
        if not _LEET_CHARS.isdisjoint(clean):
            folded = clean.translate(_LEET_MAP)
            if folded != clean:
                candidates.append(folded)

        best_match = None
        best_dist = self.max_distance + 1
        for cand in candidates:
            for kw in self.keywords:
                if abs(len(cand) - len(kw)) > self.max_distance:
                    continue
                dist = _damerau_levenshtein(cand, kw)
                if dist <= self.max_distance and dist < best_dist:
                    best_dist = dist
                    best_match = kw

        result = (best_match, best_dist)
        self._match_cache[clean] = result
        return result

    def normalize(self, text: str) -> str:
        """Normalize typos in text. Returns corrected text."""
        self.corrections = []
        # Per-call memo of the expensive DL keyword match, keyed by cleaned token.
        # Dedupes repeated tokens so O(tokens x keywords) becomes
        # O(unique_tokens x keywords) — the ReDoS-class blowup on bulk repeated
        # input collapses to a single DL scan per distinct token.
        self._match_cache: Dict[str, tuple] = {}
        tokens = text.split()
        result = []

        for token in tokens:
            clean = token.strip(".,;:!?\"'()[]{}").lower()
            if len(clean) < self.min_length:
                result.append(token)
                continue

            if clean in self.denylist:
                result.append(token)
                continue

            if clean in self.keywords:
                result.append(token)
                continue

            best_match, best_dist = self._best_keyword_match(clean)

            if best_match:
                corrected = best_match
                if token and token[0].isupper():
                    corrected = corrected.capitalize()
                if token.isupper():
                    corrected = corrected.upper()

                self.corrections.append({
                    "original": token,
                    "corrected": corrected,
                    "distance": best_dist,
                })
                result.append(corrected)
            else:
                result.append(token)

        return " ".join(result)
