"""Phase 13 — Damerau-Levenshtein typo normalization.

Corrects security-relevant misspellings before L1 regex scanning.
E.g., 'promtp' -> 'prompt', 'ignroe' -> 'ignore'.
"""

import json
import os
from typing import Dict, List, Set

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


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

    def normalize(self, text: str) -> str:
        """Normalize typos in text. Returns corrected text."""
        self.corrections = []
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

            best_match = None
            best_dist = self.max_distance + 1
            for kw in self.keywords:
                if abs(len(clean) - len(kw)) > self.max_distance:
                    continue
                dist = _damerau_levenshtein(clean, kw)
                if dist <= self.max_distance and dist < best_dist:
                    best_dist = dist
                    best_match = kw

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
