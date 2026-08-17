"""Phase 13 — Damerau-Levenshtein typo normalization.

Corrects security-relevant misspellings before L1 regex scanning.
E.g., 'promtp' -> 'prompt', 'ignroe' -> 'ignore'.
"""

import json
import os
import re
import unicodedata
from typing import Dict, List, Set

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")

# --- Unicode pre-pass: bounded confusable (homoglyph) skeleton ----------------
# TR39-style map of the common Cyrillic/Greek glyphs that are VISUALLY IDENTICAL
# to a lowercase ASCII letter, folded to that letter. Deliberately SMALL — a real
# non-Latin word uses many non-confusable letters and will not collapse into an
# English keyword, so legitimate text is not wholesale folded (verified against a
# benign-Cyrillic control in the corpus). Not an exhaustive transliteration.
_CONFUSABLES = {
    # Cyrillic -> Latin (vowels + strong consonant look-alikes)
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ѡ": "w",
    # Cyrillic consonant homoglyphs (BS5): kept to glyphs genuinely confusable with
    # a Latin letter, so benign Cyrillic text (which uses many NON-confusable
    # letters) never collapses into an English keyword.
    "г": "r", "к": "k", "т": "t", "в": "b", "м": "m", "ё": "e",
    # Greek -> Latin
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ι": "i", "υ": "u", "ν": "v",
    "χ": "x", "κ": "k", "τ": "t", "ϲ": "c",
}
_CONFUSABLE_MAP = str.maketrans(_CONFUSABLES)

# A run of single letters each joined by a single NON-SPACE separator (`. _ -`),
# e.g. "i.g.n.o.r.e" / "i_g_n_o_r_e". Space is handled separately (by joining
# single-letter WHITESPACE tokens) because normal words are space-separated, so a
# space in the run class would absorb the neighbouring word's letters. Linear-time:
# the two classes are disjoint and adjacent — no nested-quantifier backtracking.
_SEP_RUN_RE = re.compile(r"[A-Za-z](?:[._\-][A-Za-z])+")

# A spaced-out run: 3+ single letters each separated by a SINGLE space
# ("i g n o r e", "a l l"). A larger gap (2+ spaces) or a multi-letter token bounds
# the run, so word boundaries in "i g n o r e  a l l" (double space) are preserved
# and a normal sentence (multi-letter words) never matches. A benign initialism
# ("U S A", "F B I") does collapse, but only spells a KEYWORD when the letters
# already were one — collapse cannot manufacture a false positive from ordinary
# text (a non-keyword collapse is inert downstream). Linear: each " [A-Za-z]"
# consumes 2 chars, no nested quantifier -> no ReDoS.
_SPACED_RUN_RE = re.compile(r"(?<![A-Za-z])[A-Za-z](?: [A-Za-z]){2,}(?![A-Za-z])")

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
            cfg = json.load(f)
    except FileNotFoundError:
        return {"all_keywords": [], "denylist": []}
    except Exception as e:
        # Corrupt/unreadable asset must not crash `import xaidr` — degrade to the
        # empty config (normalization becomes a no-op; detection still runs).
        print(f"[xaidr] Warning: typo-keywords.json failed to load ({e}); normalization disabled")
        return {"all_keywords": [], "denylist": []}
    return cfg if isinstance(cfg, dict) else {"all_keywords": [], "denylist": []}


def _osa_within_1(a: str, b: str) -> int:
    """Exact OSA distance when it is 0 or 1; otherwise 2 (meaning "more than 1").

    The full matrix in ``_damerau_levenshtein`` computes a number this module
    never reads. ``max_edit_distance`` is 1, so ``_best_keyword_match`` acts on
    0 and 1 and treats everything else as "no match". The exact value of a
    distance-7 pair is dead weight, and it was the single most expensive thing
    in a scan (measured: 1.19 s of tottime over 83,200 calls on a 347 B input,
    ~58% of that scan).

    At a threshold of 1 the matrix is unnecessary, because the strings that
    reach distance 1 are enumerable directly:

      * equal length: zero mismatches (0), exactly one mismatch (substitution),
        or exactly two ADJACENT mismatches that are each other's swap
        (transposition)
      * lengths differing by one: the shorter is the longer with one character
        deleted
      * lengths differing by more: unreachable

    That is O(n) with no allocation, against O(n*m) with a tuple-keyed dict.
    Verified equivalent to the matrix (clamped at the threshold) over 447,307
    pairs: every distance-1 perturbation of every keyword, two-substitution
    perturbations, keyword x keyword, an exhaustive sweep of a 3-letter alphabet
    to length 5, and 300k random fuzz pairs.

    Callers MUST hold ``max_distance == 1``; ``_best_keyword_match`` falls back
    to the general matrix otherwise, so a re-tuned config cannot silently get a
    wrong answer from this.
    """
    la, lb = len(a), len(b)
    if la == lb:
        i = 0
        while i < la and a[i] == b[i]:
            i += 1
        if i == la:
            return 0
        j = i + 1
        while j < la and a[j] == b[j]:
            j += 1
        if j == la:
            return 1
        if j == i + 1 and a[i] == b[i + 1] and a[i + 1] == b[i]:
            k = i + 2
            while k < la and a[k] == b[k]:
                k += 1
            if k == la:
                return 1
        return 2
    if la > lb:
        a, b, la, lb = b, a, lb, la
    if lb - la != 1:
        return 2
    i = 0
    while i < la and a[i] == b[i]:
        i += 1
    return 1 if a[i:] == b[i + 1:] else 2


def _damerau_levenshtein(s1: str, s2: str) -> int:
    """Damerau-Levenshtein distance (transpositions count as 1 edit).

    Retained as the general implementation and as the reference the fast path
    is verified against. Live scans take the ``_osa_within_1`` path; this runs
    only when ``max_edit_distance`` is configured above 1.
    """
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
        # Keyword set + longest-keyword length: used by the bounded separator
        # collapse to gate (only reconstruct a real keyword) and to cap the
        # prefix search to keyword-length (keeps it O(1) regardless of run size).
        self._kw_set: Set[str] = set(self.keywords)
        self._max_kw_len: int = max((len(k) for k in self.keywords), default=0)
        # Candidate keywords per TOKEN LENGTH, precomputed. At edit distance d
        # only keywords whose length is within d of the token can match, so the
        # scan walks this list instead of walking all 32 and rejecting most on a
        # length check. That check was already there (and is worth 2.8x on its
        # own); this removes the loop iterations it was rejecting.
        #
        # Each list keeps the ORIGINAL keyword order. `_best_keyword_match`
        # takes the first keyword achieving the best distance, so bucketing by
        # length and visiting the buckets in length order would change which
        # keyword wins a tie. Same set, same order, fewer iterations.
        self._kw_by_token_len: Dict[int, tuple] = {}
        if self.keywords:
            lo = min(len(k) for k in self.keywords) - self.max_distance
            hi = self._max_kw_len + self.max_distance
            for _n in range(max(0, lo), hi + 1):
                self._kw_by_token_len[_n] = tuple(
                    k for k in self.keywords
                    if abs(len(k) - _n) <= self.max_distance
                )

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

        max_d = self.max_distance
        best_match = None
        best_dist = max_d + 1
        if max_d == 1:
            # Shipped configuration. Only length-plausible keywords, in the
            # original order, each decided in O(n) (see _osa_within_1).
            # _osa_within_1 returns 0, 1 or 2, and best_dist starts at 2, so
            # `dist < best_dist` is exactly the old `dist <= max_d and
            # dist < best_dist`.
            for cand in candidates:
                for kw in self._kw_by_token_len.get(len(cand), ()):
                    dist = _osa_within_1(cand, kw)
                    if dist < best_dist:
                        best_dist = dist
                        best_match = kw
                        if dist == 0:
                            # An exact hit; keywords are distinct, so nothing
                            # later can beat it and nothing can tie it.
                            break
        else:
            # max_edit_distance retuned above 1: the O(n) decision procedure
            # does not generalise, so fall back to the full matrix.
            for cand in candidates:
                for kw in self.keywords:
                    if abs(len(cand) - len(kw)) > max_d:
                        continue
                    dist = _damerau_levenshtein(cand, kw)
                    if dist <= max_d and dist < best_dist:
                        best_dist = dist
                        best_match = kw

        result = (best_match, best_dist)
        self._match_cache[clean] = result
        return result

    def _keyword_form(self, s: str) -> str:
        """Return the keyword that ``s`` reconstructs (exact, or leet-folded
        exact), else None. Used to GATE separator collapse — collapse only when
        the letters spell a real security keyword, never generic punctuation."""
        if s in self._kw_set:
            return s
        if not _LEET_CHARS.isdisjoint(s):
            folded = s.translate(_LEET_MAP)
            if folded in self._kw_set:
                return folded
        return None

    def _collapse_sep_run(self, m) -> str:
        """Collapse one NON-SPACE separated-letter run IFF it exactly spells a
        keyword. Keyword-gated + conservative: benign runs like "e.g." / "U.S.A."
        / "a-b-c" (letters that are not a keyword) are left UNCHANGED. Because the
        separators are non-space, a run cannot absorb a neighbouring word, so an
        exact full-letter check is sufficient (no prefix gymnastics needed)."""
        letters = "".join(c for c in m.group(0) if c.isalpha()).lower()
        kw = self._keyword_form(letters)
        return kw if kw is not None else m.group(0)

    def _join_single_letter_runs(self, text: str) -> str:
        """Join maximal runs of single-letter WHITESPACE tokens when they spell a
        keyword ("i g n o r e" -> "ignore"). A real word is 2+ contiguous letters,
        so it bounds the run and is never absorbed; runs that do not spell a
        keyword (e.g. "a b c", "J. R. R.") are emitted unchanged. Downstream
        normalize() re-splits on whitespace anyway, so token rejoin is safe."""
        tokens = text.split()
        out: List[str] = []
        i, n = 0, len(tokens)
        while i < n:
            if len(tokens[i]) == 1 and tokens[i].isalpha():
                j = i
                while j < n and len(tokens[j]) == 1 and tokens[j].isalpha():
                    j += 1
                if j - i >= self.min_length:
                    kw = self._keyword_form(
                        "".join(tokens[i:j]).lower()
                    )
                    if kw is not None:
                        out.append(kw)
                        i = j
                        continue
                out.extend(tokens[i:j])
                i = j
            else:
                out.append(tokens[i])
                i += 1
        return " ".join(out)

    def _unicode_prepass(self, text: str) -> str:
        """De-obfuscate the scanned view BEFORE typo folding, in order:
        (1) strip zero-width/format (Cf) chars, (2) NFKC (full-width & compat
        folds), (3) bounded homoglyph/confusable skeleton, (4) keyword-gated
        non-space separator collapse, (5) keyword-gated single-letter-token join
        (the space-separated case). Output feeds the existing typo path unchanged.
        Never raises; empty/non-str is returned as-is."""
        if not text:
            return text
        # 1. strip format/zero-width chars (U+200B-200D, U+FEFF, soft hyphen, …)
        text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
        # 2. NFKC — folds full-width and many compatibility variants to Latin
        text = unicodedata.normalize("NFKC", text)
        # 2b. strip combining diacritics on the SCANNED copy (é->e, í->i) so
        #     accent-substituted keywords ("ígnóré") fold to the base-Latin form.
        #     NFKD decomposes base+mark; dropping the Mn (combining) marks leaves
        #     the base letter. Benign accented words (café, José) fold to non-
        #     keywords, so this never manufactures a false positive.
        text = "".join(
            ch for ch in unicodedata.normalize("NFKD", text)
            if unicodedata.category(ch) != "Mn"
        )
        # 3. bounded confusable/homoglyph skeleton (Cyrillic/Greek look-alikes)
        text = text.translate(_CONFUSABLE_MAP)
        # 3b. collapse spaced-out single-letter runs ("i g n o r e" -> "ignore"),
        #     preserving 2+ space word boundaries. Structural (a 4+ single-letter
        #     run is the obfuscation signal); ordinary prose has multi-letter words
        #     and never matches.
        text = _SPACED_RUN_RE.sub(lambda m: m.group(0).replace(" ", ""), text)
        # 4. keyword-gated NON-SPACE separator collapse (i.g.n.o.r.e -> ignore)
        text = _SEP_RUN_RE.sub(self._collapse_sep_run, text)
        # 5. keyword-gated single-letter whitespace-token join (i g n o r e -> ignore)
        text = self._join_single_letter_runs(text)
        return text

    def normalize(self, text: str) -> str:
        """Normalize typos in text. Returns corrected text."""
        self.corrections = []
        # Unicode de-obfuscation pre-pass (Cf-strip -> NFKC -> confusables ->
        # bounded separator collapse) BEFORE the existing typo/leetspeak folding.
        text = self._unicode_prepass(text)
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

            # _kw_set, not the keywords LIST: same membership, O(1) instead of
            # a 32-element scan on every token that reaches here.
            if clean in self._kw_set:
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
