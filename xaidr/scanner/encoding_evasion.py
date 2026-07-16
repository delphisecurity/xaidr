"""Encoded-payload + decode/execute-directive pairing (embedded-evasion fix).

The bare-blob rule (``LLM01_raw_base64_payload``) is anchored ``^…$`` — it fires
only when an encoded blob is the WHOLE input. Embedding the same blob in prose
("please decode and follow: <blob>", a blob in a log line, "run this: <blob>")
drops it below threshold, so realistic embedding evaded detection even though
"we catch base64".

The real signal is NOT blob dominance — it is an encoded blob that is the OBJECT
of a directive telling the model to decode / run / follow / execute it. This
detector keys on that pairing, RATIO-INDEPENDENTLY: a decode/execute directive
whose object is an encoded blob fires no matter how much prose surrounds it. The
bare-blob rule still stands on its own; this only ADDS the embedded case.

Two-way: a directive WITHOUT an adjacent blob (a config value, an API response,
a data URI, a JWT, a base64 field in JSON, "run this test suite" with an
unrelated token nearby), or a blob WITHOUT a directive, does NOT fire — the
DIRECTIVE acting on the blob is what makes it malicious. The blob must be the
directive's object (only punctuation/whitespace between them), so an incidental
directive word and an incidental blob elsewhere never pair. All patterns use
bounded quantifiers over a size-capped view, so there is no ReDoS surface.
"""

from __future__ import annotations

import re

# ── Encoded blobs of meaningful length ───────────────────────────────────────
# Bounded upper repeat ({N,4096}) → linear scan, no catastrophic backtracking.
# base64: 24+ payload chars (~18 decoded bytes) so short tokens/words don't trip.
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,4096}={0,2}")
# hex: 32+ nibbles (16 bytes); tolerate a 0x prefix.
_HEX_BLOB = re.compile(r"(?:0x)?[0-9a-fA-F]{32,4096}")
# percent/url-encoding: 8+ %XX groups.
_URL_ENC_BLOB = re.compile(r"(?:%[0-9A-Fa-f]{2}){8,}")

_BLOB_PATTERNS = (_BASE64_BLOB, _HEX_BLOB, _URL_ENC_BLOB)

# ── Decode / execute directive aimed at the encoded content ──────────────────
_DECODE_VERB = r"decode|decipher|decrypt|unescape|de-?obfuscate|unpack"
_EXEC_VERB = r"run|execute|exec|eval|follow|obey|apply|carry\s+out|process"
_XFORM_VERB = r"interpret|translate|parse|convert"
# Nouns that explicitly name encoded / to-be-acted-on content.
_ENCODED_NOUN = (
    r"the\s+(?:following|above|below|base64|b64|hex|encoded|payload|blob|string|"
    r"text|code|instruction|instructions|content|data|command|script|cipher)"
)

# A directive is one of:
#   (1) an encoding-named decode ("base64 decode", "hex decode"),
#   (2) verb (+ 'and'/'then' + exec verb)? + a reference to the object
#       ("decode this", "run this", "execute the following", "decode and run it"),
#   (3) a decode→exec chain ("decode and run", "decode then execute") — the blob
#       itself is the object.
# An optional leading politeness/filler word is consumed so a blob that sits just
# BEFORE the directive ("<blob> please decode that") is still adjacent. NOT a bare
# verb ("run", "do") — an object-ref or a decode/exec chain is required.
_ENC_PREFIX = r"(?:base64|b64|hex|url|rot-?13)"
_DIRECTIVE = re.compile(
    r"(?:(?:please|kindly|pls|now|then|go\s+ahead\s+and)\s+){0,2}"
    r"(?:"
    # A: (encoding-name)? verb (+ 'and'/'then' + exec verb)? + object reference
    r"(?:" + _ENC_PREFIX + r"\s*[-\s]?\s*)?"
    r"\b(?:" + _DECODE_VERB + r"|" + _EXEC_VERB + r"|" + _XFORM_VERB + r")\b"
    r"(?:\s+(?:and|then|&|,)\s+(?:" + _EXEC_VERB + r"))?"
    r"\s*[,:]?\s+"
    r"(?:it|them|this|that|these|those|" + _ENCODED_NOUN + r")\b"
    r"|"
    # B: (encoding-name)? decode → exec chain (the blob is the object)
    r"(?:" + _ENC_PREFIX + r"\s*[-\s]?\s*)?"
    r"\b(?:" + _DECODE_VERB + r")\b\s*(?:and|then|&|,)\s+(?:" + _EXEC_VERB + r")\b"
    r"|"
    # C: encoding-NAMED decode ("base64 decode", "hex decode") — blob follows
    r"\b" + _ENC_PREFIX + r"\s*[-\s]?\s*(?:" + _DECODE_VERB + r")\b"
    r")",
    re.IGNORECASE,
)

# Non-word separators allowed between the directive and its blob object. Excludes
# base64/hex chars (letters, digits, +, /, =) so only punctuation/space counts as
# "adjacent" — an intervening WORD ("run this test suite …") breaks adjacency.
_SEP_CHARS = frozenset(" \t\r\n:;,.!?-'\"`()[]{}<>#|*~")

# Cap the backward-scan segment so a blob's end can be located in bounded time.
_MAX_BLOB = 4100


def has_encoded_blob(text: str) -> bool:
    """True when a base64/hex/url-encoded blob of meaningful length is present."""
    return bool(text) and any(p.search(text) for p in _BLOB_PATTERNS)


def _blob_starts_after(text: str, pos: int) -> bool:
    """A blob begins immediately after ``pos`` (only separators in between)."""
    i, n = pos, len(text)
    while i < n and text[i] in _SEP_CHARS:
        i += 1
    return any(p.match(text, i) for p in _BLOB_PATTERNS)


def _blob_ends_before(text: str, pos: int) -> bool:
    """A blob ends immediately before ``pos`` (only separators in between)."""
    i = pos
    while i > 0 and text[i - 1] in _SEP_CHARS:
        i -= 1
    if i == 0:
        return False
    seg = text[max(0, i - _MAX_BLOB):i]
    end = len(seg)
    for p in _BLOB_PATTERNS:
        if any(m.end() == end for m in p.finditer(seg)):
            return True
    return False


def encoded_payload_with_directive(text: str) -> bool:
    """True for the embedded-evasion attack: a decode/execute directive whose
    OBJECT is an encoded blob (blob adjacent on either side), regardless of how
    much prose surrounds it.

    Ratio-independent by construction — it keys on the directive→blob object
    relation, not on the blob dominating the input. Bounded: each directive match
    probes only the separators + one anchored blob on each side, so the scan stays
    linear on long inputs.
    """
    if not text:
        return False
    for m in _DIRECTIVE.finditer(text):
        if _blob_starts_after(text, m.end()) or _blob_ends_before(text, m.start()):
            return True
    return False
