"""UTS-46 ToASCII — the one host encoding the core compares in (ruling 3.6).

WHY THIS EXISTS. A destination written ``pаypal.example`` (Cyrillic ``а``) and
one written ``xn--pypal-4ve.example`` are the same DNS name, and neither is
``paypal.example``. Rejecting non-ASCII labels instead would make them not
destinations at all, so a poisoned read naming one could never be recorded and a
call to it would come back ``unresolved`` — which never blocks. That is an
evasion, which is why ruling 3.6 accepts Unicode labels and encodes them.

THE FLAGS, as settled 2026-09-24 (CheckJoiners since 1.22.0):

    Transitional_Processing   false   ß stays ß (xn--zca), as browsers resolve it
    UseSTD3ASCIIRules         false   (the table keeps the STD3 statuses apart)
    CheckHyphens              false
    CheckBidi                 true    RFC 5893, classes from Unicode 13.0
    CheckJoiners              true    CONTEXTJ (RFC 5892 A.1, A.2): Joining_Type
                                      and the viramas, from Unicode 13.0
    VerifyDnsLength           false

``strict=True`` turns on UseSTD3ASCIIRules, CheckHyphens and VerifyDnsLength
too: the settings IdnaTestV2 13.0.0 is computed with, so the conformance test
can check every row of it (tests/value_origin_conformance/test_idna_v2.py).

The data is Unicode 13.0 -- see ``scripts/gen_value_origin_data.py`` for why
that makes the result the same on every supported interpreter. Nothing here
reads the interpreter's case mapping: ``fold`` is the table's.

Returns ``None`` on any failure; never raises.
"""
from __future__ import annotations

import bisect
import unicodedata

from . import _idna_data as _D

_RTL = frozenset({"R", "AL"})
_RTL_ALLOWED = frozenset({"R", "AL", "AN", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"})
_RTL_END = frozenset({"R", "AL", "EN", "AN"})
_LTR_ALLOWED = frozenset({"L", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"})
_LTR_END = frozenset({"L", "EN"})
_ZWNJ, _ZWJ = "\u200c", "\u200d"


def _lookup(starts, values, cp):
    return values[bisect.bisect_right(starts, cp) - 1]


def _status(ch: str) -> str:
    return _lookup(_D.STATUS_STARTS, _D.STATUS_VALUES, ord(ch))


def _bidi(ch: str) -> str:
    return _lookup(_D.BIDI_STARTS, _D.BIDI_VALUES, ord(ch))


def _is_mark(ch: str) -> bool:
    return _lookup(_D.MARK_STARTS, _D.MARK_VALUES, ord(ch))


def _joining(ch: str):
    return _lookup(_D.JOINING_STARTS, _D.JOINING_VALUES, ord(ch))


def assigned(ch: str) -> bool:
    """Unicode 13.0 assigns ``ch`` (ASCII included)."""
    return ord(ch) < 0x80 or _lookup(_D.ASSIGNED_STARTS, _D.ASSIGNED_VALUES, ord(ch))


_PLACEHOLDER = "\ufffd"


def pinned(text: str) -> str:
    """``text`` with every code point Unicode 13.0 leaves unassigned replaced by
    U+FFFD, one for one, so a position in it is the same position in ``text``.
    Every character class the reader decides (a regex's ``\\w`` and ``\\d``,
    ``isalpha``, ``casefold``) is decided on this text and the value is taken from
    ``text``: such a code point is a letter or a digit to a newer interpreter and
    nothing to 3.10, and over the code points 13.0 assigns those classes agree on
    every supported interpreter (V-4)."""
    if text.isascii():
        return text
    odd = {c for c in set(text) if not assigned(c)}
    if not odd:
        return text
    return "".join(_PLACEHOLDER if c in odd else c for c in text)


def pinned_casefold(text: str):
    """(``text`` case-folded, the same with every code point 13.0 leaves
    unassigned as U+FFFD), equally long. Such a code point is not folded: a newer
    interpreter may give it a case pair that 3.10 does not."""
    if text.isascii():
        folded = text.casefold()
        return folded, folded
    odd = {c for c in set(text) if not assigned(c)}
    if not odd:
        folded = text.casefold()
        return folded, folded
    out, scan = [], []
    for c in text:
        if c in odd:
            out.append(c)
            scan.append(_PLACEHOLDER)
        else:
            f = c.casefold()
            out.append(f)
            scan.append(f)
    return "".join(out), "".join(scan)


def _map(s: str, std3: bool = False):
    out = []
    for ch in s:
        st = _status(ch)
        k = st[0]
        if k == "V" or (k == "S" and not std3):
            out.append(ch)
        elif k == "I":
            continue
        elif k == "M" or (k == "T" and not std3):
            out.append(st[1:])
        else:
            return None
    return "".join(out)


def fold(s: str) -> str:
    """``s`` with the table's case mapping and nothing else: each mapped code
    point replaced by its mapping, every other one kept (a disallowed one too).
    The interpreter's ``str.lower`` follows its own Unicode version and applies
    Final_Sigma, so it is never used for a key (V-4)."""
    out = []
    for ch in s:
        st = _status(ch)
        out.append(st[1:] if st[0] in "MT" else ch)
    return "".join(out)


def _contextj_ok(label: str) -> bool:
    """RFC 5892 Appendix A.1 (ZWNJ) and A.2 (ZWJ)."""
    for i, ch in enumerate(label):
        if ch not in (_ZWNJ, _ZWJ):
            continue
        if i > 0 and ord(label[i - 1]) in _D.VIRAMAS:
            continue
        if ch == _ZWJ:
            return False
        j = i - 1
        while j >= 0 and _joining(label[j]) == "T":
            j -= 1
        if j < 0 or _joining(label[j]) not in ("L", "D"):
            return False
        k = i + 1
        while k < len(label) and _joining(label[k]) == "T":
            k += 1
        if k >= len(label) or _joining(label[k]) not in ("R", "D"):
            return False
    return True


def _valid_label(label: str, std3: bool = False, hyphens: bool = False) -> bool:
    """UTS-46 4.1, nontransitional."""
    if not label:
        return True
    if unicodedata.normalize("NFC", label) != label:
        return False                                            # V1
    if hyphens and (label[2:4] == "--" or label[0] == "-" or label[-1] == "-"):
        return False                                            # V2, V3
    if "." in label:
        return False                                            # V4
    if _is_mark(label[0]):
        return False                                            # V5
    for ch in label:
        k = _status(ch)[0]
        if not (k == "V" or (k == "S" and not std3)):
            return False                                        # V6
    return _contextj_ok(label)                                  # V7, CONTEXTJ


def _bidi_ok(labels) -> bool:
    classes = [[_bidi(ch) for ch in lab] for lab in labels]
    if not any(c in ("R", "AL", "AN") for cl in classes for c in cl):
        return True                          # not a Bidi domain name
    for cl in classes:
        if not cl:
            continue
        first = cl[0]
        trimmed = list(cl)
        while trimmed and trimmed[-1] == "NSM":
            trimmed.pop()
        if not trimmed:
            return False
        last = trimmed[-1]
        if first in _RTL:
            if any(c not in _RTL_ALLOWED for c in cl):
                return False
            if last not in _RTL_END:
                return False
            if "EN" in cl and "AN" in cl:
                return False
        elif first == "L":
            if any(c not in _LTR_ALLOWED for c in cl):
                return False
            if last not in _LTR_END:
                return False
        else:
            return False
    return True


def to_unicode_labels(host: str, *, strict: bool = False):
    """UTS-46 steps 1-4: the validated U-labels of ``host``, or None."""
    mapped = _map(host, std3=strict)
    if mapped is None:
        return None
    mapped = unicodedata.normalize("NFC", mapped)
    labels = []
    for lab in mapped.split("."):
        if lab.startswith("xn--"):
            try:
                dec = lab[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                return None
            if not dec or dec.isascii():
                return None
            if not _valid_label(dec, strict, strict):
                return None
            labels.append(dec)
        else:
            if not _valid_label(lab, strict, strict):
                return None
            labels.append(lab)
    if not _bidi_ok(labels):
        return None
    return labels


def to_ascii(host: str, *, strict: bool = False):
    """UTS-46 ToASCII of ``host`` (A-labels, lowercase), or None on failure."""
    try:
        if not isinstance(host, str):
            return None
        labels = to_unicode_labels(host, strict=strict)
        if labels is None:
            return None
        out = []
        for lab in labels:
            if lab.isascii():
                out.append(lab)
            else:
                out.append("xn--" + lab.encode("punycode").decode("ascii"))
        result = ".".join(out)
        if strict:                                              # VerifyDnsLength
            body = out[:-1] if len(out) > 1 and out[-1] == "" else out
            if not 1 <= len(".".join(body)) <= 253 or not all(1 <= len(x) <= 63 for x in body):
                return None
        return result
    except Exception:
        return None
