"""UTS-46 ToASCII — the one host encoding the core compares in (ruling 3.6).

WHY THIS EXISTS. A destination written ``pаypal.example`` (Cyrillic ``а``) and
one written ``xn--pypal-4ve.example`` are the same DNS name, and neither is
``paypal.example``. Rejecting non-ASCII labels instead would make them not
destinations at all, so a poisoned read naming one could never be recorded and a
call to it would come back ``unresolved`` — which never blocks. That is an
evasion, which is why ruling 3.6 accepts Unicode labels and encodes them.

THE FLAGS, as settled 2026-09-24:

    Transitional_Processing   false   ß stays ß (xn--zca), as browsers resolve it
    UseSTD3ASCIIRules         false   (folded into the generated table)
    CheckHyphens              false
    CheckBidi                 true    RFC 5893, classes from Unicode 13.0
    CheckJoiners              STRICT  any ZWJ/ZWNJ fails: CONTEXTJ needs
                                      Joining_Type, which the stdlib lacks
    VerifyDnsLength           false

The mapping table is Unicode 13.0 — see ``scripts/gen_value_origin_data.py`` for
why that makes the result the same on every supported interpreter.

Returns ``None`` on any failure; never raises.
"""
from __future__ import annotations

import bisect
import unicodedata

from . import _idna_data as _D

_ZW_JOINERS = frozenset("‌‍")
_RTL = frozenset({"R", "AL"})
_RTL_ALLOWED = frozenset({"R", "AL", "AN", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"})
_RTL_END = frozenset({"R", "AL", "EN", "AN"})
_LTR_ALLOWED = frozenset({"L", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"})
_LTR_END = frozenset({"L", "EN"})


def _lookup(starts, values, cp):
    return values[bisect.bisect_right(starts, cp) - 1]


def _status(ch: str) -> str:
    return _lookup(_D.STATUS_STARTS, _D.STATUS_VALUES, ord(ch))


def _bidi(ch: str) -> str:
    return _lookup(_D.BIDI_STARTS, _D.BIDI_VALUES, ord(ch))


def _is_mark(ch: str) -> bool:
    return _lookup(_D.MARK_STARTS, _D.MARK_VALUES, ord(ch))


def _map(s: str):
    out = []
    for ch in s:
        st = _status(ch)
        if st == "V":
            out.append(ch)
        elif st == "I":
            continue
        elif st[0] == "M":
            out.append(st[1:])
        else:
            return None
    return "".join(out)


def _valid_label(label: str) -> bool:
    if not label:
        return True
    if unicodedata.normalize("NFC", label) != label:
        return False
    if "." in label:
        return False
    if _is_mark(label[0]):
        return False
    for ch in label:
        if ch in _ZW_JOINERS:
            return False
        if _status(ch) != "V":
            return False
    return True


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


def to_unicode_labels(host: str):
    """UTS-46 steps 1-4: the validated U-labels of ``host``, or None."""
    mapped = _map(host)
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
            if not _valid_label(dec):
                return None
            labels.append(dec)
        else:
            if not _valid_label(lab):
                return None
            labels.append(lab)
    if not _bidi_ok(labels):
        return None
    return labels


def to_ascii(host: str):
    """UTS-46 ToASCII of ``host`` (A-labels, lowercase), or None on failure."""
    try:
        if not isinstance(host, str):
            return None
        labels = to_unicode_labels(host)
        if labels is None:
            return None
        out = []
        for lab in labels:
            if lab.isascii():
                out.append(lab)
            else:
                out.append("xn--" + lab.encode("punycode").decode("ascii"))
        return ".".join(out)
    except Exception:
        return None
