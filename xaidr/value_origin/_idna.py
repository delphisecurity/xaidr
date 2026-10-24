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
import re
import unicodedata

from . import _idna_data as _D
from . import _nameprep_data as _N

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


# ── IDNA 2003: the socket layer's encoding of a non-ASCII host ───────────────
# urllib.request and http.client hand a str host to the socket layer, which
# encodes a non-ASCII one with the stdlib ``idna`` codec (RFC 3490 ToASCII over
# RFC 3491 nameprep): ``straße`` is ``strasse``. That codec maps with the interpreter's
# ``stringprep``. Fixed (3.10.22, 3.12.15, 3.14.9 and later), its table B.3 is RFC
# 3454's. Before the fix (3.10.20, 3.11.15, 3.12.2, 3.12.13 and 3.14.5, measured
# 2026-10-24) a code point B.3 does not map fell back to the interpreter's own
# ``str.lower``, so each unfixed interpreter encodes by its own Unicode version:
# ``Ⴜ`` (U+10BC) is lowercased by 3.12.2 and kept by 3.12.15, and a code point
# Unicode 16.0 assigned is lowercased by 3.14.5 alone. Every one of those encodings
# is written out here from fixed data, so the readings are the same on every
# interpreter: RFC 3454's tables and Unicode 16.0's lowercase with each code
# point's age (``_nameprep_data``), and Unicode 3.2 (``ucd_3_2_0``, frozen in every
# interpreter) for NFKC, the prohibited code points and the bidi rule.
_U32 = unicodedata.ucd_3_2_0
_IDNA_DOTS = re.compile("[.。．｡]")
_C22 = frozenset([1757, 1807, 6158, 8204, 8205, 8232, 8233, 65279] + list(range(8288, 8292))
                 + list(range(8298, 8304)) + list(range(65529, 65533))
                 + list(range(119155, 119163)))
_C6 = frozenset(range(65529, 65534))
_C7 = frozenset(range(12272, 12284))
_C8 = frozenset([832, 833, 8206, 8207] + list(range(8234, 8239)) + list(range(8298, 8304)))
_C9 = frozenset([917505] + list(range(917536, 917632)))


def _b3_rfc(ch: str) -> str:
    """Table B.3 as RFC 3454 writes it (CPython's fixed ``stringprep``)."""
    return _N.B3.get(ord(ch), ch)


#: The Unicode version of each supported CPython line (3.10 to 3.14): an unfixed
#: release of each lowercases by it.
_UNFIXED_UNICODE = ((13, 0), (14, 0), (15, 0), (15, 1), (16, 0))


def _b3_unfixed(unicode):
    """Table B.3 as an unfixed ``stringprep`` reads it on an interpreter whose
    Unicode is ``unicode``: the RFC's mapping where it has one, else ``str.lower``
    by that Unicode, which is Unicode 16.0's lowercase for a code point assigned by
    then and the code point itself otherwise (a lowercase does not change once
    assigned)."""
    def b3(ch: str) -> str:
        r = _N.B3.get(ord(ch))
        if r is not None:
            return r
        low = _N.LOWER.get(ord(ch))
        return low[0] if low is not None and low[1] <= unicode else ch
    return b3


_B3_UNFIXED = tuple((u, _b3_unfixed(u)) for u in _UNFIXED_UNICODE)


def _b2(ch: str, b3) -> str:
    """Table B.2 from B.3 and NFKC, as CPython's ``stringprep.map_table_b2``."""
    al = b3(ch)
    b = _U32.normalize("NFKC", al)
    c = _U32.normalize("NFKC", "".join(b3(x) for x in b))
    return c if b != c else al


def _prohibited(ch: str) -> bool:
    """RFC 3491 section 5: tables C.1.2, C.2.2, C.3 to C.9."""
    c, cat = ord(ch), _U32.category(ch)
    return ((cat == "Zs" and ch != " ") or (c >= 128 and (cat == "Cc" or c in _C22))
            or cat in ("Co", "Cs") or 0xFDD0 <= c < 0xFDF0 or (c & 0xFFFF) >= 0xFFFE
            or c in _C6 or c in _C7 or c in _C8 or c in _C9)


def _nameprep(label: str, b3) -> str:
    """RFC 3491 nameprep, as CPython's ``encodings.idna.nameprep``; raises
    UnicodeError where the codec does."""
    label = "".join(_b2(ch, b3) for ch in label if ord(ch) not in _N.B1)
    label = _U32.normalize("NFKC", label)
    if any(_prohibited(ch) for ch in label):
        raise UnicodeError("prohibited")
    ral = [_U32.bidirectional(ch) in ("R", "AL") for ch in label]
    if any(ral):
        if any(_U32.bidirectional(ch) == "L" for ch in label):
            raise UnicodeError("bidi 2")
        if not ral[0] or not ral[-1]:
            raise UnicodeError("bidi 3")
    return label


def _to_ascii_2003(label: str, b3) -> str:
    """RFC 3490 ToASCII of one label, as CPython's ``encodings.idna.ToASCII``."""
    if label.isascii():
        if 0 < len(label) < 64:
            return label
        raise UnicodeError("label empty or too long")
    label = _nameprep(label, b3)
    if label.isascii():
        if 0 < len(label) < 64:
            return label
        raise UnicodeError("label empty or too long")
    if label.lower().startswith("xn--"):
        raise UnicodeError("ACE prefix")
    out = "xn--" + label.encode("punycode").decode("ascii")
    if len(out) < 64:
        return out
    raise UnicodeError("label too long")


def _variants(host: str):
    """RFC 3454's B.3, then each unfixed interpreter's whose encoding of ``host``
    can differ from the one before it: only a code point a newer Unicode assigned
    and lowercases tells two of them apart."""
    yield _b3_rfc
    seen = set()
    for unicode, b3 in _B3_UNFIXED:
        key = frozenset(c for c in host
                        if ord(c) in _N.LOWER and _N.LOWER[ord(c)][1] <= unicode)
        if key not in seen:
            seen.add(key)
            yield b3


def idna2003(host: str) -> list:
    """The names the socket layer resolves for a non-ASCII ``host``: its IDNA 2003
    encoding with RFC 3454's table B.3 (a fixed interpreter's), and, where they
    differ, with the table each unfixed interpreter computes (3.10 to 3.14, each by
    its own Unicode). The same list on every interpreter. Empty where none encodes;
    an ASCII host is sent as it is and is not this function's."""
    out = []
    for b3 in _variants(host):
        try:
            labels = _IDNA_DOTS.split(host)
            trailing = "." if labels and not labels[-1] else ""
            if trailing:
                del labels[-1]
            name = ".".join(_to_ascii_2003(lab, b3) for lab in labels) + trailing
        except (UnicodeError, ValueError):
            continue
        if name and name not in out:
            out.append(name)
    return out
