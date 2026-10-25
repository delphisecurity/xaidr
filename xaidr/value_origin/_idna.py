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

from . import _idna_data as _D
from . import _nameprep_data as _N
from . import _ucd

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
        folded = _ucd.lower(text)              # ASCII: casefold is lower
        return folded, folded
    odd = {c for c in set(text) if not assigned(c)}
    if not odd:
        folded = _ucd.casefold(text)
        return folded, folded
    out, scan = [], []
    for c in text:
        if c in odd:
            out.append(c)
            scan.append(_PLACEHOLDER)
        else:
            f = _ucd.casefold(c)
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
    if _ucd.normalize("NFC", label) != label:
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
    mapped = _ucd.normalize("NFC", mapped)
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
# RFC 3491 nameprep): ``straße`` is ``strasse``. That codec depends on the
# interpreter twice. Its ``stringprep`` table B.3: fixed (3.10.22, 3.11.17, 3.12.15,
# 3.14.8, 3.14.9 and later) it is RFC 3454's; before the fix (3.10.20, 3.11.15,
# 3.12.2, 3.12.13, 3.14.5, measured 2026-10-24) a code point B.3 does not map fell
# back to the interpreter's own ``str.lower``. And its NFKC (``ucd_3_2_0``), which
# takes decompositions from Unicode 3.2 but combining classes and compositions
# from the interpreter's own Unicode, so a pair of code points Unicode 3.2 left
# unassigned composes on 3.14 and not on 3.10. Every one of those encodings is
# written out here from vendored data, the same list on every interpreter: RFC
# 3454's tables (``_nameprep_data``: B.1, B.3, A.1, the prohibited tables and the
# bidi tables D.1 and D.2) and Unicode 16.0 by age (``_ucd``).
_IDNA_DOTS = re.compile("[.\u3002\uff0e\uff61]")

#: The Unicode version of each supported CPython line (3.10 to 3.14): an
#: interpreter of each lowercases and normalizes by it.
_UNICODE = (_ucd.V13, _ucd.V14, _ucd.V15, _ucd.V151, _ucd.V16)


def lower_by_unicode(text: str) -> tuple:
    """``text.lower()`` as an interpreter of each Unicode in ``_UNICODE`` computes
    it, one per version in that order, the same on every interpreter: httpx,
    urllib3 and requests lowercase a host with ``str.lower``, so 3.14 sends
    ``aꟋ.example`` to ``aɤ.example`` and 3.10 refuses it."""
    return tuple(_ucd.lower(text, v) for v in _UNICODE)


def _b3_rfc(ch: str) -> str:
    """Table B.3 as RFC 3454 writes it (CPython's fixed ``stringprep``)."""
    return _N.B3.get(ord(ch), ch)


def _b3_unfixed(v):
    """Table B.3 as an unfixed ``stringprep`` reads it on an interpreter of Unicode
    ``v``: the RFC's mapping where it has one, else ``str.lower`` by ``v``."""
    def b3(ch: str) -> str:
        r = _N.B3.get(ord(ch))
        return r if r is not None else _ucd.lower(ch, v)
    return b3


_ENCODERS = tuple((b3, v) for v in _UNICODE for b3 in (_b3_rfc, _b3_unfixed(v)))


def _nfkc(text: str, v: int) -> str:
    return _ucd.normalize("NFKC", text, v, ucd32=True)


def _b2(ch: str, b3, v: int) -> str:
    """Table B.2 from B.3 and NFKC, as CPython's ``stringprep.map_table_b2``."""
    al = b3(ch)
    b = _nfkc(al, v)
    c = _nfkc("".join(b3(x) for x in b), v)
    return c if b != c else al


def _nameprep(label: str, b3, v: int) -> str:
    """RFC 3491 nameprep, as CPython's ``encodings.idna.nameprep`` on an
    interpreter of Unicode ``v``; raises UnicodeError where the codec does."""
    label = "".join(_b2(ch, b3, v) for ch in label if ord(ch) not in _N.B1)
    label = _nfkc(label, v)
    if any(_ucd.prohibited_3_2(ch) for ch in label):
        raise UnicodeError("prohibited")
    ral = [_ucd.randal_3_2(ch) for ch in label]
    if any(ral):
        if any(_ucd.l_3_2(ch) for ch in label):
            raise UnicodeError("bidi 2")
        if not ral[0] or not ral[-1]:
            raise UnicodeError("bidi 3")
    return label


def _to_ascii_2003(label: str, b3, v: int) -> str:
    """RFC 3490 ToASCII of one label, as CPython's ``encodings.idna.ToASCII``."""
    if label.isascii():
        if 0 < len(label) < 64:
            return label
        raise UnicodeError("label empty or too long")
    label = _nameprep(label, b3, v)
    if label.isascii():
        if 0 < len(label) < 64:
            return label
        raise UnicodeError("label empty or too long")
    if label.startswith("xn--"):
        raise UnicodeError("ACE prefix")
    out = "xn--" + label.encode("punycode").decode("ascii")
    if len(out) < 64:
        return out
    raise UnicodeError("label too long")


def idna2003(host: str) -> list:
    """The names the socket layer resolves for a non-ASCII ``host``: its IDNA 2003
    encoding as every supported interpreter computes it, fixed or not, by its own
    Unicode (3.10 to 3.14), RFC 3454's table B.3 first. The same list on every
    interpreter. Empty where none encodes; an ASCII host is sent as it is and is
    not this function's."""
    out = []
    labels = _IDNA_DOTS.split(host)
    trailing = "." if labels and not labels[-1] else ""
    if trailing:
        del labels[-1]
    for b3, v in _ENCODERS:
        try:
            name = ".".join(_to_ascii_2003(lab, b3, v) for lab in labels) + trailing
        except (UnicodeError, ValueError):
            continue
        if name and name not in out:
            out.append(name)
    return out
