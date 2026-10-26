"""Unicode properties from vendored Unicode 16.0 data, asked as a given version has them.

No reading consults the running interpreter's Unicode database. Every character
class, case mapping and normalization a reading decides comes from
``_ucd_data`` (generated from Unicode 16.0's files, vendored in
tests/published_vectors/upstream/) and each code point's age. A property is
asked "as Unicode V has it": a code point V does not assign has no property in
V. The core's own decisions are made as Unicode 13.0 makes them (``V13``, the
oldest supported interpreter's version, ruling 3.6), the same on every
interpreter; a reading that models a client on another interpreter asks that
interpreter's version.

The definitions are Python's (CPython's makeunicodedata): ``isspace`` is
category Zs or bidi WS, B or S; ``isalpha`` is category L*; ``isdecimal``,
``isdigit`` and ``isnumeric`` are UnicodeData's fields 6, 7 and 8; ``lower`` maps
U+03A3 by Final_Sigma; the normalizer is CPython's ``unicodedata`` algorithm,
including the ``ucd_3_2_0`` database its IDNA 2003 codec normalizes with, which
takes decompositions from Unicode 3.2 and combining classes and compositions from
the interpreter's own version (``normalize(..., ucd32=True)``).
"""
from __future__ import annotations

import bisect
import re as _re

from . import _nameprep_data as _N
from . import _ucd_data as _D

V13, V14, V15, V151, V16 = 1300, 1400, 1500, 1501, 1600

_AGE_STARTS = [a for a, _, _ in _D.AGE]
_AGE_ENDS = [b for _, b, _ in _D.AGE]
_AGE_VALUES = [v for _, _, v in _D.AGE]


def age(cp: int) -> int:
    """The version that assigned ``cp`` (major * 100 + minor), 0 if none."""
    i = bisect.bisect_right(_AGE_STARTS, cp) - 1
    return _AGE_VALUES[i] if i >= 0 and cp <= _AGE_ENDS[i] else 0


def assigned(cp: int, v: int = V13) -> bool:
    a = age(cp)
    return 0 < a <= v


class _Ranges:
    __slots__ = ("starts", "ends")

    def __init__(self, ranges):
        self.starts = [a for a, _ in ranges]
        self.ends = [b for _, b in ranges]

    def __contains__(self, cp: int) -> bool:
        i = bisect.bisect_right(self.starts, cp) - 1
        return i >= 0 and cp <= self.ends[i]


_ALPHA, _SPACE = _Ranges(_D.ALPHA), _Ranges(_D.SPACE)
_DECIMAL, _DIGIT, _NUMERIC = _Ranges(_D.DECIMAL), _Ranges(_D.DIGIT), _Ranges(_D.NUMERIC)
_CASED, _CASE_IGNORABLE = _Ranges(_D.CASED), _Ranges(_D.CASE_IGNORABLE)
_COMPAT = _Ranges(_D.COMPAT)
_A1, _PROHIBITED = _Ranges(_N.A1), _Ranges(_N.PROHIBITED)
_D1, _D2 = _Ranges(_N.D1), _Ranges(_N.D2)


def _has(prop: _Ranges, ch: str, v: int) -> bool:
    cp = ord(ch)
    return cp in prop and assigned(cp, v)


def isspace(ch: str, v: int = V13) -> bool:
    return _has(_SPACE, ch, v)


def isalpha(ch: str, v: int = V13) -> bool:
    return _has(_ALPHA, ch, v)


def isdecimal(ch: str, v: int = V13) -> bool:
    return _has(_DECIMAL, ch, v)


def isdigit(ch: str, v: int = V13) -> bool:
    return _has(_DIGIT, ch, v)


def isalnum(ch: str, v: int = V13) -> bool:
    """CPython's: alphabetic, decimal, digit or numeric. Numeric is UnicodeData's
    field 8 only; CPython adds Unihan's values for some CJK ideographs, every one
    of which is alphabetic, so ``isalnum`` agrees (tests/test_value_origin_ucd.py)."""
    cp = ord(ch)
    return (assigned(cp, v) and (cp in _ALPHA or cp in _DECIMAL or cp in _DIGIT
                                 or cp in _NUMERIC))


def any_space(text: str, v: int = V13) -> bool:
    return any(_has(_SPACE, c, v) for c in text)


#: Every whitespace code point (it is the same set in every version from 6.3 on).
WHITESPACE = "".join(chr(cp) for a, b in _D.SPACE for cp in range(a, b + 1))


def strip(text: str, chars: str = WHITESPACE) -> str:
    """``str.strip()`` with Unicode 16.0's whitespace."""
    return text.strip(chars)


def split(text: str) -> list:
    """``str.split()`` with Unicode 16.0's whitespace."""
    out, cur = [], []
    for c in text:
        if c in _WS_SET:
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur))
    return out


_WS_SET = frozenset(WHITESPACE)


# ── regular-expression classes ───────────────────────────────────────────────
def _union(*range_sets):
    out = []
    for a, b in sorted(r for rs in range_sets for r in rs):
        if out and a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def _minus(ranges, removed):
    out = []
    for a, b in ranges:
        for x, y in removed:
            if y < a or x > b:
                continue
            if x > a:
                out.append([a, x - 1])
            a = y + 1
            if a > b:
                break
        if a <= b:
            out.append([a, b])
    return out


_CACHE: dict = {}


def _cached(fn):
    """A per-argument memo (the core imports nothing outside the stdlib's core
    modules, tests/value_origin_conformance/test_self_contained.py)."""
    def wrapper(*args):
        key = (fn.__name__,) + args
        if key not in _CACHE:
            _CACHE[key] = fn(*args)
        return _CACHE[key]
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


def _in_version(ranges, v: int):
    """``ranges`` cut to the code points Unicode ``v`` assigns."""
    keep = _union([(a, b) for a, b, ver in _D.AGE if 0 < ver <= v])
    out, i = [], 0
    for a, b in ranges:
        while i < len(keep) and keep[i][1] < a:
            i += 1
        j = i
        while j < len(keep) and keep[j][0] <= b:
            x, y = max(a, keep[j][0]), min(b, keep[j][1])
            if x <= y:
                out.append((x, y))
            j += 1
    return out


def _class(ranges) -> str:
    """The body of a ``[...]`` class matching ``ranges`` (escaped for ``re``)."""
    return "".join("\\U%08x" % a if a == b else "\\U%08x-\\U%08x" % (a, b)
                   for a, b in ranges)


_WORD = _union(_D.ALPHA, _D.DECIMAL, _D.DIGIT, _D.NUMERIC, [(0x5F, 0x5F)])


@_cached
def word_class(v: int = V13) -> str:
    """``\\w`` as ``re`` reads it for ``str``: alphanumeric, or ``_``."""
    return _class(_in_version(_WORD, v))


@_cached
def word_not_digit_class(v: int = V13) -> str:
    """``[^\\W\\d_]``: a word character that is no decimal digit and no ``_``."""
    return _class(_in_version(_minus(_WORD, _union(_D.DECIMAL, [(0x5F, 0x5F)])), v))


@_cached
def decimal_class(v: int = V13) -> str:
    """``\\d`` as ``re`` reads it for ``str``: Nd."""
    return _class(_in_version(_D.DECIMAL, v))


@_cached
def space_class(v: int = V13) -> str:
    """``\\s`` as ``re`` reads it for ``str``."""
    return _class(_in_version(_D.SPACE, v))


def _written_out(pattern: str, body: dict) -> str:
    p = pattern.replace("[^\\W\\d_]", "[" + body["L"] + "]")
    out, i, in_class = [], 0, False
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            e = p[i + 1]
            if e in "wsdWSD":
                if in_class:
                    if e.isupper():
                        raise ValueError(f"a negated class escape inside a class: {pattern!r}")
                    out.append(body[e])
                else:
                    out.append(("[^" if e.isupper() else "[") + body[e.lower()] + "]")
                i += 2
                continue
            if e in "bB":
                raise ValueError(f"a word boundary decides by \\w: {pattern!r}")
            out.append(p[i:i + 2])
            i += 2
            continue
        if c == "[" and not in_class:
            in_class = True
            out.append(c)
            i += 1
            if p[i:i + 1] == "^":
                out.append("^")
                i += 1
            if p[i:i + 1] == "]":
                out.append("]")
                i += 1
            continue
        if c == "]" and in_class:
            in_class = False
        out.append(c)
        i += 1
    return "".join(out)


def _ascii_part(ranges) -> str:
    return _class([(a, min(b, 0x7F)) for a, b in ranges if a <= 0x7F])


class _Pattern:
    """A pattern with ``\\w``, ``\\s`` and ``\\d`` written out twice: from the
    vendored classes, and from their ASCII members alone. On ASCII text the two
    match exactly the same characters, and the second is far cheaper for ``re``
    to step through (a class of hundreds of ranges is checked range by range), so
    ASCII text, the common case, is matched by the second."""
    __slots__ = ("full", "ascii", "pattern")

    def __init__(self, full, ascii_, pattern):
        self.full, self.ascii, self.pattern = full, ascii_, pattern

    def _pick(self, text):
        return self.ascii if isinstance(text, str) and text.isascii() else self.full

    def search(self, string, *a):
        return self._pick(string).search(string, *a)

    def match(self, string, *a):
        return self._pick(string).match(string, *a)

    def fullmatch(self, string, *a):
        return self._pick(string).fullmatch(string, *a)

    def finditer(self, string, *a):
        return self._pick(string).finditer(string, *a)

    def findall(self, string, *a):
        return self._pick(string).findall(string, *a)

    def split(self, string, *a, **k):
        return self._pick(string).split(string, *a, **k)

    def sub(self, repl, string, *a, **k):
        return self._pick(string).sub(repl, string, *a, **k)

    def subn(self, repl, string, *a, **k):
        return self._pick(string).subn(repl, string, *a, **k)


def compile(pattern: str, flags: int = 0, v: int = V13):
    """``re.compile`` with ``\\w``, ``\\s`` and ``\\d`` (and ``\\W``, ``\\S``,
    ``\\D``, and ``[^\\W\\d_]``) written out from the vendored classes, and
    ``re.ASCII``, so the pattern decides nothing by the running interpreter's
    Unicode (``IGNORECASE`` then folds ASCII only)."""
    word = _in_version(_WORD, v)
    letters = _in_version(_minus(_WORD, _union(_D.DECIMAL, [(0x5F, 0x5F)])), v)
    digits = _in_version(_D.DECIMAL, v)
    spaces = _in_version(_D.SPACE, v)
    full = {"w": _class(word), "s": _class(spaces), "d": _class(digits), "L": _class(letters)}
    ascii_ = {"w": _ascii_part(word), "s": _ascii_part(spaces),
              "d": _ascii_part(digits), "L": _ascii_part(letters)}
    return _Pattern(_re.compile(_written_out(pattern, full), flags | _re.ASCII),
                    _re.compile(_written_out(pattern, ascii_), flags | _re.ASCII), pattern)


# ── case ─────────────────────────────────────────────────────────────────────
def _cased(cp: int, v: int) -> bool:
    return cp in _CASED and assigned(cp, v)


def _ignorable(cp: int, v: int) -> bool:
    return cp in _CASE_IGNORABLE and assigned(cp, v)


def lower(text: str, v: int = V13) -> str:
    """``str.lower`` as an interpreter of Unicode ``v`` computes it, Final_Sigma
    included."""
    if text.isascii():
        return text.lower()                    # ASCII case mapping: no Unicode data
    out = []
    n = len(text)
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp == 0x3A3:
            j = i - 1
            while j >= 0 and _ignorable(ord(text[j]), v):
                j -= 1
            final = j >= 0 and _cased(ord(text[j]), v)
            if final and i + 1 < n:
                j = i + 1
                while j < n and _ignorable(ord(text[j]), v):
                    j += 1
                final = j == n or not _cased(ord(text[j]), v)
            out.append("ς" if final else "σ")
            continue
        low = _D.LOWER.get(cp)
        out.append(low if low is not None and assigned(cp, v) else ch)
    return "".join(out)


def casefold(text: str, v: int = V13) -> str:
    """``str.casefold`` (CaseFolding C and F) as an interpreter of Unicode ``v``."""
    out = []
    for ch in text:
        cp = ord(ch)
        f = _D.FOLD.get(cp)
        out.append(f if f is not None and assigned(cp, v) else ch)
    return "".join(out)


# ── normalization: CPython's unicodedata algorithm ───────────────────────────
_SBASE, _LBASE, _VBASE, _TBASE = 0xAC00, 0x1100, 0x1161, 0x11A7
_LCOUNT, _VCOUNT, _TCOUNT = 19, 21, 28
_NCOUNT = _VCOUNT * _TCOUNT
_SCOUNT = _LCOUNT * _NCOUNT


def _ccc(cp: int, v: int) -> int:
    return _D.CCC.get(cp, 0) if assigned(cp, v) else 0


def _decompose(text: str, compat: bool, v: int, ucd32: bool) -> list:
    out = []
    for ch in text:
        stack = [ord(ch)]
        while stack:
            code = stack.pop()
            if _SBASE <= code < _SBASE + _SCOUNT:
                s = code - _SBASE
                out.append(_LBASE + s // _NCOUNT)
                out.append(_VBASE + (s % _NCOUNT) // _TCOUNT)
                if s % _TCOUNT:
                    out.append(_TBASE + s % _TCOUNT)
                continue
            if ucd32:
                old = _D.CORRECTIONS_3_2.get(code)
                if old is not None:
                    stack.append(old)
                    continue
                known = code not in _A1          # ucd_3_2_0: no decomposition if 3.2 lacks it
            else:
                known = assigned(code, v)
            d = _D.DECOMP.get(code) if known else None
            if d is None or (code in _COMPAT and not compat):
                out.append(code)
                continue
            stack.extend(ord(c) for c in reversed(d))
    # canonical ordering: each run of non-zero combining classes, stably by class
    i = 0
    while i < len(out):
        if _ccc(out[i], v) == 0:
            i += 1
            continue
        j = i
        while j < len(out) and _ccc(out[j], v) != 0:
            j += 1
        out[i:j] = sorted(out[i:j], key=lambda c: _ccc(c, v))
        i = j
    return out


@_cached
def _composition(v: int):
    pairs = {(ord(k[0]), ord(k[1])): c for k, c in _D.COMP.items() if assigned(c, v)}
    return pairs, frozenset(a for a, _ in pairs), frozenset(b for _, b in pairs)


def _compose(codes: list, v: int) -> list:
    pairs, first, last = _composition(v)
    out, skipped, i, n = [], set(), 0, len(codes)
    while i < n:
        if i in skipped:
            skipped.discard(i)
            i += 1
            continue
        code = codes[i]
        if (_LBASE <= code < _LBASE + _LCOUNT and i + 1 < n
                and _VBASE <= codes[i + 1] < _VBASE + _VCOUNT):
            code = _SBASE + ((code - _LBASE) * _VCOUNT + codes[i + 1] - _VBASE) * _TCOUNT
            i += 2
            if i < n and _TBASE < codes[i] < _TBASE + _TCOUNT:
                code += codes[i] - _TBASE
                i += 1
            out.append(code)
            continue
        if code not in first:
            out.append(code)
            i += 1
            continue
        i1, comb, cur = i + 1, 0, code
        while i1 < n:
            code1 = codes[i1]
            comb1 = _ccc(code1, v)
            if comb:
                if comb1 == 0:
                    break
                if comb >= comb1:
                    i1 += 1
                    continue
            composed = pairs.get((cur, code1)) if code1 in last else None
            if composed is None:
                if comb1 == 0:
                    break
                comb = comb1
                i1 += 1
                continue
            cur = composed
            skipped.add(i1)
            i1 += 1
            if cur not in first:
                break
        out.append(cur)
        i += 1
    return out


def normalize(form: str, text: str, v: int = V13, ucd32: bool = False) -> str:
    """``unicodedata.normalize(form, text)`` on an interpreter of Unicode ``v``;
    ``ucd32`` is that interpreter's ``unicodedata.ucd_3_2_0.normalize``."""
    if text.isascii():
        return text
    compat = form in ("NFKC", "NFKD")
    codes = _decompose(text, compat, v, ucd32)
    if form in ("NFC", "NFKC"):
        codes = _compose(codes, v)
    return "".join(map(chr, codes))


# ── RFC 3454's own tables (Unicode 3.2), for nameprep ────────────────────────
def unassigned_3_2(ch: str) -> bool:
    return ord(ch) in _A1


def prohibited_3_2(ch: str) -> bool:
    """RFC 3491 section 5: tables C.1.2, C.2.2 and C.3 to C.9."""
    return ord(ch) in _PROHIBITED


def randal_3_2(ch: str) -> bool:
    return ord(ch) in _D1


def l_3_2(ch: str) -> bool:
    return ord(ch) in _D2
