"""Regenerate the two data modules the value-origin core vendors.

    python scripts/gen_value_origin_data.py \
        --psl public_suffix_list.dat \
        --idna IdnaMappingTable.txt \
        --bidi DerivedBidiClass.txt \
        --gc DerivedGeneralCategory.txt \
        --joining DerivedJoiningType.txt \
        --ccc DerivedCombiningClass.txt

writes ``xaidr/value_origin/_idna_data.py`` and ``xaidr/value_origin/_psl_data.py``
(``--idna-only`` writes the first alone, leaving the PSL snapshot as it is).

    python scripts/gen_value_origin_data.py --nameprep

writes ``xaidr/value_origin/_nameprep_data.py`` alone, from the files vendored in
``tests/published_vectors/upstream/`` (``MANIFEST.json`` holds each one's URL,
version, sha256 and licence, as for the published suites, and the generator
refuses a file whose bytes differ): RFC 3454's tables
B.1 and B.3, which the core's IDNA 2003 encoding (the socket layer's,
``_idna.idna2003``) maps with, and Unicode 16.0's lowercase mapping of every code
point B.3 leaves alone, with the version that assigned it. The interpreter's
``stringprep`` is not used: before CPython's fix (3.10.22, 3.12.15, 3.14.9), its
B.3 fell back to the interpreter's own ``str.lower``, so an unfixed interpreter
encodes a name by its own Unicode version (``Ⴜ`` is lowercased by 3.12.2 and kept
by 3.12.15). The age lets the core write out each of those encodings on every
interpreter: a code point's lowercase does not change once it is assigned
(measured 2026-10-24 over every code point: ``str.lower`` on 3.10.20, 3.11.15,
3.12.13 and 3.14.5 is this table restricted to the code points each one's Unicode
assigns, 0 exceptions).

WHY GENERATED MODULES AND NOT DATA FILES. A downstream package that vendors
``xaidr/value_origin/**`` byte-identically may build its wheel with an
``include`` of ``xaidr/**/*.py`` + ``xaidr/rules/*.json``. A ``.dat`` file
would ship in this wheel and silently not in that one. A ``.py`` module ships
under every build config.

WHERE THE INPUTS COME FROM. Nothing here fetches. The operator downloads:

    https://publicsuffix.org/list/public_suffix_list.dat
    https://www.unicode.org/Public/idna/13.0.0/IdnaMappingTable.txt
    https://www.unicode.org/Public/13.0.0/ucd/extracted/DerivedBidiClass.txt
    https://www.unicode.org/Public/13.0.0/ucd/extracted/DerivedGeneralCategory.txt
    https://www.unicode.org/Public/13.0.0/ucd/extracted/DerivedJoiningType.txt
    https://www.unicode.org/Public/13.0.0/ucd/extracted/DerivedCombiningClass.txt

except the inputs of ``--nameprep``, which are vendored (see above).

WHY UNICODE 13.0 (docs/value-origin-rulings.md, ruling 3.6). UTS-46 maps, then
NFC-normalises with the interpreter's ``unicodedata``. That database is Unicode
13.0 on Python 3.10 and 16.0 on 3.14. Pinning the mapping table to 13.0 — the
oldest supported interpreter's — means every code point the table calls valid is
ASSIGNED on every supported interpreter, and Unicode's normalization stability
policy fixes NFC for assigned code points. A newer table would accept code
points 3.10 treats as unassigned, and the same core bytes would decide
differently on different Pythons. Bidi classes,
combining marks and the assigned code points come from the same 13.0 release for
the same reason, rather than from ``unicodedata``: a code point 13.0 leaves
unassigned is one no character class of the reader's is decided by (measured
2026-10-23: over every code point 13.0 assigns, the regex classes, ``isalpha``,
``isalnum``, ``isdigit``, ``isspace``, ``casefold`` and ``lower`` agree on 3.10.22
and 3.14.9).

Refreshing either input is a core change: a new ``expected.jsonl`` question and
a new pin.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "xaidr" / "value_origin"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _ranges(path: Path, field_filter):
    """(start, end, value) from a UCD-style ``a..b ; value`` file."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(";")]
        cps = fields[0].split("..")
        a = int(cps[0], 16)
        b = int(cps[-1], 16)
        v = field_filter(fields)
        if v is not None:
            out.append((a, b, v))
    out.sort()
    return out


def _coalesce(ranges):
    """Merge adjacent ranges with the same value; returns (starts, values)
    covering 0..0x10FFFF with no gaps (gaps take ``None``)."""
    starts, values = [], []

    def push(a, v):
        if values and values[-1] == v:
            return
        starts.append(a)
        values.append(v)

    nxt = 0
    for a, b, v in ranges:
        if a < nxt:
            raise SystemExit(f"overlapping ranges at U+{a:04X}")
        if a > nxt:
            push(nxt, None)
        push(a, v)
        nxt = b + 1
    if nxt <= 0x10FFFF:
        push(nxt, None)
    return starts, values


def gen_idna(idna: Path, bidi: Path, gc: Path, joining: Path, ccc: Path) -> str:
    # UTS-46 status, nontransitional (deviation = valid):
    # "V" valid, "I" ignored, "D" disallowed, "M<chars>" mapped, and the two
    # UseSTD3ASCIIRules statuses kept apart so the rule can be applied or not:
    # "S" disallowed_STD3_valid, "T<chars>" disallowed_STD3_mapped. With the
    # rule off (the core's flag, 3.6) they are valid and mapped.
    def status(fields):
        st = fields[1]
        if st in ("valid", "deviation"):
            return "V"
        if st == "disallowed_STD3_valid":
            return "S"
        if st == "ignored":
            return "I"
        if st == "disallowed":
            return "D"
        if st == "mapped":
            return "M" + "".join(chr(int(h, 16)) for h in fields[2].split())
        if st == "disallowed_STD3_mapped":
            return "T" + "".join(chr(int(h, 16)) for h in fields[2].split())
        raise SystemExit(f"unknown IDNA status {st!r}")

    st_starts, st_vals = _coalesce(_ranges(idna, status))
    if None in st_vals:
        raise SystemExit("IdnaMappingTable leaves a gap; refusing")

    # Bidi classes the RFC 5893 rule needs; everything else defaults to L.
    wanted = {"R", "AL", "AN", "EN", "ES", "CS", "ET", "ON", "BN", "NSM", "L"}
    bd_starts, bd_vals = _coalesce(
        _ranges(bidi, lambda f: f[1] if f[1] in wanted else "OTHER"))
    # General category M (Mn/Mc/Me): a label may not begin with one.
    mk_starts, mk_vals = _coalesce(
        _ranges(gc, lambda f: True if f[1] in ("Mn", "Mc", "Me") else None))
    # CONTEXTJ (RFC 5892 Appendix A.1, A.2): Joining_Type, and the viramas
    # (Canonical_Combining_Class 9).
    jt_starts, jt_vals = _coalesce(
        _ranges(joining, lambda f: f[1] if f[1] in ("L", "D", "R", "T") else None))
    viramas = tuple(cp for a, b, v in _ranges(ccc, lambda f: f[1] == "9" or None)
                    for cp in range(a, b + 1))
    # Assigned (General_Category other than Cn). A code point 13.0 leaves
    # unassigned is a letter, a digit or a case pair to a newer interpreter and
    # nothing to 3.10, so the reader decides no character class from it (V-4).
    as_starts, as_vals = _coalesce(_ranges(gc, lambda f: f[1] != "Cn" or None))

    lines = [
        '"""GENERATED by scripts/gen_value_origin_data.py — DO NOT EDIT.',
        "",
        "UTS-46 mapping (nontransitional; the UseSTD3ASCIIRules statuses kept apart),",
        "Bidi_Class, General_Category=M, the assigned code points, Joining_Type and the",
        "viramas, all from Unicode 13.0.0. See the generator for why 13.0.",
        "",
        f"IdnaMappingTable.txt          sha256 {_sha(idna)}",
        f"DerivedBidiClass.txt          sha256 {_sha(bidi)}",
        f"DerivedGeneralCategory.txt    sha256 {_sha(gc)}",
        f"DerivedJoiningType.txt        sha256 {_sha(joining)}",
        f"DerivedCombiningClass.txt     sha256 {_sha(ccc)}",
        "",
        "Unicode data: Copyright (c) 1991-2020 Unicode, Inc. Distributed under the",
        "Unicode License Agreement - Data Files and Software (see NOTICE).",
        '"""',
        "",
        'UNICODE_VERSION = "13.0.0"',
        "",
        f"STATUS_STARTS = {tuple(st_starts)!r}",
        f"STATUS_VALUES = {tuple(st_vals)!r}",
        f"BIDI_STARTS = {tuple(bd_starts)!r}",
        f"BIDI_VALUES = {tuple(v if v is not None else 'L' for v in bd_vals)!r}",
        f"MARK_STARTS = {tuple(mk_starts)!r}",
        f"MARK_VALUES = {tuple(bool(v) for v in mk_vals)!r}",
        f"JOINING_STARTS = {tuple(jt_starts)!r}",
        f"JOINING_VALUES = {tuple(jt_vals)!r}",
        f"VIRAMAS = frozenset({viramas!r})",
        f"ASSIGNED_STARTS = {tuple(as_starts)!r}",
        f"ASSIGNED_VALUES = {tuple(bool(v) for v in as_vals)!r}",
        "",
    ]
    return "\n".join(lines)


def _rfc3454_table(text: str, name: str):
    """[(code point, [mapped code points])] of one RFC 3454 table."""
    m = re.search(rf"----- Start Table {re.escape(name)} -----\n(.*?)----- End Table "
                  rf"{re.escape(name)} -----", text, re.S)
    if not m:
        raise SystemExit(f"rfc3454.txt has no table {name}")
    rows = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("RFC 3454") or line.startswith("Hoffman"):
            continue                       # a page header or footer
        f = [x.strip() for x in line.split(";")]
        if len(f) < 2 or not re.fullmatch(r"[0-9A-F]{4,6}", f[0]):
            continue
        rows.append((int(f[0], 16), [int(h, 16) for h in f[1].split()]))
    return rows


SOURCES = ROOT / "tests" / "published_vectors"
NAMEPREP_INPUTS = ("rfc3454.txt", "UnicodeData-16.0.0.txt", "DerivedAge-16.0.0.txt",
                   "SpecialCasing-16.0.0.txt")
UCD_INPUTS = ("UnicodeData-16.0.0.txt", "DerivedAge-16.0.0.txt", "SpecialCasing-16.0.0.txt",
              "CaseFolding-16.0.0.txt", "CompositionExclusions-16.0.0.txt",
              "NormalizationCorrections-16.0.0.txt", "DerivedCoreProperties-16.0.0.txt")


def _vendored(src: Path):
    """{name: Path} of the vendored inputs, each checked against MANIFEST.json."""
    import json
    manifest = json.loads((src / "MANIFEST.json").read_text(encoding="utf-8"))
    want = {e["path"]: e["sha256"] for e in manifest["files"]}
    out = {}
    for name in sorted(set(NAMEPREP_INPUTS) | set(UCD_INPUTS)):
        rel = "upstream/" + name
        if rel not in want:
            raise SystemExit(f"MANIFEST.json lists no {rel}; refusing")
        p = src / rel
        if _sha(p) != want[rel]:
            raise SystemExit(f"{p} sha256 {_sha(p)} differs from MANIFEST.json "
                             f"({want[rel]}); refusing")
        out[name] = p
    return out


def _unicode_lower(unicode_data: Path, special: Path):
    """{code point: its full lowercase} wherever that is not the code point: the
    simple mapping (UnicodeData field 13), or an unconditional SpecialCasing one,
    as ``str.lower`` takes it for a single code point."""
    lower = {}
    for line in unicode_data.read_text(encoding="utf-8").splitlines():
        f = line.split(";")
        if f[13]:
            lower[int(f[0], 16)] = chr(int(f[13], 16))
    for raw in special.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        f = [x.strip() for x in line.split(";")]
        if len(f) > 4 and f[4]:
            continue                       # a conditional mapping (context, language)
        cp = int(f[0], 16)
        low = "".join(chr(int(h, 16)) for h in f[1].split())
        if low != chr(cp):
            lower[cp] = low
    return lower


def _ages(derived_age: Path):
    """{code point: (major, minor)} of every code point DerivedAge assigns."""
    age = {}
    for raw in derived_age.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        rng, ver = (x.strip() for x in line.split(";"))
        a, _, b = rng.partition("..")
        major, minor = (int(x) for x in ver.split("."))
        for cp in range(int(a, 16), int(b or a, 16) + 1):
            age[cp] = (major, minor)
    return age


def _rfc3454_ranges(text: str, name: str):
    """[(first, last)] of one RFC 3454 table whose rows are a code point or a
    range ``XXXX-YYYY``, each optionally followed by ``; ...`` (A.1, C.*, D.*)."""
    m = re.search(rf"----- Start Table {re.escape(name)} -----\n(.*?)----- End Table "
                  rf"{re.escape(name)} -----", text, re.S)
    if not m:
        raise SystemExit(f"rfc3454.txt has no table {name}")
    out = []
    for line in m.group(1).splitlines():
        cell = line.split(";", 1)[0].strip()
        r = re.fullmatch(r"([0-9A-F]{4,6})(?:-([0-9A-F]{4,6}))?", cell)
        if r:
            out.append((int(r.group(1), 16), int(r.group(2) or r.group(1), 16)))
    return out


_NAMEPREP_PROHIBITED = ("C.1.2", "C.2.2", "C.3", "C.4", "C.5", "C.6", "C.7", "C.8", "C.9")


def gen_nameprep(src: Path = SOURCES) -> str:
    files = _vendored(src)
    rfc = files["rfc3454.txt"]
    text = rfc.read_text(encoding="utf-8")
    if "Request for Comments: 3454" not in text:
        raise SystemExit(f"{rfc} is not RFC 3454")
    b1 = [cp for cp, to in _rfc3454_table(text, "B.1")]
    if any(to for cp, to in _rfc3454_table(text, "B.1")):
        raise SystemExit("table B.1 maps to something; refusing")
    b3 = {cp: "".join(chr(c) for c in to) for cp, to in _rfc3454_table(text, "B.3")}
    if len(b1) != 27 or len(b3) != 838:               # the RFC's own row counts
        raise SystemExit(f"tables B.1 ({len(b1)}) or B.3 ({len(b3)}) look truncated")
    lower = _unicode_lower(files["UnicodeData-16.0.0.txt"], files["SpecialCasing-16.0.0.txt"])
    age = _ages(files["DerivedAge-16.0.0.txt"])
    # Only the code points B.3 does not map: B.3's own rows are B.3's answer on
    # every interpreter, fixed or not.
    legacy = {cp: (low, age[cp]) for cp, low in sorted(lower.items()) if cp not in b3}
    if any(cp not in age for cp in lower):
        raise SystemExit("a lowercase mapping for a code point DerivedAge does not assign")
    a1 = _rfc3454_ranges(text, "A.1")
    prohibited = sorted(r for t in _NAMEPREP_PROHIBITED for r in _rfc3454_ranges(text, t))
    d1, d2 = _rfc3454_ranges(text, "D.1"), _rfc3454_ranges(text, "D.2")
    if not (len(a1) == 396 and len(d1) == 34 and len(d2) == 360):   # the RFC's row counts
        raise SystemExit(f"tables A.1 ({len(a1)}), D.1 ({len(d1)}) or D.2 ({len(d2)}) "
                         "look truncated")
    lines = [
        '"""GENERATED by scripts/gen_value_origin_data.py --nameprep — DO NOT EDIT.',
        "",
        "RFC 3454 (stringprep) table B.1 (commonly mapped to nothing) and table B.3",
        "(case folding, no normalization), for the IDNA 2003 encoding the socket layer",
        "applies to a non-ASCII host (``_idna.idna2003``); and LOWER, Unicode 16.0's",
        "lowercase of every code point B.3 does not map, with the Unicode version that",
        "assigned it, for the encoding an interpreter whose ``stringprep`` predates",
        "CPython's fix computes.",
        "",
        "Sources, vendored in tests/published_vectors/upstream/ (MANIFEST.json):",
    ]
    for name in NAMEPREP_INPUTS:
        lines.append(f"    {name:<26} sha256 {_sha(files[name])}")
    lines += [
        '"""',
        "",
        f"B1 = frozenset({tuple(b1)!r})",
        "",
        f"B3 = {dict(sorted(b3.items()))!r}",
        "",
        "#: (first, last) ranges: A.1, the code points Unicode 3.2 leaves unassigned;",
        "#: the union of the tables nameprep prohibits (RFC 3491 section 5: C.1.2,",
        "#: C.2.2, C.3 to C.9); D.1 (RandALCat) and D.2 (LCat), the bidi rule's.",
        f"A1 = {tuple(a1)!r}",
        f"PROHIBITED = {tuple(prohibited)!r}",
        f"D1 = {tuple(d1)!r}",
        f"D2 = {tuple(d2)!r}",
        "",
        "#: code point -> (its lowercase, (major, minor) of the Unicode that assigned it)",
        # ascii(), not repr(): repr() escapes a code point the RUNNING interpreter's
        # Unicode leaves unassigned, so the module would differ by interpreter.
        f"LOWER = {ascii(legacy)}",
        "",
    ]
    return "\n".join(lines)


def _unicode_data(path: Path):
    """{code point: UnicodeData fields}, the ``<..., First>``/``<..., Last>`` ranges
    expanded."""
    rows, first = {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        f = line.split(";")
        cp = int(f[0], 16)
        if f[1].endswith(", First>"):
            first = cp
            continue
        if f[1].endswith(", Last>"):
            for c in range(first, cp + 1):
                rows[c] = f
            continue
        rows[cp] = f
    return rows


def _property_ranges(path: Path, wanted):
    """{property: [code point]} for the binary properties ``wanted`` of a UCD
    ``a..b ; Property`` file."""
    out = {w: [] for w in wanted}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        rng, prop = (x.strip() for x in line.split(";")[:2])
        if prop in out:
            a, _, b = rng.partition("..")
            out[prop].extend(range(int(a, 16), int(b or a, 16) + 1))
    return out


def _ranges(cps):
    """Sorted, merged (first, last) ranges of an iterable of code points."""
    out = []
    for cp in sorted(set(cps)):
        if out and out[-1][1] == cp - 1:
            out[-1][1] = cp
        else:
            out.append([cp, cp])
    return tuple((a, b) for a, b in out)


def gen_ucd(src: Path = SOURCES) -> str:
    """``_ucd_data.py``: the Unicode 16.0 properties a reading decides with, each
    code point's age beside them, so every property can be asked as Unicode V has
    it (a property of an assigned code point does not change between the versions
    the supported interpreters carry; measured, tests/test_value_origin_ucd.py).
    Python's own definitions, from CPython's makeunicodedata: ``isspace`` is Zs or
    bidi WS, B or S; ``isalpha`` is L*; ``isdecimal``, ``isdigit`` and
    ``isnumeric`` are UnicodeData fields 6, 7 and 8; ``lower`` is the simple
    mapping or an unconditional SpecialCasing one; ``casefold`` is CaseFolding's C
    and F; a composition pair is a canonical two-code-point decomposition outside
    CompositionExclusions whose first code point has combining class 0."""
    files = _vendored(src)
    ud = _unicode_data(files["UnicodeData-16.0.0.txt"])
    age = _ages(files["DerivedAge-16.0.0.txt"])
    ages = sorted(age.items())
    age_ranges = []
    for cp, v in ages:
        code = v[0] * 100 + v[1]
        if age_ranges and age_ranges[-1][1] == cp - 1 and age_ranges[-1][2] == code:
            age_ranges[-1][1] = cp
        else:
            age_ranges.append([cp, cp, code])
    alpha = [cp for cp, f in ud.items() if f[2] in ("Lm", "Lt", "Lu", "Ll", "Lo")]
    space = [cp for cp, f in ud.items() if f[2] == "Zs" or f[4] in ("WS", "B", "S")]
    decimal = [cp for cp, f in ud.items() if f[6]]
    digit = [cp for cp, f in ud.items() if f[7]]
    numeric = [cp for cp, f in ud.items() if f[8]]
    ccc = {cp: int(f[3]) for cp, f in ud.items() if f[3] != "0"}
    decomp, compat = {}, []
    for cp, f in ud.items():
        if f[5]:
            parts = f[5].split()
            if parts[0].startswith("<"):
                compat.append(cp)
                parts = parts[1:]
            decomp[cp] = "".join(chr(int(h, 16)) for h in parts)
    excl = set()
    for raw in files["CompositionExclusions-16.0.0.txt"].read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            excl.add(int(line, 16))
    compat_set = set(compat)
    comp = {}
    for cp, d in decomp.items():
        if (cp not in compat_set and len(d) == 2 and cp not in excl
                and ccc.get(ord(d[0]), 0) == 0):
            comp[d] = cp
    corr32 = {}
    for raw in files["NormalizationCorrections-16.0.0.txt"].read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        f = [x.strip() for x in line.split(";")]
        if tuple(int(x) for x in f[3].split(".")) > (3, 2, 0):
            corr32[int(f[0], 16)] = int(f[1], 16)
    lower = _unicode_lower(files["UnicodeData-16.0.0.txt"], files["SpecialCasing-16.0.0.txt"])
    fold = {}
    for raw in files["CaseFolding-16.0.0.txt"].read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        f = [x.strip() for x in line.split(";")]
        if f[1] in ("C", "F"):
            fold[int(f[0], 16)] = "".join(chr(int(h, 16)) for h in f[2].split())
    props = _property_ranges(files["DerivedCoreProperties-16.0.0.txt"],
                             ("Cased", "Case_Ignorable"))
    names = ", ".join(UCD_INPUTS)
    lines = [
        '"""GENERATED by scripts/gen_value_origin_data.py --nameprep — DO NOT EDIT.',
        "",
        "Unicode 16.0's properties, each code point's age beside them, for every",
        "reading the core makes, so no reading consults the running interpreter's",
        "Unicode database (``_ucd``). Ranges are (first, last); a version is",
        "major * 100 + minor.",
        "",
        "Sources, vendored in tests/published_vectors/upstream/ (MANIFEST.json):",
    ]
    for name in UCD_INPUTS:
        lines.append(f"    {name:<38} sha256 {_sha(files[name])}")
    lines += [
        '"""',
        "",
        f"AGE = {tuple(tuple(r) for r in age_ranges)!r}",
        f"ALPHA = {_ranges(alpha)!r}",
        f"SPACE = {_ranges(space)!r}",
        f"DECIMAL = {_ranges(decimal)!r}",
        f"DIGIT = {_ranges(digit)!r}",
        f"NUMERIC = {_ranges(numeric)!r}",
        f"CASED = {_ranges(props['Cased'])!r}",
        f"CASE_IGNORABLE = {_ranges(props['Case_Ignorable'])!r}",
        f"CCC = {dict(sorted(ccc.items()))!r}",
        f"COMPAT = {_ranges(compat)!r}",
        # ascii(), not repr(): repr() escapes by the RUNNING interpreter's Unicode.
        f"DECOMP = {ascii(dict(sorted(decomp.items())))}",
        f"COMP = {ascii(dict(sorted(comp.items())))}",
        f"CORRECTIONS_3_2 = {dict(sorted(corr32.items()))!r}",
        f"LOWER = {ascii(dict(sorted(lower.items())))}",
        f"FOLD = {ascii(dict(sorted(fold.items())))}",
        "",
    ]
    return "\n".join(lines)


def gen_psl(psl: Path) -> str:
    text = psl.read_text(encoding="utf-8")
    version = re.search(r"^// VERSION: (\S+)", text, re.M)
    commit = re.search(r"^// COMMIT: (\S+)", text, re.M)
    if not version:
        raise SystemExit("public_suffix_list.dat carries no VERSION line")
    snapshot_date = version.group(1)[:10]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", snapshot_date):
        raise SystemExit(f"cannot read a date from VERSION {version.group(1)!r}")

    # Rules are converted to A-labels with the CORE's OWN UTS-46 step, so a
    # rule and a host are compared in the one encoding the core produces.
    # Loaded as a bare namespace so the package __init__ (which needs the PSL
    # module this function is about to write) does not run.
    import importlib
    import types
    ns = types.ModuleType("_vo_gen")
    ns.__path__ = [str(PKG)]
    sys.modules["_vo_gen"] = ns
    to_ascii = importlib.import_module("_vo_gen._idna").to_ascii

    sections = {"ICANN": [], "PRIVATE": []}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// ===BEGIN ICANN"):
            current = "ICANN"
            continue
        if line.startswith("// ===BEGIN PRIVATE"):
            current = "PRIVATE"
            continue
        if line.startswith("// ===END"):
            current = None
            continue
        if current is None or not line or line.startswith("//"):
            continue
        rule = line.split()[0]
        prefix = ""
        body = rule
        if body.startswith("!"):
            prefix, body = "!", body[1:]
        labels = body.split(".")
        conv = []
        for lab in labels:
            if lab == "*":
                conv.append("*")
                continue
            a = to_ascii(lab)
            if a is None:
                raise SystemExit(f"PSL rule {rule!r}: label {lab!r} fails UTS-46")
            conv.append(a)
        sections[current].append(prefix + ".".join(conv))
    if not sections["ICANN"] or not sections["PRIVATE"]:
        raise SystemExit("PSL sections not found; refusing to write an empty list")

    lines = [
        '"""GENERATED by scripts/gen_value_origin_data.py — DO NOT EDIT.',
        "",
        "The Public Suffix List, both sections, rules converted to A-labels by the",
        "core's own UTS-46 step. Never fetched at runtime.",
        "",
        "Source: https://publicsuffix.org/list/public_suffix_list.dat",
        f"VERSION: {version.group(1)}",
        f"COMMIT:  {commit.group(1) if commit else '(none recorded)'}",
        f"sha256:  {_sha(psl)}",
        "",
        "This Source Code Form is subject to the terms of the Mozilla Public",
        "License, v. 2.0. If a copy of the MPL was not distributed with this",
        "file, You can obtain one at https://mozilla.org/MPL/2.0/.",
        '"""',
        "",
        f'PSL_SNAPSHOT_DATE = "{snapshot_date}"',
        "",
        f"ICANN_RULES = {tuple(sections['ICANN'])!r}",
        "",
        f"PRIVATE_RULES = {tuple(sections['PRIVATE'])!r}",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--psl", type=Path)
    ap.add_argument("--nameprep", action="store_true",
                    help="write _nameprep_data.py and _ucd_data.py, from tests/published_vectors/")
    ap.add_argument("--idna", type=Path)
    ap.add_argument("--bidi", type=Path)
    ap.add_argument("--gc", type=Path)
    ap.add_argument("--joining", type=Path)
    ap.add_argument("--ccc", type=Path)
    ap.add_argument("--idna-only", action="store_true")
    a = ap.parse_args(argv)
    if a.nameprep:
        (PKG / "_nameprep_data.py").write_text(gen_nameprep(), encoding="utf-8")
        (PKG / "_ucd_data.py").write_text(gen_ucd(), encoding="utf-8")
        print("wrote", PKG / "_nameprep_data.py", "and", PKG / "_ucd_data.py")
        return 0
    if None in (a.idna, a.bidi, a.gc, a.joining, a.ccc):
        ap.error("--idna, --bidi, --gc, --joining and --ccc are required")
    if a.psl is None and not a.idna_only:
        ap.error("--psl is required unless --idna-only")
    head = a.idna.read_text(encoding="utf-8").splitlines()[:3]
    if not any("IdnaMappingTable" in h for h in head):
        raise SystemExit(f"{a.idna} does not look like IdnaMappingTable.txt")
    for p, needle in ((a.bidi, "13.0.0"), (a.gc, "13.0.0"), (a.joining, "13.0.0"),
                      (a.ccc, "13.0.0")):
        if needle not in p.read_text(encoding="utf-8").splitlines()[0]:
            raise SystemExit(f"{p} is not the Unicode {needle} file")
    (PKG / "_idna_data.py").write_text(
        gen_idna(a.idna, a.bidi, a.gc, a.joining, a.ccc), encoding="utf-8")
    if a.idna_only:
        print("wrote", PKG / "_idna_data.py")
        return 0
    (PKG / "_psl_data.py").write_text(gen_psl(a.psl), encoding="utf-8")
    print("wrote", PKG / "_idna_data.py", "and", PKG / "_psl_data.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
