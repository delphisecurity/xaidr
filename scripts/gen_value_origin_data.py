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

WHY UNICODE 13.0 (docs/value-origin-rulings.md, ruling 3.6). UTS-46 maps, then
NFC-normalises with the interpreter's ``unicodedata``. That database is Unicode
13.0 on Python 3.10 and 16.0 on 3.14. Pinning the mapping table to 13.0 — the
oldest supported interpreter's — means every code point the table calls valid is
ASSIGNED on every supported interpreter, and Unicode's normalization stability
policy fixes NFC for assigned code points. A newer table would accept code
points 3.10 treats as unassigned, and the same core bytes would decide
differently on different Pythons. Bidi classes
and combining marks come from the same 13.0 release for the same reason, rather
than from ``unicodedata``.

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

    lines = [
        '"""GENERATED by scripts/gen_value_origin_data.py — DO NOT EDIT.',
        "",
        "UTS-46 mapping (nontransitional; the UseSTD3ASCIIRules statuses kept apart),",
        "Bidi_Class, General_Category=M, Joining_Type and the viramas, all from Unicode",
        "13.0.0. See the generator for why 13.0.",
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
    ap.add_argument("--idna", type=Path, required=True)
    ap.add_argument("--bidi", type=Path, required=True)
    ap.add_argument("--gc", type=Path, required=True)
    ap.add_argument("--joining", type=Path, required=True)
    ap.add_argument("--ccc", type=Path, required=True)
    ap.add_argument("--idna-only", action="store_true")
    a = ap.parse_args(argv)
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
