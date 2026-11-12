"""No reading consults the running interpreter's Unicode database.

Every character class, case mapping and normalization a reading decides comes
from ``xaidr/value_origin/_ucd_data.py``, generated from Unicode 16.0's files
vendored in tests/published_vectors/upstream/, asked as a given Unicode version
has it (``_ucd``). So a value reads the same on every interpreter, including an
older patch release, whatever the newest characters in it.

Three checks: the reading modules call nothing that reads the interpreter's
data (static); the vendored tables, asked at THIS interpreter's version, are
this interpreter's data (so the emulation of a client on another interpreter is
that interpreter's, measured in CI on 3.10, 3.12.2, the newest 3.12 and 3.14);
and pinned readings of values built from Unicode 14-16 characters, whose
expected names are every interpreter's own codec output (measured 2026-10-25 on
3.10.20, 3.10.22, 3.11.15, 3.12.2, 3.12.13, 3.12.15, 3.14.5 and 3.14.9).
"""
from __future__ import annotations

import ast
import re
import unicodedata
from pathlib import Path

import pytest

from xaidr.value_origin import _ucd
from xaidr.value_origin import _ucd_data as D
from xaidr.value_origin._idna import idna2003

CORE = Path(__file__).resolve().parents[1] / "xaidr" / "value_origin"

#: ``str`` methods whose answer comes from the interpreter's Unicode database.
_DATA_METHODS = {"isspace", "isalpha", "isalnum", "isdigit", "isdecimal", "isnumeric",
                 "isprintable", "isidentifier", "islower", "isupper", "istitle",
                 "lower", "upper", "casefold", "title", "swapcase", "capitalize"}
#: With no argument these split or strip on the interpreter's whitespace.
_WHITESPACE_METHODS = {"strip", "lstrip", "rstrip", "split", "rsplit"}
_UNICODE_ESCAPES = re.compile(r"\\[wWsSdDbB]")
#: Every ``int()`` in a reading, each on text an ASCII-digit check already passed
#: (``int`` takes any Unicode decimal digit, so an unchecked one would not be).
_INT_CALLS = {
    "int(digits, 16)": "_HEX_DIGITS checked first",
    "int(p, 8)": "_OCT_DIGITS checked first",
    "int(p, 10)": "ASCII 0-9 checked first",
    "int(m.group(1), 16)": "_PCT_RE: [0-9A-Fa-f]{2}",
    "int(digits, 10)": "_DEC_QUAD_RE: [0-9]",
    "int(lp[2:], 16)": "_HEX_DIGITS checked first",
    "int(lp, 8)": "_OCT_DIGITS checked first",
    "int(lp, 10)": "ASCII 0-9 checked first",
    "int(port)": "_PORT_RE: [0-9]{1,5}",
}


def _reading_modules():
    for path in sorted(CORE.glob("*.py")):
        if path.name == "_ucd.py" or path.name.endswith("_data.py"):
            continue
        yield path


def test_no_reading_path_consults_the_interpreters_unicode_data():
    uses = []
    for path in _reading_modules():
        src = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            where = f"{path.name}:{getattr(node, 'lineno', '?')}"
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                if "unicodedata" in names:
                    uses.append(f"{where} imports unicodedata")
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Attribute):
                if f.attr in _DATA_METHODS and not (isinstance(f.value, ast.Name)
                                                     and f.value.id == "_ucd"):
                    uses.append(f"{where} .{f.attr}()")
                if f.attr in _WHITESPACE_METHODS and not node.args and not node.keywords:
                    uses.append(f"{where} .{f.attr}() on the interpreter's whitespace")
                if (isinstance(f.value, ast.Name) and f.value.id == "re" and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)):
                    pattern = node.args[0].value
                    flags = ast.get_source_segment(src, node.args[1]) if len(node.args) > 1 else ""
                    if _UNICODE_ESCAPES.search(pattern) or re.search(r"\bI\b|IGNORECASE", flags or ""):
                        uses.append(f"{where} re.{f.attr}({pattern!r}) decides by Unicode classes")
            if isinstance(f, ast.Name) and f.id == "int":
                seg = ast.get_source_segment(src, node)
                if seg not in _INT_CALLS:
                    uses.append(f"{where} {seg}: int() takes any Unicode decimal digit")
    assert not uses, ("a reading decides by the running interpreter's Unicode data, so "
                      "the same value reads otherwise on another interpreter: " + "; ".join(uses))


def test_the_tables_are_the_vendored_files():
    """``_ucd_data.py`` is what the committed generator writes from the vendored
    Unicode 16.0 files (their sha256 is checked against MANIFEST.json on the way)."""
    import importlib.util
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("gen", root / "scripts" / "gen_value_origin_data.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert gen.gen_ucd() == (CORE / "_ucd_data.py").read_text(encoding="utf-8")


_V = int(unicodedata.unidata_version.split(".")[0]) * 100 + int(unicodedata.unidata_version.split(".")[1])


def test_the_classes_and_case_are_this_interpreters_at_its_version():
    """Asked at this interpreter's own Unicode version, the vendored classes and
    case mappings are this interpreter's, over every code point of planes 0-2."""
    bad = []
    for cp in list(range(0x30000)) + list(range(0xE0000, 0xE0200)):
        if 0xD800 <= cp < 0xE000:
            continue
        c = chr(cp)
        for name, ours, theirs in (("isspace", _ucd.isspace(c, _V), c.isspace()),
                                   ("isalpha", _ucd.isalpha(c, _V), c.isalpha()),
                                   ("isdecimal", _ucd.isdecimal(c, _V), c.isdecimal()),
                                   ("isdigit", _ucd.isdigit(c, _V), c.isdigit()),
                                   ("isalnum", _ucd.isalnum(c, _V), c.isalnum()),
                                   ("lower", _ucd.lower(c, _V), c.lower()),
                                   ("casefold", _ucd.casefold(c, _V), c.casefold())):
            if ours != theirs:
                bad.append((name, hex(cp)))
    assert not bad, f"{len(bad)} differ from this interpreter's data, e.g. {bad[:8]}"


def test_the_regex_classes_are_this_interpreters_at_its_version():
    pats = {r"\w": _ucd.compile(r"\w", v=_V), r"\d": _ucd.compile(r"\d", v=_V),
            r"\s": _ucd.compile(r"\s", v=_V), r"[^\W\d_]": _ucd.compile(r"[^\W\d_]", v=_V)}
    bad = []
    for cp in range(0x30000):
        if 0xD800 <= cp < 0xE000:
            continue
        c = chr(cp)
        for p, ours in pats.items():
            if bool(ours.fullmatch(c)) != bool(re.fullmatch(p, c)):
                bad.append((p, hex(cp)))
    assert not bad, f"{len(bad)} differ, e.g. {bad[:8]}"


def test_final_sigma_is_this_interpreters():
    cases = ["ΟΣ", "ΣΟ", "ΟΣ́ x", "xΣ", "Ο.Σ",
             "ᾼΣ", "a­Σ", "Σ", " Σ ", "ΑΣΑ"]
    assert [_ucd.lower(s, _V) for s in cases] == [s.lower() for s in cases]


def _normalization_inputs():
    seqs = []
    for k in D.COMP:
        seqs += [k, k + k, "x" + k, k[0] + "́" + k[1]]
    seqs += [chr(cp) for cp in D.DECOMP] + [chr(cp) + "̖̀" for cp in D.CCC]
    return seqs


def test_normalization_is_this_interpreters_at_its_version():
    """CPython's normalizer, and its ``ucd_3_2_0`` (decompositions from Unicode
    3.2, combining classes and compositions from the interpreter's own version),
    over every decomposition, combining mark and composition pair."""
    u32 = unicodedata.ucd_3_2_0
    bad = []
    for s in _normalization_inputs():
        for form in ("NFC", "NFD", "NFKC", "NFKD"):
            if _ucd.normalize(form, s, _V) != unicodedata.normalize(form, s):
                bad.append((form, ascii(s)))
        if _ucd.normalize("NFKC", s, _V, ucd32=True) != u32.normalize("NFKC", s):
            bad.append(("ucd_3_2_0 NFKC", ascii(s)))
    assert not bad, f"{len(bad)} differ, e.g. {bad[:8]}"


# Every interpreter's own ``host.encode("idna")``: 3.10.20 to 3.12.15 give the
# first name, 3.14.5 and 3.14.9 (whose Unicode composes the pair) the second.
@pytest.mark.parametrize("host,names", [
    ("\U0001611e\U0001611e.example", ["xn--fy7ea.example", "xn--iy7e.example"]),
    ("x\U000105d2̇.example", ["xn--x-9bb6689q.example", "xn--x-jh3i.example"]),
    ("\U00016d67\U00016d67n.example", ["xn--n-9r6ma.example", "xn--n-cs6m.example"]),
])
def test_a_pair_a_newer_unicode_composes_is_read_both_ways_everywhere(host, names):
    assert sorted(idna2003(host)) == sorted(names), (
        f"{host!r}: http.client resolves {names} on one interpreter or another; the core "
        f"reads {idna2003(host)} here, so a sensor on one interpreter misses the name a "
        "client on another sends to")


def test_this_interpreters_codec_name_is_read_for_every_pair():
    missing = []
    for k in D.COMP:
        host = "x" + k + ".example"
        try:
            sent = host.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        if sent not in idna2003(host):
            missing.append((ascii(host), sent))
    assert not missing, f"{len(missing)} pairs this interpreter sends elsewhere: {missing[:5]}"
