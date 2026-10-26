"""The core reads a value the same on every supported interpreter (V-4): the same
findings, the same wire, not only the same block decision.

Two things an interpreter brings with it would otherwise decide a reading:

* ``urllib.parse.urlsplit``, whose bracketed-host validation differs between
  patch releases (3.12.2 reads netlocs that 3.10.22, 3.12.15 and 3.14.9 refuse).
  The core splits with its own written-out copy of 3.12.2's rules, so whether a
  value is a parse failure, and whether a URL_PREFIX designation trusts it, never
  follows the interpreter;
* the interpreter's Unicode database, which makes a code point Unicode 13.0
  leaves unassigned a letter, a digit or a case pair on a newer Python. Every
  character class the core decides is decided as Unicode 13.0 decides it.

The cross-interpreter comparison itself runs in CI (the published-differential
cells and ``scripts/published_agreement.py``); these tests pin the mechanisms on
whichever interpreter runs them.
"""
from __future__ import annotations

import ast
import unicodedata
from pathlib import Path

import pytest

from xaidr.value_origin import (MatchKind, SourceDesignation, bind_fresh_ledger,
                                evaluate_call, extract_destinations, record_principal_input,
                                record_tool_result, unbind_ledger)
from xaidr.value_origin._extract import key_ngram, tokens

CORE = Path(__file__).resolve().parents[1] / "xaidr" / "value_origin"


def _readings(v):
    return [f.destination.key() if f.destination is not None else f.reason.value
            for f in extract_destinations({"v": v})[0]]


def test_the_core_never_calls_the_interpreters_url_parser():
    calls = []
    for path in sorted(CORE.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            name = (node.func.attr if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    else node.func.id if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    else None)
            if name in ("urlsplit", "urlparse", "urlunsplit", "urljoin"):
                calls.append(f"{path.name}:{node.lineno} {name}")
    assert not calls, f"the core calls the interpreter's URL parser: {calls}"


# CPython 3.12.2's urlsplit reads each of these; 3.10.22, 3.12.15 and 3.14.9 refuse
# them (a bracket that does not end the host).
@pytest.mark.parametrize("v,want", [
    ("http://[::5]q.example/", ["ip:::5", "dns:[::5]q.example"]),
    ("scheme://[::6].tail", ["ip:::6"]),
    ("https://[fe80::9]-80/x", ["ip:fe80::9", "dns:[fe80::9]-80"]),
])
def test_a_bracket_later_patch_releases_refuse_reads_as_3_12_2_reads_it(v, want):
    assert _readings(v) == want


def test_the_principals_own_bracket_value_authorizes_on_every_interpreter():
    v = "scheme://[::6].tail"
    bind_fresh_ledger()
    try:
        record_principal_input(v, None, input_clean=True)
        wire = evaluate_call("open", {"target": v}, flow_active=True).wire.value
    finally:
        unbind_ledger()
    assert wire == "principal_undeclared_span", wire


def test_a_url_prefix_designation_reads_the_same_split():
    """A read through a designated source is trusted by the core's own split of the
    URL: a bracket only around a whole IPv6 literal, no userinfo, no backslash."""
    from xaidr.value_origin._designations import _url_prefix_match
    assert _url_prefix_match("http://[::5]/docs/a", "http://[::5]/docs")
    for v in ("http://[::5]q/docs/a", "http://[::5]\\@x/docs/a", "http://u@[::5]/docs/a",
              "http://[fe80::5%25en0]/docs/a", "http://[::5]:99999/docs/a",
              "http://[::5]/docs\\..\\..\\x"):
        assert not _url_prefix_match(v, "http://[::5]/docs"), v


# Letters and digits Unicode added after 13.0. On 3.10 (Unicode 13.0) each is
# unassigned; a newer interpreter calls it a letter or a digit.
_NEWER = ["\U0001E290",     # TOTO LETTER PA (14.0)
          "\U00011F04",     # KAWI LETTER A (15.0)
          "\U0001E4D0",     # NAG MUNDARI LETTER O (15.0)
          "\U0001E4F0"]     # NAG MUNDARI DIGIT ZERO (15.0)


def test_the_newer_code_points_here_are_unassigned_in_13_0():
    from xaidr.value_origin._idna import assigned
    assert not any(assigned(c) for c in _NEWER)
    if unicodedata.unidata_version >= "15":
        assert all(c.isalnum() for c in _NEWER), unicodedata.unidata_version


@pytest.mark.parametrize("c", _NEWER)
def test_a_code_point_13_0_leaves_unassigned_is_no_letter_to_the_reader(c):
    # A scheme-less host needs letters, digits and hyphens: with it, no host.
    assert _readings(f"a{c}.example/x") == []
    assert _readings(f"x.a{c}/x") == []
    # Prose: the bare-host and mailbox patterns stop at it, as on 3.10.
    bind_fresh_ledger()
    try:
        record_tool_result("web_fetch", {"q": "x"}, f"see a{c}.example and bob@a{c}.example",
                           designations=(), result_blocked=False)
        wire = evaluate_call("http_get", {"url": f"a{c}.example/x"}, flow_active=True).wire.value
    finally:
        unbind_ledger()
    assert wire == "no_destination", wire


def test_a_code_point_13_0_leaves_unassigned_is_not_case_folded():
    """U+A7C0 (14.0) folds to U+A7C1 on a newer interpreter and to itself on 3.10;
    a key token keeps it, and splits at it, as 3.10 does."""
    assert tokens("Ref Ꟁ-7 ok") == ["ref", "-7", "ok"]
    assert key_ngram("Ꟁ") is None


def test_a_designation_does_not_trust_a_value_with_two_readings():
    from xaidr.value_origin._ledger import _read_trust, _KeyPlan  # noqa: F401
    from xaidr.value_origin._designations import source_matches
    d = SourceDesignation(tool="web_fetch", label="docs", match=MatchKind.URL_PREFIX,
                          source_arg="url", pattern="https://docs.northbank.example/")
    assert source_matches(d, "web_fetch", {"url": "https://docs.northbank.example/a"})
    assert not source_matches(d, "web_fetch",
                              {"url": "https://docs.northbank.example\\x.attacker.test/a"})


# httpx, urllib3 and requests lowercase a host with the interpreter's own
# ``str.lower``: on 3.14.9 all three send these to the lowercased name (measured
# 2026-10-24), and on 3.10.22 all three refuse them. The reading is every
# interpreter's, read on every interpreter, the principal's text included.
@pytest.mark.parametrize("v,sent", [
    ("http://aꟋ.example/", "dns:xn--a-y1a.example"),   # U+A7CB (16.0) -> U+0264
    ("http://aꟜ.example/", "dns:xn--a-hqa.example"),   # U+A7DC (16.0) -> U+019B
])
def test_a_name_a_newer_interpreters_str_lower_makes_is_read_on_every_interpreter(v, sent):
    from xaidr.value_origin._authority import classify_value
    res = classify_value(v, arg_mode=True, stdlib=False)
    keys = [a.key() for a in (res if isinstance(res, list) else [res])]
    assert sent in keys, (
        f"{v!r}: httpx on 3.14 sends to {sent}; the principal's reading here is {keys}, "
        "so whether a principal's URL authorizes the call would follow the interpreter")
    assert [f.destination.key() for f in extract_destinations({"v": v})[0]][1] == sent
