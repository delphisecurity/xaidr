"""No docstring or comment in the package may describe how to reproduce a fix.

THE DEFECT. A fix's explanation was written where the fix lives: in the
docstring and comments of the module that replaced a bad pattern. The text named
the retired pattern, the input that triggered it, and how long that input took.
Every ``.py`` under ``xaidr/`` ships verbatim in the wheel and the sdist, and a
published file on PyPI cannot be edited, so that text stays readable in every
release that carried it for as long as the release is up. Retiring the pattern
does not retire the text: an installation pinned to a version that still has the
pattern is reading its own reproduction recipe.

Neither earlier gate sees it. ``tests/test_rule_asset_annotations.py`` refuses
annotation keys in the rule JSONs and reads nothing else. The release runbook's
step 3a scans the built wheel with ``--exclude='*.py'``, and its advisory shape
wants the timing directly beside the size, so on the tree this gate was written
against it matched none of these sites even with ``.py`` included.

WHY SHAPES AND NOT STRINGS. A test that searched for the trigger would have to
contain it, and this file ships in the sdist. So it looks for the two shapes the
leak takes, never its words:

  TIMING_NEAR_SIZE    a duration (a number with ms, s, seconds, ...) within
                      ``NEAR`` characters of an input size (a number with chars,
                      characters, bytes, k, KB, or a count of spaces, tabs or
                      newlines). That is "this input takes this long".
  RETIRED_NEAR_QUOTE  a reference to a retired, old, original, previous, former
                      or legacy pattern or regex within ``NEAR`` characters of a
                      quoted literal. That is the pattern itself, quoted where
                      it is discussed.

Spaces, tabs and newlines are on the size side because a trigger is often
counted in the one character it repeats rather than in characters; a size list
without them did not match one of the two sites this gate was written for.

``NEAR`` is measured on the text with whitespace runs and comment markers
collapsed, so a pairing broken across lines is still one pairing. It is two
80-column lines. It was set before the scan was first run and is not a knob for
shortening the allowlist.

WHAT IT DOES NOT CATCH. A pattern written as an indented block rather than
quoted, a timing given in words ("a minute"), a size with no unit, or a pairing
in an allowlisted scope rewritten one for one so the count does not move. The
shapes are a floor, not a review.

FALSE POSITIVES ARE EXPECTED. A legitimate performance note pairs a timing with
a size too. Each one is allowlisted individually below, with a reason and the
exact number of PAIRS in its scope, so a new pairing added to an allowlisted
scope still fails, including one added inside the very block that was
allowlisted. Counting blocks instead of pairs missed exactly that: one of the
sites this gate was written for sat in the same comment as a legitimate
calibration note.

The failure message names the file, the line, the scope and the shape. It never
prints the text: CI logs on a public repository are public, and printing what
this gate exists to keep out of the package would publish it somewhere else.
"""
from __future__ import annotations

import ast
import io
import pathlib
import re
import tokenize

REPO = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = REPO / "xaidr"

NEAR = 160

TIMING_NEAR_SIZE = "timing-near-size"
RETIRED_NEAR_QUOTE = "retired-near-quote"

_NUMBER = r"\b\d[\d,]*(?:\.\d+)?\s*-?\s*"
_TIMING = re.compile(
    _NUMBER + r"(?:ms|milliseconds?|s|secs?|seconds?|us|µs|microseconds?"
    r"|ns|nanoseconds?|mins?|minutes?)\b",
    re.IGNORECASE)
_SIZE = re.compile(
    _NUMBER + r"(?:chars?|characters?|bytes?|k|[kmg]i?b|spaces?|tabs?"
    r"|newlines?)\b",
    re.IGNORECASE)
_RETIRED_REF = re.compile(
    r"\b(?:retired|old|older|original|previous|prior|former|legacy|earlier)"
    r"\s+(?:[\w-]+\s+){0,2}?(?:patterns?|regex(?:es|ps?)?|expressions?)\b",
    re.IGNORECASE)
_QUOTED = re.compile(
    r"``[^`\n]+``|`[^`\n]+`|(?<![\w'])'[^'\n]{1,80}'(?![\w'])|\"[^\"\n]{1,80}\"")

_SHAPES = {
    TIMING_NEAR_SIZE: (_TIMING, _SIZE),
    RETIRED_NEAR_QUOTE: (_RETIRED_REF, _QUOTED),
}

# (file under xaidr/, scope, shape) -> (pairs in that scope, why it is allowed).
#
# An entry is a claim that the pairing describes what the code does now, not
# what used to break it. The count is exact and counts PAIRS, not prose blocks:
# a timing or size added anywhere near the other half raises it, so the scope
# fails until someone reads the new text and raises the count with a reason.
_ALLOWED = {
    ("autopatch/__init__.py", "protect", TIMING_NEAR_SIZE): (2, (
        "the COST paragraph: the size is the ONNX model artifact that "
        "enable_nano=True loads, and the timings are protect() with and without "
        "loading it. A startup cost of the call being documented; no scanner "
        "input is involved."
    )),
    ("scanner/l1.py", "<module>", TIMING_NEAR_SIZE): (2, (
        "the calibration of _L1_RULE_SLOW_SEC: the slowest single CURRENT rule "
        "on an input at L1_MAX_SCAN_CHARS, and the threshold set above it. It "
        "states the bound this code enforces and names no input."
    )),
    ("scanner/local.py", "<module>", TIMING_NEAR_SIZE): (2, (
        "the scanner's typical latency and its worst case at the input cap, on "
        "the current code: the bound the cap exists to provide, which an adopter "
        "sizes capacity against. It names the input class that reaches the "
        "bound, which the shapes cannot judge; whether that name should stay is "
        "a review call, and this entry is where to revisit it."
    )),
    ("scanner/nano.py", "<module>", TIMING_NEAR_SIZE): (4, (
        "inference cost of the opt-in classifier by sequence length, and the "
        "share of it spent tokenising an input at the scan cap. Model cost on "
        "honest input, the figure an adopter needs to choose MAX_LENGTH; the "
        "table's last column header also lands beside its unit row once "
        "whitespace is collapsed."
    )),
}


def _scopes(tree):
    """(first line, last line, qualname) of every def and class, outermost first."""
    out = []

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)):
                name = f"{prefix}{child.name}"
                out.append((child.lineno, child.end_lineno, name))
                visit(child, f"{name}.")
            else:
                visit(child, prefix)

    visit(tree, "")
    return out


def _scope_of(scopes, line):
    inner = "<module>"
    for first, last, name in scopes:
        if first <= line <= last:
            inner = name  # outermost first, so the last containing one wins
    return inner


def _prose_blocks(source):
    """Yield (line, scope, kind, text) for every docstring and comment block.

    A docstring is any statement that is a bare string, which covers module,
    class and function docstrings and attribute docstrings. A comment block is a
    run of comments on consecutive lines, joined, so a sentence that wraps
    across ``#`` lines is read as one sentence.
    """
    tree = ast.parse(source)
    scopes = _scopes(tree)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            yield (node.lineno, _scope_of(scopes, node.lineno), "docstring",
                   node.value.value)

    block, start, prev = [], None, None
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type != tokenize.COMMENT:
            continue
        line = tok.start[0]
        if block and line != prev + 1:
            yield start, _scope_of(scopes, start), "comment", " ".join(block)
            block = []
        if not block:
            start = line
        block.append(tok.string.lstrip("#"))
        prev = line
    if block:
        yield start, _scope_of(scopes, start), "comment", " ".join(block)


def _pairings(text):
    """``{shape: pairs}`` for every shape ``text`` exhibits, where a pair is one
    match of each half within ``NEAR`` characters of the other."""
    flat = re.sub(r"\s+", " ", text)
    found = {}
    for shape, (left, right) in _SHAPES.items():
        a = [m.span() for m in left.finditer(flat)]
        b = [m.span() for m in right.finditer(flat)]
        pairs = sum(1 for s1, e1 in a for s2, e2 in b
                    if max(s2 - e1, s1 - e2, 0) <= NEAR)
        if pairs:
            found[shape] = pairs
    return found


def _package_sources():
    return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def _hits():
    """Every (file, line, scope, kind, shape, pairs) in the package."""
    hits = []
    for path in _package_sources():
        rel = path.relative_to(PACKAGE).as_posix()
        source = path.read_text(encoding="utf-8")
        for line, scope, kind, text in _prose_blocks(source):
            for shape, pairs in _pairings(text).items():
                hits.append((rel, line, scope, kind, shape, pairs))
    return hits


def _counts(hits):
    """Pairs per (file, scope, shape), the unit _ALLOWED is written in."""
    counts = {}
    for rel, _line, scope, _kind, shape, pairs in hits:
        key = (rel, scope, shape)
        counts[key] = counts.get(key, 0) + pairs
    return counts


def test_each_shape_matches_its_own_kind_of_sentence():
    """Non-vacuity: a shape that cannot match reports a clean package.

    The samples are invented and describe nothing in this package.
    """
    one = {TIMING_NEAR_SIZE: 1}
    assert _pairings("a 64 KB body parses in 3 ms") == one
    assert _pairings("parsing a 900-character header took 2.5 seconds") == one
    assert _pairings("40 tabs in a row took 9 s") == one
    assert _pairings("the original regex ``x+y`` was replaced") == {
        RETIRED_NEAR_QUOTE: 1}
    assert _pairings("the retired pattern matched `ab`") == {
        RETIRED_NEAR_QUOTE: 1}
    # each half alone is not a pairing
    assert _pairings("a cap of 4096 characters") == {}
    assert _pairings("the timeout is 30 seconds") == {}
    assert _pairings("the old pattern is gone") == {}
    # and the halves have to be near each other
    assert _pairings("3 ms " + "x " * NEAR + "64 KB") == {}


def test_a_pairing_added_to_an_allowlisted_block_raises_its_count():
    """The allowlist counts pairs, so it cannot be satisfied by a block that
    keeps its legitimate note and gains a second claim beside it. Counting
    blocks would see one block before and one block after."""
    legitimate = "the slowest rule takes 3 ms on a 64 KB input."
    assert _pairings(legitimate) == {TIMING_NEAR_SIZE: 1}
    grown = legitimate + " Another input of 900 chars took 9 s."
    assert _pairings(grown)[TIMING_NEAR_SIZE] > 1


def test_a_pairing_split_across_lines_is_still_found():
    """Prose wraps. A gate that read line by line would miss a sentence whose
    timing ends one ``#`` line and whose size starts the next."""
    source = (
        "def f():\n"
        "    # a body of 64 KB\n"
        "    # parses in 3 ms\n"
        "    '''a 900-character header\n"
        "    takes 2 seconds'''\n"
        "    return 1\n"
    )
    blocks = list(_prose_blocks(source))
    assert [(line, scope, kind) for line, scope, kind, _ in blocks] == [
        (4, "f", "docstring"), (2, "f", "comment")]
    assert all(_pairings(text) == {TIMING_NEAR_SIZE: 1} for *_, text in blocks)


def test_the_scan_scope_is_not_empty():
    """An empty scope has no leaks and would pass. The package has dozens of
    modules and hundreds of prose blocks; a walk that finds a handful is broken."""
    sources = _package_sources()
    assert len(sources) > 30, f"only {len(sources)} .py files under {PACKAGE}"
    blocks = [b for p in sources
              for b in _prose_blocks(p.read_text(encoding="utf-8"))]
    kinds = {kind for _, _, kind, _ in blocks}
    assert kinds == {"docstring", "comment"}, kinds
    assert len(blocks) > 500, f"only {len(blocks)} prose blocks in the package"


def test_no_docstring_or_comment_describes_how_to_reproduce_a_fix():
    hits = _hits()
    counts = _counts(hits)
    unexpected = sorted(
        h for h in hits
        if counts[(h[0], h[2], h[4])] > _ALLOWED.get((h[0], h[2], h[4]),
                                                     (0, ""))[0])
    assert not unexpected, (
        f"{len(unexpected)} docstring/comment pairing(s) under xaidr/ have the "
        "shape of a reproduction recipe, and every .py there ships verbatim in "
        "the wheel and the sdist. A published file cannot be edited, so text "
        "that reaches a release stays readable for as long as that release "
        "is up.\n  "
        + "\n  ".join(f"xaidr/{rel}:{line} {scope} [{kind}, {shape}, "
                      f"{pairs} pair(s); scope allows "
                      f"{_ALLOWED.get((rel, scope, shape), (0, ''))[0]}]"
                      for rel, line, scope, kind, shape, pairs in unexpected)
        + "\nRewrite the text to say what the code does now. If the reason for "
        "its shape cannot be given without naming what used to break it, say "
        "the shape is deliberate and leave the reason out. If the pairing is a "
        "legitimate performance note, add it to _ALLOWED with the exact pair "
        "count for its scope and a reason.")


def test_the_allowlist_has_no_stale_entries():
    """An entry whose pairing is gone is an exemption waiting for new text.

    Without this, a scope that is cleaned up keeps its permission, and the next
    pairing written there inherits a reason given for different prose.
    """
    counts = _counts(_hits())
    stale = sorted(f"xaidr/{rel} {scope} [{shape}]: allowed {n}, found "
                   f"{counts.get((rel, scope, shape), 0)}"
                   for (rel, scope, shape), (n, _why) in _ALLOWED.items()
                   if counts.get((rel, scope, shape), 0) < n)
    assert not stale, (
        "_ALLOWED entries that describe more pairings than the scope has — the "
        "prose was rewritten or removed and the exemption outlived it:\n  "
        + "\n  ".join(stale))
