"""Rule assets must load from a SHALLOW stack, and exactly once.

Two guards, both written against a defect that shipped.

THE DEFECT. ``scanner/normalizer.py`` re-read ``typo-keywords.json`` on every
``TypoNormalizer()``, i.e. every ``LocalScanner``, i.e. every ``Sensor``. The
read went through ``json.load``, which is a thin wrapper that calls the MODULE
GLOBAL ``json.loads`` — so each Sensor construction re-entered whatever
``json.loads`` was bound to at that instant. The loader's ``except Exception``
then turned any fault in that window into "normalization disabled", recorded in
the process-global registry in ``failclosed`` that nothing ever clears.

One transient fault therefore disabled the typo normaliser for the REST OF THE
PROCESS, and made every later Sensor report a degradation it had nothing to do
with. On CI, where the whole suite is a single process,
``tests/test_cleanup_a9_a5.py`` (which patches ``json.loads`` to raise, to prove
the A2A extractor survives it, and builds a Sensor inside the patched window)
poisoned ``test_open_posture_is_the_default_and_unchanged`` several thousand
tests later — reporting a ``RecursionError`` that nothing in the scanner raised.

WHAT DISABLING THE NORMALISER COSTS, measured by running with ``_TYPO_CONFIG``
emptied — the exact value ``_read_typo_config`` returns when the asset fails to
load. 37 tests fail; 36 of them are the cost, and the 37th is
``test_building_a_sensor_under_a_broken_json_does_not_disable_normalization``
below correctly detecting the simulated condition. The breakdown, so the next
person does not re-derive it from a partial sweep:

    12  test_unicode_normalization.py   obfuscated attacks NOT CAUGHT — six
                                        shapes x both surfaces (scan, scan_a2a):
                                        leetspeak, dot/underscore/dash separator
                                        evasion, homoglyph+separator
    19  test_normalizer_fast_path.py    the fold itself
     2  test_bs5_normalizer_completeness.py
     1  test_normalizer.py              leetspeak fold
     1  test_override_paraphrase.py     real typos stop folding
     1  test_security_invariants.py     leetspeak evasion defeats the sensor

The 12 are the ones that matter: a silent, total loss of the de-obfuscation
layer, so it must not be reachable by accident.

AND WHAT THE CORPORA SEE OF THAT: nothing. The same measurement over all five
shipped corpus reports (``corpus_report``, ``asi_battery_report``,
``heldout_report``, ``benign_toolcall_report``, ``benign_a2a_report``) moves ZERO
verdicts; one already-missed item (ASI02-A08) drops 0.15 to 0.00 and no headline
changes. That is a fact about the corpora, not a reason to relax: the published
pools contain no obfuscated phrasing, so they cannot see this layer fail, and
the 36 tests above — and the 12 in particular — are the ONLY thing standing
between a failed asset load and a silent detection loss. Do not move a
de-obfuscation gate out of pytest and into a corpus report on the assumption
the report would catch it.
"""

from __future__ import annotations

import glob
import json
import json.decoder
import json.scanner
import os
import sys
from contextlib import contextmanager

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(ROOT, "xaidr", "rules")

# The structural bound. Asserted directly so the failure message can say WHICH
# asset got deep rather than only that something ran out of stack.
MAX_ASSET_NESTING_DEPTH = 12

# A decoder pinned to the PURE-PYTHON scanner. This is the whole point of the
# recursion-limit gate and it is not an implementation detail.
#
# `json.loads` uses the `_json` C accelerator, whose recursion is bounded by its
# own budget rather than by `sys.setrecursionlimit` — entirely so on CPython
# 3.12+, where the C and Python recursion counters were split, and at roughly
# half the pure-Python cost on 3.10/3.11. A gate written against `json.loads`
# therefore barely fails on depth at all — the passes-vacuously shape, reading
# as coverage while performing none. That is exactly what this file shipped
# before: `test_the_parser_under_test_is_the_pure_python_scanner` below is the
# guard-on-the-guard, and it goes red if this is switched back.
#
# The pure-Python scanner is also the STRICTER of the two and it is a path real
# users take (any build without the C extension), so gating against it covers
# both.
_PY_DECODER = json.decoder.JSONDecoder()
_PY_DECODER.scan_once = json.scanner.py_make_scanner(_PY_DECODER)


def _py_loads(text: str):
    """`json.loads`, forced onto the recursive-descent Python scanner."""
    return _PY_DECODER.decode(text)


def _nest(depth: int) -> str:
    """An object-rooted JSON document nested exactly ``depth`` deep."""
    doc = "1"
    for _ in range(depth):
        doc = '{"k":' + doc + "}"
    return doc


def _assets() -> list:
    return sorted(glob.glob(os.path.join(RULES_DIR, "*.json")))


@contextmanager
def _recursion_limit(limit: int):
    """Run the body under an ABSOLUTE ``sys.setrecursionlimit(limit)``.

    LOWERS the limit for the duration — the opposite of the fix nobody should
    reach for. Raising ``sys.setrecursionlimit`` moves the cliff; this walks up
    to the cliff on purpose so a deep asset falls off it here, in CI, instead of
    on a user's stack.

    ABSOLUTE, NOT RELATIVE TO THE CURRENT DEPTH, and that is the whole point of
    the rewrite this file went through. The previous form was
    ``sys.setrecursionlimit(len(f_back chain) + frames)``, i.e. "leave exactly
    N frames of headroom". That is only the headroom it claims to be if the
    interpreter's recursion counter equals the length of the ``f_back`` chain,
    and on CPython <= 3.11 it does not — the counter also advances for C-level
    recursion that creates no Python frame. Measured inside a pytest run on
    3.11.16: ``f_back`` chain 35, interpreter-reported depth 42. Seven frames
    the walk cannot see, and the number differs between the module-import stack
    and the test-call stack, so a headroom measured at one site was short by one
    frame when spent at the other. See ``_parses_under``.
    """
    old = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(limit)
    except RecursionError:  # pragma: no cover - only on a pathologically deep host
        raise RuntimeError(
            f"cannot lower the recursion limit to {limit}: this process is "
            "already deeper than that. The limits in this file assume an "
            "ordinary pytest stack (tens of frames, not hundreds)."
        ) from None
    try:
        yield
    finally:
        sys.setrecursionlimit(old)


def _nesting_depth(text: str) -> int:
    """Max bracket nesting of a JSON document, ignoring brackets inside strings."""
    depth = best = 0
    in_str = esc = False
    for ch in text:
        if esc:
            esc = False
            continue
        if in_str:
            if ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            best = max(best, depth)
        elif ch in "]}":
            depth -= 1
    return best


def _parses_under(text: str, limit: int, loads=None) -> bool:
    """Does ``text`` parse with the recursion limit pinned to ``limit``?

    AN OUTCOME, NOT A MEASUREMENT. It answers "did the parser get through it",
    which is the only thing this file has ever actually needed to know, and it
    is the same answer on every interpreter.
    """
    if loads is None:
        loads = _py_loads
    with _recursion_limit(limit):
        try:
            loads(text)
            return True
        except RecursionError:
            return False


# The total recursion limit a rule asset must load under.
#
# NOT a tuning knob and NOT a limit to raise. xaidr is a library: it is called
# from inside host frameworks, recursive document walkers and deep middleware
# stacks, so the stack left when our loader runs is the HOST's business, not
# ours. An asset that needs a deep stack to parse is an asset that fails on
# somebody else's call graph and nowhere in our tests.
#
# THE NUMBER IS ABSOLUTE AND IT IS CHOSEN FOR ITS MARGINS, not fitted to an
# interpreter. Measured with `_py_loads` at an ambient depth of 1, on all three
# supported CPythons — the cost is 2*depth + 7, and 2*depth + 6 on 3.12, so the
# three agree to within one frame at every depth:
#
#     document nested   12    needs limit    31        the permitted depth
#     document nested  240    needs limit   487        MAX * 20
#     document nested  500    needs limit  1007        GROSSLY_NESTED_DEPTH
#     the 7 shipped assets    need limits 11..19
#
# 400 therefore sits with a ~20x margin above every asset we ship and a ~2.5x
# margin below a grossly nested one. An ordinary pytest stack is a few tens of
# frames, so the ambient depth moves the effective figure by tens against
# margins of hundreds — which is exactly the property the previous form lacked.
#
# WHY NOT A TIGHT PER-FRAME BUDGET, since one would be stricter. Because this
# file has now tried that three times and it does not survive contact with the
# interpreter. The history, so nobody fits a fourth one:
#
#   1. `2 * MAX_ASSET_NESTING_DEPTH + 3 = 27`, a constant fitted to CPython
#      3.12's frame cost. Depth 12 costs one more frame on 3.10/3.11, so the
#      permitted depth was unreachable there and four of six pytest jobs went
#      red.
#   2. The budget measured at import instead of fitted. Green standalone on all
#      three versions, red on py3.11 in the full suite: a headroom measured on
#      the collection stack was spent on the test-call stack.
#   3. The budget measured per call, at the point of use. Same failure.
#
# All three were the same error. `recursion_headroom(n)` computed the limit as
# `len(f_back chain) + n`, and on CPython <= 3.11 the interpreter's recursion
# counter is NOT the f_back chain length — C-level recursion advances it
# without creating a Python frame. Measured inside a pytest run on 3.11.16:
# f_back 35, interpreter depth 42; budget measured at import 32, cost of the
# same document at test time 33. One frame short, every time, on one
# interpreter. The gap is invisible from Python and varies with the call path,
# so it is not a measurement that can be refined — it is a quantity the
# assertion was never entitled to use. 3.12 is green because it split the C and
# Python recursion counters, which makes the f_back walk correct there.
#
# The exact depth bound that a per-frame budget was reaching for is enforced
# directly and deterministically by `test_asset_nesting_depth_is_bounded`, which
# counts brackets and needs no interpreter cooperation at all.
RECURSION_LIMIT_FOR_ASSET_LOAD = 400

# What "grossly nested" means for the non-vacuity check below. Deep enough that
# no plausible ambient stack changes the answer.
GROSSLY_NESTED_DEPTH = 500


# ── the guard the next deeply-nested asset trips ─────────────────────────────

def test_the_asset_set_is_not_empty():
    """The vacuity guard. A glob that matches nothing passes every test below."""
    found = _assets()
    assert len(found) >= 7, (
        f"only {len(found)} JSON assets under {RULES_DIR} — this gate has "
        "stopped covering the rule assets it exists for."
    )


@pytest.mark.parametrize("path", _assets(), ids=lambda p: os.path.basename(p))
def test_asset_loads_under_a_hard_recursion_limit(path):
    """Every shipped rule asset must parse from a deliberately shallow stack."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    assert _parses_under(text, RECURSION_LIMIT_FOR_ASSET_LOAD), (
        f"{os.path.basename(path)} nests {_nesting_depth(text)} deep and "
        f"cannot be parsed under a recursion limit of "
        f"{RECURSION_LIMIT_FOR_ASSET_LOAD}. xaidr is called from inside host "
        "stacks, so this asset would fail to load on a deep caller and "
        "silently degrade the layer that reads it. FLATTEN THE ASSET — do not "
        "raise sys.setrecursionlimit, which moves the cliff instead of "
        "removing it."
    )


# ── the guard on the guard ───────────────────────────────────────────────────

def test_a_grossly_nested_asset_is_refused():
    """The limit above MUST reject something. Stated as an outcome, not a count.

    The discriminating direction, and the one the first version of this file
    skipped. `test_asset_loads_under_a_hard_recursion_limit` going green proves
    the shipped assets are shallow OR proves nothing at all, and it cannot tell
    you which — a limit that no input can exhaust passes on every asset forever.

    BOTH HALVES ARE THE SAME CALL WITH THE SAME LIMIT, differing only in the
    document. That is what makes this portable: nothing here depends on how many
    frames either parse took, on where in the stack the test was called from, or
    on what ran before it in the process. `_py_loads` either gets through the
    document under a limit of 400 or it does not, and the measured costs (31 for
    the conforming document, 1007 for the grossly nested one) put both answers
    an order of magnitude clear of any ambient stack this runs on.
    """
    conforming = _nest(MAX_ASSET_NESTING_DEPTH)
    assert _parses_under(conforming, RECURSION_LIMIT_FOR_ASSET_LOAD), (
        f"a document at the permitted depth of {MAX_ASSET_NESTING_DEPTH} does "
        f"not parse under a limit of {RECURSION_LIMIT_FOR_ASSET_LOAD}. The "
        "bound is unreachable, so the gate rejects assets that conform to it."
    )

    grossly_nested = _nest(GROSSLY_NESTED_DEPTH)
    assert not _parses_under(grossly_nested, RECURSION_LIMIT_FOR_ASSET_LOAD), (
        f"a document nested {GROSSLY_NESTED_DEPTH} deep parsed under a limit "
        f"of {RECURSION_LIMIT_FOR_ASSET_LOAD}. The limit no longer separates a "
        "conforming asset from a grossly nested one, so every asset passes "
        "vacuously."
    )


def test_the_depth_counter_is_not_vacuous():
    """`_nesting_depth` is now the exact bound; it must actually count.

    With the per-frame budget gone, `test_asset_nesting_depth_is_bounded` is the
    only thing asserting the EXACT limit of 12 — the recursion limit above has
    deliberately wide margins and would wave a depth-13 asset straight through.
    So the counter carries that weight alone, and a counter that returned 0 for
    everything would make it green forever.
    """
    assert _nesting_depth(_nest(MAX_ASSET_NESTING_DEPTH)) == MAX_ASSET_NESTING_DEPTH
    assert _nesting_depth(_nest(MAX_ASSET_NESTING_DEPTH + 1)) > MAX_ASSET_NESTING_DEPTH
    assert _nesting_depth('{"a": 1}') == 1
    assert _nesting_depth('{"a": [1, 2]}') == 2
    # Brackets inside strings are not nesting, and must not be counted as it —
    # a rule asset is mostly regex patterns full of `[` and `{`.
    assert _nesting_depth('{"pattern": "[a-z]{2,3}"}') == 1
    assert _nesting_depth('{"pattern": "\\\\[[{{{"}') == 1


def test_the_parser_under_test_is_the_pure_python_scanner():
    """Why `_py_loads` and not `json.loads`, asserted rather than commented.

    `json.loads` dispatches to the `_json` C accelerator, whose recursion is
    bounded by its own budget and not by `sys.setrecursionlimit` — completely so
    on CPython 3.12+, where the C and Python recursion counters were split, and
    partially on 3.10/3.11, where it is roughly HALF the pure-Python cost. Under
    the limit this file sets, measured at an ambient depth of 1:

        depth 240   `_py_loads` needs limit 487     `json.loads` needs 246
        depth 500   `_py_loads` needs limit 1007    `json.loads` needs 506
        3.12: `json.loads` needs limit 5 at EVERY depth — entirely ungoverned.

    So a document nested `MAX_ASSET_NESTING_DEPTH * 20` deep is refused by the
    scanner we use and accepted by the one we do not, under the same limit, on
    all three supported versions. Without this test someone "simplifies"
    `_py_loads` back to `json.loads`, the whole file stays green, and the gate
    silently stops constraining anything.

    STATED AS THE PROPERTY, NOT AS A VERSION SPLIT. The previous form branched
    on `sys.version_info` and asserted each side, which is asserting the
    behaviour of interpreters rather than the requirement we have. The
    requirement is that the parser this gate runs is the one the limit governs,
    and that is checkable everywhere without knowing why.

    `MAX_ASSET_NESTING_DEPTH * 20` is not arbitrary and it is the tightest
    margin in this file: the contrast only exists for depths where the Python
    cost is over the limit and the C cost is still under it, which at a limit of
    400 is roughly depth 176 to 350. 240 sits in the middle of that window, a
    ~110-frame swing in the ambient stack from either edge. Everything else here
    has an order of magnitude; if you change the limit, re-derive this depth.
    """
    deep = _nest(MAX_ASSET_NESTING_DEPTH * 20)

    assert not _parses_under(deep, RECURSION_LIMIT_FOR_ASSET_LOAD), (
        f"a document nested {MAX_ASSET_NESTING_DEPTH * 20} deep parsed under a "
        f"limit of {RECURSION_LIMIT_FOR_ASSET_LOAD}. The parser this gate runs "
        "is not bounded by sys.setrecursionlimit — if `_py_loads` was switched "
        "to `json.loads`, switch it back."
    )
    assert _parses_under(deep, RECURSION_LIMIT_FOR_ASSET_LOAD, loads=json.loads), (
        "`json.loads` refused a document the C accelerator has always accepted "
        "under this limit. This test's premise — that the C path is the more "
        "permissive one, which is why the gate does not use it — no longer "
        "holds on "
        f"{'.'.join(str(v) for v in sys.version_info[:3])}; re-measure before "
        "changing anything above."
    )


@pytest.mark.parametrize("path", _assets(), ids=lambda p: os.path.basename(p))
def test_asset_nesting_depth_is_bounded(path):
    """THE EXACT BOUND, and since the per-frame budget was removed, the only one.

    The recursion limit above is a wide outcome check — it refuses a grossly
    nested asset and would pass a depth-13 one. This is what holds the line at
    exactly 12, it names the asset and its depth when it fires, and it needs no
    cooperation from the interpreter: it counts brackets.
    """
    with open(path, encoding="utf-8") as fh:
        depth = _nesting_depth(fh.read())
    assert depth <= MAX_ASSET_NESTING_DEPTH, (
        f"{os.path.basename(path)} nests {depth} deep, over the "
        f"{MAX_ASSET_NESTING_DEPTH} bound. Deep nesting in a rule asset is a "
        "load-time hazard on a deep host stack; flatten it."
    )


# ── the loader must not be re-enterable by a caller's json ───────────────────

def test_the_asset_is_read_once_at_import_not_per_sensor():
    """A Sensor construction must not touch the parser at all.

    This is the property that makes the poisoning above impossible: if building
    a Sensor never calls ``json.loads``, then nothing a caller has done to the
    json module can disable normalization.
    """
    import xaidr.scanner.normalizer as nz

    sentinel = {"all_keywords": ["ignore"], "denylist": []}
    original = nz._TYPO_CONFIG
    nz._TYPO_CONFIG = sentinel
    try:
        assert nz._load_typo_config() is sentinel, (
            "_load_typo_config() re-read the asset instead of returning the "
            "config parsed at import — the per-construction read is back."
        )
    finally:
        nz._TYPO_CONFIG = original


def test_building_a_sensor_under_a_broken_json_does_not_disable_normalization():
    """THE REGRESSION. Reproduces the CI failure in one test.

    A caller whose ``json.loads`` raises — a test patching it, an
    ``orjson``-style monkeypatch, a tracing shim — must not cost us the
    normaliser, and must not record an asset fault against a file that is fine.
    """
    from xaidr import Sensor
    from xaidr.failclosed import asset_faults

    class _NullReporter:
        def report(self, *a, **k): pass
        def close(self, *a, **k): pass

    before = len(asset_faults())
    real = json.loads
    json.loads = lambda *a, **k: (_ for _ in ()).throw(RecursionError())
    try:
        s = Sensor(agent_id="asset-load", reporter=_NullReporter())
    finally:
        json.loads = real

    try:
        # THE DELTA, NOT THE TOTAL. `degradations` reads a process-global
        # registry that legitimately carries entries from earlier tests —
        # `test_operational_resilience.py::test_corrupt_rule_asset_degrades_to_
        # empty_ruleset` corrupts a tmp copy of all-l1-rules.json on purpose and
        # records two faults, and it sorts before this file. Asserting the total
        # is empty asserts on the whole session's history, which is how the
        # first version of this test failed on CI while passing locally: the
        # same process-global-state trap as the defect it guards.
        new = asset_faults()[before:]
        assert not new, (
            "building a Sensor while json.loads was broken recorded "
            f"{[f.reason for f in new]}. The asset is read once at import; a "
            "construction must not re-enter the parser."
        )
        # And the normaliser is genuinely live, not merely unrecorded.
        assert s._scanner._normalizer.keywords, (
            "the normaliser loaded an EMPTY keyword set — normalization is off "
            "while reporting no degradation, which is worse than the original "
            "defect."
        )
    finally:
        s.close_sync()
