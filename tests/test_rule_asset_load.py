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
load. 35 tests fail, including 12 obfuscated-attack detections lost across BOTH
the ``scan`` and ``scan_a2a`` surfaces — leetspeak, dot/underscore/dash
separator evasion, and homoglyph+separator evasion. It is a silent, total loss
of the de-obfuscation layer, so it must not be reachable by accident.

AND WHAT THE CORPORA SEE OF THAT: nothing. The same measurement over all five
shipped corpus reports (``corpus_report``, ``asi_battery_report``,
``heldout_report``, ``benign_toolcall_report``, ``benign_a2a_report``) moves ZERO
verdicts; one already-missed item (ASI02-A08) drops 0.15 to 0.00 and no headline
changes. That is a fact about the corpora, not a reason to relax: the published
pools contain no obfuscated phrasing, so they cannot see this layer fail, and
the 35 tests above are the ONLY thing standing between a failed asset load and a
silent detection loss. Do not move a de-obfuscation gate out of pytest and into
a corpus report on the assumption the report would catch it.
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

# The headroom a rule asset must parse within, in PYTHON stack frames.
#
# NOT a tuning knob and NOT a limit to raise. xaidr is a library: it is called
# from inside host frameworks, recursive document walkers and deep middleware
# stacks, so the frames left when our loader runs are the HOST's business, not
# ours. An asset that needs a deep stack to parse is an asset that fails on
# somebody else's call graph and nowhere in our tests.
#
# DERIVED, not picked. `json.decoder`'s recursive-descent scanner costs a
# measured `2 * depth + 2` frames for an array-rooted document and one more for
# an object-rooted one, so the deepest asset `MAX_ASSET_NESTING_DEPTH` permits
# needs `2 * 12 + 3 = 27`. Measured on CPython 3.12.2, the shipped assets:
#
#     15  impact-classes.json   (nests 6)      9  all-l1-rules.json   (nests 3)
#     13  composite-rules.json  (nests 5)      9  typo-keywords.json  (nests 3)
#     11  attack-chains.json    (nests 4)      7  dangerous-intents.json
#                                              7  output-l1-rules.json
#
# The derivation is what keeps the two constants from contradicting each other.
# At the previous hand-picked 20, an asset at depth 10 or more satisfied
# MAX_ASSET_NESTING_DEPTH and could not satisfy this — a bound is not a bound if
# obeying it fails the neighbouring test.
RECURSION_BUDGET_FRAMES = 2 * MAX_ASSET_NESTING_DEPTH + 3


# A decoder pinned to the PURE-PYTHON scanner. This is the whole point of the
# budget test and it is not an implementation detail.
#
# `json.loads` uses the `_json` C accelerator, whose recursion is bounded by a
# FIXED C-stack budget that `sys.setrecursionlimit` does not govern on CPython
# 3.12+ (the C and Python recursion counters were split). Under the C scanner a
# 500-deep document parses with 20 Python frames available, so a budget test
# written against `json.loads` cannot fail on depth — it is the passes-vacuously
# shape, reading as coverage while performing none. That is exactly what this
# file shipped before: `test_the_recursion_budget_guard_actually_fires` below is
# the guard-on-the-guard, and it goes red if this is switched back.
#
# The pure-Python scanner is also the STRICTER of the two and it is a path real
# users take (any build without the C extension), so budgeting against it covers
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


def _stack_depth() -> int:
    n, f = 0, sys._getframe()
    while f is not None:
        n += 1
        f = f.f_back
    return n


@contextmanager
def recursion_headroom(frames: int):
    """Run the body with only ``frames`` stack frames left before the limit.

    LOWERS the limit for the duration — the opposite of the fix nobody should
    reach for. Raising ``sys.setrecursionlimit`` moves the cliff; this walks up
    to the cliff on purpose so a deep asset falls off it here, in CI, instead of
    on a user's stack.
    """
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(_stack_depth() + frames)
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


# ── the guard the next deeply-nested asset trips ─────────────────────────────

def test_the_asset_set_is_not_empty():
    """The vacuity guard. A glob that matches nothing passes every test below."""
    found = _assets()
    assert len(found) >= 7, (
        f"only {len(found)} JSON assets under {RULES_DIR} — this gate has "
        "stopped covering the rule assets it exists for."
    )


@pytest.mark.parametrize("path", _assets(), ids=lambda p: os.path.basename(p))
def test_asset_parses_within_a_conservative_recursion_budget(path):
    """Every shipped rule asset must parse from a nearly-exhausted stack."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        with recursion_headroom(RECURSION_BUDGET_FRAMES):
            _py_loads(text)
    except RecursionError:
        pytest.fail(
            f"{os.path.basename(path)} nests {_nesting_depth(text)} deep and "
            f"cannot be parsed with {RECURSION_BUDGET_FRAMES} stack frames "
            "available. xaidr is called from inside host stacks, so this asset "
            "would fail to load on a deep caller and silently degrade the "
            "layer that reads it. FLATTEN THE ASSET — do not raise "
            "sys.setrecursionlimit, which moves the cliff instead of removing it."
        )


# ── the guard on the guard ───────────────────────────────────────────────────

def test_the_recursion_budget_guard_actually_fires():
    """A document past the depth bound MUST be rejected by the budget above.

    The discriminating direction, and the one the first version of this file
    skipped. `test_asset_parses_...` going green proves the shipped assets are
    shallow OR proves nothing at all, and it cannot tell you which — a budget
    that no input can exhaust passes on every asset forever.

    Both sides are asserted here against the same mechanism the budget test
    uses, so the pair is: depth 12 (the bound) parses, depth 13 does not.
    """
    at_bound = _nest(MAX_ASSET_NESTING_DEPTH)
    assert _nesting_depth(at_bound) == MAX_ASSET_NESTING_DEPTH
    with recursion_headroom(RECURSION_BUDGET_FRAMES):
        _py_loads(at_bound)          # the bound is REACHABLE, not aspirational

    past_bound = _nest(MAX_ASSET_NESTING_DEPTH + 1)
    with pytest.raises(RecursionError):
        with recursion_headroom(RECURSION_BUDGET_FRAMES):
            _py_loads(past_bound)


def test_the_budget_is_measured_on_the_scanner_the_headroom_reaches():
    """Why `_py_loads` and not `json.loads`, asserted rather than commented.

    `json.loads` dispatches to the `_json` C accelerator, and on CPython 3.12+
    the C and Python recursion counters are separate: the accelerator is bounded
    by a FIXED C-stack budget that `sys.setrecursionlimit` does not govern. So
    on 3.12+ the headroom this file lowers never reaches it and a 240-deep
    document parses with 27 Python frames available — a budget test written
    against `json.loads` is the passes-vacuously shape, green on every asset
    forever. On 3.10/3.11 the counters were shared and the same call does raise,
    which is why this defect was invisible: it depended on the runner's Python.

    The pure-Python scanner behaves the same way on every supported version,
    which is the property the budget needs. Without this test someone
    "simplifies" `_py_loads` back to `json.loads`, the whole file stays green,
    and the guard silently stops constraining anything on the newest Python we
    ship for.
    """
    deep = _nest(MAX_ASSET_NESTING_DEPTH * 20)

    # The scanner we DO use: bounded by the headroom, on every version.
    with pytest.raises(RecursionError):
        with recursion_headroom(RECURSION_BUDGET_FRAMES):
            _py_loads(deep)

    # The scanner we do NOT use, and the version split that is the reason.
    if sys.version_info >= (3, 12):
        with recursion_headroom(RECURSION_BUDGET_FRAMES):
            json.loads(deep)         # no RecursionError — the C path ignores us
    else:
        with pytest.raises(RecursionError):
            with recursion_headroom(RECURSION_BUDGET_FRAMES):
                json.loads(deep)


@pytest.mark.parametrize("path", _assets(), ids=lambda p: os.path.basename(p))
def test_asset_nesting_depth_is_bounded(path):
    """The structural half, so the failure names the asset and its depth."""
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
